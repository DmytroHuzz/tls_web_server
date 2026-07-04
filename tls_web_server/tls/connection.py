"""Buffer-oriented client and server for the educational TLS-like protocol.

This file adapts the final TLS-series handshake to the web-server event loop.
The original TLS demo could call blocking functions like `recv_record(sock)`.
A non-blocking web server cannot do that, so both client and server expose the
same three-buffer pattern:

* `feed_wire_data(...)` accepts arbitrary TCP chunks;
* `pop_pending_wire_data()` returns handshake/application bytes to send;
* `read_plaintext()` returns decrypted HTTP bytes.

The cryptographic recap:

* X25519 ephemeral keys create a fresh shared secret per connection.
* The RSA identity key signs the ephemeral public keys to prove server identity.
* HKDF turns the shared secret into directional AES-GCM keys.
* AES-GCM records protect HTTP bytes after the handshake.
"""

from __future__ import annotations

from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .certificates import ServerIdentity, verify_server_certificate
from .framing import RecordBuffer, frame_payload
from .key_schedule import derive_session_keys
from .messages import (
    TAG_CERTIFICATE,
    TAG_CERTIFICATE_VERIFY,
    TAG_X25519_PUBLIC,
    decode_message,
    encode_message,
    first_field,
)
from .record_protection import protect_record, unprotect_record


class ToyTLSProtocolError(Exception):
    pass


def _sign_ephemeral_pubkeys_with_identity(
    identity_private_key: rsa.RSAPrivateKey,
    client_ephemeral_public_bytes: bytes,
    server_ephemeral_public_bytes: bytes,
) -> bytes:
    # CertificateVerify in this educational protocol signs the two ephemeral
    # public keys. This proves that the peer with the server certificate also
    # owns the matching private key for this specific key exchange.
    return identity_private_key.sign(
        client_ephemeral_public_bytes + server_ephemeral_public_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def _verify_ephemeral_pubkeys_with_identity(
    identity_public_key: rsa.RSAPublicKey,
    signature: bytes,
    client_ephemeral_public_bytes: bytes,
    server_ephemeral_public_bytes: bytes,
) -> None:
    identity_public_key.verify(
        signature,
        client_ephemeral_public_bytes + server_ephemeral_public_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


class ToyTLSServerConnection:
    """Buffer-oriented server side of the toy TLS-like protocol.

    The standalone TLS series used blocking `recv_record(sock)` calls. This
    class is the integration-friendly version: callers feed arbitrary TCP chunks
    and pull encrypted output / decrypted plaintext buffers.
    """

    WAIT_CLIENT_HELLO = "WAIT_CLIENT_HELLO"
    ESTABLISHED = "ESTABLISHED"

    def __init__(self, identity: ServerIdentity):
        self.identity = identity
        self.state = self.WAIT_CLIENT_HELLO
        self._records = RecordBuffer()
        self._pending_wire = bytearray()
        self._plaintext = bytearray()
        self._send_seq = 0
        self._recv_seq = 0
        self._client_write_key: Optional[bytes] = None
        self._server_write_key: Optional[bytes] = None

    @property
    def is_established(self) -> bool:
        return self.state == self.ESTABLISHED

    def feed_wire_data(self, data: bytes) -> None:
        if not data:
            return
        # TCP may split or merge records. RecordBuffer hides that detail and
        # yields only complete length-prefixed TLS-like records.
        self._records.feed(data)
        while True:
            record = self._records.pop_record()
            if record is None:
                return
            if self.state == self.WAIT_CLIENT_HELLO:
                self._handle_client_hello(record)
            elif self.state == self.ESTABLISHED:
                self._handle_application_record(record)
            else:
                raise ToyTLSProtocolError(f"Unexpected server TLS state: {self.state}")

    def pop_pending_wire_data(self) -> bytes:
        data = bytes(self._pending_wire)
        self._pending_wire.clear()
        return data

    def read_plaintext(self) -> bytes:
        data = bytes(self._plaintext)
        self._plaintext.clear()
        return data

    def protect_application_data(self, plaintext: bytes) -> bytes:
        if not self.is_established or self._server_write_key is None:
            raise ToyTLSProtocolError("Cannot send application data before TLS is established")
        protected = protect_record(self._server_write_key, self._send_seq, plaintext)
        self._send_seq += 1
        return frame_payload(protected)

    def _handle_client_hello(self, record: bytes) -> None:
        fields = decode_message(record)
        client_ephemeral_public_bytes = first_field(fields, TAG_X25519_PUBLIC)
        client_ephemeral_public = X25519PublicKey.from_public_bytes(client_ephemeral_public_bytes)

        # Generate a fresh server ephemeral key for this connection. This is
        # discarded after the shared secret is derived, giving forward secrecy in
        # the same simplified sense as the original TLS series.
        server_ephemeral_private = X25519PrivateKey.generate()
        server_ephemeral_public_bytes = server_ephemeral_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        server_hello = encode_message([(TAG_X25519_PUBLIC, server_ephemeral_public_bytes)])
        self._pending_wire.extend(frame_payload(server_hello))

        signature = _sign_ephemeral_pubkeys_with_identity(
            self.identity.private_key,
            client_ephemeral_public_bytes,
            server_ephemeral_public_bytes,
        )
        auth_fields = [(TAG_CERTIFICATE, self.identity.certificate.public_bytes(Encoding.DER))]
        # ServerAuth carries the leaf certificate first and intermediates after
        # it, matching the certificate-chain mental model from the TLS series.
        for cert in self.identity.intermediate_certificates:
            auth_fields.append((TAG_CERTIFICATE, cert.public_bytes(Encoding.DER)))
        auth_fields.append((TAG_CERTIFICATE_VERIFY, signature))
        self._pending_wire.extend(frame_payload(encode_message(auth_fields)))

        shared_secret = server_ephemeral_private.exchange(client_ephemeral_public)
        # Directional keys are important: client_write_key decrypts records from
        # the client, server_write_key encrypts records sent by the server.
        self._client_write_key, self._server_write_key = derive_session_keys(shared_secret)
        self.state = self.ESTABLISHED

    def _handle_application_record(self, record: bytes) -> None:
        if self._client_write_key is None:
            raise ToyTLSProtocolError("Missing client write key")
        plaintext = unprotect_record(self._client_write_key, self._recv_seq, record)
        self._recv_seq += 1
        self._plaintext.extend(plaintext)


class ToyTLSClientConnection:
    WAIT_SERVER_HELLO = "WAIT_SERVER_HELLO"
    WAIT_SERVER_AUTH = "WAIT_SERVER_AUTH"
    ESTABLISHED = "ESTABLISHED"

    def __init__(self, trusted_root: x509.Certificate, dns_name: str):
        self.trusted_root = trusted_root
        self.dns_name = dns_name
        self.state = self.WAIT_SERVER_HELLO
        self._records = RecordBuffer()
        self._pending_wire = bytearray()
        self._plaintext = bytearray()
        self._send_seq = 0
        self._recv_seq = 0
        self._client_write_key: Optional[bytes] = None
        self._server_write_key: Optional[bytes] = None
        self._server_ephemeral_public_bytes: Optional[bytes] = None

        self._client_ephemeral_private = X25519PrivateKey.generate()
        self._client_ephemeral_public_bytes = self._client_ephemeral_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        client_hello = encode_message([(TAG_X25519_PUBLIC, self._client_ephemeral_public_bytes)])
        self._pending_wire.extend(frame_payload(client_hello))

    @property
    def is_established(self) -> bool:
        return self.state == self.ESTABLISHED

    def feed_wire_data(self, data: bytes) -> None:
        if not data:
            return
        # TCP may split or merge records. RecordBuffer hides that detail and
        # yields only complete length-prefixed TLS-like records.
        self._records.feed(data)
        while True:
            record = self._records.pop_record()
            if record is None:
                return
            if self.state == self.WAIT_SERVER_HELLO:
                self._handle_server_hello(record)
            elif self.state == self.WAIT_SERVER_AUTH:
                self._handle_server_auth(record)
            elif self.state == self.ESTABLISHED:
                self._handle_application_record(record)
            else:
                raise ToyTLSProtocolError(f"Unexpected client TLS state: {self.state}")

    def pop_pending_wire_data(self) -> bytes:
        data = bytes(self._pending_wire)
        self._pending_wire.clear()
        return data

    def read_plaintext(self) -> bytes:
        data = bytes(self._plaintext)
        self._plaintext.clear()
        return data

    def protect_application_data(self, plaintext: bytes) -> bytes:
        if not self.is_established or self._client_write_key is None:
            raise ToyTLSProtocolError("Cannot send application data before TLS is established")
        protected = protect_record(self._client_write_key, self._send_seq, plaintext)
        self._send_seq += 1
        return frame_payload(protected)

    def _handle_server_hello(self, record: bytes) -> None:
        fields = decode_message(record)
        self._server_ephemeral_public_bytes = first_field(fields, TAG_X25519_PUBLIC)
        self.state = self.WAIT_SERVER_AUTH

    def _handle_server_auth(self, record: bytes) -> None:
        if self._server_ephemeral_public_bytes is None:
            raise ToyTLSProtocolError("ServerAuth received before ServerHello")
        fields = decode_message(record)
        cert_der_list = [value for tag, value in fields if tag == TAG_CERTIFICATE]
        signatures = [value for tag, value in fields if tag == TAG_CERTIFICATE_VERIFY]
        if not cert_der_list:
            raise ToyTLSProtocolError("ServerAuth missing certificate")
        if not signatures:
            raise ToyTLSProtocolError("ServerAuth missing CertificateVerify")

        server_cert = x509.load_der_x509_certificate(cert_der_list[0])
        intermediate_certs = [x509.load_der_x509_certificate(value) for value in cert_der_list[1:]]
        verify_server_certificate(self.trusted_root, intermediate_certs, server_cert, self.dns_name)

        identity_public_key = server_cert.public_key()
        if not isinstance(identity_public_key, rsa.RSAPublicKey):
            raise ToyTLSProtocolError("Server certificate must contain an RSA public key")
        _verify_ephemeral_pubkeys_with_identity(
            identity_public_key,
            signatures[0],
            self._client_ephemeral_public_bytes,
            self._server_ephemeral_public_bytes,
        )

        server_ephemeral_public = X25519PublicKey.from_public_bytes(self._server_ephemeral_public_bytes)
        shared_secret = self._client_ephemeral_private.exchange(server_ephemeral_public)
        # The labels in key_schedule.py make both peers derive the same two
        # directional keys without sending those keys over the network.
        self._client_write_key, self._server_write_key = derive_session_keys(shared_secret)
        self.state = self.ESTABLISHED

    def _handle_application_record(self, record: bytes) -> None:
        if self._server_write_key is None:
            raise ToyTLSProtocolError("Missing server write key")
        plaintext = unprotect_record(self._server_write_key, self._recv_seq, record)
        self._recv_seq += 1
        self._plaintext.extend(plaintext)
