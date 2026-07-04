from pathlib import Path

import pytest

from tls_web_server.tls.certificates import generate_certificate_chain, load_server_identity, load_trusted_root
from tls_web_server.tls.connection import ToyTLSClientConnection, ToyTLSServerConnection


def _make_client_and_server(certs_dir: Path, dns_name: str = "localhost"):
    generate_certificate_chain(certs_dir, dns_name="localhost")
    identity = load_server_identity(
        certs_dir / "server_key.pem",
        certs_dir / "server_cert.pem",
        [certs_dir / "intermediate_cert.pem"],
    )
    trusted_root = load_trusted_root(certs_dir / "root_cert.pem")
    client = ToyTLSClientConnection(trusted_root=trusted_root, dns_name=dns_name)
    server = ToyTLSServerConnection(identity=identity)
    return client, server


def _flush_tls_handshake(client: ToyTLSClientConnection, server: ToyTLSServerConnection) -> None:
    # Deliberately fragment every transfer to prove the TLS layer is buffer-based,
    # not dependent on recv() returning a whole record.
    pending = client.pop_pending_wire_data()
    for i in range(0, len(pending), 3):
        server.feed_wire_data(pending[i : i + 3])

    pending = server.pop_pending_wire_data()
    for i in range(0, len(pending), 5):
        client.feed_wire_data(pending[i : i + 5])


def test_tls_state_machine_handles_fragmented_handshake_and_application_records(tmp_path: Path):
    client, server = _make_client_and_server(tmp_path / "certs")

    _flush_tls_handshake(client, server)

    assert client.is_established
    assert server.is_established

    encrypted_request = client.protect_application_data(b"GET / HTTP/1.1\r\n\r\n")
    for i in range(0, len(encrypted_request), 2):
        server.feed_wire_data(encrypted_request[i : i + 2])

    assert server.read_plaintext() == b"GET / HTTP/1.1\r\n\r\n"

    encrypted_response = server.protect_application_data(b"HTTP/1.1 200 OK\r\n\r\nhello")
    for i in range(0, len(encrypted_response), 4):
        client.feed_wire_data(encrypted_response[i : i + 4])

    assert client.read_plaintext() == b"HTTP/1.1 200 OK\r\n\r\nhello"


def test_tls_client_rejects_certificate_for_wrong_dns_name(tmp_path: Path):
    client, server = _make_client_and_server(tmp_path / "certs", dns_name="wrong.localhost")

    server.feed_wire_data(client.pop_pending_wire_data())

    with pytest.raises(Exception):
        client.feed_wire_data(server.pop_pending_wire_data())

    assert not client.is_established


def test_tls_server_rejects_tampered_application_record(tmp_path: Path):
    client, server = _make_client_and_server(tmp_path / "certs")
    _flush_tls_handshake(client, server)

    encrypted_request = bytearray(client.protect_application_data(b"GET / HTTP/1.1\r\n\r\n"))
    encrypted_request[-1] ^= 0x01

    with pytest.raises(Exception):
        server.feed_wire_data(bytes(encrypted_request))


def test_tls_server_rejects_out_of_order_sequence_number(tmp_path: Path):
    client, server = _make_client_and_server(tmp_path / "certs")
    _flush_tls_handshake(client, server)

    _first_record_with_sequence_zero = client.protect_application_data(b"first")
    second_record_with_sequence_one = client.protect_application_data(b"second")

    with pytest.raises(ValueError, match="Sequence mismatch"):
        server.feed_wire_data(second_record_with_sequence_one)


def test_tls_plaintext_can_arrive_as_multiple_application_records(tmp_path: Path):
    client, server = _make_client_and_server(tmp_path / "certs")
    _flush_tls_handshake(client, server)

    server.feed_wire_data(client.protect_application_data(b"GET / HTTP/1.1\r\nHost: local"))
    assert server.read_plaintext() == b"GET / HTTP/1.1\r\nHost: local"

    server.feed_wire_data(client.protect_application_data(b"host\r\n\r\n"))
    assert server.read_plaintext() == b"host\r\n\r\n"
