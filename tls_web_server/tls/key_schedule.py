from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CLIENT_WRITE_KEY_LABEL = b"toy tls client write key"
SERVER_WRITE_KEY_LABEL = b"toy tls server write key"
KEY_LEN = 32


def derive_session_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    client_write_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=CLIENT_WRITE_KEY_LABEL,
    ).derive(shared_secret)
    server_write_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=SERVER_WRITE_KEY_LABEL,
    ).derive(shared_secret)
    return client_write_key, server_write_key
