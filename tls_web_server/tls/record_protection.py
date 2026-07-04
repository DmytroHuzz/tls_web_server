from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
SEQ_LEN = 8
TAG_LEN = 16


def protect_record(key: bytes, seq: int, plaintext: bytes) -> bytes:
    seq_bytes = struct.pack("!Q", seq)
    nonce = os.urandom(NONCE_LEN)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, seq_bytes)
    return seq_bytes + nonce + ciphertext_and_tag


def unprotect_record(key: bytes, expected_seq: int, payload: bytes) -> bytes:
    minimum = SEQ_LEN + NONCE_LEN + TAG_LEN
    if len(payload) < minimum:
        raise ValueError("Protected record too short")
    seq_bytes = payload[:SEQ_LEN]
    nonce = payload[SEQ_LEN : SEQ_LEN + NONCE_LEN]
    ciphertext_and_tag = payload[SEQ_LEN + NONCE_LEN :]
    (received_seq,) = struct.unpack("!Q", seq_bytes)
    if received_seq != expected_seq:
        raise ValueError(f"Sequence mismatch: got {received_seq}, expected {expected_seq}")
    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, seq_bytes)
