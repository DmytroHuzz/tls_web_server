from __future__ import annotations

import struct
from typing import Iterable, List, Tuple

TAG_X25519_PUBLIC = 0x0010
TAG_CERTIFICATE = 0x0020
TAG_CERTIFICATE_VERIFY = 0x0021

Field = Tuple[int, bytes]


def encode_message(fields: Iterable[Field]) -> bytes:
    out = bytearray()
    for tag, value in fields:
        out.extend(struct.pack("!HI", tag, len(value)))
        out.extend(value)
    return bytes(out)


def decode_message(data: bytes) -> List[Field]:
    fields: List[Field] = []
    pos = 0
    while pos < len(data):
        if len(data) - pos < 6:
            raise ValueError("Truncated handshake field header")
        tag, length = struct.unpack("!HI", data[pos : pos + 6])
        pos += 6
        if len(data) - pos < length:
            raise ValueError("Truncated handshake field value")
        fields.append((tag, data[pos : pos + length]))
        pos += length
    return fields


def first_field(fields: Iterable[Field], tag: int) -> bytes:
    for field_tag, value in fields:
        if field_tag == tag:
            return value
    raise ValueError(f"Missing handshake field tag 0x{tag:04x}")
