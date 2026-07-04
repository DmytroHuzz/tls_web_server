from __future__ import annotations

import struct
from typing import List, Optional

MAX_RECORD_SIZE = 16 * 1024 * 1024


def frame_payload(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


class RecordBuffer:
    """Length-prefixed record reader for TCP streams.

    TCP has no message boundaries. This class lets the TLS layer accept arbitrary
    socket chunks and emit complete records only when enough bytes have arrived.
    """

    def __init__(self):
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        self._buffer.extend(data)

    def pop_record(self) -> Optional[bytes]:
        if len(self._buffer) < 4:
            return None
        (length,) = struct.unpack("!I", self._buffer[:4])
        if length > MAX_RECORD_SIZE:
            raise ValueError(f"Record too large: {length}")
        if len(self._buffer) < 4 + length:
            return None
        payload = bytes(self._buffer[4 : 4 + length])
        del self._buffer[: 4 + length]
        return payload

    def pop_all(self) -> List[bytes]:
        records: List[bytes] = []
        while True:
            record = self.pop_record()
            if record is None:
                return records
            records.append(record)
