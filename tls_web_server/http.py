"""HTTP parsing and static-file response helpers.

This is intentionally close to the web-server series: parse bytes into an
HTTPMessage, choose the longest matching `location`, and serve a file from the
configured root directory.

The TLS integration does not change this module. TLS connections decrypt bytes
before they get here, so this code always sees plaintext HTTP.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import unquote, urlsplit

from .config import LocationConfig, ServerBlock


class IncompleteMessageError(Exception):
    """Raised when the byte buffer contains a valid but incomplete HTTP message."""


class InvalidMessageError(Exception):
    """Raised when the byte buffer cannot be parsed as an HTTP message."""


@dataclass(frozen=True)
class HTTPMessage:
    method: str
    url: str
    version: str
    headers: Dict[str, str]
    body: bytes


class HTTPParser:
    @staticmethod
    def parse_message(data: bytes) -> Tuple[Optional[HTTPMessage], int]:
        if not data:
            return None, 0
        # HTTP headers end with an empty line. If this marker has not arrived
        # yet, the request may simply be split across multiple TCP/TLS records.
        separator = b"\r\n\r\n"
        header_end = data.find(separator)
        if header_end == -1:
            raise IncompleteMessageError("Missing CRLF CRLF header terminator")

        header_text = data[:header_end].decode("iso-8859-1", errors="replace")
        rest = data[header_end + len(separator) :]
        lines = header_text.split("\r\n")
        start_line = lines[0]
        parts = start_line.split(" ", 2)
        if len(parts) != 3:
            raise InvalidMessageError(f"Malformed start line: {start_line!r}")
        method, url, version = parts
        if not version.startswith("HTTP/"):
            raise InvalidMessageError(f"Unsupported HTTP version field: {version!r}")

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                raise InvalidMessageError(f"Malformed header line: {line!r}")
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        content_length = headers.get("content-length")
        if content_length is None:
            # For simple GET/HEAD requests, no body is expected.
            body = b""
            consumed = header_end + len(separator)
        else:
            try:
                length = int(content_length)
            except ValueError as exc:
                raise InvalidMessageError(f"Invalid Content-Length: {content_length!r}") from exc
            if len(rest) < length:
                raise IncompleteMessageError("Incomplete HTTP body")
            body = rest[:length]
            consumed = header_end + len(separator) + length
        return HTTPMessage(method=method, url=url, version=version, headers=headers, body=body), consumed


class DataProvider:
    def __init__(self):
        self._data = b""

    @property
    def data(self) -> bytes:
        return self._data

    def append(self, chunk: bytes) -> None:
        # Be explicit that new bytes are appended to the existing stream buffer.
        # A property assignment that secretly appended was harder for beginners
        # to read and easier to misuse while following the data flow.
        self._data += chunk

    def reduce_data(self, size: int) -> None:
        self._data = self._data[size:]


def match_location(locations: Dict[str, LocationConfig], uri: str) -> LocationConfig:
    # Same idea as NGINX prefix locations: choose the longest configured prefix
    # that matches the requested URI.
    best = locations.get("/") or LocationConfig(path="/", root="html")
    best_len = len(best.path)
    for path, location in locations.items():
        if uri.startswith(path) and len(path) >= best_len:
            best = location
            best_len = len(path)
    return best


def _reason_phrase(status_code: int) -> str:
    return {
        200: "OK",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
    }.get(status_code, "Unknown")


def http_response(
    status_code: int,
    body: bytes,
    content_type: str = "text/plain",
    close: bool = True,
    content_length: Optional[int] = None,
) -> bytes:
    reason = _reason_phrase(status_code)
    connection = "close" if close else "keep-alive"
    declared_length = len(body) if content_length is None else content_length
    headers = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Length: {declared_length}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Connection: {connection}\r\n"
        "\r\n"
    )
    return headers.encode("ascii") + body


def _safe_file_path(base_dir: Path, location: LocationConfig, uri: str) -> Optional[Path]:
    # Convert the URL path into a path under the selected location root. The
    # `relative_to(root)` check prevents `../` path traversal from escaping the
    # static-file directory.
    parsed_path = unquote(urlsplit(uri).path)
    if parsed_path == "/":
        parsed_path = "/index.html"
    root = (base_dir / location.root).resolve()
    relative = parsed_path.lstrip("/")
    candidate = (root / relative).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def build_http_response(request: HTTPMessage, server_block: ServerBlock, base_dir: Path) -> Tuple[bytes, bool]:
    close = request.headers.get("connection", "").lower() != "keep-alive"
    if request.method.upper() not in {"GET", "HEAD"}:
        return http_response(405, b"405 Method Not Allowed", close=True), True

    uri = urlsplit(request.url).path or "/"
    location = match_location(server_block.locations, uri)
    file_path = _safe_file_path(base_dir, location, uri)
    if file_path is None:
        return http_response(403, b"403 Forbidden", close=True), True
    if not file_path.is_file():
        return http_response(404, b"404 Not Found", close=True), True

    body = file_path.read_bytes()
    content_type = "text/html" if file_path.suffix.lower() in {".html", ".htm"} else "text/plain"
    if request.method.upper() == "HEAD":
        # HEAD returns the same headers GET would return, but without the body.
        return http_response(200, b"", content_type=content_type, close=close, content_length=len(body)), close
    return http_response(200, body, content_type=content_type, close=close), close
