from pathlib import Path

from tls_web_server.config import ListenDirective, LocationConfig, ServerBlock
from tls_web_server.http import DataProvider, HTTPParser, build_http_response


def test_data_provider_uses_explicit_append_method():
    provider = DataProvider()

    provider.append(b"GET / HTTP/1.1\r\n")
    provider.append(b"Host: localhost\r\n\r\n")

    request, consumed = HTTPParser.parse_message(provider.data)

    assert request is not None
    assert request.method == "GET"
    assert consumed == len(provider.data)


def test_head_response_keeps_get_body_content_length(tmp_path: Path):
    (tmp_path / "html").mkdir()
    (tmp_path / "html" / "index.html").write_text("hello", encoding="utf-8")
    request, _ = HTTPParser.parse_message(
        b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    assert request is not None

    response, should_close = build_http_response(
        request,
        ServerBlock(
            listens=[ListenDirective(port=8080)],
            locations={"/": LocationConfig(path="/", root="html")},
        ),
        tmp_path,
    )

    headers, body = response.split(b"\r\n\r\n", 1)
    assert should_close is True
    assert b"HTTP/1.1 200 OK" in headers
    assert b"Content-Length: 5" in headers
    assert body == b""
