import socket
import threading
from pathlib import Path

from tls_web_server.server import WebServer
from tls_web_server.tls.certificates import generate_certificate_chain, load_trusted_root
from tls_web_server.tls.connection import ToyTLSClientConnection


def _recv_plain_http_response(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def _recv_tls_http_response(sock: socket.socket, tls: ToyTLSClientConnection) -> bytes:
    plaintext = bytearray()
    while True:
        data = sock.recv(4096)
        if not data:
            break
        tls.feed_wire_data(data)
        outgoing = tls.pop_pending_wire_data()
        if outgoing:
            sock.sendall(outgoing)
        plaintext.extend(tls.read_plaintext())
        if b"\r\n\r\n" in plaintext:
            headers, body = bytes(plaintext).split(b"\r\n\r\n", 1)
            for line in headers.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    expected = int(line.split(b":", 1)[1].strip())
                    if len(body) >= expected:
                        return bytes(plaintext)
    return bytes(plaintext)


def _start_test_server(tmp_path: Path) -> tuple[WebServer, threading.Thread, Path]:
    (tmp_path / "html").mkdir()
    (tmp_path / "html" / "index.html").write_text("hello from the integrated server\n", encoding="utf-8")
    certs_dir = tmp_path / "certs"
    generate_certificate_chain(certs_dir, dns_name="localhost")

    config_path = tmp_path / "server.conf"
    config_path.write_text(
        """
        http {
            server {
                listen 0;
                listen 0 ssl;
                server_name localhost;

                ssl_certificate certs/server_cert.pem;
                ssl_certificate_key certs/server_key.pem;
                ssl_certificate_chain certs/intermediate_cert.pem;

                location / {
                    root html;
                }
            }
        }
        """,
        encoding="utf-8",
    )

    server = WebServer(config_path=config_path, base_dir=tmp_path)
    thread = threading.Thread(target=server.serve_forever, kwargs={"host": "127.0.0.1"}, daemon=True)
    thread.start()
    server.wait_until_ready(timeout=5)
    return server, thread, certs_dir


def _establish_tls_client(certs_dir: Path, tls_port: int) -> tuple[socket.socket, ToyTLSClientConnection]:
    trusted_root = load_trusted_root(certs_dir / "root_cert.pem")
    tls_client = ToyTLSClientConnection(trusted_root=trusted_root, dns_name="localhost")
    sock = socket.create_connection(("127.0.0.1", tls_port), timeout=5)
    sock.sendall(tls_client.pop_pending_wire_data())
    while not tls_client.is_established:
        data = sock.recv(4096)
        if not data:
            sock.close()
            raise RuntimeError("Server closed before TLS handshake completed")
        tls_client.feed_wire_data(data)
        outgoing = tls_client.pop_pending_wire_data()
        if outgoing:
            sock.sendall(outgoing)
    return sock, tls_client


def test_web_server_serves_plain_http_and_http_over_self_written_tls(tmp_path: Path):
    server, thread, certs_dir = _start_test_server(tmp_path)

    try:
        plain_port = server.bound_port(ssl=False)
        tls_port = server.bound_port(ssl=True)

        with socket.create_connection(("127.0.0.1", plain_port), timeout=5) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            plain_response = _recv_plain_http_response(sock)

        assert b"HTTP/1.1 200 OK" in plain_response
        assert b"hello from the integrated server" in plain_response

        sock, tls_client = _establish_tls_client(certs_dir, tls_port)
        with sock:
            sock.sendall(
                tls_client.protect_application_data(
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
            )
            tls_response = _recv_tls_http_response(sock, tls_client)

        assert b"HTTP/1.1 200 OK" in tls_response
        assert b"hello from the integrated server" in tls_response
    finally:
        server.stop()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_tls_http_request_can_be_split_across_multiple_encrypted_records(tmp_path: Path):
    server, thread, certs_dir = _start_test_server(tmp_path)

    try:
        tls_port = server.bound_port(ssl=True)
        sock, tls_client = _establish_tls_client(certs_dir, tls_port)
        with sock:
            sock.sendall(tls_client.protect_application_data(b"GET / HTTP/1.1\r\nHost: local"))
            sock.settimeout(0.2)
            try:
                early_data = sock.recv(4096)
            except socket.timeout:
                early_data = b""
            assert early_data == b""

            sock.settimeout(5)
            sock.sendall(tls_client.protect_application_data(b"host\r\nConnection: close\r\n\r\n"))
            tls_response = _recv_tls_http_response(sock, tls_client)

        assert b"HTTP/1.1 200 OK" in tls_response
        assert b"hello from the integrated server" in tls_response
    finally:
        server.stop()
        thread.join(timeout=5)
        assert not thread.is_alive()
