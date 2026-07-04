#!/usr/bin/env python3
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tls_web_server.server import WebServer
from tls_web_server.tls.certificates import generate_certificate_chain, load_trusted_root
from tls_web_server.tls.connection import ToyTLSClientConnection


def recv_plain_response(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def recv_tls_response(sock: socket.socket, tls: ToyTLSClientConnection) -> bytes:
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


def main() -> int:
    demo_dir = PROJECT_ROOT / "demo_site"
    html_dir = demo_dir / "html"
    certs_dir = demo_dir / "certs"
    html_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)

    (html_dir / "index.html").write_text(
        """<!doctype html>
<html>
  <head><title>Self-written TLS + Web Server</title></head>
  <body>
    <h1>Hello from the integrated server</h1>
    <p>This response was produced by the HTTP layer. On port 8443-style mode it travelled through the self-written TLS-like record layer.</p>
  </body>
</html>
""",
        encoding="utf-8",
    )

    print("[demo] Generating local root/intermediate/server certificates...")
    generate_certificate_chain(certs_dir, dns_name="localhost")

    config_path = demo_dir / "server.conf"
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

    server = WebServer(config_path=config_path, base_dir=demo_dir)
    thread = threading.Thread(target=server.serve_forever, kwargs={"host": "127.0.0.1"}, daemon=True)
    thread.start()
    server.wait_until_ready(timeout=5)

    try:
        plain_port = server.bound_port(ssl=False)
        tls_port = server.bound_port(ssl=True)
        print(f"[demo] Server ready")
        print(f"       plain HTTP listener:        http://127.0.0.1:{plain_port}/")
        print(f"       self-written TLS listener:  127.0.0.1:{tls_port} (custom client only)")

        print("\n[demo] Plain HTTP request")
        with socket.create_connection(("127.0.0.1", plain_port), timeout=5) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            plain_response = recv_plain_response(sock)
        print(plain_response.decode("utf-8", errors="replace"))

        print("\n[demo] HTTP over the self-written TLS-like layer")
        trusted_root = load_trusted_root(certs_dir / "root_cert.pem")
        tls = ToyTLSClientConnection(trusted_root=trusted_root, dns_name="localhost")
        with socket.create_connection(("127.0.0.1", tls_port), timeout=5) as sock:
            print("       -> sending ClientHello")
            sock.sendall(tls.pop_pending_wire_data())

            while not tls.is_established:
                data = sock.recv(4096)
                if not data:
                    raise RuntimeError("Server closed before TLS handshake completed")
                tls.feed_wire_data(data)
                outgoing = tls.pop_pending_wire_data()
                if outgoing:
                    sock.sendall(outgoing)

            print("       <- certificate chain and CertificateVerify accepted")
            print("       -> sending encrypted HTTP request")
            sock.sendall(
                tls.protect_application_data(
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
            )
            tls_response = recv_tls_response(sock, tls)

        print("       <- decrypted HTTP response")
        print(tls_response.decode("utf-8", errors="replace"))
        print("\n[demo] Done.")
        return 0
    finally:
        server.stop()
        thread.join(timeout=5)
        # Give the OS a moment to release ephemeral sockets in very fast reruns.
        time.sleep(0.05)


if __name__ == "__main__":
    raise SystemExit(main())
