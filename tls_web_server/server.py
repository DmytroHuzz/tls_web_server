"""Selectors-based web server with optional self-written TLS.

This module is the integration point between the two previous series:

* The web-server series ended with an event-loop server that reads TCP bytes,
  parses HTTP, matches routes, and writes HTTP responses.
* The TLS series ended with a TLS-like secure channel that turns unsafe TCP
  bytes into authenticated plaintext application bytes.

The important beginner-friendly idea is: HTTP does not parse encrypted bytes.
Encrypted connections first pass through `ToyTLSServerConnection`. Only the
resulting plaintext is appended to the same `DataProvider` used by plain HTTP.
"""

from __future__ import annotations

import logging
import selectors
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .config import AppConfig, ListenDirective, ServerBlock, load_config
from .http import (
    DataProvider,
    HTTPParser,
    IncompleteMessageError,
    InvalidMessageError,
    build_http_response,
    http_response,
)
from .tls.certificates import ServerIdentity, load_server_identity
from .tls.connection import ToyTLSProtocolError, ToyTLSServerConnection

try:
    from cryptography.exceptions import InvalidTag
except ImportError:  # pragma: no cover - cryptography always provides this in supported versions
    InvalidTag = ValueError  # type: ignore[misc, assignment]


logger = logging.getLogger(__name__)


@dataclass
class ListenerContext:
    listen: ListenDirective
    server_block: ServerBlock
    identity: Optional[ServerIdentity]


@dataclass
class BoundListener:
    socket: socket.socket
    context: ListenerContext
    port: int


class ConnectionContext:
    def __init__(
        self,
        sock: socket.socket,
        server_block: ServerBlock,
        tls: Optional[ToyTLSServerConnection] = None,
    ):
        self.sock = sock
        self.server_block = server_block
        # `tls is None` means normal HTTP. A ToyTLSServerConnection means socket
        # bytes must first pass through the self-written TLS-like layer.
        self.tls = tls
        # HTTPParser consumes this buffer. TLS connections append only decrypted
        # application bytes here, never encrypted wire bytes.
        self.http_input = DataProvider()
        # Non-blocking send() may write only part of a response. Keep the rest
        # until the selector reports that the socket is writable again.
        self.output_buffer = bytearray()
        self.closing_after_write = False


class WebServer:
    """Single-threaded selectors-based HTTP server with optional toy TLS.

    TLS is intentionally implemented at the connection layer. The HTTP parser
    sees only plaintext bytes, regardless of whether they came from a plain TCP
    listener or were decrypted from the self-written TLS record layer.
    """

    def __init__(self, config_path: Path, base_dir: Optional[Path] = None):
        self.config_path = Path(config_path)
        self.base_dir = Path(base_dir) if base_dir is not None else self.config_path.parent
        self.config: AppConfig = load_config(self.config_path)
        self.selector = selectors.DefaultSelector()
        self._stopping = threading.Event()
        self._ready = threading.Event()
        self._bound_listeners: List[BoundListener] = []

    def serve_forever(self, host: str = "127.0.0.1") -> None:
        try:
            self._setup_listeners(host)
            self._ready.set()
            while not self._stopping.is_set():
                # One selector drives listening sockets and client sockets. This
                # is the single-threaded non-blocking model from the web-server
                # series: no thread is created per connection.
                events = self.selector.select(timeout=0.1)
                for key, mask in events:
                    if isinstance(key.data, ListenerContext):
                        self._accept_connection(key.fileobj, key.data)
                    else:
                        self._service_connection(key, mask)
        finally:
            self._cleanup()
            self._ready.set()

    def wait_until_ready(self, timeout: Optional[float] = None) -> None:
        if not self._ready.wait(timeout):
            raise TimeoutError("Server did not become ready")

    def stop(self) -> None:
        self._stopping.set()

    def bound_port(self, ssl: bool) -> int:
        for listener in self._bound_listeners:
            if listener.context.listen.ssl == ssl:
                return listener.port
        raise LookupError(f"No bound listener for ssl={ssl}")

    @property
    def bound_listeners(self) -> List[BoundListener]:
        return list(self._bound_listeners)

    def _setup_listeners(self, host: str) -> None:
        for server_block in self.config.servers:
            # Identity material is long-term TLS state: certificate, private key,
            # and intermediate certificates. Ephemeral X25519 keys are still
            # generated per connection inside ToyTLSServerConnection.
            identity = self._load_identity(server_block) if any(listen.ssl for listen in server_block.listens) else None
            for listen in server_block.listens:
                if listen.ssl and identity is None:
                    raise ValueError("TLS listener configured without certificate/key")
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind((host, listen.port))
                server_sock.listen()
                server_sock.setblocking(False)
                context = ListenerContext(listen=listen, server_block=server_block, identity=identity if listen.ssl else None)
                # Listener sockets store ListenerContext. Accepted client sockets
                # store ConnectionContext. This is how the event loop knows
                # whether an event means "accept a client" or "service a client".
                self.selector.register(server_sock, selectors.EVENT_READ, data=context)
                self._bound_listeners.append(BoundListener(socket=server_sock, context=context, port=server_sock.getsockname()[1]))

    def _load_identity(self, server_block: ServerBlock) -> ServerIdentity:
        if server_block.tls is None:
            raise ValueError("TLS listener configured but server block has no TLS config")
        tls = server_block.tls
        return load_server_identity(
            self.base_dir / tls.private_key_path,
            self.base_dir / tls.certificate_path,
            [self.base_dir / path for path in tls.chain_paths],
        )

    def _accept_connection(self, server_sock: socket.socket, listener: ListenerContext) -> None:
        try:
            conn, _addr = server_sock.accept()
        except BlockingIOError:
            return
        conn.setblocking(False)
        # A TLS listener creates TLS state immediately after accept. The actual
        # handshake still progresses later, when selector read events bring bytes.
        tls = ToyTLSServerConnection(listener.identity) if listener.identity is not None else None
        context = ConnectionContext(sock=conn, server_block=listener.server_block, tls=tls)
        self.selector.register(conn, selectors.EVENT_READ, data=context)

    def _service_connection(self, key: selectors.SelectorKey, mask: int) -> None:
        context: ConnectionContext = key.data
        if mask & selectors.EVENT_READ:
            self._read_from_connection(context)
        if context.sock.fileno() != -1 and mask & selectors.EVENT_WRITE:
            self._flush_output(context)

    def _read_from_connection(self, context: ConnectionContext) -> None:
        try:
            data = context.sock.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except (ConnectionResetError, OSError):
            self._close_connection(context)
            return

        if not data:
            if context.output_buffer:
                context.closing_after_write = True
            else:
                self._close_connection(context)
            return

        if context.tls is not None:
            try:
                # TLS path: TCP bytes are handshake/application records, not HTTP.
                # Feeding data may produce ServerHello/ServerAuth bytes and/or
                # decrypted HTTP request bytes.
                context.tls.feed_wire_data(data)
            except (ToyTLSProtocolError, ValueError, InvalidTag) as exc:
                logger.info("Closing TLS connection after protocol error: %s", exc)
                self._close_connection(context)
                return
            self._queue_output(context, context.tls.pop_pending_wire_data())
            plaintext = context.tls.read_plaintext()
            if plaintext:
                context.http_input.append(plaintext)
                self._handle_http_messages(context)
        else:
            # Plain path: socket bytes are already HTTP bytes.
            context.http_input.append(data)
            self._handle_http_messages(context)

    def _handle_http_messages(self, context: ConnectionContext) -> None:
        while context.sock.fileno() != -1:
            try:
                # Parse one complete request from the current plaintext buffer.
                # If a client pipelined multiple requests, the loop continues
                # after reducing the consumed bytes.
                request, consumed = HTTPParser.parse_message(context.http_input.data)
            except IncompleteMessageError:
                # Valid so far, but incomplete. Wait for another read event.
                return
            except InvalidMessageError as exc:
                self._send_application_bytes(context, http_response(400, str(exc).encode("utf-8"), close=True))
                context.closing_after_write = True
                return

            if request is None:
                return
            context.http_input.reduce_data(consumed)
            response, should_close = build_http_response(request, context.server_block, self.base_dir)
            self._send_application_bytes(context, response)
            if should_close:
                context.closing_after_write = True
                return

    def _send_application_bytes(self, context: ConnectionContext, plaintext_response: bytes) -> None:
        if context.tls is not None:
            try:
                # The HTTP layer always returns plaintext. TLS connections wrap
                # that plaintext into an encrypted application record here.
                wire = context.tls.protect_application_data(plaintext_response)
            except ToyTLSProtocolError:
                self._close_connection(context)
                return
        else:
            wire = plaintext_response
        self._queue_output(context, wire)

    def _queue_output(self, context: ConnectionContext, data: bytes) -> None:
        if not data or context.sock.fileno() == -1:
            return
        context.output_buffer.extend(data)
        try:
            self.selector.modify(context.sock, selectors.EVENT_READ | selectors.EVENT_WRITE, data=context)
        except KeyError:
            pass

    def _flush_output(self, context: ConnectionContext) -> None:
        if not context.output_buffer:
            if context.closing_after_write:
                self._close_connection(context)
            else:
                self._modify_read_only(context)
            return
        try:
            sent = context.sock.send(context.output_buffer)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._close_connection(context)
            return
        del context.output_buffer[:sent]
        if not context.output_buffer:
            if context.closing_after_write:
                self._close_connection(context)
            else:
                self._modify_read_only(context)

    def _modify_read_only(self, context: ConnectionContext) -> None:
        if context.sock.fileno() == -1:
            return
        try:
            self.selector.modify(context.sock, selectors.EVENT_READ, data=context)
        except KeyError:
            pass

    def _close_connection(self, context: ConnectionContext) -> None:
        try:
            self.selector.unregister(context.sock)
        except (KeyError, ValueError, OSError):
            pass
        try:
            context.sock.close()
        except OSError:
            pass

    def _cleanup(self) -> None:
        for key in list(self.selector.get_map().values()):
            try:
                self.selector.unregister(key.fileobj)
            except (KeyError, ValueError, OSError):
                pass
            try:
                key.fileobj.close()
            except OSError:
                pass
        self._bound_listeners.clear()
        try:
            self.selector.close()
        except OSError:
            pass
