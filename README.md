# Adding self-written TLS to a self-written web server

This repository is the bridge between two learning projects:

- **Building Your Own Web Server** — article series: [Part 1 on DEV](https://dev.to/dmytro_huz/building-your-own-web-server-part-1-theory-and-foundations-3kgo), source code: [DmytroHuzz/build_own_webserver](https://github.com/DmytroHuzz/build_own_webserver)
- **Rebuilding TLS from Scratch** — complete series: [dmytrohuz.com](https://www.dmytrohuz.com/p/rebuilding-tls-from-scratch-my-complete), source code: [DmytroHuzz/rebuilding_tls](https://github.com/DmytroHuzz/rebuilding_tls)

The web-server series rebuilt the server side of HTTP: sockets, config parsing, route matching, file serving, and finally a single-threaded non-blocking server.

The TLS series rebuilt the secure channel: X25519 key exchange, HKDF, AES-GCM records, certificates, and server authentication.

This project combines them into one question:

> What changes in the web server when the bytes coming from TCP are encrypted?

The answer is the same architectural boundary used by real servers like NGINX: TLS sits **below HTTP**.

```text
TCP socket
   ↓
self-written TLS handshake + record layer
   ↓ decrypted plaintext bytes
HTTP parser / router / file serving
   ↓ plaintext HTTP response
self-written TLS record protection
   ↓ encrypted bytes
TCP socket
```

The HTTP parser does not know whether the request came from a plain socket or from the self-written TLS layer. It receives bytes that look like ordinary HTTP either way.

> This is an educational TLS-like protocol, not browser-compatible HTTPS. Browsers and `curl https://...` expect the real TLS 1.3 wire format. This project keeps the wire format small so the integration boundary is easy to see.

## Visual walkthrough

Read the published walkthrough here:

**[Adding self-written TLS to a self-written web server](https://dmytrohuzz.github.io/tls_web_server/)**

The same page is also available in the repository for local reading:

```text
docs/index.html
walkthrough/walkthrough.html
```

---

## Setup from a fresh clone

Use a virtual environment so the cryptography dependency is installed for the same Python interpreter that runs the project.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

Then run the demo and tests:

```bash
python3 scripts/demo.py
python3 -m pytest -q
```

---

## If you did not read the previous series

You can still follow this project if you keep four ideas in mind:

1. TCP gives programs a **byte stream**, not ready-made HTTP messages.
2. HTTP is plaintext text-like bytes before TLS is added.
3. TLS first performs a **handshake** to authenticate the server and create shared keys.
4. After the handshake, TLS carries encrypted **application data records**. Those records decrypt back into ordinary HTTP bytes.

This repository focuses on the integration boundary, not on implementing full browser-compatible TLS.

---

## Minimum concepts

| Term | Beginner meaning |
|---|---|
| TCP | A reliable byte stream between two programs. It does not preserve message boundaries. |
| HTTP parser | Code that turns plaintext HTTP bytes into a request object. |
| TLS record | A framed chunk of bytes. After the handshake, application records are encrypted. |
| Handshake | The setup phase where peers agree on keys and the client verifies the server. |
| Certificate chain | A server certificate plus issuer certificates that lead to a trusted root. |
| Ephemeral key | A temporary key used for one connection, then thrown away. |
| X25519 | The Diffie-Hellman key exchange used here to create a shared secret. |
| HKDF | A key derivation function that turns the shared secret into encryption keys. |
| AES-GCM | Authenticated encryption: it hides bytes and detects tampering. |
| Directional keys | Separate keys for client→server and server→client records. |
| State machine | Code that remembers which protocol step a connection is currently in. |

---

## Quick conceptual recap

### From the web-server series

The final web server had this flow:

```text
accept TCP connection
   ↓
read bytes into per-connection buffer
   ↓
parse one HTTP request from the buffer
   ↓
match URL against NGINX-style `location` blocks
   ↓
read a file from the configured `root`
   ↓
write an HTTP response
```

The important piece was the per-connection buffer. TCP is a stream, so one `recv()` call may contain half a request, one full request, or multiple pipelined requests.

### From the TLS series

The final TLS demo had this flow:

```text
ClientHello: client sends ephemeral X25519 public key
   ↓
ServerHello: server sends ephemeral X25519 public key
   ↓
ServerAuth: server sends certificate chain + CertificateVerify signature
   ↓
both sides derive the same X25519 shared secret
   ↓
HKDF derives directional AES-GCM keys
   ↓
application data is protected as encrypted records
```

The important mental model was the separation between two key worlds:

| Key type | Lifetime | Purpose |
|---|---:|---|
| identity key | long-term | proves who the server is |
| ephemeral key | one connection | derives fresh session keys |

This project keeps that model and places it directly in front of the HTTP parser.

---

## NGINX / OpenSSL analogy

Production NGINX does not ask the HTTP parser to understand encrypted TLS records. A TLS library such as OpenSSL terminates the secure connection first, then NGINX processes plaintext HTTP bytes.

This project uses the same boundary, but with smaller educational pieces:

```text
Production-ish mental model:
TCP → OpenSSL/TLS state → plaintext HTTP → NGINX HTTP processing

This repository:
TCP → ToyTLSServerConnection → plaintext HTTP → HTTPParser / route matcher
```

The analogy is architectural, not protocol-compatible. This repository is not a replacement for OpenSSL and does not implement the real TLS 1.3 wire format.

---

## What changed in this repository

The standalone TLS demo used blocking socket reads:

```text
recv ClientHello
send ServerHello
send ServerAuth
recv encrypted request
send encrypted response
```

That is fine for a linear demo, but not for the final web-server design. The server in the web-server series is event-loop based. One slow TLS client must not block all other connections.

So the TLS layer was refactored into a buffer-oriented state machine:

```python
tls.feed_wire_data(socket_bytes)
pending = tls.pop_pending_wire_data()
plaintext = tls.read_plaintext()
```

That lets the selector loop stay non-blocking.

---

## Repository map

Read the files in this order:

```text
server_side.py              # visible server-side workflow, like the original projects
client_side.py              # visible client-side workflow, including the custom TLS client

tls_web_server/
  config.py                 # NGINX-style config lexer/parser + typed config objects
  http.py                   # HTTP parser, location matching, static response builder
  server.py                 # selectors-based web server with plain and TLS listeners
  tls/
    certificates.py         # local CA/server cert generation and verification
    connection.py           # buffer-oriented client/server TLS state machines
    framing.py              # length-prefixed record buffering over TCP streams
    key_schedule.py         # HKDF session key derivation
    messages.py             # simple handshake TLV messages
    record_protection.py    # AES-GCM records with sequence numbers

scripts/demo.py             # one-command demo that starts server + client in one process
tests/                      # config, TLS-state-machine, integration, HTTP, and docs tests
walkthrough/walkthrough.html # long-form visual walkthrough
```

---

## The configuration

The config intentionally keeps the NGINX-like style from the web-server series:

```nginx
http {
    server {
        listen 8080;
        listen 8443 ssl;
        server_name localhost;

        ssl_certificate certs/server_cert.pem;
        ssl_certificate_key certs/server_key.pem;
        ssl_certificate_chain certs/intermediate_cert.pem;

        location / {
            root html;
        }
    }
}
```

`listen 8080;` creates a plain HTTP listener.

`listen 8443 ssl;` creates a listener that attaches a `ToyTLSServerConnection` to every accepted socket.

Both listeners share the same HTTP parser and same routing logic.

---

## Running the server-side and client-side workflows

Terminal 1:

```bash
python3 server_side.py
```

Terminal 2:

```bash
python3 client_side.py
```

The server-side file prepares the demo site, generates certificates, writes the config, and starts the server.

The client-side file performs two requests:

1. plain HTTP request to `127.0.0.1:8080`,
2. HTTP-over-self-written-TLS request to `127.0.0.1:8443`.

The second request uses the custom client from this repository, because the TLS-like wire format is educational and not compatible with browser HTTPS.

---

## One-command demo

If you want to see the full flow without two terminals:

```bash
python3 scripts/demo.py
```

It starts the server in a background thread, sends a plain HTTP request, sends an encrypted HTTP request through the custom TLS layer, prints both responses, and exits.

---

## Expected demo output

The ports are chosen dynamically, but the important lines should look like this:

```text
[demo] Generating local root/intermediate/server certificates...
[demo] Server ready
       plain HTTP listener:        http://127.0.0.1:<port>/
       self-written TLS listener:  127.0.0.1:<port> (custom client only)

[demo] Plain HTTP request
HTTP/1.1 200 OK
...

[demo] HTTP over the self-written TLS-like layer
       -> sending ClientHello
       <- certificate chain and CertificateVerify accepted
       -> sending encrypted HTTP request
       <- decrypted HTTP response
HTTP/1.1 200 OK
...

[demo] Done.
```

If both paths return `HTTP/1.1 200 OK`, the integration works.

---

## Tests

```bash
python3 -m pytest -q
```

The tests cover:

- config parsing for `listen 8443 ssl`, certificate paths, and locations;
- fragmented TLS handshake and fragmented encrypted application records;
- wrong DNS name rejection during certificate verification;
- tampered encrypted record rejection;
- sequence-number mismatch rejection;
- HTTP requests split across multiple encrypted TLS records;
- end-to-end plain HTTP and HTTP-over-self-written-TLS through the same server;
- reader-facing documentation expectations and standalone workflow files.

---

## What to look for while reading the code

The most important line of thought is this:

```text
socket bytes are not always HTTP bytes
```

For a plain listener, they are:

```python
context.http_input.append(socket_bytes)
```

For a TLS listener, they are not. They must first pass through the TLS record layer:

```python
context.tls.feed_wire_data(socket_bytes)
context.http_input.append(context.tls.read_plaintext())
```

After that, the web-server logic is the same.

That is the bridge between the two series.

---

## What is intentionally simplified

This project keeps the same educational scope as the original TLS series. It does not implement real browser HTTPS.

Missing pieces compared with real TLS 1.3 include:

- real TLS record headers,
- real `ClientHello` / `ServerHello` structures,
- transcript hash binding,
- encrypted TLS handshake messages,
- `Finished` messages,
- SNI / ALPN negotiation,
- session resumption,
- alerts such as `close_notify`,
- OCSP / CRL revocation checking.

Those omissions keep the focus on the architecture:

> TLS terminates below HTTP and produces a secure byte stream for the web server.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError: cryptography` | Dependencies are not installed in the active Python environment. | Activate `.venv`, then run `python3 -m pip install -e ".[dev]"`. |
| `ModuleNotFoundError: pytest` | Dev dependencies were not installed. | Run `python3 -m pip install -e ".[dev]"`. |
| `Address already in use` on `8080` or `8443` | Another process is using the demo ports. | Stop the old process or pass different ports to `server_side.py` and `client_side.py`. |
| Browser or `curl https://localhost:8443` fails | Expected: this is not real TLS 1.3. | Use `python3 client_side.py` or `python3 scripts/demo.py`. |
| Certificate verification fails | Client and server are using different generated demo directories or DNS names. | Restart `python3 server_side.py`, then run `python3 client_side.py` with the same `--demo-dir`. |

---

## Possible next step

The natural follow-up article would be: **What would it take to make this browser-compatible?**

That means replacing the toy wire format with real TLS 1.3 while preserving the same high-level server boundary:

```text
TCP → real TLS 1.3 → plaintext HTTP → real TLS 1.3 → TCP
```
