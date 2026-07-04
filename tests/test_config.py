from pathlib import Path

from tls_web_server.config import load_config


def test_config_parses_plain_and_tls_listeners(tmp_path: Path):
    config_path = tmp_path / "server.conf"
    config_path.write_text(
        """
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
        """,
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert len(config.servers) == 1
    server = config.servers[0]
    assert [(listen.port, listen.ssl) for listen in server.listens] == [
        (8080, False),
        (8443, True),
    ]
    assert server.server_name == "localhost"
    assert server.tls is not None
    assert server.tls.certificate_path == "certs/server_cert.pem"
    assert server.tls.private_key_path == "certs/server_key.pem"
    assert server.tls.chain_paths == ["certs/intermediate_cert.pem"]
    assert server.locations["/"].root == "html"
