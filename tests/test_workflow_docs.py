from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_reader_facing_docs_do_not_mention_local_agent_environment():
    docs = [
        ROOT / "README.md",
        ROOT / "walkthrough" / "walkthrough.html",
        ROOT / "docs" / "index.html",
        ROOT / "scripts" / "demo.py",
    ]
    for path in docs:
        text = path.read_text(encoding="utf-8")
        assert "Hermes" not in text
        assert "env -u" not in text
        assert "PYTHONPATH" not in text


def test_public_repo_does_not_hide_local_python_path_hacks():
    assert not (ROOT / "sitecustomize.py").exists()
    package_init = (ROOT / "tls_web_server" / "__init__.py").read_text(encoding="utf-8")
    assert "sys.path" not in package_init
    assert "site-packages" not in package_init


def test_reader_docs_link_back_to_the_original_series():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    walkthrough = (ROOT / "walkthrough" / "walkthrough.html").read_text(encoding="utf-8")

    expected_links = [
        "https://dev.to/dmytro_huz/building-your-own-web-server-part-1-theory-and-foundations-3kgo",
        "https://www.dmytrohuz.com/p/rebuilding-tls-from-scratch-my-complete",
        "https://github.com/DmytroHuzz/build_own_webserver",
        "https://github.com/DmytroHuzz/rebuilding_tls",
    ]
    for link in expected_links:
        assert link in readme
        assert link in walkthrough


def test_readme_contains_setup_glossary_expected_output_and_troubleshooting():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    required_sections = [
        "## Setup from a fresh clone",
        "## If you did not read the previous series",
        "## Minimum concepts",
        "## NGINX / OpenSSL analogy",
        "## Expected demo output",
        "## Troubleshooting",
    ]
    for section in required_sections:
        assert section in readme

    required_commands = [
        "python3 -m venv .venv",
        "python3 -m pip install -e \".[dev]\"",
        "python3 scripts/demo.py",
        "python3 -m pytest -q",
    ]
    for command in required_commands:
        assert command in readme


def test_readme_links_to_published_github_pages_walkthrough():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "## Visual walkthrough" in readme
    assert "https://dmytrohuzz.github.io/tls_web_server/" in readme
    assert "docs/index.html" in readme


def test_github_pages_entrypoint_matches_walkthrough():
    walkthrough = (ROOT / "walkthrough" / "walkthrough.html").read_text(encoding="utf-8")
    pages_index = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")

    assert pages_index == walkthrough
    assert (ROOT / "docs" / ".nojekyll").exists()


def test_standalone_client_and_server_workflow_files_exist():
    server_file = ROOT / "server_side.py"
    client_file = ROOT / "client_side.py"

    assert server_file.exists()
    assert client_file.exists()

    server_text = server_file.read_text(encoding="utf-8")
    client_text = client_file.read_text(encoding="utf-8")

    assert "prepare_demo_site" in server_text
    assert "WebServer" in server_text
    assert "ToyTLSClientConnection" in client_text
    assert "plain HTTP" in client_text
    assert "self-written TLS" in client_text


def test_walkthrough_explains_tls_client_server_workflow_as_phases():
    walkthrough = (ROOT / "walkthrough" / "walkthrough.html").read_text(encoding="utf-8")

    required_reader_signposts = [
        "Phase 0 — before the connection",
        "Phase 1 — handshake",
        "Phase 2 — encrypted HTTP",
        "Client side state",
        "Server side state",
        "What is on the wire",
        "What each side can compute",
        "Now HTTP can start",
    ]
    for signpost in required_reader_signposts:
        assert signpost in walkthrough


def test_walkthrough_has_beginner_glossary_run_command_and_nginx_analogy():
    walkthrough = (ROOT / "walkthrough" / "walkthrough.html").read_text(encoding="utf-8")

    required_text = [
        "Minimum concepts before reading",
        "Run the project first",
        "python3 scripts/demo.py",
        "NGINX / OpenSSL analogy",
        "Wrong mental model",
        "Right mental model",
    ]
    for text in required_text:
        assert text in walkthrough
