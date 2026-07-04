"""NGINX-style configuration parser used by the learning server.

The web-server series introduced a tiny lexer/parser for blocks like:

    http { server { listen 8080; location / { root html; } } }

This version keeps the same shape and adds the TLS directives needed to decide
which listener should create a ToyTLSServerConnection:

    listen 8443 ssl;
    ssl_certificate ...;
    ssl_certificate_key ...;
    ssl_certificate_chain ...;
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

Token = Tuple[str, str]
RawConfig = Dict[str, Union[List[str], "RawConfig", List["RawConfig"], List[List[str]]]]


@dataclass(frozen=True)
class ListenDirective:
    port: int
    ssl: bool = False


@dataclass(frozen=True)
class LocationConfig:
    path: str
    root: str


@dataclass(frozen=True)
class TLSConfig:
    certificate_path: str
    private_key_path: str
    chain_paths: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ServerBlock:
    listens: List[ListenDirective]
    server_name: str = "localhost"
    locations: Dict[str, LocationConfig] = field(default_factory=dict)
    tls: Optional[TLSConfig] = None


@dataclass(frozen=True)
class AppConfig:
    servers: List[ServerBlock]


class ConfigLexer:
    """Small lexer for the subset of NGINX config used by the demo.

    The lexer does not understand config semantics. It only turns characters
    into tokens such as WORD, LBRACE, RBRACE, and SEMICOLON. The parser decides
    what those tokens mean.
    """

    TOKEN_PATTERNS = [
        ("COMMENT", r"#.*"),
        ("LBRACE", r"\{"),
        ("RBRACE", r"\}"),
        ("SEMICOLON", r";"),
        ("STRING", r'"[^"]*"'),
        ("WORD", r"[a-zA-Z0-9_./:\\-]+"),
        ("WHITESPACE", r"[ \t\r\n]+"),
    ]

    def __init__(self, config_text: str):
        self.config_text = config_text

    def tokenize(self) -> List[Token]:
        pattern = "|".join(f"(?P<{name}>{regex})" for name, regex in self.TOKEN_PATTERNS)
        token_re = re.compile(pattern)
        pos = 0
        tokens: List[Token] = []
        while pos < len(self.config_text):
            match = token_re.match(self.config_text, pos)
            if not match:
                raise SyntaxError(f"Unexpected character at position {pos}: {self.config_text[pos]!r}")
            kind = match.lastgroup or ""
            value = match.group()
            if kind in ("WHITESPACE", "COMMENT"):
                pass
            elif kind == "STRING":
                tokens.append((kind, value.strip('"')))
            else:
                tokens.append((kind, value))
            pos = match.end()
        return tokens


class ConfigParser:
    """Recursive descent parser for simple directives and nested blocks.

    It builds a raw nested dictionary first. A second pass converts that raw
    shape into typed dataclasses such as ServerBlock, ListenDirective, and
    TLSConfig. Keeping those two steps separate makes the parser easier to read.
    """

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def parse(self) -> RawConfig:
        return self._parse_block()

    def _parse_block(self) -> RawConfig:
        config: RawConfig = {}
        while self.pos < len(self.tokens):
            token_type, token_value = self.tokens[self.pos]
            if token_type == "RBRACE":
                self.pos += 1
                return config
            if token_type != "WORD":
                raise SyntaxError(f"Expected directive name, got {token_type} {token_value!r}")

            key = token_value
            self.pos += 1
            args: List[str] = []

            while self.pos < len(self.tokens):
                current_type, current_value = self.tokens[self.pos]
                if current_type == "LBRACE":
                    if len(args) > 1:
                        raise SyntaxError(f"Block {key!r} accepts at most one argument, got {args}")
                    self.pos += 1
                    nested = self._parse_block()
                    if args:
                        arg_key = args[0]
                        existing = config.setdefault(key, {})
                        if not isinstance(existing, dict):
                            raise SyntaxError(f"Cannot nest block under simple directive {key!r}")
                        existing[arg_key] = nested
                    else:
                        self._append_repeated(config, key, nested)
                    break
                if current_type == "SEMICOLON":
                    self.pos += 1
                    # Keep every directive value as a list of arguments. This
                    # preserves the difference between `listen 8080;` and
                    # `listen 8443 ssl;` without guessing later.
                    self._append_repeated(config, key, list(args))
                    break
                if current_type not in ("WORD", "STRING"):
                    raise SyntaxError(f"Unexpected token {current_type} {current_value!r}")
                args.append(current_value)
                self.pos += 1
            else:
                raise SyntaxError(f"Unexpected end of input after {key!r}")
        return config

    @staticmethod
    def _append_repeated(config: RawConfig, key: str, value):
        if key not in config:
            config[key] = value
            return
        existing = config[key]
        if isinstance(existing, list) and (not existing or not all(isinstance(item, str) for item in existing)):
            existing.append(value)
        else:
            config[key] = [existing, value]


def _directive_values(raw_value) -> List[List[str]]:
    if raw_value is None:
        return []
    if isinstance(raw_value, list):
        if not raw_value:
            return [[]]
        if all(isinstance(item, str) for item in raw_value):
            return [raw_value]
        return raw_value
    raise TypeError(f"Expected directive value list, got {raw_value!r}")


def _first_arg(raw_value, default: str = "") -> str:
    values = _directive_values(raw_value)
    if not values or not values[0]:
        return default
    return values[0][0]


def _parse_listen(raw_value) -> List[ListenDirective]:
    listens: List[ListenDirective] = []
    for args in _directive_values(raw_value):
        if not args:
            continue
        try:
            port = int(args[0])
        except ValueError as exc:
            raise ValueError(f"Invalid listen port: {args[0]!r}") from exc
        listens.append(ListenDirective(port=port, ssl="ssl" in args[1:]))
    return listens or [ListenDirective(port=8080, ssl=False)]


def _parse_locations(raw_locations) -> Dict[str, LocationConfig]:
    locations: Dict[str, LocationConfig] = {}
    if not isinstance(raw_locations, dict):
        return locations
    for path, block in raw_locations.items():
        if not isinstance(block, dict):
            continue
        root = _first_arg(block.get("root"), default="html")
        locations[path] = LocationConfig(path=path, root=root)
    return locations or {"/": LocationConfig(path="/", root="html")}


def _parse_tls(server_raw: RawConfig) -> Optional[TLSConfig]:
    cert = _first_arg(server_raw.get("ssl_certificate"), default="")
    key = _first_arg(server_raw.get("ssl_certificate_key"), default="")
    if not cert and not key:
        return None
    if not cert or not key:
        raise ValueError("Both ssl_certificate and ssl_certificate_key are required for TLS listeners")
    chain_paths = [args[0] for args in _directive_values(server_raw.get("ssl_certificate_chain")) if args]
    return TLSConfig(certificate_path=cert, private_key_path=key, chain_paths=chain_paths)


def parse_config_dict(raw: RawConfig) -> AppConfig:
    http = raw.get("http", {})
    if not isinstance(http, dict):
        raise ValueError("Config must contain an http block")

    raw_servers = http.get("server", [])
    if isinstance(raw_servers, dict):
        server_items = [raw_servers]
    elif isinstance(raw_servers, list):
        server_items = raw_servers
    else:
        server_items = []

    servers: List[ServerBlock] = []
    for server_raw in server_items:
        if not isinstance(server_raw, dict):
            continue
        listens = _parse_listen(server_raw.get("listen"))
        server_name = _first_arg(server_raw.get("server_name"), default="localhost")
        locations = _parse_locations(server_raw.get("location", {}))
        tls = _parse_tls(server_raw)
        servers.append(ServerBlock(listens=listens, server_name=server_name, locations=locations, tls=tls))

    if not servers:
        raise ValueError("Config must define at least one server block")
    return AppConfig(servers=servers)


def load_config(path: Union[str, Path]) -> AppConfig:
    config_path = Path(path)
    text = config_path.read_text(encoding="utf-8")
    tokens = ConfigLexer(text).tokenize()
    raw = ConfigParser(tokens).parse()
    return parse_config_dict(raw)
