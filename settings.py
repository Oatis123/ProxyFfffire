"""Profile validation, PAC generation and local persistence."""

import ipaddress
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


APP_NAME = "ProxyFfffire"
PROTOCOLS = ("HTTP CONNECT", "SOCKS5")
MODES = ("Manual", "Selected Domains", "System Proxy")
DEFAULT_PORT = 8787
DEFAULT_TEST_URL = "https://example.com/"
CLAUDE_PRESET = {
    "name": "Claude Desktop",
    "source": "https://code.claude.com/docs/en/desktop#network-access-requirements",
    "verified_date": "2026-11-18",
    "domains": [
        "anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai",
        "claude.com", "*.claude.com", "claude.app", "*.claude.app",
        "*.claudeusercontent.com", "*.claudemcpcontent.com",
    ],
}


def data_dir():
    return Path(os.environ["LOCALAPPDATA"]) / APP_NAME


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".pending-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(value, file, indent=2, ensure_ascii=False)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def host_name(value):
    value = value.removesuffix(".")
    if "%" not in value:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid hostname.") from None
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(value) > 253 or not all(re.fullmatch(label, part) for part in value.split(".")):
        raise ValueError("Invalid hostname.")
    return value


def port_number(value):
    if not str(value).isascii() or not str(value).isdecimal() or not 1 <= int(value) <= 65535:
        raise ValueError("Ports must be numbers from 1 to 65535.")
    return int(value)


def parse_url(value, scheme):
    if any(ord(char) <= 32 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError(f"Enter a valid {scheme.upper()} URL.")
    try:
        url = urlsplit(value)
        if url.scheme != scheme or not url.hostname or url.username is not None or "#" in value:
            raise ValueError
        if url.netloc.endswith(":"):
            raise ValueError
        return url, host_name(url.hostname), port_number(url.port if url.port is not None else (443 if scheme == "https" else 80))
    except ValueError:
        raise ValueError(f"Enter a valid {scheme.upper()} URL with no credentials or fragment.") from None


def domain_rules(lines):
    result = []
    for rule in lines:
        rule = rule.strip()
        if not rule:
            continue
        wildcard = rule.startswith("*.")
        host = host_name(rule[2:] if wildcard else rule)
        if "." not in host or re.fullmatch(r"[0-9.]+", host):
            raise ValueError("Enter a domain such as example.com or *.example.com.")
        result.append("*." + host if wildcard else host)
    return list(dict.fromkeys(result))


def make_pac(rules, port):
    return f"""function FindProxyForURL(url, host) {{
    var rules = {json.dumps(rules)};
    var proxy = "PROXY 127.0.0.1:{port}";
    host = host.toLowerCase().replace(/\\.$/, "");
    for (var i = 0; i < rules.length; i++) {{
        var rule = rules[i];
        if (rule.substring(0, 2) === "*.") {{
            var suffix = rule.substring(1);
            if (host.length > suffix.length && host.slice(-suffix.length) === suffix) return proxy;
        }} else if (host === rule) {{
            return proxy;
        }}
    }}
    return "DIRECT";
}}
""".encode("ascii")


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    protocol: str
    host: str
    port: int
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)

    @classmethod
    def from_form(cls, id, name, protocol, host, port, username, password):
        name = name.strip()
        if not name or len(name) > 80 or not name.isprintable():
            raise ValueError("Enter a profile name of up to 80 printable characters.")
        if protocol not in PROTOCOLS:
            raise ValueError("Select a supported proxy protocol.")
        if password and not username:
            raise ValueError("Enter a username when using a password.")
        if protocol == "HTTP CONNECT" and ":" in username:
            raise ValueError("An HTTP CONNECT username cannot contain a colon.")
        if protocol == "SOCKS5" and any(len(item.encode("utf-8")) > 255 for item in (username, password)):
            raise ValueError("SOCKS5 credentials can use up to 255 UTF-8 bytes per field.")
        host = host.strip()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return cls(id, name, protocol, host_name(host), port_number(port), username, password)


class Store:
    def __init__(self, path, protect, unprotect):
        self.path = path
        self.protect = protect
        self.unprotect = unprotect

    def load(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            data = {"profiles": [], "presets": {"claude": dict(CLAUDE_PRESET)}, "routing": {}}
        return data

    def save(self, data):
        atomic_json(self.path, data)

    def pack(self, profile):
        return {
            "id": profile.id, "name": profile.name, "protocol": profile.protocol,
            "host": profile.host, "port": profile.port, "username": profile.username,
            "protected_password": self.protect(profile.password) if profile.password else "",
        }

    def unpack(self, record):
        fields = dict(record)
        secret = fields.pop("protected_password", "")
        return Profile(**fields, password=self.unprotect(secret) if secret else "")
