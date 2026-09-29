"""
Input validation and normalization for values written to dnscrypt-proxy config.
Every function returns the normalized value or raises ValueError with a
user-facing message.
"""

import ipaddress
import re

_LABEL = r"[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_DOMAIN_RE = re.compile(rf"^(\*\.)?({_LABEL}\.)*{_LABEL}\.?$")
_STAMP_RE = re.compile(r"^sdns://[A-Za-z0-9_\-]+=*$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,99}$")


def domain_pattern(value: str) -> str:
    v = value.strip().lower()
    if not v:
        raise ValueError("Domain is empty")
    if not v.isascii():
        raise ValueError("Use the punycode (xn--) form for international domains")
    if not _DOMAIN_RE.match(v):
        raise ValueError("Use a domain like example.com, lan, or *.corp.example")
    return v.rstrip(".")


def host_port(value: str, default_port: int = 53) -> str:
    """'1.2.3.4', '1.2.3.4:53', '::1', '[::1]:53' -> normalized 'ip:port'."""
    v = value.strip()
    if not v:
        raise ValueError("Address is empty")

    port = default_port
    m = re.match(r"^\[([0-9A-Fa-f:.%a-zA-Z0-9]+)\](?::(\d+))?$", v)
    if m:
        host, p = m.group(1), m.group(2)
        if p:
            port = int(p)
    elif v.count(":") == 1:
        host, p = v.split(":")
        port = int(p) if p.isdigit() else -1
    else:
        host = v

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f"'{value}' is not an IP address")
    if not 0 < port < 65536:
        raise ValueError(f"'{value}' has an invalid port")
    return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"


def forward_target(value: str) -> str:
    v = value.strip()
    if v in ("$DHCP", "$BOOTSTRAP"):
        return v
    return host_port(v)


def is_private_target(target: str) -> bool:
    """True when a forwarding target never leaves the local network."""
    if target.startswith("$"):
        return True
    host = target.rsplit(":", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def resolver_name(value: str) -> str:
    v = value.strip()
    if not _NAME_RE.match(v):
        raise ValueError("Resolver names may only contain letters, digits, '.', '_' and '-'")
    return v


def stamp(value: str) -> str:
    v = value.strip()
    if not _STAMP_RE.match(v):
        raise ValueError("A server stamp looks like sdns://AgcAAAAA…")
    return v


def comment(value: str) -> str:
    return " ".join(value.replace("#", "").split())
