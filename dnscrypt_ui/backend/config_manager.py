"""
Configuration Manager for dnscrypt-proxy and forwarding-rules.
Parses, edits, and writes dnscrypt-proxy.toml and forwarding-rules.txt,
preserving comments and every setting the UI does not manage.
"""

import copy
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union

from . import tomledit
from .tomledit import toml_bool, toml_str, toml_str_list

CONFIG_DIR = Path("/etc/dnscrypt-proxy")
DEFAULT_QUERY_LOG = "/var/log/dnscrypt-proxy/query.log"
DEFAULT_BOOTSTRAP = ["9.9.9.11:53", "8.8.8.8:53"]

# Disabled rules are written with this marker so they can be told apart
# from ordinary comments and the examples shipped in the stock file.
DISABLED_PREFIX = "# [disabled] "

# TOML key -> ConfigManager attribute, for root settings the UI manages
ROOT_KEYS = {
    "listen_addresses": "listen_addresses",
    "server_names": "server_names",
    "bootstrap_resolvers": "bootstrap_resolvers",
    "doh_servers": "doh_servers",
    "dnscrypt_servers": "dnscrypt_servers",
    "require_dnssec": "require_dnssec",
    "require_nolog": "require_nolog",
    "require_nofilter": "require_nofilter",
    "forwarding_rules": "forwarding_rules_file",
}

_RULE_RE = re.compile(r"^(\S+)\s+([^\s#]+)\s*(?:#\s*(.*))?$")


@dataclass(eq=False)
class ForwardingRule:
    domain: str
    servers: List[str]
    comment: str = ""
    enabled: bool = True

    @property
    def servers_str(self) -> str:
        return ", ".join(self.servers)

    def to_line(self) -> str:
        line = f"{self.domain} {','.join(self.servers)}"
        if self.comment:
            line += f"  # {self.comment}"
        return line if self.enabled else DISABLED_PREFIX + line


def parse_rules(text: str) -> List[Union[str, ForwardingRule]]:
    """Returns the file as a list of raw lines and ForwardingRule objects."""
    items: List[Union[str, ForwardingRule]] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        enabled = True
        body = stripped
        if stripped.startswith(DISABLED_PREFIX.strip()):
            enabled = False
            body = stripped[len(DISABLED_PREFIX.strip()):].strip()
        elif not stripped or stripped.startswith("#"):
            items.append(raw)
            continue

        m = _RULE_RE.match(body)
        if not m:
            items.append(raw)
            continue
        servers = [s.strip() for s in m.group(2).split(",") if s.strip()]
        items.append(ForwardingRule(m.group(1), servers, (m.group(3) or "").strip(), enabled))
    return items


RULES_HEADER = """# Forwarding rules for dnscrypt-proxy, managed by DNSCrypt UI.
# Syntax: <domain> <server>[,<server>...]  [# note]
# A rule for example.com also matches all of its subdomains.
# Queries forwarded here are sent as plain, unencrypted DNS.
"""


class ConfigManager:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = Path(config_dir) if config_dir else CONFIG_DIR
        self.toml_path = self.config_dir / "dnscrypt-proxy.toml"

        self.raw_toml: str = ""
        self.raw_rules: str = ""
        self.parsed_toml: dict = {}
        self.load_error: str = ""

        self.listen_addresses: List[str] = ["127.0.0.1:53"]
        self.server_names: List[str] = []
        self.bootstrap_resolvers: List[str] = list(DEFAULT_BOOTSTRAP)
        self.ipv4_servers = True
        self.ipv6_servers = False
        self.doh_servers = True
        self.dnscrypt_servers = True
        self.odoh_servers = False
        self.require_dnssec = False
        self.require_nolog = True
        self.require_nofilter = True
        self.forwarding_rules_file = "forwarding-rules.txt"
        self.query_log_enabled = False
        self.query_log_file = DEFAULT_QUERY_LOG
        self.static_stamps: Dict[str, str] = {}

        self.rules: List[ForwardingRule] = []
        self._rule_items: List[Union[str, ForwardingRule]] = []

        self.load()

    @property
    def available(self) -> bool:
        return self.toml_path.exists() and not self.load_error

    @property
    def rules_path(self) -> Path:
        p = Path(self.forwarding_rules_file)
        return p if p.is_absolute() else self.config_dir / p

    # Loading

    def load(self):
        self.load_error = ""
        try:
            self.raw_toml = self.toml_path.read_text(encoding="utf-8")
            self.parsed_toml = tomllib.loads(self.raw_toml)
        except FileNotFoundError:
            self.raw_toml = ""
            self.parsed_toml = {}
            self.load_error = f"{self.toml_path} does not exist. Is dnscrypt-proxy installed?"
        except (OSError, tomllib.TOMLDecodeError) as e:
            self.parsed_toml = {}
            self.load_error = f"Cannot read {self.toml_path}: {e}"

        t = self.parsed_toml
        self.listen_addresses = list(t.get("listen_addresses", ["127.0.0.1:53"]))
        self.server_names = list(t.get("server_names", []))
        self.bootstrap_resolvers = list(
            t.get("bootstrap_resolvers") or t.get("fallback_resolvers") or DEFAULT_BOOTSTRAP
        )
        self.ipv4_servers = bool(t.get("ipv4_servers", True))
        self.ipv6_servers = bool(t.get("ipv6_servers", False))
        self.doh_servers = bool(t.get("doh_servers", True))
        self.dnscrypt_servers = bool(t.get("dnscrypt_servers", True))
        self.odoh_servers = bool(t.get("odoh_servers", False))
        self.require_dnssec = bool(t.get("require_dnssec", False))
        self.require_nolog = bool(t.get("require_nolog", True))
        self.require_nofilter = bool(t.get("require_nofilter", True))
        self.forwarding_rules_file = str(t.get("forwarding_rules", "forwarding-rules.txt"))

        qlog = t.get("query_log", {})
        qfile = qlog.get("file", "") if isinstance(qlog, dict) else ""
        self.query_log_enabled = bool(qfile)
        self.query_log_file = qfile or DEFAULT_QUERY_LOG

        static = t.get("static", {})
        self.static_stamps = {
            name: entry["stamp"]
            for name, entry in (static.items() if isinstance(static, dict) else [])
            if isinstance(entry, dict) and "stamp" in entry
        }

        self._loaded = {key: copy.deepcopy(getattr(self, attr)) for key, attr in ROOT_KEYS.items()}
        self._load_rules()
        self._baseline = self.get_staged_files() if self.available else {}

    def _load_rules(self):
        try:
            self.raw_rules = self.rules_path.read_text(encoding="utf-8")
        except OSError:
            self.raw_rules = ""
        text = self.raw_rules if self.raw_rules.strip() else RULES_HEADER
        self._rule_items = parse_rules(text)
        self.rules = [i for i in self._rule_items if isinstance(i, ForwardingRule)]

    @property
    def query_log_path(self) -> Path:
        p = Path(self.query_log_file)
        return p if p.is_absolute() else self.config_dir / p

    @property
    def is_dirty(self) -> bool:
        if not self.available:
            return False
        return self.get_staged_files() != self._baseline

    # Rule management

    def add_rule(self, domain: str, servers: List[str], comment: str = "", enabled: bool = True):
        rule = ForwardingRule(domain, list(servers), comment, enabled)
        self.rules.append(rule)
        self._rule_items.append(rule)

    def update_rule(self, rule: ForwardingRule, domain: str, servers: List[str], comment: str):
        rule.domain = domain
        rule.servers = list(servers)
        rule.comment = comment

    def remove_rule(self, rule: ForwardingRule):
        self.rules = [r for r in self.rules if r is not rule]
        self._rule_items = [i for i in self._rule_items if i is not rule]

    # Upstream resolvers

    def toggle_resolver(self, name: str, active: bool):
        if active and name not in self.server_names:
            self.server_names.append(name)
        elif not active and name in self.server_names:
            self.server_names.remove(name)

    def add_static_resolver(self, name: str, stamp: str):
        self.static_stamps[name] = stamp
        self.toggle_resolver(name, True)

    # Serialization

    def generate_rules_content(self) -> str:
        lines = [i.to_line() if isinstance(i, ForwardingRule) else i for i in self._rule_items]
        return "\n".join(lines).rstrip("\n") + "\n"

    def generate_toml_content(self) -> str:
        text = self.raw_toml
        root = {
            "listen_addresses": toml_str_list(self.listen_addresses),
            "server_names": toml_str_list(self.server_names),
            "bootstrap_resolvers": toml_str_list(self.bootstrap_resolvers),
            "doh_servers": toml_bool(self.doh_servers),
            "dnscrypt_servers": toml_bool(self.dnscrypt_servers),
            "require_dnssec": toml_bool(self.require_dnssec),
            "require_nolog": toml_bool(self.require_nolog),
            "require_nofilter": toml_bool(self.require_nofilter),
            "forwarding_rules": toml_str(self.forwarding_rules_file),
        }
        t = self.parsed_toml
        for key, value in root.items():
            # Only write what the user changed, so untouched settings keep
            # their original formatting and missing keys stay at defaults.
            if getattr(self, ROOT_KEYS[key]) == self._loaded.get(key):
                continue
            text = tomledit.set_key(text, None, key, value)

        # fallback_resolvers was renamed and is ignored once bootstrap_resolvers exists
        if "fallback_resolvers" in t:
            if "bootstrap_resolvers" not in t:
                text = tomledit.set_key(text, None, "bootstrap_resolvers", root["bootstrap_resolvers"])
            text = tomledit.remove_key(text, None, "fallback_resolvers")

        qlog = t.get("query_log", {}) if isinstance(t.get("query_log"), dict) else {}
        if self.query_log_enabled:
            if qlog.get("file") != self.query_log_file:
                text = tomledit.set_key(text, "query_log", "file", toml_str(self.query_log_file))
            if qlog.get("format") != "tsv":
                text = tomledit.set_key(text, "query_log", "format", toml_str("tsv"))
        elif "file" in qlog:
            text = tomledit.remove_key(text, "query_log", "file")

        existing_static = t.get("static", {}) if isinstance(t.get("static"), dict) else {}
        for name, stamp in self.static_stamps.items():
            if name in existing_static:
                if existing_static[name].get("stamp") != stamp:
                    text = tomledit.set_key(text, f"static.{name}", "stamp", toml_str(stamp))
                continue
            suffix = "" if text.endswith("\n") else "\n"
            text += f"{suffix}\n[static.{toml_str(name)}]\nstamp = {toml_str(stamp)}\n"

        return text

    def get_staged_files(self) -> Dict[str, str]:
        return {
            "toml": self.generate_toml_content(),
            "rules": self.generate_rules_content(),
        }
