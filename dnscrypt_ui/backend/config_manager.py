"""
Configuration Manager for dnscrypt-proxy and forwarding-rules.
Parses, edits, and writes dnscrypt-proxy.toml and forwarding-rules.txt.
Supports surgical updates to preserve existing comments and custom settings.
"""

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Tuple


@dataclass
class ForwardingRule:
    domain: str
    servers: List[str]
    comment: str = ""
    enabled: bool = True

    @property
    def servers_str(self) -> str:
        return ", ".join(self.servers)


DEFAULT_SYSTEM_DIR = Path("/etc/dnscrypt-proxy")
DEFAULT_USER_DIR = Path.home() / ".config" / "dnscrypt-proxy"


DEFAULT_TOML_TEMPLATE = """# Configuration for dnscrypt-proxy managed by DNSCrypt UI
listen_addresses = ['127.0.0.1:53']
max_clients = 250

# Active upstream resolvers (DoH, DNSCrypt)
server_names = ['quad9-doh-ip4-filter-pri', 'cloudflare']

# Fallback resolvers when no upstream servers can be reached
fallback_resolvers = ['9.9.9.9:53', '1.1.1.1:53']

# Protocol filters
doh_servers = true
dnscrypt_servers = true

# Security and privacy requirements
require_dnssec = false
require_nolog = false
require_nofilter = false

# Split-DNS / YogaDNS style domain-based forwarding rules
forwarding_rules = 'forwarding-rules.txt'

# Live DNS query logging
[query_log]
file = '/var/log/dnscrypt-proxy/query.log'
format = 'tsv'
ignored = []
"""

DEFAULT_RULES_TEMPLATE = """# Forwarding rules for dnscrypt-proxy (Split-DNS / YogaDNS style)
# Syntax: <domain_pattern> <resolver_ip_1>[,<resolver_ip_2>]
#
# Examples:
# Route local home/LAN devices to local router
*.lan 192.168.1.1:53
*.local 192.168.1.1:53

# Route corporate / work intranet domains to internal company DNS
# *.internal 10.0.0.53
"""


class ConfigManager:
    def __init__(self, config_dir: Optional[Path] = None):
        if config_dir:
            self.config_dir = Path(config_dir)
        elif DEFAULT_SYSTEM_DIR.exists():
            self.config_dir = DEFAULT_SYSTEM_DIR
        else:
            self.config_dir = DEFAULT_USER_DIR

        self.toml_path = self.config_dir / "dnscrypt-proxy.toml"
        self.rules_path = self.config_dir / "forwarding-rules.txt"

        # Parsed state
        self.raw_toml: str = ""
        self.parsed_toml: dict = {}
        self.listen_addresses: List[str] = ["127.0.0.1:53"]
        self.server_names: List[str] = ["quad9-doh-ip4-filter-pri", "cloudflare"]
        self.fallback_resolvers: List[str] = ["9.9.9.9:53", "1.1.1.1:53"]
        self.doh_servers: bool = True
        self.dnscrypt_servers: bool = True
        self.require_dnssec: bool = False
        self.require_nolog: bool = False
        self.require_nofilter: bool = False
        self.forwarding_rules_file: str = "forwarding-rules.txt"
        self.query_log_enabled: bool = True
        self.query_log_file: str = "/var/log/dnscrypt-proxy/query.log"

        self.rules: List[ForwardingRule] = []
        self._dirty: bool = False

        self.load()

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    def set_dirty(self, dirty: bool = True):
        self._dirty = dirty

    def load(self):
        """Loads configuration from files or initializes with defaults."""
        self._load_toml()
        self._load_rules()
        self._dirty = False

    def _load_toml(self):
        if self.toml_path.exists():
            try:
                with open(self.toml_path, "r", encoding="utf-8") as f:
                    self.raw_toml = f.read()
                self.parsed_toml = tomllib.loads(self.raw_toml)
            except Exception as e:
                print(f"[ConfigManager] Error reading {self.toml_path}: {e}")
                self.raw_toml = DEFAULT_TOML_TEMPLATE
                self.parsed_toml = tomllib.loads(self.raw_toml)
        else:
            self.raw_toml = DEFAULT_TOML_TEMPLATE
            self.parsed_toml = tomllib.loads(self.raw_toml)

        # Extract values
        self.listen_addresses = list(self.parsed_toml.get("listen_addresses", ["127.0.0.1:53"]))
        self.server_names = list(self.parsed_toml.get("server_names", ["quad9-doh-ip4-filter-pri", "cloudflare"]))
        self.fallback_resolvers = list(self.parsed_toml.get("fallback_resolvers", ["9.9.9.9:53", "1.1.1.1:53"]))
        self.doh_servers = bool(self.parsed_toml.get("doh_servers", True))
        self.dnscrypt_servers = bool(self.parsed_toml.get("dnscrypt_servers", True))
        self.require_dnssec = bool(self.parsed_toml.get("require_dnssec", False))
        self.require_nolog = bool(self.parsed_toml.get("require_nolog", False))
        self.require_nofilter = bool(self.parsed_toml.get("require_nofilter", False))
        self.forwarding_rules_file = str(self.parsed_toml.get("forwarding_rules", "forwarding-rules.txt"))

        qlog = self.parsed_toml.get("query_log", {})
        if isinstance(qlog, dict):
            self.query_log_file = qlog.get("file", "/var/log/dnscrypt-proxy/query.log")
            self.query_log_enabled = bool(self.query_log_file and not self.query_log_file.startswith("#"))
        else:
            self.query_log_enabled = False

    def _load_rules(self):
        self.rules = []
        rules_path = self.rules_path
        if not rules_path.is_absolute():
            rules_path = self.config_dir / self.forwarding_rules_file

        if not rules_path.exists():
            # Check default template
            lines = DEFAULT_RULES_TEMPLATE.splitlines()
        else:
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception as e:
                print(f"[ConfigManager] Error reading rules from {rules_path}: {e}")
                lines = []

        last_comment = ""
        for line in lines:
            line_str = line.strip()
            if not line_str:
                last_comment = ""
                continue
            if line_str.startswith("#"):
                # Check if it's a disabled rule: e.g. '# *.corp 10.0.0.1'
                content = line_str.lstrip("#").strip()
                tokens = content.split()
                if len(tokens) >= 2 and ("." in tokens[0] or ":" in tokens[1] or re.match(r"^\d+\.\d+\.\d+\.\d+", tokens[1])):
                    domain = tokens[0]
                    servers = [s.strip() for s in tokens[1].split(",") if s.strip()]
                    self.rules.append(ForwardingRule(domain=domain, servers=servers, comment=last_comment, enabled=False))
                    last_comment = ""
                else:
                    last_comment = content
                continue

            # Active rule
            tokens = line_str.split(None, 1)
            if len(tokens) >= 2:
                domain = tokens[0]
                rest = tokens[1].split("#", 1)
                servers_part = rest[0].strip()
                inline_comment = rest[1].strip() if len(rest) > 1 else ""
                comment = inline_comment or last_comment
                servers = [s.strip() for s in servers_part.split(",") if s.strip()]
                self.rules.append(ForwardingRule(domain=domain, servers=servers, comment=comment, enabled=True))
                last_comment = ""

    # Rule Management Methods
    def add_rule(self, domain: str, servers: List[str], comment: str = "", enabled: bool = True):
        rule = ForwardingRule(domain=domain.strip(), servers=servers, comment=comment.strip(), enabled=enabled)
        self.rules.append(rule)
        self.set_dirty()

    def update_rule(self, index: int, domain: str, servers: List[str], comment: str = "", enabled: bool = True):
        if 0 <= index < len(self.rules):
            self.rules[index] = ForwardingRule(domain=domain.strip(), servers=servers, comment=comment.strip(), enabled=enabled)
            self.set_dirty()

    def remove_rule(self, index: int):
        if 0 <= index < len(self.rules):
            self.rules.pop(index)
            self.set_dirty()

    def toggle_rule(self, index: int):
        if 0 <= index < len(self.rules):
            self.rules[index].enabled = not self.rules[index].enabled
            self.set_dirty()

    # Upstream Resolver Management
    def toggle_resolver(self, name: str, active: bool):
        if active and name not in self.server_names:
            self.server_names.append(name)
            self.set_dirty()
        elif not active and name in self.server_names:
            self.server_names.remove(name)
            self.set_dirty()

    def set_resolvers(self, names: List[str]):
        if self.server_names != names:
            self.server_names = list(names)
            self.set_dirty()

    # Serialization
    def generate_rules_content(self) -> str:
        lines = [
            "# Forwarding rules generated by DNSCrypt UI",
            "# YogaDNS-style Split DNS (domain pattern -> target resolver)",
            "",
        ]
        for r in self.rules:
            if r.comment:
                lines.append(f"# {r.comment}")
            servers_part = ",".join(r.servers)
            if r.enabled:
                lines.append(f"{r.domain} {servers_part}")
            else:
                lines.append(f"# {r.domain} {servers_part}")
            lines.append("")
        return "\n".join(lines)

    def generate_toml_content(self) -> str:
        """
        Surgically updates the existing TOML or creates a clean new one.
        Ensures all root-level keys remain in the root section before any [section] header.
        """
        base = self.raw_toml if self.raw_toml.strip() else DEFAULT_TOML_TEMPLATE
        raw_lines = base.splitlines()

        # 1. Clean up any broken appended settings at the end of the file
        cleaned_lines = []
        skip_appended = False
        for l in raw_lines:
            if "# Settings added by DNSCrypt UI" in l or "# Root settings managed by DNSCrypt UI" in l:
                skip_appended = True
            if not skip_appended:
                cleaned_lines.append(l)

        def format_str_list(lst: List[str]) -> str:
            items = ", ".join(f"'{x}'" for x in lst)
            return f"[{items}]"

        keys_to_update = {
            "listen_addresses": format_str_list(self.listen_addresses),
            "server_names": format_str_list(self.server_names),
            "fallback_resolvers": format_str_list(self.fallback_resolvers),
            "doh_servers": "true" if self.doh_servers else "false",
            "dnscrypt_servers": "true" if self.dnscrypt_servers else "false",
            "require_dnssec": "true" if self.require_dnssec else "false",
            "require_nolog": "true" if self.require_nolog else "false",
            "require_nofilter": "true" if self.require_nofilter else "false",
            "forwarding_rules": f"'{self.forwarding_rules_file}'",
        }

        updated_keys = set()
        new_lines = []
        in_root_section = True

        for line in cleaned_lines:
            stripped = line.strip()

            # When we encounter the first section header (e.g. [query_log], [static], etc.)
            if in_root_section and stripped.startswith("[") and not stripped.startswith("['"):
                in_root_section = False
                # Insert any root keys that haven't been matched yet BEFORE this section!
                missing = [k for k in keys_to_update if k not in updated_keys]
                if missing:
                    new_lines.append("\n# Root settings managed by DNSCrypt UI")
                    for k in missing:
                        new_lines.append(f"{k} = {keys_to_update[k]}")
                        updated_keys.add(k)
                    new_lines.append("")

            if in_root_section:
                matched = False
                for k, val in keys_to_update.items():
                    # Match both 'key =' and '# key =' in root section!
                    pattern = rf"^\s*#?\s*{re.escape(k)}\s*="
                    if re.match(pattern, stripped):
                        new_lines.append(f"{k} = {val}")
                        updated_keys.add(k)
                        matched = True
                        break
                if not matched:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        # If there were no section headers, insert any remaining missing keys
        missing = [k for k in keys_to_update if k not in updated_keys]
        if missing:
            new_lines.append("\n# Root settings managed by DNSCrypt UI")
            for k in missing:
                new_lines.append(f"{k} = {keys_to_update[k]}")

        # Ensure [query_log] is properly configured
        content = "\n".join(new_lines)
        if "[query_log]" not in content:
            content += f"\n\n[query_log]\nfile = '{self.query_log_file}'\nformat = 'tsv'\n"

        return content

    def get_staged_files(self) -> Dict[Path, str]:
        """Returns dict of destination Path -> file content to write."""
        rules_path = self.rules_path
        if not rules_path.is_absolute():
            rules_path = self.config_dir / self.forwarding_rules_file

        return {
            self.toml_path: self.generate_toml_content(),
            rules_path: self.generate_rules_content(),
        }
