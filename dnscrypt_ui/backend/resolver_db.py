"""
Resolver catalog for dnscrypt-proxy.

The catalog is read from dnscrypt-proxy itself (`-list-all -json`), so names
and properties always match the sources configured in dnscrypt-proxy.toml.
A small curated list marks well-known providers as "recommended".
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

CACHE_FILE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "dnscrypt-ui" / "resolvers.json"

RECOMMENDED = {
    "quad9-doh-ip4-port443-filter-pri": "Quad9 (malware blocking)",
    "quad9-doh-ip4-port443-nofilter-pri": "Quad9 (unfiltered)",
    "cloudflare": "Cloudflare 1.1.1.1",
    "cloudflare-security": "Cloudflare 1.1.1.2 (malware blocking)",
    "cloudflare-family": "Cloudflare 1.1.1.3 (malware + adult blocking)",
    "mullvad-doh": "Mullvad (unfiltered)",
    "mullvad-adblock-doh": "Mullvad (ad blocking)",
    "adguard-dns-doh": "AdGuard (ad blocking)",
    "adguard-dns-unfiltered-doh": "AdGuard (unfiltered)",
    "adguard-dns-family-doh": "AdGuard Family",
    "nextdns": "NextDNS",
    "google": "Google Public DNS",
}


def _normalize(entry: Dict) -> Dict:
    return {
        "name": entry.get("name", ""),
        "proto": entry.get("proto", "?"),
        "ipv6": bool(entry.get("ipv6", False)),
        "dnssec": bool(entry.get("dnssec", False)),
        "nolog": bool(entry.get("nolog", False)),
        "nofilter": bool(entry.get("nofilter", False)),
        "description": (entry.get("description") or "").split("\n")[0],
        "label": RECOMMENDED.get(entry.get("name", ""), entry.get("name", "")),
        "recommended": entry.get("name") in RECOMMENDED,
    }


def load_cached() -> List[Dict]:
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def fetch_catalog(config_path: Path, timeout: int = 60) -> List[Dict]:
    """
    Asks dnscrypt-proxy for every server in its sources. Blocking: call from
    a worker thread. Raises RuntimeError when the list cannot be produced.
    """
    binary = shutil.which("dnscrypt-proxy") or "/usr/bin/dnscrypt-proxy"
    try:
        res = subprocess.run(
            [binary, "-config", str(config_path), "-list-all", "-json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(config_path.parent),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(str(e))
    try:
        data = json.loads(res.stdout)
    except ValueError:
        tail = (res.stderr or "").strip().splitlines()[-1:] or ["no output"]
        raise RuntimeError(f"dnscrypt-proxy could not list servers: {tail[0]}")

    catalog = [_normalize(e) for e in data if isinstance(e, dict)]
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(catalog), encoding="utf-8")
    except OSError:
        pass
    return catalog


def find_resolver(catalog: List[Dict], name: str) -> Optional[Dict]:
    for r in catalog:
        if r["name"] == name:
            return r
    return None


def exclusion_reason(entry: Optional[Dict], cfg) -> Optional[str]:
    """
    Why dnscrypt-proxy would skip this server with the current settings,
    or None if it is usable. `cfg` is a ConfigManager.
    """
    if entry is None:
        return "Not found in the resolver sources"
    proto = entry["proto"]
    if proto == "DoH" and not cfg.doh_servers:
        return "DoH servers are disabled in Settings"
    if proto == "DNSCrypt" and not cfg.dnscrypt_servers:
        return "DNSCrypt servers are disabled in Settings"
    if proto == "ODoH" and not cfg.odoh_servers:
        return "ODoH servers are disabled"
    if entry["ipv6"] and not cfg.ipv6_servers:
        return "IPv6 servers are disabled"
    if cfg.require_dnssec and not entry["dnssec"]:
        return "Does not validate DNSSEC (required)"
    if cfg.require_nolog and not entry["nolog"]:
        return "May log queries (no-log is required)"
    if cfg.require_nofilter and not entry["nofilter"]:
        return "Filters results (no-filter is required)"
    return None


def exclusion_fix(entry: Optional[Dict], cfg) -> Optional[tuple]:
    """
    The setting change that would stop dnscrypt-proxy skipping this server:
    (config attribute, new value, button label), or None if it is usable or
    cannot be fixed by a setting. Mirrors the order of exclusion_reason().
    """
    if entry is None:
        return None
    proto = entry["proto"]
    if proto == "DoH" and not cfg.doh_servers:
        return ("doh_servers", True, "Enable DoH")
    if proto == "DNSCrypt" and not cfg.dnscrypt_servers:
        return ("dnscrypt_servers", True, "Enable DNSCrypt")
    if proto == "ODoH" and not cfg.odoh_servers:
        return None
    if entry["ipv6"] and not cfg.ipv6_servers:
        return None
    if cfg.require_dnssec and not entry["dnssec"]:
        return ("require_dnssec", False, "Allow without DNSSEC")
    if cfg.require_nolog and not entry["nolog"]:
        return ("require_nolog", False, "Allow logging")
    if cfg.require_nofilter and not entry["nofilter"]:
        return ("require_nofilter", False, "Allow filtering")
    return None


def effective_servers(catalog: List[Dict], cfg) -> Optional[List[str]]:
    """
    Names dnscrypt-proxy will actually use. Returns None when server_names is
    empty (dnscrypt-proxy then picks from every server matching the filters),
    or when the catalog is unknown.
    """
    if not cfg.server_names or not catalog:
        return None
    usable = []
    for name in cfg.server_names:
        if name in cfg.static_stamps:
            usable.append(name)
        elif exclusion_reason(find_resolver(catalog, name), cfg) is None:
            usable.append(name)
    return usable
