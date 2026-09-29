"""
Catalog of public and secure DNS resolvers supported by dnscrypt-proxy.
Provides metadata (protocol, DNSSEC support, logging policy, filter policy)
for easy browsing and selection in the UI.
"""

from typing import List, Dict, Optional

KNOWN_RESOLVERS: List[Dict] = [
    {
        "name": "quad9-doh-ip4-filter-pri",
        "label": "Quad9 (Malware Blocking + DNSSEC)",
        "protocol": "DoH",
        "description": "Recommended. Blocks malware and malicious domains. DNSSEC validated, no telemetry/logs.",
        "dnssec": True,
        "nolog": True,
        "nofilter": False,
        "default": True,
    },
    {
        "name": "quad9-doh-ip4-nofilter-pri",
        "label": "Quad9 Uncensored (No Filter)",
        "protocol": "DoH",
        "description": "Quad9 without threat intelligence filtering. DNSSEC validated, no logs.",
        "dnssec": True,
        "nolog": True,
        "nofilter": True,
        "default": False,
    },
    {
        "name": "cloudflare",
        "label": "Cloudflare Public DNS (1.1.1.1)",
        "protocol": "DoH",
        "description": "High performance global anycast DoH resolver. DNSSEC validated, privacy certified.",
        "dnssec": True,
        "nolog": True,
        "nofilter": True,
        "default": True,
    },
    {
        "name": "cloudflare-security",
        "label": "Cloudflare Security (1.1.1.2)",
        "protocol": "DoH",
        "description": "Cloudflare 1.1.1.2 with automated malware and threat blocking.",
        "dnssec": True,
        "nolog": True,
        "nofilter": False,
        "default": False,
    },
    {
        "name": "cloudflare-family",
        "label": "Cloudflare Family (1.1.1.3)",
        "protocol": "DoH",
        "description": "Cloudflare 1.1.1.3 with malware blocking and adult content filtering.",
        "dnssec": True,
        "nolog": True,
        "nofilter": False,
        "default": False,
    },
    {
        "name": "google",
        "label": "Google Public DNS (8.8.8.8)",
        "protocol": "DoH",
        "description": "Google DoH resolver. Fast and highly reliable global infrastructure.",
        "dnssec": True,
        "nolog": False,
        "nofilter": True,
        "default": False,
    },
    {
        "name": "adguard-dns",
        "label": "AdGuard Default (Ads and Trackers Blocked)",
        "protocol": "DoH",
        "description": "Blocks advertisements, tracking domains, and phishing.",
        "dnssec": True,
        "nolog": True,
        "nofilter": False,
        "default": False,
    },
    {
        "name": "adguard-dns-family",
        "label": "AdGuard Family Protection",
        "protocol": "DoH",
        "description": "Blocks ads, trackers, malicious domains, and adult sites with SafeSearch.",
        "dnssec": True,
        "nolog": True,
        "nofilter": False,
        "default": False,
    },
    {
        "name": "mullvad-doh",
        "label": "Mullvad Privacy DNS",
        "protocol": "DoH",
        "description": "Strict zero-log DNS hosted in Sweden by Mullvad VPN. QNAME minimization.",
        "dnssec": True,
        "nolog": True,
        "nofilter": True,
        "default": False,
    },
    {
        "name": "mullvad-adblock-doh",
        "label": "Mullvad AdBlock DNS",
        "protocol": "DoH",
        "description": "Mullvad DoH with built-in ad and tracker blocking list.",
        "dnssec": True,
        "nolog": True,
        "nofilter": False,
        "default": False,
    },
    {
        "name": "nextdns",
        "label": "NextDNS Public",
        "protocol": "DoH",
        "description": "NextDNS public resolver. Ultra-low latency and anycast routing.",
        "dnssec": True,
        "nolog": True,
        "nofilter": True,
        "default": False,
    },
    {
        "name": "opendns",
        "label": "Cisco OpenDNS",
        "protocol": "DoH",
        "description": "Cisco OpenDNS Home with basic phishing and botnet protection.",
        "dnssec": False,
        "nolog": False,
        "nofilter": False,
        "default": False,
    },
    {
        "name": "cisco-familyshield",
        "label": "Cisco OpenDNS FamilyShield",
        "protocol": "DoH",
        "description": "Cisco OpenDNS with automated adult content and malware blocking.",
        "dnssec": False,
        "nolog": False,
        "nofilter": False,
        "default": False,
    },
    {
        "name": "cs-us",
        "label": "DNSCrypt.info US",
        "protocol": "DNSCrypt",
        "description": "Classic DNSCrypt protocol server located in the US. No logs, DNSSEC.",
        "dnssec": True,
        "nolog": True,
        "nofilter": True,
        "default": False,
    },
    {
        "name": "cs-de",
        "label": "DNSCrypt.info Germany",
        "protocol": "DNSCrypt",
        "description": "Classic DNSCrypt protocol server located in Frankfurt, Germany. No logs.",
        "dnssec": True,
        "nolog": True,
        "nofilter": True,
        "default": False,
    },
]


def get_all_resolvers() -> List[Dict]:
    return KNOWN_RESOLVERS


def find_resolver(name: str) -> Optional[Dict]:
    for r in KNOWN_RESOLVERS:
        if r["name"] == name:
            return r
    return None
