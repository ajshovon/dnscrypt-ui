"""
Run with: python3 -m unittest discover -s tests -v   (from dnscrypt-ui/)
"""

import hashlib
import importlib.machinery
import importlib.util
import io
import itertools
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dnscrypt_ui.backend import resolver_db, tomledit, validate  # noqa: E402
from dnscrypt_ui.backend.config_manager import ConfigManager, parse_rules, ForwardingRule  # noqa: E402
from dnscrypt_ui.backend.query_monitor import parse_line  # noqa: E402

SAMPLE_TOML = """\
## Comment header
# server_names = ['scaleway-fr', 'google']
server_names = [
  'cloudflare',
  'quad9-doh-ip4-filter-pri',
]

listen_addresses = ['127.0.0.1:53']
require_nolog = true
require_nofilter = true
bootstrap_resolvers = ['9.9.9.11:53', '8.8.8.8:53']
# forwarding_rules = 'forwarding-rules.txt'
forwarding_rules = 'forwarding-rules.txt'

# Root settings managed by DNSCrypt UI
fallback_resolvers = ['9.9.9.9:53', '1.1.1.1:53']

[query_log]

## Path to the query log file
# file = 'query.log'

# format = 'tsv'

[sources]

  [sources.public-resolvers]
    urls = ['https://example.invalid/public-resolvers.md']
    cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
"""

STOCK_RULES = """\
##################################
#        Forwarding rules        #
##################################

## Forward *.lan to 192.168.1.1
# lan 192.168.1.1

# example.com 9.9.9.9,8.8.8.8
"""


def make_cfg(toml=SAMPLE_TOML, rules=STOCK_RULES) -> ConfigManager:
    d = Path(tempfile.mkdtemp())
    (d / "dnscrypt-proxy.toml").write_text(toml)
    if rules is not None:
        (d / "forwarding-rules.txt").write_text(rules)
    return ConfigManager(config_dir=d)


class TomlEditTests(unittest.TestCase):
    def test_replaces_multiline_array_and_keeps_comments(self):
        out = tomledit.set_key(SAMPLE_TOML, None, "server_names", "['a']")
        self.assertEqual(tomllib.loads(out)["server_names"], ["a"])
        self.assertIn("# server_names = ['scaleway-fr', 'google']", out)
        self.assertNotIn("'cloudflare',", out)

    def test_does_not_uncomment_examples(self):
        out = tomledit.set_key(SAMPLE_TOML, None, "require_dnssec", "true")
        parsed = tomllib.loads(out)
        self.assertTrue(parsed["require_dnssec"])
        self.assertEqual(out.count("forwarding_rules = "), 2)  # commented + active, untouched

    def test_collapses_duplicates(self):
        text = "a = 1\nb = 2\na = 3\n[t]\na = 9\n"
        out = tomledit.set_key(text, None, "a", "5")
        self.assertEqual(tomllib.loads(out), {"a": 5, "b": 2, "t": {"a": 9}})

    def test_sets_key_inside_table(self):
        out = tomledit.set_key(SAMPLE_TOML, "query_log", "file", "'/var/log/x.log'")
        parsed = tomllib.loads(out)
        self.assertEqual(parsed["query_log"]["file"], "/var/log/x.log")
        self.assertNotIn("file", parsed)
        # placed right after the commented example
        self.assertIn("# file = 'query.log'\nfile = '/var/log/x.log'", out)

    def test_creates_missing_table(self):
        out = tomledit.set_key("a = 1\n", "query_log", "file", "'x'")
        self.assertEqual(tomllib.loads(out), {"a": 1, "query_log": {"file": "x"}})

    def test_new_root_key_goes_before_first_table(self):
        out = tomledit.set_key(SAMPLE_TOML, None, "doh_servers", "false")
        self.assertIs(tomllib.loads(out)["doh_servers"], False)

    def test_quoted_table_names(self):
        text = "[static.'my-server']\nstamp = 'sdns://old'\n"
        out = tomledit.set_key(text, "static.my-server", "stamp", "'sdns://new'")
        self.assertEqual(tomllib.loads(out)["static"]["my-server"]["stamp"], "sdns://new")

    def test_remove_key(self):
        out = tomledit.remove_key(SAMPLE_TOML, None, "fallback_resolvers")
        self.assertNotIn("fallback_resolvers", tomllib.loads(out))


class ConfigManagerTests(unittest.TestCase):
    def test_load_values(self):
        cfg = make_cfg()
        self.assertEqual(cfg.server_names, ["cloudflare", "quad9-doh-ip4-filter-pri"])
        self.assertFalse(cfg.query_log_enabled)
        self.assertEqual(cfg.bootstrap_resolvers, ["9.9.9.11:53", "8.8.8.8:53"])

    def test_not_dirty_after_load(self):
        self.assertFalse(make_cfg().is_dirty)

    def test_unchanged_config_only_drops_deprecated_key(self):
        cfg = make_cfg()
        out = cfg.generate_toml_content()
        self.assertEqual(out, tomledit.remove_key(SAMPLE_TOML, None, "fallback_resolvers"))

    def test_enable_query_log(self):
        cfg = make_cfg()
        cfg.query_log_enabled = True
        self.assertTrue(cfg.is_dirty)
        parsed = tomllib.loads(cfg.generate_toml_content())
        self.assertEqual(parsed["query_log"], {"file": "/var/log/dnscrypt-proxy/query.log", "format": "tsv"})

    def test_disable_query_log(self):
        cfg = make_cfg(SAMPLE_TOML.replace("# file = 'query.log'", "file = 'q.log'"))
        self.assertTrue(cfg.query_log_enabled)
        cfg.query_log_enabled = False
        self.assertNotIn("file", tomllib.loads(cfg.generate_toml_content())["query_log"])

    def test_toggle_back_is_not_dirty(self):
        cfg = make_cfg()
        cfg.toggle_resolver("google", True)
        self.assertTrue(cfg.is_dirty)
        cfg.toggle_resolver("google", False)
        self.assertFalse(cfg.is_dirty)

    def test_static_stamp(self):
        cfg = make_cfg()
        cfg.add_static_resolver("my-dns", "sdns://AgcAAAAAAAAA")
        parsed = tomllib.loads(cfg.generate_toml_content())
        self.assertEqual(parsed["static"]["my-dns"]["stamp"], "sdns://AgcAAAAAAAAA")
        self.assertIn("my-dns", parsed["server_names"])

    def test_stock_rule_examples_are_not_rules(self):
        cfg = make_cfg()
        self.assertEqual(cfg.rules, [])
        self.assertEqual(cfg.generate_rules_content(), STOCK_RULES)

    def test_rules_round_trip(self):
        cfg = make_cfg()
        cfg.add_rule("lan", ["$DHCP"], "home")
        cfg.add_rule("corp.example", ["10.0.0.53:53"])
        cfg.rules[1].enabled = False
        text = cfg.generate_rules_content()
        self.assertIn("lan $DHCP  # home", text)
        self.assertIn("# [disabled] corp.example 10.0.0.53:53", text)
        self.assertTrue(text.startswith(STOCK_RULES.rstrip("\n")))

        items = parse_rules(text)
        rules = [i for i in items if isinstance(i, ForwardingRule)]
        self.assertEqual([(r.domain, r.servers, r.comment, r.enabled) for r in rules],
                         [("lan", ["$DHCP"], "home", True), ("corp.example", ["10.0.0.53:53"], "", False)])

    def test_remove_rule(self):
        cfg = make_cfg(rules="a 1.1.1.1\nb 2.2.2.2\n")
        cfg.remove_rule(cfg.rules[0])
        self.assertEqual(cfg.generate_rules_content(), "b 2.2.2.2\n")

    def test_missing_rules_file(self):
        cfg = make_cfg(rules=None)
        self.assertEqual(cfg.rules, [])
        self.assertFalse(cfg.is_dirty)


class ValidateTests(unittest.TestCase):
    def test_domains(self):
        self.assertEqual(validate.domain_pattern(" Corp.Example. "), "corp.example")
        self.assertEqual(validate.domain_pattern("*.lan"), "*.lan")
        for bad in ("", "a b", "exa mple.com", "-bad.com", "münchen.de", "a..b"):
            with self.assertRaises(ValueError, msg=bad):
                validate.domain_pattern(bad)

    def test_addresses(self):
        self.assertEqual(validate.host_port("1.2.3.4"), "1.2.3.4:53")
        self.assertEqual(validate.host_port("1.2.3.4:5353"), "1.2.3.4:5353")
        self.assertEqual(validate.host_port("2620:fe::fe"), "[2620:fe::fe]:53")
        self.assertEqual(validate.host_port("[::1]:5300"), "[::1]:5300")
        for bad in ("host.example", "1.2.3.4:99999", "1.2.3", ""):
            with self.assertRaises(ValueError, msg=bad):
                validate.host_port(bad)
        self.assertEqual(validate.forward_target("$DHCP"), "$DHCP")

    def test_loopback_listen(self):
        self.assertEqual(validate.loopback_host_port("127.0.0.1"), "127.0.0.1:53")
        self.assertEqual(validate.loopback_host_port("[::1]:5353"), "[::1]:5353")
        for bad in ("0.0.0.0:53", "192.168.1.10:53", "[::]:53"):
            with self.assertRaises(ValueError, msg=bad):
                validate.loopback_host_port(bad)

    def test_private_targets(self):
        self.assertTrue(validate.is_private_target("192.168.1.1:53"))
        self.assertTrue(validate.is_private_target("$DHCP"))
        self.assertFalse(validate.is_private_target("8.8.8.8:53"))

    def test_stamp_and_name(self):
        validate.stamp("sdns://AgcAAAAAAAAAF1sy")
        with self.assertRaises(ValueError):
            validate.stamp("https://dns.example")
        with self.assertRaises(ValueError):
            validate.resolver_name("bad name")


class QueryLogTests(unittest.TestCase):
    def test_parse_tsv(self):
        e = parse_line("[2026-09-29 20:49:12]\t127.0.0.1\texample.com\tA\tPASS\t4ms\tcloudflare\n")
        self.assertEqual((e.time_str, e.domain, e.status, e.duration, e.server),
                         ("20:49:12", "example.com", "PASS", "4ms", "cloudflare"))
        self.assertFalse(e.is_blocked)

    def test_blocked_codes(self):
        self.assertTrue(parse_line("[t]\tc\tads.example\tA\tREJECT\t0ms\t-").is_blocked)
        self.assertEqual(parse_line("[t]\tc\tads.example\tA\tREJECT\t0ms\t-").server, "")
        self.assertTrue(parse_line("[t]\tc\tx\tA\tSERVFAIL\t1ms\t-").is_error)

    def test_garbage(self):
        self.assertIsNone(parse_line("not a log line"))


class ResolverTests(unittest.TestCase):
    GOOGLE = {"name": "google", "proto": "DoH", "ipv6": False, "dnssec": True, "nolog": False, "nofilter": True}
    FILTERING = {"name": "cloudflare-security", "proto": "DoH", "ipv6": False, "dnssec": True, "nolog": True, "nofilter": False}

    def test_requirements_do_not_apply_to_named_servers(self):
        # Verified against dnscrypt-proxy 2.1.14 with `-list`
        cfg = make_cfg()
        cfg.require_nolog = cfg.require_nofilter = cfg.require_dnssec = True
        self.assertIsNone(resolver_db.exclusion_reason(self.GOOGLE, cfg))
        self.assertIsNone(resolver_db.exclusion_reason(dict(self.FILTERING, dnssec=False), cfg))

    def test_named_servers_are_filtered_by_protocol_family_and_disabled_list(self):
        cfg = make_cfg()
        self.assertIn("Not found", resolver_db.exclusion_reason(None, cfg))
        cfg.doh_servers = False
        self.assertIn("DoH", resolver_db.exclusion_reason(self.GOOGLE, cfg))
        cfg.doh_servers = True
        self.assertIn("IPv6", resolver_db.exclusion_reason(dict(self.GOOGLE, ipv6=True), cfg))
        cfg.disabled_server_names = ["google"]
        self.assertIn("disabled", resolver_db.exclusion_reason(self.GOOGLE, cfg))

    def test_exclusion_fix_only_offers_protocol_switches(self):
        cfg = make_cfg()
        self.assertIsNone(resolver_db.exclusion_fix(self.GOOGLE, cfg))
        cfg.doh_servers = False
        self.assertEqual(resolver_db.exclusion_fix(self.GOOGLE, cfg)[:2], ("doh_servers", True))
        self.assertIsNone(resolver_db.exclusion_fix(None, cfg))

    def test_effective_servers(self):
        cfg = make_cfg()
        cfg.server_names = ["google", "missing-server"]
        self.assertEqual(resolver_db.effective_servers([self.GOOGLE], cfg), ["google"])
        cfg.server_names = []
        self.assertIsNone(resolver_db.effective_servers([self.GOOGLE], cfg))

    def test_deprecated_servers_are_not_recommended(self):
        entry = resolver_db._normalize({"name": "mullvad-doh", "proto": "DoH",
                                        "description": "Mullvad resolver. - Deprecated, will be shot down"})
        self.assertTrue(entry["deprecated"])
        self.assertFalse(entry["recommended"])
        self.assertTrue(resolver_db._normalize({"name": "google", "proto": "DoH"})["recommended"])


class ApplyPayloadTests(unittest.TestCase):
    def test_base_hashes_match_file_bytes(self):
        cfg = make_cfg()
        base = cfg.apply_payload()["base"]
        self.assertEqual(base["toml"], hashlib.sha256(cfg.toml_path.read_bytes()).hexdigest())
        self.assertEqual(base["rules"], hashlib.sha256(cfg.rules_path.read_bytes()).hexdigest())

    def test_missing_rules_file_hashes_empty(self):
        cfg = make_cfg(rules=None)
        self.assertEqual(cfg.apply_payload()["base"]["rules"], hashlib.sha256(b"").hexdigest())


def load_helper():
    path = ROOT / "helper" / "dnscrypt-ui-helper"
    loader = importlib.machinery.SourceFileLoader("dnscrypt_ui_helper", str(path))
    spec = importlib.util.spec_from_loader("dnscrypt_ui_helper", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def sandbox_helper(test: unittest.TestCase, root: Path):
    """A helper module whose every path points inside `root`, with root-only
    and slow operations stubbed. Patches of shared modules are undone after the test."""
    h = load_helper()
    h.CONFIG_DIR = root / "etc-dnscrypt-proxy"
    h.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    h.BACKUP_ROOT = h.CONFIG_DIR / ".dnscrypt-ui-backup"
    h.CONFIG_BACKUPS = h.BACKUP_ROOT / "config"
    h.NETWORK_BACKUPS = h.BACKUP_ROOT / "network"
    h.PARK_DIR = h.CONFIG_DIR / ".dnscrypt-ui-parked"
    h.LOG_DIR = root / "log"
    h.CACHE_DIR = root / "cache"
    h.RESOLVED_DROPIN = root / "resolved.conf.d" / "zz-dnscrypt-ui.conf"
    h.LEGACY_RESOLVED_DROPIN = root / "resolved.conf.d" / "dnscrypt.conf"
    h.NM_DROPIN = root / "nm.conf.d" / "90-dnscrypt-ui.conf"
    h.SERVICE_DROPIN = root / "service.d" / "50-dnscrypt-ui.conf"
    h.RESOLV_CONF = root / "resolv.conf"
    h.ROUTING_FILES = {
        "resolved.conf": h.RESOLVED_DROPIN,
        "networkmanager.conf": h.NM_DROPIN,
        "service.conf": h.SERVICE_DROPIN,
    }
    h.restorecon = lambda *a: None
    test.enterContext(mock.patch.object(time, "sleep", lambda s: None))
    test.enterContext(mock.patch.object(time, "monotonic", itertools.count().__next__))
    test.enterContext(mock.patch.object(socket, "if_nameindex", lambda: [(1, "lo"), (2, "enp4s0")]))
    return h


LEAKING = "Global: 127.0.0.1\nLink 2 (enp4s0): 192.168.31.1\nLink 3 (wlp5s0):\n"
CLEAN = "Global: 127.0.0.1\nLink 2 (enp4s0):\nLink 3 (wlp5s0):\n"


@unittest.skipIf(os.geteuid() == 0, "helper tests must not run as root")
class HelperTests(unittest.TestCase):
    def setUp(self):
        self.helper = sandbox_helper(self, Path(tempfile.mkdtemp()))
        self.calls = []
        self.dns_outputs = []
        self.state = "active"
        self.helper.run = self.fake_run
        self.helper.service_state = lambda: (self.state, "running")
        self.helper.dns_probe = lambda addr, timeout: True

    def fake_run(self, argv, timeout=60, check=False):
        self.calls.append(argv)
        out = self.dns_outputs.pop(0) if argv == ["resolvectl", "dns"] else ""
        return subprocess.CompletedProcess(argv, 0, out, "")

    # input validation

    def test_rejects_rules_outside_config_dir(self):
        for bad in ("/etc/shadow", "../x.txt", "sub/x.txt"):
            with self.assertRaises(self.helper.HelperError, msg=bad):
                self.helper.validate_input({"toml": f"forwarding_rules = '{bad}'", "rules": "", "base": {}})

    def test_rejects_invalid_toml_and_missing_base(self):
        with self.assertRaises(self.helper.HelperError):
            self.helper.validate_input({"toml": "a = = 1", "rules": "", "base": {}})
        with self.assertRaises(self.helper.HelperError):
            self.helper.validate_input({"toml": "", "rules": ""})

    def test_accepts_default_rules_path(self):
        _, path = self.helper.validate_input({"toml": "server_names = []", "rules": "", "base": {}})
        self.assertEqual(path, self.helper.CONFIG_DIR / "forwarding-rules.txt")

    # what apply may change

    OLD = {
        "server_names": ["cloudflare"], "listen_addresses": ["127.0.0.1:53"], "require_nolog": True,
        "fallback_resolvers": ["9.9.9.9:53"], "log_level": 2,
        "sources": {"public-resolvers": {"cache_file": "/var/cache/dnscrypt-proxy/public-resolvers.md"}},
        "query_log": {"format": "tsv"},
    }

    def change(self, **updates):
        new = json.loads(json.dumps(self.OLD))
        for dotted, value in updates.items():
            *parents, last = dotted.split("__")
            table = new
            for part in parents:
                table = table.setdefault(part, {})
            if value is None:
                table.pop(last, None)
            else:
                table[last] = value
        self.helper.check_allowed_changes(self.OLD, new)

    def test_allows_changes_the_app_makes(self):
        log = str(self.helper.LOG_DIR / "query.log")
        self.change(server_names=["google", "quad9-doh-ip4-port443-nofilter-pri"], require_nolog=False,
                    listen_addresses=["127.0.0.1:5353", "[::1]:53"], bootstrap_resolvers=["9.9.9.11:53"],
                    fallback_resolvers=None, query_log__file=log)
        self.change(static__my_dns__stamp="sdns://AgcAAAAAAAAA")

    def test_rejects_everything_else(self):
        for updates in (
            {"log_file": "/etc/cron.d/x"},
            {"sources__public-resolvers__cache_file": "/etc/profile.d/x.sh"},
            {"forwarding_rules": "/etc/shadow"},
            {"log_level": 0},
            {"listen_addresses": ["0.0.0.0:53"]},
            {"listen_addresses": []},
            {"query_log__file": "/etc/passwd"},
            {"query_log__file": str(self.helper.LOG_DIR)},
            {"static__x__stamp": "https://evil.example"},
            {"require_nolog": "no"},
            {"server_names": ["bad name"]},
        ):
            with self.assertRaises(self.helper.HelperError, msg=updates):
                self.change(**updates)

    def test_resolved_dns_value(self):
        self.assertEqual(self.helper.resolved_dns_value("127.0.0.1:53"), "127.0.0.1")
        self.assertEqual(self.helper.resolved_dns_value("127.0.0.1:5353"), "127.0.0.1:5353")
        self.assertEqual(self.helper.resolved_dns_value("[::1]:5353"), "[::1]:5353")
        with self.assertRaises(self.helper.HelperError):
            self.helper.resolved_dns_value("192.168.1.10:53")

    # network reload

    def test_link_dns_parser(self):
        self.dns_outputs = [LEAKING]
        self.assertEqual(self.helper.link_dns(), {"enp4s0": ["192.168.31.1"]})

    def test_route_clears_link_dns_without_nm_restart_when_clean(self):
        self.dns_outputs = [CLEAN]
        self.assertEqual(self.helper.reload_network(clear_link_dns=True), {})
        restart = self.calls.index(["systemctl", "restart", "systemd-resolved"])
        reverts = [i for i, c in enumerate(self.calls) if c[:2] == ["resolvectl", "revert"]]
        self.assertEqual([self.calls[i][2] for i in reverts], ["enp4s0"])
        self.assertTrue(all(i > restart for i in reverts))
        self.assertNotIn(["systemctl", "restart", "NetworkManager"], self.calls)

    def test_route_restarts_nm_when_dns_comes_back(self):
        self.dns_outputs = [LEAKING, CLEAN]
        self.assertEqual(self.helper.reload_network(clear_link_dns=True), {})
        nm = self.calls.index(["systemctl", "restart", "NetworkManager"])
        self.assertTrue(any(c[:2] == ["resolvectl", "revert"] for c in self.calls[nm:]))

    def test_route_reports_leftover(self):
        self.dns_outputs = [LEAKING, LEAKING]
        self.assertEqual(self.helper.reload_network(clear_link_dns=True), {"enp4s0": ["192.168.31.1"]})

    def test_unroute_restarts_nm_and_does_not_revert(self):
        self.helper.reload_network(clear_link_dns=False)
        self.assertIn(["systemctl", "restart", "NetworkManager"], self.calls)
        self.assertFalse(any(c[:2] == ["resolvectl", "revert"] for c in self.calls))

    # setup / undo / disable / enable

    def write_listen(self, addr="127.0.0.1:53"):
        (self.helper.CONFIG_DIR / "dnscrypt-proxy.toml").write_text(f"listen_addresses = ['{addr}']\n")

    def test_setup_writes_routing_and_quick_restart(self):
        h = self.helper
        os.symlink(h.STUB_RESOLV, h.RESOLV_CONF)
        h.LEGACY_RESOLVED_DROPIN.parent.mkdir(parents=True)
        h.LEGACY_RESOLVED_DROPIN.write_text("[Resolve]\nDNSStubListener=no\n")
        h.PARK_DIR.mkdir(parents=True)
        (h.PARK_DIR / "resolved.conf").write_text("stale")
        self.dns_outputs = [CLEAN]
        result = h.cmd_setup_dns("127.0.0.1:53")
        self.assertTrue(result["ok"], result)
        self.assertIn("DNS=127.0.0.1\n", h.RESOLVED_DROPIN.read_text())
        self.assertIn("systemd-resolved=false", h.NM_DROPIN.read_text())
        self.assertIn("RestartSec=2s", h.SERVICE_DROPIN.read_text())
        self.assertFalse(h.LEGACY_RESOLVED_DROPIN.exists())
        self.assertFalse(h.PARK_DIR.exists())
        self.assertIn(["systemctl", "daemon-reload"], self.calls)

    def test_setup_refuses_when_proxy_not_answering(self):
        h = self.helper
        h.dns_probe = lambda addr, timeout: False
        with self.assertRaises(h.HelperError):
            h.cmd_setup_dns("127.0.0.1:53")
        self.assertFalse(h.RESOLVED_DROPIN.exists())

    def test_disable_parks_routing_before_stopping(self):
        h = self.helper
        for p in h.ROUTING_FILES.values():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(p.name)
        result = h.cmd_disable()
        self.assertTrue(result["ok"], result)
        self.assertEqual(sorted(result["parked"]), sorted(h.ROUTING_FILES))
        self.assertFalse(any(p.exists() for p in h.ROUTING_FILES.values()))
        for label, p in h.ROUTING_FILES.items():
            self.assertEqual((h.PARK_DIR / label).read_text(), p.name)
        nm = self.calls.index(["systemctl", "restart", "NetworkManager"])
        stop = self.calls.index(["systemctl", "stop", "dnscrypt-proxy.service"])
        self.assertLess(nm, stop, "network DNS must be back before the proxy stops")

    def test_disable_without_routing_just_stops(self):
        result = self.helper.cmd_disable()
        self.assertEqual(result["parked"], [])
        self.assertIn(["systemctl", "stop", "dnscrypt-proxy.service"], self.calls)
        self.assertNotIn(["systemctl", "restart", "NetworkManager"], self.calls)

    def test_enable_restores_parked_routing(self):
        h = self.helper
        self.write_listen()
        for p in h.ROUTING_FILES.values():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(p.name)
        h.cmd_disable()
        self.calls.clear()
        self.dns_outputs = [CLEAN]
        result = h.cmd_enable()
        self.assertTrue(result["ok"] and result["routed"], result)
        self.assertTrue(all(p.exists() for p in h.ROUTING_FILES.values()))
        self.assertFalse(h.PARK_DIR.exists())
        # the parked resolved drop-in is rewritten to match the listen address
        self.assertIn("DNS=127.0.0.1\n", h.RESOLVED_DROPIN.read_text())

    def test_enable_keeps_network_dns_if_proxy_not_answering(self):
        h = self.helper
        self.write_listen()
        h.PARK_DIR.mkdir(parents=True)
        (h.PARK_DIR / "resolved.conf").write_text("x")
        h.dns_probe = lambda addr, timeout: False
        with self.assertRaises(h.HelperError):
            h.cmd_enable()
        self.assertFalse(h.RESOLVED_DROPIN.exists())
        self.assertTrue((h.PARK_DIR / "resolved.conf").exists())

    def test_enable_without_parked_routing_only_starts(self):
        self.write_listen()
        result = self.helper.cmd_enable()
        self.assertFalse(result["routed"])
        self.assertIn(["systemctl", "start", "dnscrypt-proxy.service"], self.calls)
        self.assertNotIn(["systemctl", "restart", "systemd-resolved"], self.calls)

    def test_undo_removes_active_and_parked_routing(self):
        h = self.helper
        h.RESOLVED_DROPIN.parent.mkdir(parents=True)
        h.RESOLVED_DROPIN.write_text("x")
        h.PARK_DIR.mkdir(parents=True)
        (h.PARK_DIR / "networkmanager.conf").write_text("x")
        h.cmd_undo_dns()
        self.assertFalse(h.RESOLVED_DROPIN.exists())
        self.assertFalse(h.PARK_DIR.exists())

    def test_sync_resolved_follows_listen_address(self):
        h = self.helper
        h.RESOLVED_DROPIN.parent.mkdir(parents=True)
        h.RESOLVED_DROPIN.write_text(h.RESOLVED_TEMPLATE.format(dns="127.0.0.1"))
        h.sync_resolved("127.0.0.1:5353")
        self.assertIn("DNS=127.0.0.1:5353\n", h.RESOLVED_DROPIN.read_text())
        self.assertIn(["systemctl", "restart", "systemd-resolved"], self.calls)
        self.calls.clear()
        h.sync_resolved("127.0.0.1:5353")
        self.assertEqual(self.calls, [], "no restart when already in sync")

    def test_backups_rotate_separately(self):
        h = self.helper
        f = h.CONFIG_DIR / "dnscrypt-proxy.toml"
        f.write_text("x")
        h.backup({"dnscrypt-proxy.toml": f}, h.CONFIG_BACKUPS)
        for _ in range(h.KEEP_BACKUPS + 3):
            h.backup(h.ROUTING_FILES, h.NETWORK_BACKUPS)
        self.assertEqual(len(list(h.CONFIG_BACKUPS.iterdir())), 1)
        self.assertEqual(len(list(h.NETWORK_BACKUPS.iterdir())), h.KEEP_BACKUPS)


@unittest.skipIf(os.geteuid() == 0, "helper tests must not run as root")
@unittest.skipUnless(Path("/usr/bin/dnscrypt-proxy").exists() and Path("/etc/dnscrypt-proxy").is_dir(),
                     "dnscrypt-proxy not installed")
class HelperApplySandbox(unittest.TestCase):
    """Runs the helper's apply flow against a copy of the config, with systemd stubbed."""

    def setUp(self):
        root = Path(tempfile.mkdtemp())
        h = self.helper = sandbox_helper(self, root)
        shutil.rmtree(h.CONFIG_DIR)
        shutil.copytree("/etc/dnscrypt-proxy", h.CONFIG_DIR,
                        ignore=shutil.ignore_patterns(".dnscrypt-ui-backup", ".dnscrypt-ui-parked"))
        self.calls = []
        real_run = h.run

        def fake_run(argv, timeout=60, check=False):
            if argv[0] in ("systemctl", "journalctl", "resolvectl"):
                self.calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, "", "")
            return real_run(argv, timeout, check)

        h.run = fake_run
        h.service_state = lambda: (self.state, "running")
        h.dns_probe = lambda addr, timeout: True
        self.state = "active"
        self.toml = h.CONFIG_DIR / "dnscrypt-proxy.toml"
        self.original = self.toml.read_text()
        self.cfg = ConfigManager(config_dir=h.CONFIG_DIR)

    def apply(self, payload):
        with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload))):
            return self.helper.cmd_apply()

    def test_success_writes_and_backs_up(self):
        self.cfg.server_names = ["google"]
        result = self.apply(self.cfg.apply_payload())
        self.assertTrue(result["ok"], result)
        self.assertEqual(tomllib.loads(self.toml.read_text())["server_names"], ["google"])
        backups = list(self.helper.CONFIG_BACKUPS.iterdir())
        self.assertEqual((backups[0] / "dnscrypt-proxy.toml").read_text(), self.original)
        self.assertIn(["systemctl", "restart", "dnscrypt-proxy.service"], self.calls)

    def test_not_restarted_when_encrypted_dns_is_off(self):
        self.state = "inactive"
        self.cfg.server_names = ["google"]
        self.assertTrue(self.apply(self.cfg.apply_payload())["ok"])
        self.assertNotIn(["systemctl", "restart", "dnscrypt-proxy.service"], self.calls)

    def test_conflict_when_file_changed_on_disk(self):
        self.cfg.server_names = ["google"]
        payload = self.cfg.apply_payload()
        self.toml.write_text(self.original + "\n# edited by hand\n")
        with self.assertRaises(self.helper.HelperError) as ctx:
            self.apply(payload)
        self.assertEqual(ctx.exception.extra["stage"], "conflict")
        self.assertIn("# edited by hand", self.toml.read_text())

    def test_rejects_unmanaged_change(self):
        payload = self.cfg.apply_payload()
        payload["toml"] = "log_file = '/etc/cron.d/owned'\n" + payload["toml"]
        with self.assertRaises(self.helper.HelperError):
            self.apply(payload)
        self.assertEqual(self.toml.read_text(), self.original)
        self.assertFalse(self.helper.CONFIG_BACKUPS.exists())

    def test_check_failure_restores(self):
        # Allowed by the helper, but `dnscrypt-proxy -check` fails: "None of the
        # servers listed in the server_names list were found"
        self.cfg.server_names = ["does-not-exist"]
        with self.assertRaises(self.helper.HelperError) as ctx:
            self.apply(self.cfg.apply_payload())
        self.assertEqual(ctx.exception.extra["stage"], "check")
        self.assertIn("server_names", ctx.exception.extra["output"])
        self.assertEqual(self.toml.read_text(), self.original)
        self.assertFalse(any(c[:2] == ["systemctl", "restart"] for c in self.calls))

    def test_restart_failure_restores(self):
        self.state = "failed"
        self.cfg.server_names = ["google"]
        payload = self.cfg.apply_payload()
        # service is "failed" before apply, so apply must not try to restart it
        self.assertTrue(self.apply(payload)["ok"])
        self.state = "active"
        states = iter(["active"] + ["failed"] * 1000)
        self.helper.service_state = lambda: (next(states), "")
        self.cfg.load()
        self.cfg.server_names = ["cloudflare"]
        with self.assertRaises(self.helper.HelperError) as ctx:
            self.apply(self.cfg.apply_payload())
        self.assertEqual(ctx.exception.extra["stage"], "restart")
        self.assertEqual(tomllib.loads(self.toml.read_text())["server_names"], ["google"])

    def test_query_log_is_private(self):
        self.cfg.query_log_enabled = True
        self.cfg.query_log_file = str(self.helper.LOG_DIR / "query.log")
        chowns = []
        with mock.patch.object(os, "chown", lambda p, u, g: chowns.append((str(p), u, g))), \
             mock.patch.dict(os.environ, {"PKEXEC_UID": str(os.getuid())}):
            self.assertTrue(self.apply(self.cfg.apply_payload())["ok"])
        log = self.helper.LOG_DIR / "query.log"
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o640)
        self.assertEqual(chowns, [(str(log), 0, os.getgid())])

    def test_listen_change_updates_system_dns(self):
        h = self.helper
        h.RESOLVED_DROPIN.parent.mkdir(parents=True)
        h.RESOLVED_DROPIN.write_text(h.RESOLVED_TEMPLATE.format(dns="127.0.0.1"))
        self.cfg.listen_addresses = ["127.0.0.1:5353"]
        self.assertTrue(self.apply(self.cfg.apply_payload())["ok"])
        self.assertIn("DNS=127.0.0.1:5353\n", h.RESOLVED_DROPIN.read_text())


@unittest.skipUnless(Path("/usr/bin/dnscrypt-proxy").exists() and Path("/etc/dnscrypt-proxy").is_dir(),
                     "dnscrypt-proxy not installed")
class DnscryptCheckIntegration(unittest.TestCase):
    """Generated configs must pass `dnscrypt-proxy -check` on the real system config."""

    def test_generated_config_passes_check(self):
        d = Path(tempfile.mkdtemp()) / "conf"
        shutil.copytree("/etc/dnscrypt-proxy", d, ignore=shutil.ignore_patterns(".dnscrypt-ui-backup"))
        cfg = ConfigManager(config_dir=d)
        cfg.query_log_enabled = True
        cfg.query_log_file = str(d / "query.log")
        cfg.server_names = ["cloudflare", "quad9-doh-ip4-port443-nofilter-pri"]
        cfg.add_rule("lan", ["$DHCP"], "home network")
        cfg.add_rule("corp.example", ["[2001:db8::53]:53"])
        cfg.rules[-1].enabled = False
        staged = cfg.get_staged_files()
        (d / "dnscrypt-proxy.toml").write_text(staged["toml"])
        cfg.rules_path.write_text(staged["rules"])
        res = subprocess.run(["/usr/bin/dnscrypt-proxy", "-config", str(d / "dnscrypt-proxy.toml"), "-check"],
                             capture_output=True, text=True, timeout=90, cwd=d)
        self.assertEqual(res.returncode, 0, res.stderr[-800:])
        self.assertIn("successfully checked", res.stderr + res.stdout)


if __name__ == "__main__":
    unittest.main()
