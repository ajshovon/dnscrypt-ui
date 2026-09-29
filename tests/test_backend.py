"""
Run with: python3 -m unittest discover -s tests -v   (from dns-crypt-ui/)
"""

import importlib.machinery
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

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
    ENTRY = {"name": "x", "proto": "DoH", "ipv6": False, "dnssec": True, "nolog": True, "nofilter": False}

    def test_exclusion(self):
        cfg = make_cfg()
        self.assertIn("no-filter", resolver_db.exclusion_reason(self.ENTRY, cfg))
        cfg.require_nofilter = False
        self.assertIsNone(resolver_db.exclusion_reason(self.ENTRY, cfg))
        cfg.doh_servers = False
        self.assertIn("DoH", resolver_db.exclusion_reason(self.ENTRY, cfg))
        self.assertIn("Not found", resolver_db.exclusion_reason(None, cfg))

    def test_effective(self):
        cfg = make_cfg()
        catalog = [dict(self.ENTRY, name="cloudflare", nofilter=True)]
        self.assertEqual(resolver_db.effective_servers(catalog, cfg), ["cloudflare"])
        cfg.server_names = []
        self.assertIsNone(resolver_db.effective_servers(catalog, cfg))


def load_helper():
    path = ROOT / "helper" / "dnscrypt-ui-helper"
    loader = importlib.machinery.SourceFileLoader("dnscrypt_ui_helper", str(path))
    spec = importlib.util.spec_from_loader("dnscrypt_ui_helper", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.helper = load_helper()
        self.dir = Path(tempfile.mkdtemp())
        self.helper.CONFIG_DIR = self.dir

    def test_rejects_rules_outside_config_dir(self):
        for bad in ("/etc/shadow", "../x.txt", "sub/x.txt"):
            with self.assertRaises(self.helper.HelperError, msg=bad):
                self.helper.validate_input({"toml": f"forwarding_rules = '{bad}'", "rules": ""})

    def test_rejects_invalid_toml(self):
        with self.assertRaises(self.helper.HelperError):
            self.helper.validate_input({"toml": "a = = 1", "rules": ""})

    def test_accepts_default(self):
        _, path = self.helper.validate_input({"toml": "server_names = []", "rules": ""})
        self.assertEqual(path, self.dir / "forwarding-rules.txt")

    def test_parse_addr(self):
        self.assertEqual(str(self.helper.parse_addr("127.0.0.1")[0]), "127.0.0.1")
        self.assertEqual(self.helper.parse_addr("[::1]:5353")[1], 5353)


@unittest.skipUnless(Path("/usr/bin/dnscrypt-proxy").exists() and Path("/etc/dnscrypt-proxy").is_dir(),
                     "dnscrypt-proxy not installed")
class HelperApplySandbox(unittest.TestCase):
    """Runs the helper's apply flow against a copy of the config, with systemd stubbed."""

    def setUp(self):
        import io
        self.io = io
        self.helper = load_helper()
        self.dir = Path(tempfile.mkdtemp()) / "conf"
        shutil.copytree("/etc/dnscrypt-proxy", self.dir, ignore=shutil.ignore_patterns(".dnscrypt-ui-backup"))
        h = self.helper
        h.CONFIG_DIR = self.dir
        h.BACKUP_DIR = self.dir / ".dnscrypt-ui-backup"
        h.CACHE_DIR = self.dir / "cache"
        h.LOG_DIR = self.dir / "log"
        h.restorecon = lambda *a: None
        self.calls = []
        real_run = h.run

        def fake_run(argv, timeout=60, check=False):
            if argv[0] in ("systemctl", "journalctl"):
                self.calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, "", "")
            return real_run(argv, timeout, check)

        h.run = fake_run
        h.service_state = lambda: (self.state, "running")
        h.dns_probe = lambda addr, timeout: True
        h.time.sleep = lambda s: None
        self.state = "active"
        self.original = (self.dir / "dnscrypt-proxy.toml").read_text()

    def apply(self, toml, rules="lan $DHCP\n"):
        sys.stdin = self.io.StringIO(json_dumps({"toml": toml, "rules": rules}))
        try:
            return self.helper.cmd_apply()
        finally:
            sys.stdin = sys.__stdin__

    def test_success_writes_and_backs_up(self):
        new = self.original + "\n# changed\n"
        # time.monotonic must advance for the stability window
        clock = iter(range(0, 1000))
        self.helper.time.monotonic = lambda: next(clock)
        result = self.apply(new)
        self.assertTrue(result["ok"], result)
        self.assertEqual((self.dir / "dnscrypt-proxy.toml").read_text(), new)
        backups = list((self.dir / ".dnscrypt-ui-backup").iterdir())
        self.assertEqual((backups[0] / "dnscrypt-proxy.toml").read_text(), self.original)
        self.assertIn(["systemctl", "restart", "dnscrypt-proxy.service"], self.calls)

    def test_check_failure_restores(self):
        # Unknown keys only warn, so use a type error that -check rejects
        bad = re.sub(r"(?m)^listen_addresses = .*$", "listen_addresses = 53", self.original)
        with self.assertRaises(self.helper.HelperError) as ctx:
            self.apply(bad)
        self.assertEqual(ctx.exception.extra["stage"], "check")
        self.assertEqual((self.dir / "dnscrypt-proxy.toml").read_text(), self.original)
        self.assertFalse(any(c[:2] == ["systemctl", "restart"] for c in self.calls))

    def test_restart_failure_restores(self):
        self.state = "failed"
        clock = iter(range(0, 1000))
        self.helper.time.monotonic = lambda: next(clock)
        with self.assertRaises(self.helper.HelperError) as ctx:
            self.apply(self.original + "\n# changed\n")
        self.assertEqual(ctx.exception.extra["stage"], "restart")
        self.assertEqual((self.dir / "dnscrypt-proxy.toml").read_text(), self.original)


def json_dumps(obj):
    import json
    return json.dumps(obj)


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
