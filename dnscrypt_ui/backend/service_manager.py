"""
Service and system integration for dnscrypt-proxy.

- Service state and control go through systemd's D-Bus API, so polkit shows
  its own "manage system services" prompt.
- Writing configuration and changing system DNS go through the privileged
  helper (helper/dnscrypt-ui-helper) started with pkexec.
- DNS routing checks read systemd-resolved over D-Bus and /etc/resolv.conf.

All methods block; call them from worker threads.
"""

import ipaddress
import json
import random
import socket
import stat
import string
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from gi.repository import Gio, GLib

SERVICE = "dnscrypt-proxy.service"
INSTALLED_HELPER = Path("/usr/local/libexec/dnscrypt-ui-helper")
BUNDLED_HELPER = Path(__file__).resolve().parents[2] / "helper" / "dnscrypt-ui-helper"
STUB_ADDRESSES = {"127.0.0.53", "127.0.0.54"}

# Written by the helper; see helper/dnscrypt-ui-helper
RESOLVED_DROPIN = Path("/etc/systemd/resolved.conf.d/zz-dnscrypt-ui.conf")
PARKED_RESOLVED = Path("/etc/dnscrypt-proxy/.dnscrypt-ui-parked/resolved.conf")


@dataclass
class ServiceStatus:
    installed: bool
    active: bool
    status_str: str  # ActiveState: active, inactive, failed, activating, ...
    substate: str = ""
    pid: int = 0
    error: str = ""

    @property
    def transitioning(self) -> bool:
        return self.status_str in ("activating", "deactivating", "reloading")


@dataclass
class RoutingStatus:
    protected: bool
    problems: List[str] = field(default_factory=list)
    checked: bool = True


@dataclass
class DnsResult:
    ok: bool
    latency_ms: float = 0.0
    rcode: int = -1
    addresses: List[str] = field(default_factory=list)
    error: str = ""


def split_host_port(addr: str) -> Tuple[str, int]:
    addr = addr.strip()
    if addr.startswith("["):
        host, _, port = addr[1:].partition("]:")
        return host, int(port or 53)
    if addr.count(":") == 1:
        host, port = addr.split(":")
        return host, int(port)
    return addr, 53


def probe_target(listen_addresses: List[str]) -> Tuple[str, int]:
    """Address to send test queries to, derived from listen_addresses."""
    host, port = split_host_port(listen_addresses[0] if listen_addresses else "127.0.0.1:53")
    ip = ipaddress.ip_address(host)
    if ip.is_unspecified:
        host = "::1" if ip.version == 6 else "127.0.0.1"
    return host, port


class ServiceManager:
    def __init__(self):
        self._bus: Optional[Gio.DBusConnection] = None

    # systemd

    def _system_bus(self) -> Gio.DBusConnection:
        if self._bus is None:
            self._bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        return self._bus

    def get_status(self) -> ServiceStatus:
        try:
            res = subprocess.run(
                ["systemctl", "show", SERVICE, "--property=LoadState,ActiveState,SubState,MainPID"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            return ServiceStatus(installed=False, active=False, status_str="error", error=str(e))
        props = dict(l.split("=", 1) for l in res.stdout.splitlines() if "=" in l)
        installed = props.get("LoadState") == "loaded"
        state = props.get("ActiveState", "inactive")
        return ServiceStatus(
            installed=installed,
            active=installed and state == "active",
            status_str=state if installed else "not-installed",
            substate=props.get("SubState", ""),
            pid=int(props.get("MainPID", "0") or 0),
        )

    def _unit_call(self, method: str) -> Tuple[bool, str]:
        try:
            self._system_bus().call_sync(
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                method,
                GLib.Variant("(ss)", (SERVICE, "replace")),
                None,
                Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION,
                120000,
                None,
            )
            return True, ""
        except GLib.Error as e:
            msg = Gio.DBusError.get_remote_error(e) or ""
            if "AccessDenied" in msg or "InteractiveAuthorizationRequired" in msg:
                return False, "Authorization was cancelled or denied"
            return False, e.message

    def start(self) -> Tuple[bool, str]:
        return self._unit_call("StartUnit")

    def stop(self) -> Tuple[bool, str]:
        return self._unit_call("StopUnit")

    def restart(self) -> Tuple[bool, str]:
        return self._unit_call("RestartUnit")

    # Privileged helper

    @staticmethod
    def helper_status() -> str:
        """
        "installed": root-owned copy matching this version of the app
        "outdated": root-owned copy from an older version (run install.sh)
        "missing": not installed; the copy in the source tree is used
        """
        try:
            st = INSTALLED_HELPER.stat()
        except OSError:
            return "missing"
        if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return "missing"
        try:
            same = INSTALLED_HELPER.read_bytes() == BUNDLED_HELPER.read_bytes()
        except OSError:
            same = True  # running without the source tree
        return "installed" if same else "outdated"

    @classmethod
    def helper_installed(cls) -> bool:
        return cls.helper_status() == "installed"

    def run_helper(self, args: List[str], stdin: Optional[str] = None) -> Dict:
        status = self.helper_status()
        if status == "outdated":
            return {
                "ok": False,
                "message": "The installed privileged helper is from an older version of DNSCrypt UI. "
                           "Run ./install.sh in the dns-crypt-ui folder to update it.",
            }
        if status == "installed":
            argv = ["pkexec", str(INSTALLED_HELPER)]
        else:
            # Development fallback: runs the helper from the source tree
            argv = ["pkexec", "/usr/bin/python3", "-I", str(BUNDLED_HELPER)]
        try:
            res = subprocess.run(argv + args, input=stdin, capture_output=True, text=True, timeout=240)
        except (OSError, subprocess.TimeoutExpired) as e:
            return {"ok": False, "message": str(e)}
        if res.returncode in (126, 127) and not res.stdout.strip():
            return {"ok": False, "message": "Authorization was cancelled or denied", "cancelled": True}
        try:
            return json.loads(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"ok": False, "message": (res.stderr or res.stdout or f"exit code {res.returncode}").strip()[-400:]}

    def apply(self, payload: Dict) -> Dict:
        return self.run_helper(["apply"], stdin=json.dumps(payload))

    def setup_system_dns(self, listen_address: str) -> Dict:
        return self.run_helper(["setup-dns", listen_address])

    def undo_system_dns(self) -> Dict:
        return self.run_helper(["undo-dns"])

    def enable_encrypted_dns(self) -> Dict:
        """Start dnscrypt-proxy and restore system DNS routing if it was parked."""
        return self.run_helper(["enable"])

    def disable_encrypted_dns(self) -> Dict:
        """Give system DNS back to the network, then stop dnscrypt-proxy."""
        return self.run_helper(["disable"])

    @staticmethod
    def routing_state() -> str:
        """"active" (system DNS points at dnscrypt-proxy), "parked" (turned off
        with the switch, restored when turned on) or "none"."""
        if RESOLVED_DROPIN.exists():
            return "active"
        if PARKED_RESOLVED.exists():
            return "parked"
        return "none"

    # DNS routing

    def check_routing(self, listen_addresses: List[str]) -> RoutingStatus:
        """Is every DNS query on this machine going through dnscrypt-proxy?"""
        problems: List[str] = []
        proxy_host, proxy_port = probe_target(listen_addresses)
        listen_hosts = {split_host_port(a)[0] for a in listen_addresses}

        nameservers = []
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    nameservers.append(parts[1])
        except OSError as e:
            problems.append(f"Cannot read /etc/resolv.conf: {e}")

        uses_stub = any(ns in STUB_ADDRESSES for ns in nameservers)
        for ns in nameservers:
            if ns in STUB_ADDRESSES:
                continue
            if ns in listen_hosts and proxy_port == 53:
                continue
            problems.append(f"/etc/resolv.conf sends queries straight to {ns}, bypassing dnscrypt-proxy")

        if uses_stub:
            try:
                problems += self._resolved_problems(proxy_host, proxy_port)
            except GLib.Error as e:
                problems.append(f"systemd-resolved is not reachable: {e.message}")

        return RoutingStatus(protected=not problems, problems=problems)

    def _resolved_problems(self, proxy_host: str, proxy_port: int) -> List[str]:
        bus = self._system_bus()

        def get(path, iface, prop):
            return bus.call_sync(
                "org.freedesktop.resolve1", path, "org.freedesktop.DBus.Properties", "Get",
                GLib.Variant("(ss)", (iface, prop)), None, Gio.DBusCallFlags.NONE, 3000, None,
            ).unpack()[0]

        def fmt(family, raw, port=0):
            ip = ipaddress.ip_address(bytes(raw))
            return f"{ip}:{port}" if port else str(ip)

        problems = []
        servers = get("/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", "DNSEx")
        global_ok = False
        links: Dict[int, List[str]] = {}
        # Global servers are reported with ifindex 0, or with the loopback index
        # on newer systemd; resolved never accepts per-link DNS on loopback.
        global_indexes = {0} | {i for i, n in socket.if_nameindex() if n == "lo"}
        for ifindex, family, raw, port, _name in servers:
            ip = str(ipaddress.ip_address(bytes(raw)))
            if ifindex in global_indexes:
                if ip == str(ipaddress.ip_address(proxy_host)) and (port or 53) == proxy_port:
                    global_ok = True
            else:
                links.setdefault(ifindex, []).append(fmt(family, raw, port))

        if not global_ok:
            problems.append(f"systemd-resolved does not forward to dnscrypt-proxy ({proxy_host}:{proxy_port})")

        for ifindex, addrs in links.items():
            path = bus.call_sync(
                "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                "org.freedesktop.resolve1.Manager", "GetLink",
                GLib.Variant("(i)", (ifindex,)), None, Gio.DBusCallFlags.NONE, 3000, None,
            ).unpack()[0]
            if not get(path, "org.freedesktop.resolve1.Link", "DefaultRoute"):
                continue  # only used for its own routing domains (e.g. a VPN)
            try:
                name = socket.if_indextoname(ifindex)
            except OSError:
                name = f"#{ifindex}"
            problems.append(
                f"Network {name} has its own DNS ({', '.join(addrs)}); queries also go there unencrypted"
            )
        return problems

    # DNS testing

    @staticmethod
    def dns_query(host: str, port: int, name: str, qtype: int = 1, timeout: float = 3.0) -> DnsResult:
        tid = random.randint(0, 0xFFFF)
        qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.strip(".").split(".")) + b"\x00"
        packet = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            start = time.perf_counter()
            try:
                sock.sendto(packet, (host, port))
                while True:
                    resp, _ = sock.recvfrom(4096)
                    if len(resp) >= 12 and struct.unpack(">H", resp[:2])[0] == tid:
                        break
            except socket.timeout:
                return DnsResult(ok=False, error="Query timed out")
            except OSError as e:
                return DnsResult(ok=False, error=e.strerror or str(e))
            latency = (time.perf_counter() - start) * 1000.0

        _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", resp[:12])
        rcode = flags & 0x000F
        return DnsResult(ok=True, latency_ms=latency, rcode=rcode, addresses=_parse_a_records(resp, qd, an))

    def test_resolution(self, listen_addresses: List[str]) -> Tuple[DnsResult, DnsResult]:
        """
        Returns (lookup, upstream):
        - lookup: resolves cloudflare.com (may come from cache)
        - upstream: a random name that cannot be cached, so the time is a real
          round trip through the encrypted upstream
        """
        host, port = probe_target(listen_addresses)
        lookup = self.dns_query(host, port, "cloudflare.com")
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        upstream = self.dns_query(host, port, f"{label}.example.com", timeout=5.0)
        return lookup, upstream


def _skip_name(buf: bytes, pos: int) -> int:
    while pos < len(buf):
        length = buf[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += length + 1
    return pos


def _parse_a_records(resp: bytes, qdcount: int, ancount: int) -> List[str]:
    pos = 12
    try:
        for _ in range(qdcount):
            pos = _skip_name(resp, pos) + 4
        found = []
        for _ in range(ancount):
            pos = _skip_name(resp, pos)
            rtype, _, _, rdlen = struct.unpack(">HHIH", resp[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                found.append(socket.inet_ntoa(resp[pos:pos + 4]))
            pos += rdlen
        return found
    except (struct.error, IndexError):
        return []
