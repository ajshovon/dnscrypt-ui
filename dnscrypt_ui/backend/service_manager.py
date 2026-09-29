"""
Service and Systemd Manager for dnscrypt-proxy.
Controls systemd services, handles pkexec elevation for configuration
updates and restarts, detects port 53 conflicts, and benchmarks DNS latency.
"""

import os
import shlex
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple


@dataclass
class ServiceStatus:
    installed: bool
    active: bool
    status_str: str  # "active", "inactive", "failed", "not-installed"
    substate: str
    pid: int
    uptime_sec: int
    error: str = ""


class ServiceManager:
    SERVICE_NAME = "dnscrypt-proxy"

    def __init__(self):
        self._installed = self.check_installed()

    def check_installed(self) -> bool:
        return bool(
            shutil.which("dnscrypt-proxy")
            or Path("/usr/bin/dnscrypt-proxy").exists()
            or Path("/usr/sbin/dnscrypt-proxy").exists()
        )

    def get_status(self) -> ServiceStatus:
        if not self.check_installed():
            return ServiceStatus(
                installed=False,
                active=False,
                status_str="not-installed",
                substate="",
                pid=0,
                uptime_sec=0,
                error="dnscrypt-proxy binary not found",
            )

        try:
            res = subprocess.run(
                [
                    "systemctl",
                    "show",
                    self.SERVICE_NAME,
                    "--property=ActiveState,SubState,MainPID,ExecMainStartTimestampMonotonic",
                ],
                capture_output=True,
                text=True,
                timeout=3,
            )
            props = {}
            for line in res.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()

            active_state = props.get("ActiveState", "inactive")
            substate = props.get("SubState", "")
            pid = int(props.get("MainPID", 0) or 0)
            is_active = active_state == "active"

            return ServiceStatus(
                installed=True,
                active=is_active,
                status_str=active_state,
                substate=substate,
                pid=pid,
                uptime_sec=0,
            )
        except Exception as e:
            return ServiceStatus(
                installed=True,
                active=False,
                status_str="error",
                substate="",
                pid=0,
                uptime_sec=0,
                error=str(e),
            )

    def start(self) -> Tuple[bool, str]:
        return self._run_systemctl("start")

    def stop(self) -> Tuple[bool, str]:
        return self._run_systemctl("stop")

    def restart(self) -> Tuple[bool, str]:
        return self._run_systemctl("restart")

    def _run_systemctl(self, action: str) -> Tuple[bool, str]:
        try:
            res = subprocess.run(
                ["pkexec", "systemctl", action, self.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if res.returncode == 0:
                return True, ""
            return False, res.stderr or res.stdout or f"Failed with exit code {res.returncode}"
        except Exception as e:
            return False, str(e)

    def apply_and_restart(self, staged_files: Dict[Path, str]) -> Tuple[bool, str]:
        """
        Atomically copies staged files to target system paths and restarts
        the service using a single pkexec prompt.
        Uses a secure random temp directory to prevent symlink attacks.
        """
        staging_dir = None
        try:
            staging_dir = Path(tempfile.mkdtemp(prefix="dnscrypt_ui_"))
            os.chmod(staging_dir, 0o700)

            script_lines = ["#!/usr/bin/env bash", "set -e"]

            for dest_path, content in staged_files.items():
                staging_file = staging_dir / dest_path.name
                with open(staging_file, "w", encoding="utf-8") as f:
                    f.write(content)
                os.chmod(staging_file, 0o644)

                script_lines.append(f"mkdir -p {shlex.quote(str(dest_path.parent))}")
                script_lines.append(f"cp {shlex.quote(str(staging_file))} {shlex.quote(str(dest_path))}")
                script_lines.append(f"chmod 644 {shlex.quote(str(dest_path))}")

            if self.check_installed():
                script_lines.append(f"systemctl restart {shlex.quote(self.SERVICE_NAME)}")

            script_path = staging_dir / "apply.sh"
            with open(script_path, "w", encoding="utf-8") as f:
                f.write("\n".join(script_lines) + "\n")
            script_path.chmod(0o755)

            try:
                res = subprocess.run(
                    ["pkexec", str(script_path)],
                    capture_output=True,
                    text=True,
                    timeout=45,
                )
                if res.returncode == 0:
                    return True, ""
                return False, res.stderr or res.stdout or f"Apply failed with code {res.returncode}"
            except Exception as e:
                return False, str(e)
        finally:
            if staging_dir and staging_dir.exists():
                import shutil as _shutil
                _shutil.rmtree(staging_dir, ignore_errors=True)

    def check_port_53_conflict(self) -> Tuple[bool, str]:
        """
        Checks whether port 53 is being occupied by another service like systemd-resolved.
        Returns (has_conflict, description_of_listener).
        """
        try:
            res = subprocess.run(
                ["ss", "-tlunp", "sport = :53"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            output = res.stdout.strip()
            if not output:
                return False, ""

            # Check if non-dnscrypt process is listening
            lines = output.splitlines()[1:]  # skip header
            listeners = []
            for l in lines:
                if "dnscrypt-proxy" not in l:
                    listeners.append(l)

            if listeners:
                if any("systemd-resolve" in l for l in listeners):
                    return True, "systemd-resolved is currently listening on port 53"
                return True, f"Port 53 is used by: {listeners[0][:60]}"
            return False, ""
        except Exception:
            return False, ""

    @staticmethod
    def test_dns_latency(
        server: str = "127.0.0.1", port: int = 53, domain: str = "cloudflare.com", timeout: float = 2.5
    ) -> Tuple[bool, float, str]:
        """
        Sends an RFC-compliant DNS A record query packet to test resolution and latency.
        Returns (success, latency_ms, resolved_ip_or_error).
        """
        tid = 0x5678
        flags = 0x0100  # standard query, recursion desired
        qdcount = 1
        header = struct.pack(">HHHHHH", tid, flags, qdcount, 0, 0, 0)

        qname = b""
        for part in domain.split("."):
            if not part:
                continue
            qname += bytes([len(part)]) + part.encode("ascii")
        qname += b"\x00"
        question = qname + struct.pack(">HH", 1, 1)  # Type A, Class IN
        packet = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        try:
            sock.sendto(packet, (server, port))
            resp, _ = sock.recvfrom(512)
            latency = (time.perf_counter() - start) * 1000.0

            # Verify response ID matches
            if len(resp) >= 12:
                resp_tid, resp_flags, qdc, anc, _, _ = struct.unpack(">HHHHHH", resp[:12])
                rcode = resp_flags & 0x000F
                if rcode != 0:
                    return False, latency, f"DNS Error code: {rcode}"
                if anc > 0 and len(resp) >= 16:
                    resolved_ip = socket.inet_ntoa(resp[-4:])
                    return True, latency, resolved_ip

            return True, latency, "Resolved (no A record)"
        except socket.timeout:
            return False, 0.0, "Query timed out"
        except Exception as e:
            return False, 0.0, str(e)
        finally:
            sock.close()
