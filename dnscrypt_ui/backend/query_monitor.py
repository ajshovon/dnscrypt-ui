"""
DNS Query Log Monitor.
Reads and watches dnscrypt-proxy query.log in real time,
providing structured query logs for the live inspector view.
"""

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional


@dataclass
class QueryEntry:
    time_str: str
    client: str
    domain: str
    qtype: str
    status: str  # "PASS", "BLOCKED", "SYNTH", "FORWARD"
    server: str

    @property
    def is_blocked(self) -> bool:
        return "BLOCK" in self.status.upper()


class QueryMonitor:
    def __init__(self, log_path: str = "/var/log/dnscrypt-proxy/query.log", max_entries: int = 500):
        self.log_path = Path(log_path)
        self.max_entries = max_entries
        self.entries: List[QueryEntry] = []
        self._running = False
        self._paused = False
        self._thread: Optional[threading.Thread] = None
        self._file_obj = None
        self._callbacks: List[Callable[[List[QueryEntry]], None]] = []
        self._lock = threading.Lock()

    def add_callback(self, cb: Callable[[List[QueryEntry]], None]):
        self._callbacks.append(cb)

    def set_paused(self, paused: bool):
        self._paused = paused

    def clear(self):
        with self._lock:
            self.entries.clear()

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._tail_worker, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None
        if self._file_obj:
            try:
                self._file_obj.close()
            except Exception:
                pass
            self._file_obj = None

    def _parse_line(self, line: str) -> Optional[QueryEntry]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        # Tab or multi-space separated
        parts = line.split("\t")
        if len(parts) < 3:
            parts = line.split()

        if len(parts) < 4:
            return None

        # Common TSV: [Time, Client, Domain, Type, Return/Status, Cache, Server]
        time_str = parts[0]
        client = parts[1]
        domain = parts[2]
        qtype = parts[3] if len(parts) > 3 else "A"
        status = parts[4] if len(parts) > 4 else "PASS"
        server = parts[6] if len(parts) > 6 else (parts[5] if len(parts) > 5 else "local")

        # Normalize timestamp if unix epoch
        if time_str.isdigit():
            try:
                epoch = int(time_str)
                time_str = time.strftime("%H:%M:%S", time.localtime(epoch))
            except Exception:
                pass
        elif " " in time_str:
            # e.g. 2026-09-25 17:30:15 -> extract 17:30:15
            time_str = time_str.split(" ")[-1]

        return QueryEntry(
            time_str=time_str,
            client=client,
            domain=domain,
            qtype=qtype,
            status=status,
            server=server,
        )

    def _tail_worker(self):
        last_inode = None

        while self._running:
            try:
                if not self.log_path.exists():
                    time.sleep(2.0)
                    continue

                stat = self.log_path.stat()
                if stat.st_ino != last_inode:
                    if self._file_obj:
                        self._file_obj.close()
                    # Open and seek near end (last 50KB)
                    self._file_obj = open(self.log_path, "r", encoding="utf-8", errors="replace")
                    file_size = stat.st_size
                    if file_size > 50000:
                        self._file_obj.seek(file_size - 50000)
                        self._file_obj.readline()  # discard partial line
                    last_inode = stat.st_ino

                lines = self._file_obj.readlines()
                if lines and not self._paused:
                    new_entries = []
                    for l in lines:
                        parsed = self._parse_line(l)
                        if parsed:
                            new_entries.append(parsed)

                    if new_entries:
                        with self._lock:
                            self.entries.extend(new_entries)
                            if len(self.entries) > self.max_entries:
                                self.entries = self.entries[-self.max_entries:]

                        for cb in self._callbacks:
                            try:
                                cb(new_entries)
                            except Exception as e:
                                print(f"[QueryMonitor] Callback error: {e}")

                time.sleep(1.0)
            except Exception as e:
                time.sleep(2.0)

        if self._file_obj:
            self._file_obj.close()
            self._file_obj = None
