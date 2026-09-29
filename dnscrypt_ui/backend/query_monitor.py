"""
DNS Query Log Monitor.
Tails dnscrypt-proxy's TSV query log in a worker thread and hands parsed
entries to registered callbacks.
"""

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

# Return codes dnscrypt-proxy writes when a plugin stopped the query
BLOCKED_CODES = {"REJECT", "DROP", "CLOAK", "SYNTH"}
ERROR_CODES = {"SERVFAIL", "NETWORK_ERROR", "RESPONSE_ERROR", "PARSE_ERROR", "NOT_READY"}


@dataclass
class QueryEntry:
    time_str: str
    client: str
    domain: str
    qtype: str
    status: str  # PASS, FORWARD, CACHE, REJECT, ...
    duration: str
    server: str

    @property
    def is_blocked(self) -> bool:
        return self.status.upper() in BLOCKED_CODES

    @property
    def is_error(self) -> bool:
        return self.status.upper() in ERROR_CODES


def parse_line(line: str) -> Optional[QueryEntry]:
    """
    Parses one TSV line:
    [2026-09-29 20:49:12]<TAB>127.0.0.1<TAB>example.com<TAB>A<TAB>PASS<TAB>4ms<TAB>cloudflare
    """
    line = line.rstrip("\n")
    if not line.strip() or line.startswith("#"):
        return None
    parts = line.split("\t")
    if len(parts) < 5:
        return None

    time_str = parts[0].strip().strip("[]")
    if " " in time_str:
        time_str = time_str.split(" ")[-1]

    return QueryEntry(
        time_str=time_str,
        client=parts[1],
        domain=parts[2],
        qtype=parts[3],
        status=parts[4],
        duration=parts[5] if len(parts) > 5 else "",
        server=parts[6] if len(parts) > 6 and parts[6] != "-" else "",
    )


class QueryMonitor:
    def __init__(self, log_path: str, max_entries: int = 500):
        self.log_path = Path(log_path)
        self.max_entries = max_entries
        self.entries: List[QueryEntry] = []
        self.last_error: str = ""
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[List[QueryEntry]], None]] = []
        self._lock = threading.Lock()
        self._path_changed = threading.Event()

    def add_callback(self, cb: Callable[[List[QueryEntry]], None]):
        self._callbacks.append(cb)

    def set_log_path(self, path: str):
        if Path(path) != self.log_path:
            self.log_path = Path(path)
            self._path_changed.set()

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
        self._path_changed.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _emit(self, new_entries: List[QueryEntry]):
        with self._lock:
            self.entries.extend(new_entries)
            del self.entries[:-self.max_entries]
        for cb in self._callbacks:
            try:
                cb(new_entries)
            except Exception as e:
                print(f"[QueryMonitor] Callback error: {e}")

    def _tail_worker(self):
        f = None
        inode = None
        position = 0
        while self._running:
            try:
                if self._path_changed.is_set():
                    self._path_changed.clear()
                    if f:
                        f.close()
                    f, inode = None, None

                try:
                    st = self.log_path.stat()
                except FileNotFoundError:
                    self.last_error = f"{self.log_path} does not exist yet"
                    if f:
                        f.close()
                    f, inode = None, None
                    self._path_changed.wait(2.0)
                    continue

                if f is None or st.st_ino != inode or st.st_size < position:
                    # New file, rotation, or truncation: reopen and show the tail
                    if f:
                        f.close()
                    f = open(self.log_path, "rb")
                    inode = st.st_ino
                    if st.st_size > 50000:
                        f.seek(st.st_size - 50000)
                        f.readline()  # discard partial line
                self.last_error = ""

                chunk = f.read()
                if chunk:
                    # Leave an incomplete trailing line for the next round
                    cut = chunk.rfind(b"\n") + 1
                    if cut < len(chunk):
                        f.seek(cut - len(chunk), 1)
                        chunk = chunk[:cut]
                    text = chunk.decode("utf-8", errors="replace")
                    new_entries = [e for e in map(parse_line, text.splitlines()) if e]
                    if new_entries:
                        self._emit(new_entries)
                position = f.tell()
                self._path_changed.wait(1.0)
            except PermissionError:
                self.last_error = f"No permission to read {self.log_path}"
                f = None
                self._path_changed.wait(5.0)
            except Exception as e:
                self.last_error = str(e)
                f = None
                self._path_changed.wait(2.0)

        if f:
            f.close()
