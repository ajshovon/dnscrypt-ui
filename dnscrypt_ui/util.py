import threading

from gi.repository import GLib


def run_in_thread(work, done):
    """Runs work() in a thread, then done(result) on the main loop."""
    def worker():
        result = work()
        GLib.idle_add(lambda: done(result) and False)
    threading.Thread(target=worker, daemon=True).start()
