"""
Live query log: shows queries from dnscrypt-proxy's TSV query log.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk, Pango

from ..backend.query_monitor import QueryEntry

MAX_ROWS = 500


class QueryLogView(Gtk.Box):
    def __init__(self, win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.win = win
        self.cfg = win.config_mgr
        self.monitor = win.query_monitor

        self._paused = False
        self._pending = []
        self._filter = ""
        self._row_count = 0

        self._build_ui()
        self.monitor.add_callback(lambda entries: GLib.idle_add(self._on_new_entries, entries))
        self.update_state()

    def _build_ui(self):
        self.banner = Adw.Banner()
        self.banner.connect("button-clicked", self._on_banner_clicked)
        self.append(self.banner)

        clamp = Adw.Clamp(maximum_size=1100, vexpand=True)
        self.append(clamp)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                          margin_top=18, margin_bottom=18, margin_start=12, margin_end=12)
        clamp.set_child(content)

        toolbar = Gtk.Box(spacing=10)
        search = Gtk.SearchEntry(placeholder_text="Filter by domain, status, or server…", hexpand=True)
        search.connect("search-changed", self._on_search_changed)
        toolbar.append(search)

        self.btn_pause = Gtk.Button(icon_name="media-playback-pause-symbolic", tooltip_text="Pause")
        self.btn_pause.connect("clicked", self._on_pause_clicked)
        toolbar.append(self.btn_pause)

        btn_clear = Gtk.Button(icon_name="edit-clear-all-symbolic", tooltip_text="Clear")
        btn_clear.connect("clicked", self._on_clear_clicked)
        toolbar.append(btn_clear)

        self.lbl_count = Gtk.Label(css_classes=["caption", "dim-label"], valign=Gtk.Align.CENTER)
        toolbar.append(self.lbl_count)
        content.append(toolbar)

        self.scrolled = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        self.list_box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
        self.list_box.set_filter_func(self._filter_func)
        self.scrolled.set_child(self.list_box)
        content.append(self.scrolled)

        self.empty = Adw.StatusPage(icon_name="document-open-recent-symbolic", title="No queries yet", vexpand=True)
        content.append(self.empty)

    # State

    def reload(self):
        self.update_state()

    def update_state(self):
        if not self.cfg.query_log_enabled:
            self.banner.set_title("Query logging is turned off in dnscrypt-proxy")
            self.banner.set_button_label("Turn On")
            self.banner.set_revealed(True)
        elif self.monitor.last_error:
            self.banner.set_title(self.monitor.last_error)
            self.banner.set_button_label("")
            self.banner.set_revealed(True)
        else:
            self.banner.set_revealed(False)
        self._update_empty()

    def _update_empty(self):
        has_rows = self._row_count > 0
        self.scrolled.set_visible(has_rows)
        self.empty.set_visible(not has_rows)
        if not self.cfg.query_log_enabled:
            self.empty.set_description("Turn on query logging, then press Apply.")
        else:
            self.empty.set_description(f"Waiting for queries in {self.monitor.log_path}")
        paused = f" · {len(self._pending)} paused" if self._pending else ""
        self.lbl_count.set_text(f"{self._row_count} queries{paused}")

    def _on_banner_clicked(self, _):
        self.cfg.query_log_enabled = True
        self.win.config_changed()
        self.win.settings_view.reload()
        self.win.show_toast("Query logging will be turned on when you press Apply")

    # Entries

    def _on_new_entries(self, entries):
        if self._paused:
            self._pending.extend(entries)
            del self._pending[:-MAX_ROWS]
        else:
            self._append(entries)
        self._update_empty()
        return False

    def _append(self, entries):
        adj = self.scrolled.get_vadjustment()
        at_bottom = adj.get_value() >= adj.get_upper() - adj.get_page_size() - 40

        for entry in entries[-MAX_ROWS:]:
            self.list_box.append(self._create_row(entry))
            self._row_count += 1
        while self._row_count > MAX_ROWS:
            self.list_box.remove(self.list_box.get_row_at_index(0))
            self._row_count -= 1

        if at_bottom:
            GLib.idle_add(lambda: adj.set_value(adj.get_upper() - adj.get_page_size()) and False)

    def _on_search_changed(self, entry):
        self._filter = entry.get_text().strip().lower()
        self.list_box.invalidate_filter()

    def _filter_func(self, row):
        return not self._filter or self._filter in row.search_text

    def _on_pause_clicked(self, btn):
        self._paused = not self._paused
        btn.set_icon_name("media-playback-start-symbolic" if self._paused else "media-playback-pause-symbolic")
        btn.set_tooltip_text("Resume" if self._paused else "Pause")
        if not self._paused and self._pending:
            self._append(self._pending)
            self._pending = []
        self._update_empty()

    def _on_clear_clicked(self, _):
        self.list_box.remove_all()
        self._row_count = 0
        self._pending = []
        self.monitor.clear()
        self._update_empty()

    def _create_row(self, entry: QueryEntry) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow(activatable=False)
        row.search_text = f"{entry.domain} {entry.status} {entry.server} {entry.qtype}".lower()
        box = Gtk.Box(spacing=12, margin_start=14, margin_end=14, margin_top=8, margin_bottom=8)

        box.append(Gtk.Label(label=entry.time_str, width_chars=8, xalign=0, css_classes=["caption", "dim-label", "numeric"]))
        box.append(Gtk.Label(label=entry.qtype, width_chars=5, css_classes=["dns-badge", "dns-badge-neutral"]))

        domain = Gtk.Label(label=entry.domain, hexpand=True, xalign=0, ellipsize=Pango.EllipsizeMode.END, selectable=True)
        box.append(domain)

        kind = "blocked" if entry.is_blocked else "warning" if entry.is_error else "allowed"
        box.append(Gtk.Label(label=entry.status, css_classes=["dns-badge", f"dns-badge-{kind}"]))

        detail = " · ".join(x for x in (entry.duration, entry.server) if x)
        box.append(Gtk.Label(label=detail, width_chars=18, max_width_chars=26, xalign=1,
                             ellipsize=Pango.EllipsizeMode.END, css_classes=["caption", "dim-label"]))
        row.set_child(box)
        return row
