"""
Live DNS Query Inspector View for DNSCrypt UI.
Displays queries in real-time with filtering, status badges, and pause/resume controls.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib, Pango

from ..backend.config_manager import ConfigManager
from ..backend.query_monitor import QueryMonitor, QueryEntry


class QueryLogView(Adw.PreferencesPage):
    def __init__(self, config_mgr: ConfigManager, query_monitor: QueryMonitor):
        super().__init__()
        self.config_mgr = config_mgr
        self.monitor = query_monitor

        self.set_title("Query Inspector")
        self.set_icon_name("utilities-system-monitor-symbolic")

        self._paused = False
        self._auto_scroll = True
        self._search_filter = ""
        self._entries_cache = []

        self._build_ui()
        self.monitor.add_callback(self._on_new_entries)

    def _build_ui(self):
        # 1. Top Controls Group
        top_group = Adw.PreferencesGroup()
        top_group.set_title("Live DNS Query Inspector")
        top_group.set_description("Monitor DNS queries processed by dnscrypt-proxy in real time")
        self.add(top_group)

        # Toolbar Box (Clean Horizontal Layout, No squished ActionRow)
        toolbar_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        toolbar_box.set_margin_top(4)
        toolbar_box.set_margin_bottom(12)

        # Search Entry
        search_entry = Gtk.SearchEntry()
        search_entry.set_placeholder_text("Filter queries by domain name...")
        search_entry.set_hexpand(True)
        search_entry.connect("search-changed", self._on_search_changed)
        toolbar_box.append(search_entry)

        # Control Buttons
        self.btn_pause = Gtk.Button(label="Pause")
        self.btn_pause.set_icon_name("media-playback-pause-symbolic")
        self.btn_pause.connect("clicked", self._on_pause_clicked)
        toolbar_box.append(self.btn_pause)

        btn_clear = Gtk.Button(label="Clear")
        btn_clear.set_icon_name("edit-clear-symbolic")
        btn_clear.connect("clicked", self._on_clear_clicked)
        toolbar_box.append(btn_clear)

        self.lbl_count = Gtk.Label(label="0 queries")
        self.lbl_count.add_css_class("caption")
        self.lbl_count.add_css_class("dim-label")
        self.lbl_count.set_valign(Gtk.Align.CENTER)
        toolbar_box.append(self.lbl_count)

        top_group.add(toolbar_box)

        # 2. Scrolled Query List
        list_group = Adw.PreferencesGroup()
        list_group.set_title("Live Traffic Stream")
        self.add(list_group)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_min_content_height(450)
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(True)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.list_box.add_css_class("boxed-list")

        scrolled.set_child(self.list_box)
        self.scrolled_window = scrolled

        list_group.add(scrolled)

    def _on_search_changed(self, entry):
        self._search_filter = entry.get_text().strip().lower()
        self._refresh_list()

    def _on_pause_clicked(self, btn):
        self._paused = not self._paused
        self.monitor.set_paused(self._paused)
        if self._paused:
            btn.set_label("Resume")
            btn.set_icon_name("media-playback-start-symbolic")
        else:
            btn.set_label("Pause")
            btn.set_icon_name("media-playback-pause-symbolic")

    def _on_clear_clicked(self, _):
        self.monitor.clear()
        self._entries_cache.clear()
        self._refresh_list()

    def _on_new_entries(self, new_entries):
        GLib.idle_add(self._append_entries, new_entries)

    def _append_entries(self, new_entries):
        if self._paused:
            return

        self._entries_cache.extend(new_entries)
        if len(self._entries_cache) > 500:
            self._entries_cache = self._entries_cache[-500:]

        self.lbl_count.set_text(f"{len(self._entries_cache)} queries")

        for entry in new_entries:
            if self._search_filter and self._search_filter not in entry.domain.lower():
                continue
            row = self._create_query_row(entry)
            self.list_box.append(row)

        # Auto scroll to bottom
        adj = self.scrolled_window.get_vadjustment()
        adj.set_value(adj.get_upper() - adj.get_page_size())

    def _refresh_list(self):
        # Clear child rows
        while True:
            row = self.list_box.get_row_at_index(0)
            if not row:
                break
            self.list_box.remove(row)

        matched = 0
        for entry in self._entries_cache:
            if self._search_filter and self._search_filter not in entry.domain.lower():
                continue
            matched += 1
            row = self._create_query_row(entry)
            self.list_box.append(row)

        self.lbl_count.set_text(f"{matched} queries")

    def _create_query_row(self, entry: QueryEntry) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_start(14)
        box.set_margin_end(14)
        box.set_margin_top(9)
        box.set_margin_bottom(9)

        # Time
        lbl_time = Gtk.Label(label=entry.time_str)
        lbl_time.add_css_class("caption")
        lbl_time.add_css_class("dim-label")
        lbl_time.set_width_chars(8)
        lbl_time.set_xalign(0)
        box.append(lbl_time)

        # Type badge
        lbl_type = Gtk.Label(label=entry.qtype)
        lbl_type.add_css_class("dns-badge")
        lbl_type.add_css_class("dns-badge-neutral")
        box.append(lbl_type)

        # Domain
        lbl_domain = Gtk.Label(label=entry.domain)
        lbl_domain.set_hexpand(True)
        lbl_domain.set_xalign(0)
        lbl_domain.set_ellipsize(Pango.EllipsizeMode.END)
        box.append(lbl_domain)

        # Status badge
        lbl_status = Gtk.Label(label=entry.status)
        lbl_status.add_css_class("dns-badge")
        if entry.is_blocked:
            lbl_status.add_css_class("dns-badge-blocked")
        else:
            lbl_status.add_css_class("dns-badge-allowed")
        box.append(lbl_status)

        # Upstream Server
        lbl_server = Gtk.Label(label=entry.server)
        lbl_server.add_css_class("caption")
        lbl_server.add_css_class("dim-label")
        lbl_server.set_ellipsize(Pango.EllipsizeMode.END)
        lbl_server.set_max_width_chars(25)
        box.append(lbl_server)

        row.set_child(box)
        return row
