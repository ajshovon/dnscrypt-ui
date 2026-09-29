"""
Resolvers page: choose which encrypted upstream servers dnscrypt-proxy uses.
The list comes from dnscrypt-proxy's own sources, so names always exist.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..backend import resolver_db, validate

MAX_ROWS = 80
SCOPES = [("Selected", "selected"), ("Recommended", "recommended"), ("All", "all")]


def _badge(text: str, kind: str) -> Gtk.Label:
    return Gtk.Label(label=text, valign=Gtk.Align.CENTER, css_classes=["dns-badge", f"dns-badge-{kind}"])


class ResolversView(Adw.PreferencesPage):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.cfg = win.config_mgr
        self._query = ""
        self._scope = "recommended"
        self._proto = "any"
        self._usable_only = False
        self._switches = {}
        self._build_ui()
        self.reload()

    def _build_ui(self):
        top = Adw.PreferencesGroup(
            title="Upstream Resolvers",
            description="dnscrypt-proxy sends every query that no Domain Rule matches to these servers, encrypted.",
        )
        self.add(top)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin_top=4)
        row1 = Gtk.Box(spacing=10)
        search = Gtk.SearchEntry(placeholder_text="Search by name or description…", hexpand=True)
        search.connect("search-changed", self._on_search_changed)
        row1.append(search)
        btn_refresh = Gtk.Button(icon_name="view-refresh-symbolic", valign=Gtk.Align.CENTER)
        btn_refresh.set_tooltip_text("Reload the resolver list from dnscrypt-proxy")
        btn_refresh.connect("clicked", lambda _: self.win.refresh_catalog())
        row1.append(btn_refresh)
        btn_custom = Gtk.Button(label="Add Stamp", valign=Gtk.Align.CENTER)
        btn_custom.set_tooltip_text("Add a server from an sdns:// stamp")
        btn_custom.connect("clicked", lambda _: self._show_add_stamp_dialog())
        row1.append(btn_custom)
        box.append(row1)

        row2 = Gtk.Box(spacing=12)
        scope_box = Gtk.Box(css_classes=["linked"])
        first = None
        for label, code in SCOPES:
            btn = Gtk.ToggleButton(label=label, active=code == self._scope)
            if first:
                btn.set_group(first)
            first = first or btn
            btn.connect("toggled", self._on_scope_toggled, code)
            scope_box.append(btn)
        row2.append(scope_box)

        proto = Gtk.DropDown.new_from_strings(["Any protocol", "DoH", "DNSCrypt"])
        proto.connect("notify::selected", self._on_proto_changed)
        row2.append(proto)

        usable = Gtk.CheckButton(label="Usable only")
        usable.set_tooltip_text("Hide servers that the current requirements would skip")
        usable.connect("toggled", self._on_usable_toggled)
        row2.append(usable)
        box.append(row2)

        self.catalog_label = Gtk.Label(xalign=0, css_classes=["caption", "dim-label"], wrap=True)
        box.append(self.catalog_label)
        top.add(box)

        self.list_group = Adw.PreferencesGroup()
        self.add(self.list_group)

    # Filters

    def _on_search_changed(self, entry):
        self._query = entry.get_text().strip().lower()
        if self._query and self._scope == "recommended":
            self._scope = "all_search"
        elif not self._query and self._scope == "all_search":
            self._scope = "recommended"
        self.reload()

    def _on_scope_toggled(self, btn, code):
        if btn.get_active():
            self._scope = code
            self.reload()

    def _on_proto_changed(self, dd, _pspec):
        self._proto = ["any", "DoH", "DNSCrypt"][dd.get_selected()]
        self.reload()

    def _on_usable_toggled(self, btn):
        self._usable_only = btn.get_active()
        self.reload()

    # Rendering

    def update_catalog_state(self):
        state = self.win.catalog_state
        count = len(self.win.catalog)
        if state == "loading":
            text = "Loading the resolver list from dnscrypt-proxy…"
        elif state == "refreshing":
            text = f"{count} servers (cached). Refreshing…"
        elif state.startswith("error"):
            text = f"Could not load the resolver list ({state[7:]}). " + (f"Showing {count} cached servers." if count else "")
        else:
            text = f"{count} servers from dnscrypt-proxy's sources."
        self.catalog_label.set_text(text)

    def _entries(self):
        catalog = self.win.catalog
        by_name = {r["name"]: r for r in catalog}
        entries = []
        for name in self.cfg.server_names:
            if name in by_name:
                continue
            if name in self.cfg.static_stamps:
                entries.append({"name": name, "label": name, "proto": "Stamp", "description": "Custom server (static stamp)",
                                "dnssec": False, "nolog": False, "nofilter": False, "ipv6": False, "static": True})
            else:
                entries.append({"name": name, "label": name, "proto": "?", "description": "", "missing": True,
                                "dnssec": False, "nolog": False, "nofilter": False, "ipv6": False})
        entries.extend(catalog)
        return entries

    def _visible(self, entry) -> bool:
        selected = entry["name"] in self.cfg.server_names
        scope = self._scope
        if scope == "selected" and not selected:
            return False
        if scope == "recommended" and not (entry.get("recommended") or selected):
            return False
        if self._proto != "any" and entry["proto"] != self._proto:
            return False
        if self._usable_only and self._reason(entry):
            return False
        if self._query:
            q = self._query
            if q not in entry["name"].lower() and q not in entry.get("label", "").lower() and q not in entry.get("description", "").lower():
                return False
        return True

    def _reason(self, entry):
        if entry.get("static"):
            return None
        if entry.get("missing"):
            if not self.win.catalog:
                return "Resolver list not loaded yet"
            return "Not found in the resolver sources; dnscrypt-proxy ignores it"
        return resolver_db.exclusion_reason(entry, self.cfg)

    def reload(self):
        self.update_catalog_state()
        self.remove(self.list_group)
        self.list_group = Adw.PreferencesGroup()
        self.add(self.list_group)
        self._switches = {}

        shown = 0
        total = 0
        for entry in self._entries():
            if not self._visible(entry):
                continue
            total += 1
            if shown < MAX_ROWS:
                self.list_group.add(self._create_row(entry))
                shown += 1

        if not self.cfg.server_names:
            info = Adw.ActionRow(
                title="No resolvers selected",
                subtitle="dnscrypt-proxy picks automatically from every server that meets the requirements.",
            )
            info.add_prefix(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
            self.list_group.add(info)
        if total == 0:
            self.list_group.add(Adw.ActionRow(title="No servers match", subtitle="Change the search or filters"))
        elif total > shown:
            self.list_group.set_description(f"Showing {shown} of {total}. Refine the search to see more.")

    def refresh_eligibility(self):
        """Requirements changed: rebuild rows so warnings are current."""
        self.reload()

    def _create_row(self, entry) -> Adw.ActionRow:
        name = entry["name"]
        row = Adw.ActionRow(title=entry.get("label") or name, use_markup=False)
        subtitle = name
        if entry.get("description"):
            subtitle += f" · {entry['description']}"
        reason = self._reason(entry)
        selected = name in self.cfg.server_names
        if reason:
            subtitle += f"\n⚠ Skipped: {reason}" if selected else f"\nNot usable: {reason}"
        row.set_subtitle(subtitle)
        row.set_subtitle_lines(3)
        if reason and selected:
            row.add_css_class("warning")

        badges = Gtk.Box(spacing=6, valign=Gtk.Align.CENTER, margin_end=8)
        kind = {"DoH": "doh", "DNSCrypt": "dnscrypt"}.get(entry["proto"], "neutral")
        badges.append(_badge(entry["proto"], kind))
        if entry.get("dnssec"):
            badges.append(_badge("DNSSEC", "security"))
        if entry.get("nolog"):
            badges.append(_badge("No-log", "privacy"))
        if not entry.get("missing") and not entry.get("static"):
            badges.append(_badge("Unfiltered", "neutral") if entry.get("nofilter") else _badge("Filtering", "warning"))
        row.add_suffix(badges)

        switch = Gtk.Switch(active=selected, valign=Gtk.Align.CENTER)
        switch.connect("notify::active", self._on_switch_toggled, name)
        row.add_suffix(switch)
        row.set_activatable_widget(switch)
        return row

    def _on_switch_toggled(self, switch, _pspec, name: str):
        self.cfg.toggle_resolver(name, switch.get_active())
        self.win.btn_apply.set_visible(self.cfg.is_dirty)
        self.win.status_view.update_summary()

    def _show_add_stamp_dialog(self):
        dialog = Adw.AlertDialog(
            heading="Add Server from Stamp",
            body="Paste an sdns:// stamp, for example from dnscrypt.info/stamps or your DNS provider.",
        )
        entries = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        name_row = Adw.EntryRow(title="Name (e.g. my-nextdns)")
        stamp_row = Adw.EntryRow(title="Stamp (sdns://…)")
        entries.append(name_row)
        entries.append(stamp_row)
        dialog.set_extra_child(entries)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("add", "Add")
        dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)

        def revalidate(*_):
            ok = True
            for row, check in ((name_row, validate.resolver_name), (stamp_row, validate.stamp)):
                try:
                    check(row.get_text())
                    row.remove_css_class("error")
                except ValueError:
                    ok = False
                    if row.get_text():
                        row.add_css_class("error")
            dialog.set_response_enabled("add", ok)

        name_row.connect("changed", revalidate)
        stamp_row.connect("changed", revalidate)
        revalidate()

        def on_response(_d, response):
            if response == "add":
                self.cfg.add_static_resolver(validate.resolver_name(name_row.get_text()), validate.stamp(stamp_row.get_text()))
                self._scope = "selected"
                self.reload()
                self.win.config_changed()

        dialog.connect("response", on_response)
        dialog.present(self.win)
