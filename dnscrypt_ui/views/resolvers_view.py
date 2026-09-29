"""
Resolvers View for DNSCrypt UI.
Browse, search, and enable/disable upstream DoH and DNSCrypt resolvers.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from ..backend.config_manager import ConfigManager
from ..backend.resolver_db import get_all_resolvers, find_resolver


class ResolversView(Adw.PreferencesPage):
    def __init__(self, config_mgr: ConfigManager, on_change_cb):
        super().__init__()
        self.config_mgr = config_mgr
        self.on_change_cb = on_change_cb

        self.set_title("Resolvers")
        self.set_icon_name("cloud-symbolic")

        self._search_query = ""
        self._protocol_filter = "ALL"  # ALL, DOH, DNSCRYPT, DNSSEC, NOLOG

        self._build_ui()
        self.reload_resolvers()

    def _build_ui(self):
        # Header Group
        top_group = Adw.PreferencesGroup()
        top_group.set_title("Upstream DNS Resolvers")
        top_group.set_description(
            "Select which public DoH (DNS over HTTPS) or DNSCrypt resolvers dnscrypt-proxy forwards general traffic to."
        )
        self.add(top_group)

        # Toolbar Container (No ActionRow squishing)
        toolbar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        toolbar_box.set_margin_top(4)
        toolbar_box.set_margin_bottom(12)

        # Row 1: Search Entry + Add Custom Button
        search_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)

        search_entry = Gtk.SearchEntry()
        search_entry.set_placeholder_text("Search resolvers by name, provider, or features...")
        search_entry.set_hexpand(True)
        search_entry.connect("search-changed", self._on_search_changed)
        search_row.append(search_entry)

        btn_custom = Gtk.Button(label="Add Custom")
        btn_custom.set_icon_name("list-add-symbolic")
        btn_custom.add_css_class("suggested-action")
        btn_custom.set_valign(Gtk.Align.CENTER)
        btn_custom.connect("clicked", lambda _: self._show_add_custom_dialog())
        search_row.append(btn_custom)

        toolbar_box.append(search_row)

        # Row 2: Filter Pills in a Linked Box
        filter_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        filter_bar.add_css_class("linked")
        filter_bar.set_halign(Gtk.Align.START)

        filters = [
            ("All", "ALL"),
            ("DoH", "DOH"),
            ("DNSCrypt", "DNSCRYPT"),
            ("Custom", "CUSTOM"),
            ("DNSSEC", "DNSSEC"),
            ("No-Log", "NOLOG"),
        ]
        self._filter_buttons = []
        for label, code in filters:
            btn = Gtk.Button(label=label)
            if code == "ALL":
                btn.add_css_class("suggested-action")
            btn.connect("clicked", self._on_filter_clicked, code)
            filter_bar.append(btn)
            self._filter_buttons.append((btn, code))

        toolbar_box.append(filter_bar)
        top_group.add(toolbar_box)

        # Resolvers List Group
        self.resolvers_group = Adw.PreferencesGroup()
        self.resolvers_group.set_title("Available Resolvers")
        self.add(self.resolvers_group)

    def _on_search_changed(self, entry):
        self._search_query = entry.get_text().strip().lower()
        self.reload_resolvers()

    def _on_filter_clicked(self, clicked_btn, code: str):
        self._protocol_filter = code
        for btn, c in self._filter_buttons:
            if c == code:
                btn.add_css_class("suggested-action")
            else:
                btn.remove_css_class("suggested-action")
        self.reload_resolvers()

    def reload_resolvers(self):
        self.remove(self.resolvers_group)
        self.resolvers_group = Adw.PreferencesGroup()
        self.resolvers_group.set_title("Available Resolvers")
        self.add(self.resolvers_group)

        catalog = get_all_resolvers()
        # Also include any custom server_names in config not in catalog
        known_names = {r["name"] for r in catalog}
        all_resolvers = list(catalog)

        for s_name in self.config_mgr.server_names:
            if s_name not in known_names:
                all_resolvers.insert(
                    0,
                    {
                        "name": s_name,
                        "label": f"Custom: {s_name}",
                        "protocol": "Custom",
                        "description": "User-defined resolver entry",
                        "dnssec": False,
                        "nolog": False,
                        "nofilter": False,
                    },
                )

        matched = 0
        for res in all_resolvers:
            # Check filter
            if self._protocol_filter == "DOH" and res["protocol"] != "DoH":
                continue
            if self._protocol_filter == "DNSCRYPT" and res["protocol"] != "DNSCrypt":
                continue
            if self._protocol_filter == "CUSTOM" and res["protocol"] != "Custom":
                continue
            if self._protocol_filter == "DNSSEC" and not res.get("dnssec"):
                continue
            if self._protocol_filter == "NOLOG" and not res.get("nolog"):
                continue

            # Check search
            if self._search_query:
                q = self._search_query
                in_name = q in res["name"].lower()
                in_label = q in res["label"].lower()
                in_desc = q in res["description"].lower()
                if not (in_name or in_label or in_desc):
                    continue

            matched += 1
            row = self._create_resolver_row(res)
            self.resolvers_group.add(row)

        if matched == 0:
            empty_row = Adw.ActionRow()
            empty_row.set_title("No resolvers match criteria")
            empty_row.set_subtitle("Try changing the search term or protocol filter")
            self.resolvers_group.add(empty_row)

    def _create_resolver_row(self, res: dict) -> Adw.ActionRow:
        row = Adw.ActionRow()
        row.set_title(GLib.markup_escape_text(res["label"]))
        row.set_subtitle(GLib.markup_escape_text(f"{res['name']} — {res['description']}"))

        # Icon prefix
        icon_name = "network-wireless-symbolic" if res["protocol"] == "DoH" else "security-high-symbolic"
        icon = Gtk.Image.new_from_icon_name(icon_name)
        row.add_prefix(icon)

        # Tags Box (Pill Badges)
        tag_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        tag_box.set_valign(Gtk.Align.CENTER)
        tag_box.set_margin_end(12)

        proto_lbl = Gtk.Label(label=res["protocol"])
        proto_lbl.add_css_class("dns-badge")
        if res["protocol"] == "DoH":
            proto_lbl.add_css_class("dns-badge-doh")
        elif res["protocol"] == "DNSCrypt":
            proto_lbl.add_css_class("dns-badge-dnscrypt")
        else:
            proto_lbl.add_css_class("dns-badge-neutral")
        tag_box.append(proto_lbl)

        if res.get("dnssec"):
            dnssec_lbl = Gtk.Label(label="DNSSEC")
            dnssec_lbl.add_css_class("dns-badge")
            dnssec_lbl.add_css_class("dns-badge-security")
            tag_box.append(dnssec_lbl)

        if res.get("nolog"):
            nolog_lbl = Gtk.Label(label="No-Log")
            nolog_lbl.add_css_class("dns-badge")
            nolog_lbl.add_css_class("dns-badge-privacy")
            tag_box.append(nolog_lbl)

        row.add_suffix(tag_box)

        # Toggle Switch
        is_active = res["name"] in self.config_mgr.server_names
        switch = Gtk.Switch()
        switch.set_active(is_active)
        switch.set_valign(Gtk.Align.CENTER)
        switch.connect("notify::active", self._on_switch_toggled, res["name"])
        row.add_suffix(switch)

        return row

    def _on_switch_toggled(self, switch, _, name: str):
        active = switch.get_active()
        self.config_mgr.toggle_resolver(name, active)
        self.on_change_cb()

    def _show_add_custom_dialog(self):
        dialog = Adw.MessageDialog(
            transient_for=self.get_root(),
            heading="Add Custom Upstream Resolver",
            body="Enter a public resolver identifier (e.g. quad9-doh-ip4-filter-pri, cloudflare) or a plain DNS IP.",
        )

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(12)
        box.set_margin_bottom(12)

        entry = Adw.EntryRow()
        entry.set_title("Resolver Name or Plain DNS IP")
        entry.set_tooltip_text("e.g. quad9-doh-ip4-filter-pri, cloudflare, or 1.1.1.1:53")
        box.append(entry)

        hint_lbl = Gtk.Label(
            label="Tip: For domain-specific Plain DNS routing (YogaDNS style), use the 'Domain Rules' tab.\nPlain DNS IPs entered here will be added to Fallback Resolvers.",
        )
        hint_lbl.add_css_class("caption")
        hint_lbl.add_css_class("dim-label")
        hint_lbl.set_wrap(True)
        hint_lbl.set_xalign(0)
        box.append(hint_lbl)

        dialog.set_extra_child(box)

        dialog.add_response("cancel", "Cancel")
        dialog.add_response("add", "Add Resolver")
        dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)

        def on_response(d, resp_id):
            if resp_id == "add":
                val = entry.get_text().strip()
                if not val:
                    return

                import re
                # Check if it's an IP:port or plain IP
                if re.match(r"^\d+\.\d+\.\d+\.\d+(:\d+)?$", val) or ":" in val and "." not in val:
                    if ":" not in val:
                        val = f"{val}:53"
                    if val not in self.config_mgr.fallback_resolvers:
                        self.config_mgr.fallback_resolvers.append(val)
                        self.config_mgr.set_dirty(True)
                else:
                    self.config_mgr.toggle_resolver(val, True)

                self.reload_resolvers()
                self.on_change_cb()

        dialog.connect("response", on_response)
        dialog.present()
