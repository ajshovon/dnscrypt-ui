"""
Domain Rules View for DNSCrypt UI (Split-DNS / YogaDNS style).
Allows user to create, edit, toggle, and delete domain forwarding rules
that route specific domains or wildcards to custom DNS servers.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from ..backend.config_manager import ConfigManager, ForwardingRule


class RulesView(Adw.PreferencesPage):
    def __init__(self, config_mgr: ConfigManager, on_change_cb):
        super().__init__()
        self.config_mgr = config_mgr
        self.on_change_cb = on_change_cb

        self.set_title("Domain Rules")
        self.set_icon_name("view-list-bullet-symbolic")

        self._search_query = ""
        self._build_ui()
        self.reload_rules()

    def _build_ui(self):
        # Header / Controls Group
        top_group = Adw.PreferencesGroup()
        top_group.set_title("YogaDNS Split-DNS Routing Rules")
        top_group.set_description(
            "Direct queries for specific domains or wildcards (*.internal, *.lan, google.com) to custom DNS servers."
        )
        self.add(top_group)

        # Toolbar Box (Clean Search + Add Rule Button)
        toolbar_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        toolbar_box.set_margin_top(4)
        toolbar_box.set_margin_bottom(12)

        search_entry = Gtk.SearchEntry()
        search_entry.set_placeholder_text("Filter rules by domain, target IP, or note...")
        search_entry.set_hexpand(True)
        search_entry.connect("search-changed", self._on_search_changed)
        toolbar_box.append(search_entry)

        btn_add = Gtk.Button(label="Add Rule")
        btn_add.set_icon_name("list-add-symbolic")
        btn_add.add_css_class("suggested-action")
        btn_add.set_valign(Gtk.Align.CENTER)
        btn_add.connect("clicked", lambda _: self._show_rule_dialog())
        toolbar_box.append(btn_add)

        top_group.add(toolbar_box)

        # Rules List Group
        self.rules_group = Adw.PreferencesGroup()
        self.rules_group.set_title("Configured Rules")
        self.add(self.rules_group)

    def _on_search_changed(self, entry):
        self._search_query = entry.get_text().strip().lower()
        self.reload_rules()

    def reload_rules(self):
        self.remove(self.rules_group)
        self.rules_group = Adw.PreferencesGroup()
        self.rules_group.set_title("Configured Rules")
        self.add(self.rules_group)

        rules = self.config_mgr.rules
        matched_count = 0

        for idx, rule in enumerate(rules):
            if self._search_query:
                q = self._search_query
                in_domain = q in rule.domain.lower()
                in_servers = any(q in s.lower() for s in rule.servers)
                in_comment = q in rule.comment.lower()
                if not (in_domain or in_servers or in_comment):
                    continue

            matched_count += 1
            row = self._create_rule_row(idx, rule)
            self.rules_group.add(row)

        if matched_count == 0:
            empty_row = Adw.ActionRow()
            if self._search_query:
                empty_row.set_title("No matching rules found")
                empty_row.set_subtitle("Try a different search term")
            else:
                empty_row.set_title("No domain forwarding rules yet")
                empty_row.set_subtitle("Click 'Add Rule' above to route domains to specific DNS servers")
            empty_icon = Gtk.Image.new_from_icon_name("edit-find-symbolic")
            empty_row.add_prefix(empty_icon)
            self.rules_group.add(empty_row)

    def _create_rule_row(self, index: int, rule: ForwardingRule) -> Adw.ActionRow:
        row = Adw.ActionRow()
        row.set_title(GLib.markup_escape_text(rule.domain))

        subtitle_parts = [f"→ {rule.servers_str}"]
        if rule.comment:
            subtitle_parts.append(f"({rule.comment})")
        row.set_subtitle(GLib.markup_escape_text(" ".join(subtitle_parts)))

        # Icon prefix indicating status
        icon_name = "network-server-symbolic" if rule.enabled else "network-offline-symbolic"
        icon = Gtk.Image.new_from_icon_name(icon_name)
        if not rule.enabled:
            icon.add_css_class("dim-label")
        row.add_prefix(icon)

        # Enable/Disable switch with margin
        switch = Gtk.Switch()
        switch.set_active(rule.enabled)
        switch.set_valign(Gtk.Align.CENTER)
        switch.set_margin_end(8)
        switch.connect("notify::active", self._on_rule_switch_toggled, index)
        row.add_suffix(switch)

        # Edit button
        btn_edit = Gtk.Button.new_from_icon_name("document-edit-symbolic")
        btn_edit.set_tooltip_text("Edit Rule")
        btn_edit.set_valign(Gtk.Align.CENTER)
        btn_edit.add_css_class("flat")
        btn_edit.connect("clicked", lambda _, idx=index, r=rule: self._show_rule_dialog(idx, r))
        row.add_suffix(btn_edit)

        # Delete button
        btn_delete = Gtk.Button.new_from_icon_name("user-trash-symbolic")
        btn_delete.set_tooltip_text("Delete Rule")
        btn_delete.set_valign(Gtk.Align.CENTER)
        btn_delete.add_css_class("flat")
        btn_delete.add_css_class("destructive-action")
        btn_delete.connect("clicked", lambda _, idx=index: self._on_delete_rule(idx))
        row.add_suffix(btn_delete)

        return row

    def _on_rule_switch_toggled(self, switch, _, index: int):
        if index < len(self.config_mgr.rules):
            self.config_mgr.rules[index].enabled = switch.get_active()
            self.config_mgr.set_dirty(True)
            self.on_change_cb()

    def _on_delete_rule(self, index: int):
        self.config_mgr.remove_rule(index)
        self.reload_rules()
        self.on_change_cb()

    def _show_rule_dialog(self, edit_index: int = -1, existing_rule: ForwardingRule = None):
        is_edit = edit_index >= 0 and existing_rule is not None
        title = "Edit Domain Rule" if is_edit else "Add Domain Forwarding Rule"

        dialog = Adw.MessageDialog(
            transient_for=self.get_root(),
            heading=title,
            body="Specify the domain or wildcard pattern and destination DNS server(s).",
        )

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content_box.set_margin_top(12)
        content_box.set_margin_bottom(12)

        # Domain Entry
        domain_row = Adw.EntryRow()
        domain_row.set_title("Domain or Wildcard")
        if is_edit:
            domain_row.set_text(existing_rule.domain)
        else:
            domain_row.set_text("")
        domain_row.set_tooltip_text("e.g. *.internal, *.lan, corp.company.com, google.com")
        content_box.append(domain_row)

        # Preset Dropdown Box
        preset_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        lbl_preset = Gtk.Label(label="Quick Target Preset:")
        preset_box.append(lbl_preset)

        presets = [
            ("Select preset...", ""),
            ("Local Router (192.168.1.1:53)", "192.168.1.1:53"),
            ("Local Router (192.168.0.1:53)", "192.168.0.1:53"),
            ("Cloudflare DNS (1.1.1.1:53)", "1.1.1.1:53, 1.0.0.1:53"),
            ("Google Public DNS (8.8.8.8:53)", "8.8.8.8:53, 8.8.4.4:53"),
            ("Quad9 DNS (9.9.9.9:53)", "9.9.9.9:53"),
        ]
        string_list = Gtk.StringList.new([p[0] for p in presets])
        dropdown = Gtk.DropDown.new(string_list, None)
        preset_box.append(dropdown)
        content_box.append(preset_box)

        # Servers Entry
        servers_row = Adw.EntryRow()
        servers_row.set_title("Target DNS Servers (comma separated)")
        if is_edit:
            servers_row.set_text(existing_rule.servers_str)
        else:
            servers_row.set_text("192.168.1.1:53")
        content_box.append(servers_row)

        def on_preset_selected(dd, _):
            idx = dd.get_selected()
            if idx > 0 and idx < len(presets):
                val = presets[idx][1]
                servers_row.set_text(val)

        dropdown.connect("notify::selected", on_preset_selected)

        # Comment Entry
        comment_row = Adw.EntryRow()
        comment_row.set_title("Note / Description (Optional)")
        if is_edit:
            comment_row.set_text(existing_rule.comment)
        content_box.append(comment_row)

        dialog.set_extra_child(content_box)

        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save Rule" if is_edit else "Add Rule")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)

        def on_response(d, response_id):
            if response_id == "save":
                dom = domain_row.get_text().strip()
                srv_str = servers_row.get_text().strip()
                cmt = comment_row.get_text().strip()
                if not dom or not srv_str:
                    return

                srv_list = [s.strip() for s in srv_str.split(",") if s.strip()]
                if is_edit:
                    self.config_mgr.update_rule(
                        edit_index,
                        domain=dom,
                        servers=srv_list,
                        comment=cmt,
                        enabled=existing_rule.enabled,
                    )
                else:
                    self.config_mgr.add_rule(domain=dom, servers=srv_list, comment=cmt, enabled=True)

                self.reload_rules()
                self.on_change_cb()

        dialog.connect("response", on_response)
        dialog.present()
