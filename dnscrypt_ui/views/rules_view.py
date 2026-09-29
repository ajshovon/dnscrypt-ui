"""
Domain Rules (split DNS): send queries for specific domains to specific DNS
servers through dnscrypt-proxy's forwarding_rules.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..backend import validate
from ..backend.config_manager import ForwardingRule

PRESETS = [
    ("Choose a preset…", ""),
    ("DNS server from DHCP ($DHCP)", "$DHCP"),
    ("Router 192.168.1.1", "192.168.1.1:53"),
    ("Router 192.168.0.1", "192.168.0.1:53"),
    ("Tor DNSPort (127.0.0.1:9053)", "127.0.0.1:9053"),
]


class RulesView(Adw.PreferencesPage):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.cfg = win.config_mgr
        self._search_query = ""
        self._build_ui()
        self.reload()

    def _build_ui(self):
        top_group = Adw.PreferencesGroup(
            title="Split-DNS Rules",
            description=(
                "Send queries for a domain and all its subdomains to specific DNS servers, "
                "for example a home router for .lan names or a company DNS for internal domains. "
                "Forwarded queries are plain, unencrypted DNS."
            ),
        )
        self.add(top_group)

        toolbar = Gtk.Box(spacing=10, margin_top=4, margin_bottom=4)
        search = Gtk.SearchEntry(placeholder_text="Filter rules by domain, server, or note…", hexpand=True)
        search.connect("search-changed", self._on_search_changed)
        toolbar.append(search)
        btn_add = Gtk.Button(label="Add Rule", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        btn_add.connect("clicked", lambda _: self._show_rule_dialog())
        toolbar.append(btn_add)
        top_group.add(toolbar)

        self.rules_group = Adw.PreferencesGroup(title="Rules")
        self.add(self.rules_group)

    def _on_search_changed(self, entry):
        self._search_query = entry.get_text().strip().lower()
        self.reload()

    def reload(self):
        self.remove(self.rules_group)
        self.rules_group = Adw.PreferencesGroup(title="Rules")
        self.add(self.rules_group)

        shown = 0
        for rule in self.cfg.rules:
            q = self._search_query
            if q and not (
                q in rule.domain.lower()
                or any(q in s.lower() for s in rule.servers)
                or q in rule.comment.lower()
            ):
                continue
            shown += 1
            self.rules_group.add(self._create_rule_row(rule))

        if shown == 0:
            empty = Adw.ActionRow()
            if self._search_query:
                empty.set_title("No matching rules")
            else:
                empty.set_title("No forwarding rules")
                empty.set_subtitle("Add a rule to send a domain such as lan or corp.example.com to a specific DNS server")
            empty.add_prefix(Gtk.Image.new_from_icon_name("edit-find-symbolic"))
            self.rules_group.add(empty)

    def _create_rule_row(self, rule: ForwardingRule) -> Adw.ActionRow:
        row = Adw.ActionRow(title=rule.domain, use_markup=False)
        subtitle = f"→ {rule.servers_str}"
        if rule.comment:
            subtitle += f"  ({rule.comment})"
        if not all(validate.is_private_target(s) for s in rule.servers):
            subtitle += "\nSent unencrypted to a public server"
        row.set_subtitle(subtitle)

        icon = Gtk.Image.new_from_icon_name("network-server-symbolic")
        row.add_prefix(icon)

        def sync_icon():
            icon.set_opacity(1.0 if rule.enabled else 0.4)

        sync_icon()

        switch = Gtk.Switch(active=rule.enabled, valign=Gtk.Align.CENTER, margin_end=8)
        switch.set_tooltip_text("Enable or disable this rule")

        def on_toggled(sw, _pspec):
            rule.enabled = sw.get_active()
            sync_icon()
            self.win.config_changed()

        switch.connect("notify::active", on_toggled)
        row.add_suffix(switch)

        btn_edit = Gtk.Button(icon_name="document-edit-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
        btn_edit.set_tooltip_text("Edit rule")
        btn_edit.connect("clicked", lambda _: self._show_rule_dialog(rule))
        row.add_suffix(btn_edit)

        btn_delete = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
        btn_delete.set_tooltip_text("Delete rule")
        btn_delete.connect("clicked", lambda _: self._on_delete_rule(rule))
        row.add_suffix(btn_delete)
        return row

    def _on_delete_rule(self, rule: ForwardingRule):
        self.cfg.remove_rule(rule)
        self.reload()
        self.win.config_changed()
        toast = Adw.Toast(title=f"Deleted rule for {rule.domain}", button_label="Undo", timeout=5)
        toast.connect("button-clicked", lambda _: self._undo_delete(rule))
        self.win.toast_overlay.add_toast(toast)

    def _undo_delete(self, rule: ForwardingRule):
        self.cfg.add_rule(rule.domain, rule.servers, rule.comment, rule.enabled)
        self.reload()
        self.win.config_changed()

    def _show_rule_dialog(self, rule: ForwardingRule = None):
        dialog = Adw.AlertDialog(
            heading="Edit Rule" if rule else "Add Rule",
            body="Queries for the domain and all of its subdomains go to these servers.",
        )

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        entries = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        box.append(entries)

        domain_row = Adw.EntryRow(title="Domain (e.g. lan, corp.example.com)")
        servers_row = Adw.EntryRow(title="DNS servers, comma separated")
        comment_row = Adw.EntryRow(title="Note (optional)")
        preset_row = Adw.ComboRow(title="Preset", model=Gtk.StringList.new([p[0] for p in PRESETS]))
        for r in (domain_row, preset_row, servers_row, comment_row):
            entries.append(r)

        if rule:
            domain_row.set_text(rule.domain)
            servers_row.set_text(rule.servers_str)
            comment_row.set_text(rule.comment)

        status = Gtk.Label(wrap=True, xalign=0, css_classes=["caption"])
        box.append(status)
        dialog.set_extra_child(box)

        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save" if rule else "Add")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")

        parsed = {}

        def revalidate(*_):
            errors = []
            try:
                parsed["domain"] = validate.domain_pattern(domain_row.get_text())
                domain_row.remove_css_class("error")
            except ValueError as e:
                errors.append(str(e))
                domain_row.add_css_class("error")
            try:
                items = [s for s in servers_row.get_text().split(",") if s.strip()]
                if not items:
                    raise ValueError("Add at least one DNS server")
                parsed["servers"] = [validate.forward_target(s) for s in items]
                servers_row.remove_css_class("error")
            except ValueError as e:
                errors.append(str(e))
                servers_row.add_css_class("error")

            status.remove_css_class("error")
            status.remove_css_class("warning")
            if errors:
                status.set_text(errors[0] if domain_row.get_text() or servers_row.get_text() else "")
                status.add_css_class("error")
            elif not all(validate.is_private_target(s) for s in parsed["servers"]):
                status.set_text("These queries will be sent unencrypted to a public server, bypassing your encrypted resolvers.")
                status.add_css_class("warning")
            else:
                status.set_text("")
            dialog.set_response_enabled("save", not errors)

        def on_preset(row, _pspec):
            value = PRESETS[row.get_selected()][1]
            if value:
                servers_row.set_text(value)

        preset_row.connect("notify::selected", on_preset)
        for r in (domain_row, servers_row):
            r.connect("changed", revalidate)
        revalidate()

        def on_response(_d, response):
            if response != "save":
                return
            comment = validate.comment(comment_row.get_text())
            if rule:
                self.cfg.update_rule(rule, parsed["domain"], parsed["servers"], comment)
            else:
                self.cfg.add_rule(parsed["domain"], parsed["servers"], comment)
            self.reload()
            self.win.config_changed()

        dialog.connect("response", on_response)
        dialog.present(self.win)
