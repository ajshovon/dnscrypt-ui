"""
Settings: listen addresses, bootstrap resolvers, protocols, query logging,
and installation status.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..backend import validate
from ..backend.config_manager import DEFAULT_QUERY_LOG


class SettingsView(Adw.PreferencesPage):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.cfg = win.config_mgr
        self.service_mgr = win.service_mgr
        self._loading = False
        self._build_ui()
        self.reload()

    def _build_ui(self):
        # Network
        net = Adw.PreferencesGroup(title="Network")
        self.add(net)
        self.listen_row = Adw.EntryRow(title="Listen addresses (comma separated, loopback only)")
        self.listen_row.connect("changed", self._on_list_changed, "listen_addresses", validate.loopback_host_port)
        self.listen_row.set_tooltip_text(
            "Where dnscrypt-proxy accepts queries. System DNS is updated to follow the first address when you apply."
        )
        net.add(self.listen_row)

        self.bootstrap_row = Adw.EntryRow(title="Bootstrap resolvers (comma separated)")
        self.bootstrap_row.connect("changed", self._on_list_changed, "bootstrap_resolvers", validate.host_port)
        self.bootstrap_row.set_tooltip_text(
            "Plain DNS servers used only to look up resolver host names and download the resolver list. "
            "Your normal queries never go to them."
        )
        net.add(self.bootstrap_row)
        self.net_status = Gtk.Label(xalign=0, wrap=True, css_classes=["caption", "error"], margin_top=6)
        net.add(self.net_status)

        # Protocols
        proto = Adw.PreferencesGroup(
            title="Protocols",
            description="Selected resolvers that use a disabled protocol are skipped",
        )
        self.add(proto)
        self.doh_switch = Adw.SwitchRow(title="DNS-over-HTTPS (DoH)")
        self.doh_switch.connect("notify::active", self._on_bool_toggled, "doh_servers")
        proto.add(self.doh_switch)
        self.dnscrypt_switch = Adw.SwitchRow(title="DNSCrypt")
        self.dnscrypt_switch.connect("notify::active", self._on_bool_toggled, "dnscrypt_servers")
        proto.add(self.dnscrypt_switch)

        # Query log
        log = Adw.PreferencesGroup(
            title="Query Log",
            description="Logs every domain looked up on this computer. Needed for the Query Log page.",
        )
        self.add(log)
        self.log_switch = Adw.SwitchRow(title="Log queries")
        self.log_switch.connect("notify::active", self._on_bool_toggled, "query_log_enabled")
        log.add(self.log_switch)
        self.log_file_row = Adw.EntryRow(title="Log file")
        self.log_file_row.connect("changed", self._on_log_file_changed)
        log.add(self.log_file_row)

        # Installation
        inst = Adw.PreferencesGroup(title="Installation")
        self.add(inst)
        helper_row = Adw.ActionRow(title="Privileged helper")
        helper_status = self.service_mgr.helper_status()
        if helper_status == "installed":
            helper_row.set_subtitle("Installed with its own polkit action")
            helper_row.add_prefix(Gtk.Image.new_from_icon_name("object-select-symbolic"))
        elif helper_status == "outdated":
            helper_row.set_subtitle("Out of date: run ./install.sh in the dns-crypt-ui folder to update it")
            helper_row.add_prefix(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))
        else:
            helper_row.set_subtitle(
                "Not installed: changes run the helper from the source folder. "
                "Run install.sh to install it root-owned with a dedicated polkit action."
            )
            helper_row.add_prefix(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))
        inst.add(helper_row)

        for title, value in (
            ("Configuration", str(self.cfg.toml_path)),
            ("Forwarding rules", str(self.cfg.rules_path)),
            ("Backups", str(self.cfg.config_dir / ".dnscrypt-ui-backup")),
        ):
            row = Adw.ActionRow(title=title, subtitle=value, subtitle_selectable=True)
            inst.add(row)

    def reload(self):
        self._loading = True
        try:
            self.listen_row.set_text(", ".join(self.cfg.listen_addresses))
            self.bootstrap_row.set_text(", ".join(self.cfg.bootstrap_resolvers))
            self.doh_switch.set_active(self.cfg.doh_servers)
            self.dnscrypt_switch.set_active(self.cfg.dnscrypt_servers)
            self.log_switch.set_active(self.cfg.query_log_enabled)
            self.log_file_row.set_text(self.cfg.query_log_file)
            self.log_file_row.set_sensitive(self.cfg.query_log_enabled)
            for row in (self.listen_row, self.bootstrap_row, self.log_file_row):
                row.remove_css_class("error")
            self.net_status.set_visible(False)
        finally:
            self._loading = False

    def _on_list_changed(self, row, attr, check):
        if self._loading:
            return
        try:
            items = [check(s) for s in row.get_text().split(",") if s.strip()]
            if not items:
                raise ValueError("Enter at least one address")
        except ValueError as e:
            row.add_css_class("error")
            self.net_status.set_text(str(e))
            self.net_status.set_visible(True)
            return
        row.remove_css_class("error")
        self.net_status.set_visible(False)
        setattr(self.cfg, attr, items)
        self.win.config_changed()

    def _on_bool_toggled(self, row, _pspec, attr):
        if self._loading:
            return
        setattr(self.cfg, attr, row.get_active())
        if attr == "query_log_enabled":
            self.log_file_row.set_sensitive(row.get_active())
            self.win.query_log_view.update_state()
        self.win.config_changed()

    def _on_log_file_changed(self, row):
        if self._loading:
            return
        value = row.get_text().strip()
        if not value.startswith("/"):
            row.add_css_class("error")
            return
        row.remove_css_class("error")
        self.cfg.query_log_file = value or DEFAULT_QUERY_LOG
        self.win.config_changed()
