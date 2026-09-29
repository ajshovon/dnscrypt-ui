"""
Settings and Fedora Integration View for DNSCrypt UI.
Configures listening addresses, protocols, query log paths, and Fedora system integration.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from ..backend.config_manager import ConfigManager
from ..backend.service_manager import ServiceManager


class SettingsView(Adw.PreferencesPage):
    def __init__(self, config_mgr: ConfigManager, service_mgr: ServiceManager, on_change_cb):
        super().__init__()
        self.config_mgr = config_mgr
        self.service_mgr = service_mgr
        self.on_change_cb = on_change_cb

        self.set_title("Settings")
        self.set_icon_name("preferences-system-symbolic")

        self._build_ui()

    def _build_ui(self):
        # 1. Fedora System Integration Group
        fedora_group = Adw.PreferencesGroup()
        fedora_group.set_title("Fedora Integration and Package Status")
        fedora_group.set_description("Requirements to route all system DNS through dnscrypt-proxy")
        self.add(fedora_group)

        pkg_row = Adw.ActionRow()
        pkg_row.set_title("dnscrypt-proxy Package")
        if self.service_mgr.check_installed():
            pkg_row.set_subtitle("Installed on system")
            pkg_icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
        else:
            pkg_row.set_subtitle("Not installed. Run: sudo dnf install dnscrypt-proxy")
            pkg_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        pkg_row.add_prefix(pkg_icon)
        fedora_group.add(pkg_row)

        resolved_row = Adw.ActionRow()
        resolved_row.set_title("systemd-resolved Redirection")
        resolved_row.set_subtitle("Disable stub listener or route systemd-resolved to 127.0.0.1")
        res_btn = Gtk.Button(label="View Guide")
        res_btn.set_valign(Gtk.Align.CENTER)
        res_btn.connect("clicked", self._show_setup_guide)
        resolved_row.add_suffix(res_btn)
        fedora_group.add(resolved_row)

        # 2. Network & Listening Addresses
        net_group = Adw.PreferencesGroup()
        net_group.set_title("Network Listening")
        self.add(net_group)

        self.listen_row = Adw.EntryRow()
        self.listen_row.set_title("Listen Addresses")
        self.listen_row.set_text(", ".join(self.config_mgr.listen_addresses))
        self.listen_row.connect("changed", self._on_listen_changed)
        net_group.add(self.listen_row)

        self.fallback_row = Adw.EntryRow()
        self.fallback_row.set_title("Fallback Resolvers")
        self.fallback_row.set_text(", ".join(self.config_mgr.fallback_resolvers))
        self.fallback_row.connect("changed", self._on_fallback_changed)
        net_group.add(self.fallback_row)

        # 3. Protocols
        proto_group = Adw.PreferencesGroup()
        proto_group.set_title("Supported Protocols")
        self.add(proto_group)

        self.doh_switch = Adw.SwitchRow()
        self.doh_switch.set_title("DNS-over-HTTPS (DoH)")
        self.doh_switch.set_subtitle("Use HTTPS port 443 for encrypted upstream communication")
        self.doh_switch.set_active(self.config_mgr.doh_servers)
        self.doh_switch.connect("notify::active", self._on_doh_toggled)
        proto_group.add(self.doh_switch)

        self.dnscrypt_switch = Adw.SwitchRow()
        self.dnscrypt_switch.set_title("DNSCrypt Protocol")
        self.dnscrypt_switch.set_subtitle("Use traditional high-speed authenticated DNSCrypt protocol")
        self.dnscrypt_switch.set_active(self.config_mgr.dnscrypt_servers)
        self.dnscrypt_switch.connect("notify::active", self._on_dnscrypt_toggled)
        proto_group.add(self.dnscrypt_switch)

        # 4. Query Logging
        log_group = Adw.PreferencesGroup()
        log_group.set_title("Query Logging")
        self.add(log_group)

        self.log_file_row = Adw.EntryRow()
        self.log_file_row.set_title("Query Log Path")
        self.log_file_row.set_text(self.config_mgr.query_log_file)
        self.log_file_row.connect("changed", self._on_log_file_changed)
        log_group.add(self.log_file_row)

        # 5. Paths & File Locations
        paths_group = Adw.PreferencesGroup()
        paths_group.set_title("Configuration Paths")
        self.add(paths_group)

        toml_row = Adw.ActionRow()
        toml_row.set_title("Main Config (TOML)")
        toml_row.set_subtitle(str(self.config_mgr.toml_path))
        paths_group.add(toml_row)

        rules_row = Adw.ActionRow()
        rules_row.set_title("Forwarding Rules")
        rules_row.set_subtitle(str(self.config_mgr.rules_path))
        paths_group.add(rules_row)

    def _on_listen_changed(self, entry):
        val = entry.get_text().strip()
        if val:
            self.config_mgr.listen_addresses = [s.strip() for s in val.split(",") if s.strip()]
            self.config_mgr.set_dirty(True)
            self.on_change_cb()

    def _on_fallback_changed(self, entry):
        val = entry.get_text().strip()
        if val:
            self.config_mgr.fallback_resolvers = [s.strip() for s in val.split(",") if s.strip()]
            self.config_mgr.set_dirty(True)
            self.on_change_cb()

    def _on_doh_toggled(self, row, _):
        self.config_mgr.doh_servers = row.get_active()
        self.config_mgr.set_dirty(True)
        self.on_change_cb()

    def _on_dnscrypt_toggled(self, row, _):
        self.config_mgr.dnscrypt_servers = row.get_active()
        self.config_mgr.set_dirty(True)
        self.on_change_cb()

    def _on_log_file_changed(self, entry):
        val = entry.get_text().strip()
        if val:
            self.config_mgr.query_log_file = val
            self.config_mgr.set_dirty(True)
            self.on_change_cb()

    def _show_setup_guide(self, _):
        dialog = Adw.MessageDialog(
            transient_for=self.get_root(),
            heading="Fedora DNS Setup Guide",
            body=(
                "To make Fedora route all DNS requests through dnscrypt-proxy:\n\n"
                "1. Install the package:\n"
                "   sudo dnf install dnscrypt-proxy\n\n"
                "2. Disable systemd-resolved's stub listener on port 53:\n"
                "   sudo mkdir -p /etc/systemd/resolved.conf.d\n"
                "   sudo tee /etc/systemd/resolved.conf.d/dnscrypt.conf << 'EOF'\n"
                "   [Resolve]\n"
                "   DNS=127.0.0.1\n"
                "   DNSStubListener=no\n"
                "   EOF\n\n"
                "3. Restart resolved and enable dnscrypt-proxy:\n"
                "   sudo systemctl restart systemd-resolved\n"
                "   sudo systemctl enable --now dnscrypt-proxy\n"
            ),
        )
        dialog.add_response("ok", "Close")
        dialog.present()
