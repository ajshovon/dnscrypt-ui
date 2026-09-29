"""
Status and Dashboard View for DNSCrypt UI.
Displays service status, latency tester, quick toggles, and systemd-resolved conflict detector.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from ..backend.service_manager import ServiceManager
from ..backend.config_manager import ConfigManager


class StatusView(Adw.PreferencesPage):
    def __init__(self, service_mgr: ServiceManager, config_mgr: ConfigManager, on_change_cb):
        super().__init__()
        self.service_mgr = service_mgr
        self.config_mgr = config_mgr
        self.on_change_cb = on_change_cb

        self.set_title("Dashboard")
        self.set_icon_name("network-wired-symbolic")

        self._build_ui()
        self.refresh_status()

    def _build_ui(self):
        # 1. Main Service Status Group
        self.status_group = Adw.PreferencesGroup()
        self.status_group.set_title("Service Status")
        self.status_group.set_description("Status of the local dnscrypt-proxy daemon")
        self.add(self.status_group)

        # Status Row
        self.status_row = Adw.ActionRow()
        self.status_row.set_title("Checking status...")
        self.status_row.set_subtitle("Reading systemd unit state")
        self.status_icon = Gtk.Image.new_from_icon_name("network-transmit-receive-symbolic")
        self.status_icon.set_pixel_size(28)
        self.status_row.add_prefix(self.status_icon)

        # Controls in Status Row
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        btn_box.set_valign(Gtk.Align.CENTER)

        self.btn_start = Gtk.Button(label="Start")
        self.btn_start.add_css_class("suggested-action")
        self.btn_start.connect("clicked", self._on_start_clicked)

        self.btn_stop = Gtk.Button(label="Stop")
        self.btn_stop.add_css_class("destructive-action")
        self.btn_stop.connect("clicked", self._on_stop_clicked)

        self.btn_restart = Gtk.Button(label="Restart")
        self.btn_restart.connect("clicked", self._on_restart_clicked)

        btn_box.append(self.btn_start)
        btn_box.append(self.btn_stop)
        btn_box.append(self.btn_restart)
        self.status_row.add_suffix(btn_box)

        self.status_group.add(self.status_row)

        # 2. Port 53 / Fedora Conflict Banner Row
        self.conflict_row = Adw.ActionRow()
        self.conflict_row.set_title("Port 53 Conflict Detected")
        self.conflict_row.set_subtitle("systemd-resolved is currently listening on port 53")
        warn_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        self.conflict_row.add_prefix(warn_icon)
        btn_fix = Gtk.Button(label="How to Fix")
        btn_fix.set_valign(Gtk.Align.CENTER)
        btn_fix.connect("clicked", self._show_conflict_dialog)
        self.conflict_row.add_suffix(btn_fix)
        self.status_group.add(self.conflict_row)
        self.conflict_row.set_visible(False)

        # 3. DNS Benchmark / Query Test Group
        self.test_group = Adw.PreferencesGroup()
        self.test_group.set_title("DNS Resolution Test")
        self.test_group.set_description("Verify query resolution and measure latency through 127.0.0.1:53")
        self.add(self.test_group)

        self.test_row = Adw.ActionRow()
        self.test_row.set_title("Query Test (cloudflare.com)")
        self.test_row.set_subtitle("Click 'Run Test' to benchmark resolution")
        test_icon = Gtk.Image.new_from_icon_name("speedometer-symbolic")
        self.test_row.add_prefix(test_icon)

        self.btn_test = Gtk.Button(label="Run Test")
        self.btn_test.set_valign(Gtk.Align.CENTER)
        self.btn_test.connect("clicked", self._on_test_clicked)
        self.test_row.add_suffix(self.btn_test)

        self.test_group.add(self.test_row)

        # 4. Summary & Quick Stats Group
        self.stats_group = Adw.PreferencesGroup()
        self.stats_group.set_title("Summary and Rules")
        self.add(self.stats_group)

        # Active Upstream Count Row
        self.resolvers_stat_row = Adw.ActionRow()
        self.resolvers_stat_row.set_title("Active Upstream Resolvers")
        self.resolvers_stat_row.set_subtitle("DoH and DNSCrypt servers configured")
        res_icon = Gtk.Image.new_from_icon_name("cloud-symbolic")
        self.resolvers_stat_row.add_prefix(res_icon)
        self.lbl_resolvers_count = Gtk.Label(label="0")
        self.lbl_resolvers_count.add_css_class("heading")
        self.lbl_resolvers_count.add_css_class("dns-stat-pill")
        self.lbl_resolvers_count.set_valign(Gtk.Align.CENTER)
        self.resolvers_stat_row.add_suffix(self.lbl_resolvers_count)
        self.stats_group.add(self.resolvers_stat_row)

        # Split DNS Rules Count Row
        self.rules_stat_row = Adw.ActionRow()
        self.rules_stat_row.set_title("Split-DNS Domain Rules")
        self.rules_stat_row.set_subtitle("Custom per-domain forwarding rules active")
        rule_icon = Gtk.Image.new_from_icon_name("view-list-bullet-symbolic")
        self.rules_stat_row.add_prefix(rule_icon)
        self.lbl_rules_count = Gtk.Label(label="0")
        self.lbl_rules_count.add_css_class("heading")
        self.lbl_rules_count.add_css_class("dns-stat-pill")
        self.lbl_rules_count.set_valign(Gtk.Align.CENTER)
        self.rules_stat_row.add_suffix(self.lbl_rules_count)
        self.stats_group.add(self.rules_stat_row)

        # DNSSEC & Privacy Switches
        self.dnssec_row = Adw.SwitchRow()
        self.dnssec_row.set_title("Require DNSSEC")
        self.dnssec_row.set_subtitle("Reject resolvers that do not authenticate DNSSEC signatures")
        self.dnssec_row.set_active(self.config_mgr.require_dnssec)
        self.dnssec_row.connect("notify::active", self._on_dnssec_toggled)
        self.stats_group.add(self.dnssec_row)

        self.nolog_row = Adw.SwitchRow()
        self.nolog_row.set_title("Require No-Log Resolvers")
        self.nolog_row.set_subtitle("Only query resolvers that do not log DNS transactions")
        self.nolog_row.set_active(self.config_mgr.require_nolog)
        self.nolog_row.connect("notify::active", self._on_nolog_toggled)
        self.stats_group.add(self.nolog_row)

    def refresh_status(self):
        status = self.service_mgr.get_status()
        if not status.installed:
            self.status_row.set_title("dnscrypt-proxy is Not Installed")
            self.status_row.set_subtitle("Install package via: sudo dnf install dnscrypt-proxy")
            self.status_icon.set_from_icon_name("dialog-warning-symbolic")
            self.btn_start.set_sensitive(False)
            self.btn_stop.set_sensitive(False)
            self.btn_restart.set_sensitive(False)
        elif status.active:
            self.status_row.set_title("DNSCrypt-Proxy is Running")
            sub = f"Active (PID: {status.pid})" if status.pid else "Active"
            self.status_row.set_subtitle(sub)
            self.status_icon.set_from_icon_name("emblem-ok-symbolic")
            self.btn_start.set_sensitive(False)
            self.btn_stop.set_sensitive(True)
            self.btn_restart.set_sensitive(True)
        else:
            self.status_row.set_title("DNSCrypt-Proxy is Inactive")
            self.status_row.set_subtitle("The background service is stopped")
            self.status_icon.set_from_icon_name("media-playback-stop-symbolic")
            self.btn_start.set_sensitive(True)
            self.btn_stop.set_sensitive(False)
            self.btn_restart.set_sensitive(True)

        # Check port conflict
        has_conflict, desc = self.service_mgr.check_port_53_conflict()
        self.conflict_row.set_visible(has_conflict and not status.active)
        if has_conflict:
            self.conflict_row.set_subtitle(desc)

        # Update stats
        self.lbl_resolvers_count.set_text(str(len(self.config_mgr.server_names)))
        active_rules = sum(1 for r in self.config_mgr.rules if r.enabled)
        total_rules = len(self.config_mgr.rules)
        self.lbl_rules_count.set_text(f"{active_rules} active ({total_rules} total)")

    def _on_start_clicked(self, _):
        self.btn_start.set_sensitive(False)
        self.btn_restart.set_sensitive(False)

        def do_start():
            ok, err = self.service_mgr.start()
            GLib.idle_add(self._finish_service_action, ok, err, "start")

        import threading
        threading.Thread(target=do_start, daemon=True).start()

    def _on_stop_clicked(self, _):
        self.btn_stop.set_sensitive(False)
        self.btn_restart.set_sensitive(False)

        def do_stop():
            ok, err = self.service_mgr.stop()
            GLib.idle_add(self._finish_service_action, ok, err, "stop")

        import threading
        threading.Thread(target=do_stop, daemon=True).start()

    def _on_restart_clicked(self, _):
        self.btn_restart.set_sensitive(False)

        def do_restart():
            ok, err = self.service_mgr.restart()
            GLib.idle_add(self._finish_service_action, ok, err, "restart")

        import threading
        threading.Thread(target=do_restart, daemon=True).start()

    def _finish_service_action(self, ok: bool, err: str, action: str):
        self.refresh_status()
        if not ok and err:
            self._show_error_toast(f"Failed to {action} service", err)

    def _on_test_clicked(self, _):
        self.btn_test.set_sensitive(False)
        self.test_row.set_subtitle("Querying 127.0.0.1:53...")

        def run_test():
            ok, latency, res = self.service_mgr.test_dns_latency(server="127.0.0.1", port=53)
            GLib.idle_add(self._update_test_result, ok, latency, res)

        import threading
        threading.Thread(target=run_test, daemon=True).start()

    def _update_test_result(self, ok: bool, latency: float, res: str):
        self.btn_test.set_sensitive(True)
        if ok:
            self.test_row.set_title("Resolution Succeeded")
            self.test_row.set_subtitle(f"Resolved to {res} in {latency:.1f} ms")
        else:
            self.test_row.set_title("Resolution Failed")
            self.test_row.set_subtitle(f"Error: {res}")

    def _on_dnssec_toggled(self, row, _):
        self.config_mgr.require_dnssec = row.get_active()
        self.config_mgr.set_dirty(True)
        self.on_change_cb()

    def _on_nolog_toggled(self, row, _):
        self.config_mgr.require_nolog = row.get_active()
        self.config_mgr.set_dirty(True)
        self.on_change_cb()

    def _show_conflict_dialog(self, _):
        dialog = Adw.MessageDialog(
            transient_for=self.get_root(),
            heading="Fix Port 53 Conflict on Fedora",
            body=(
                "Fedora runs systemd-resolved on port 53 by default, preventing dnscrypt-proxy from binding to 127.0.0.1:53.\n\n"
                "To resolve this, disable the systemd-resolved stub listener:\n\n"
                "1. Create drop-in configuration:\n"
                "   sudo mkdir -p /etc/systemd/resolved.conf.d\n"
                "   sudo tee /etc/systemd/resolved.conf.d/dnscrypt.conf << 'EOF'\n"
                "   [Resolve]\n"
                "   DNS=127.0.0.1\n"
                "   DNSStubListener=no\n"
                "   EOF\n\n"
                "2. Restart systemd-resolved:\n"
                "   sudo systemctl restart systemd-resolved\n"
            ),
        )
        dialog.add_response("ok", "Got It")
        dialog.present()

    def _show_error_toast(self, title: str, message: str):
        dialog = Adw.MessageDialog(
            transient_for=self.get_root(),
            heading=title,
            body=message[:300],
        )
        dialog.add_response("ok", "Dismiss")
        dialog.present()
