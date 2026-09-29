"""
Dashboard for DNSCrypt UI: service state, system DNS protection (leak check
and one-click fix), a resolution test, and privacy requirements.
"""

import os

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..backend import resolver_db
from ..backend.service_manager import probe_target
from ..util import run_in_thread

RESOLVED_DROPIN = "/etc/systemd/resolved.conf.d/zz-dnscrypt-ui.conf"


class StatusView(Adw.PreferencesPage):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.cfg = win.config_mgr
        self._loading = False
        self._build_ui()
        self.reload()

    def _build_ui(self):
        # Service
        group = Adw.PreferencesGroup(title="Service")
        self.add(group)

        self.status_row = Adw.ActionRow(title="Checking status…")
        self.status_icon = Gtk.Image.new_from_icon_name("content-loading-symbolic")
        self.status_icon.set_pixel_size(24)
        self.status_row.add_prefix(self.status_icon)
        self.btn_restart = Gtk.Button(label="Restart", valign=Gtk.Align.CENTER)
        self.btn_restart.connect("clicked", self._on_restart_clicked)
        self.status_row.add_suffix(self.btn_restart)
        group.add(self.status_row)

        # System DNS protection
        group = Adw.PreferencesGroup(
            title="System DNS",
            description="Whether applications on this computer actually resolve names through dnscrypt-proxy",
        )
        self.add(group)

        self.routing_row = Adw.ExpanderRow(title="Checking…")
        self.routing_icon = Gtk.Image.new_from_icon_name("content-loading-symbolic")
        self.routing_icon.set_pixel_size(24)
        self.routing_row.add_prefix(self.routing_icon)
        self.btn_fix = Gtk.Button(label="Fix", valign=Gtk.Align.CENTER)
        self.btn_fix.add_css_class("suggested-action")
        self.btn_fix.connect("clicked", self._on_fix_clicked)
        self.routing_row.add_suffix(self.btn_fix)
        self._problem_rows = []
        group.add(self.routing_row)

        self.undo_row = Adw.ActionRow(
            title="Undo DNS routing",
            subtitle="Remove the systemd-resolved and NetworkManager settings made by DNSCrypt UI",
        )
        btn_undo = Gtk.Button(label="Undo", valign=Gtk.Align.CENTER)
        btn_undo.connect("clicked", self._on_undo_clicked)
        self.undo_row.add_suffix(btn_undo)
        group.add(self.undo_row)

        # Test
        group = Adw.PreferencesGroup(title="Resolution Test")
        self.add(group)
        self.test_row = Adw.ActionRow(title="Lookup", subtitle="Resolve cloudflare.com through dnscrypt-proxy")
        self.upstream_row = Adw.ActionRow(
            title="Upstream round trip",
            subtitle="Uncached query, measures the encrypted path to your resolvers",
        )
        self.btn_test = Gtk.Button(label="Run Test", valign=Gtk.Align.CENTER)
        self.btn_test.connect("clicked", self._on_test_clicked)
        self.test_row.add_suffix(self.btn_test)
        group.add(self.test_row)
        group.add(self.upstream_row)

        # Summary
        group = Adw.PreferencesGroup(title="Summary")
        self.add(group)
        self.resolvers_row = Adw.ActionRow(title="Upstream resolvers")
        self.lbl_resolvers = Gtk.Label(valign=Gtk.Align.CENTER, css_classes=["dns-stat-pill"])
        self.resolvers_row.add_suffix(self.lbl_resolvers)
        group.add(self.resolvers_row)
        self.rules_row = Adw.ActionRow(title="Domain rules", subtitle="Per-domain forwarding (plain DNS)")
        self.lbl_rules = Gtk.Label(valign=Gtk.Align.CENTER, css_classes=["dns-stat-pill"])
        self.rules_row.add_suffix(self.lbl_rules)
        group.add(self.rules_row)

        # Requirements
        group = Adw.PreferencesGroup(
            title="Resolver Requirements",
            description="Selected resolvers that do not meet these are skipped by dnscrypt-proxy",
        )
        self.add(group)
        self.dnssec_row = Adw.SwitchRow(title="Require DNSSEC", subtitle="Only use resolvers that validate DNSSEC")
        self.nolog_row = Adw.SwitchRow(title="Require no-log", subtitle="Only use resolvers that promise not to log queries")
        self.nofilter_row = Adw.SwitchRow(
            title="Require no-filter",
            subtitle="Only use resolvers that do not block anything. Turn off to use malware or ad blocking resolvers",
        )
        for row, attr in ((self.dnssec_row, "require_dnssec"), (self.nolog_row, "require_nolog"), (self.nofilter_row, "require_nofilter")):
            row.connect("notify::active", self._on_requirement_toggled, attr)
            group.add(row)

    # Updates from the window

    def reload(self):
        self._loading = True
        try:
            self.dnssec_row.set_active(self.cfg.require_dnssec)
            self.nolog_row.set_active(self.cfg.require_nolog)
            self.nofilter_row.set_active(self.cfg.require_nofilter)
        finally:
            self._loading = False
        self.update_summary()

    def update_status(self):
        st = self.win.service_status
        if not st.installed:
            self.status_row.set_title("dnscrypt-proxy is not installed")
            self.status_row.set_subtitle("Install it with: sudo dnf install dnscrypt-proxy")
            self.status_icon.set_from_icon_name("dialog-warning-symbolic")
        elif st.active:
            self.status_row.set_title("dnscrypt-proxy is running")
            self.status_row.set_subtitle(f"PID {st.pid}" if st.pid else "Active")
            self.status_icon.set_from_icon_name("object-select-symbolic")
        elif st.transitioning:
            self.status_row.set_title(f"dnscrypt-proxy is {st.status_str}")
            self.status_row.set_subtitle(st.substate)
            self.status_icon.set_from_icon_name("content-loading-symbolic")
        else:
            self.status_row.set_title("dnscrypt-proxy is stopped" if st.status_str != "failed" else "dnscrypt-proxy failed")
            self.status_row.set_subtitle("Use the switch in the header bar to start it")
            self.status_icon.set_from_icon_name("dialog-error-symbolic" if st.status_str == "failed" else "media-playback-stop-symbolic")
        self.btn_restart.set_sensitive(st.installed)

        routing = self.win.routing
        for row in self._problem_rows:
            self.routing_row.remove(row)
        self._problem_rows = []
        if not routing.checked:
            return
        if routing.protected and st.active:
            self.routing_row.set_title("Protected")
            self.routing_row.set_subtitle("All DNS queries go through dnscrypt-proxy")
            self.routing_icon.set_from_icon_name("security-high-symbolic")
            self.routing_row.set_enable_expansion(False)
        elif routing.protected:
            self.routing_row.set_title("Not resolving")
            self.routing_row.set_subtitle("System DNS points at dnscrypt-proxy, but the service is not running")
            self.routing_icon.set_from_icon_name("dialog-warning-symbolic")
            self.routing_row.set_enable_expansion(False)
        else:
            self.routing_row.set_title("Not protected: DNS leaks")
            self.routing_row.set_subtitle(f"{len(routing.problems)} problem(s) found. Expand for details")
            self.routing_icon.set_from_icon_name("security-low-symbolic")
            self.routing_row.set_enable_expansion(True)
            for problem in routing.problems:
                row = Adw.ActionRow(title=problem, title_lines=3)
                row.set_title_selectable(True)
                self.routing_row.add_row(row)
                self._problem_rows.append(row)
        self.btn_fix.set_visible(not routing.protected)

        self.undo_row.set_visible(os.path.exists(RESOLVED_DROPIN))

    def update_summary(self):
        selected = self.cfg.server_names
        effective = resolver_db.effective_servers(self.win.catalog, self.cfg)
        self.resolvers_row.remove_css_class("warning")
        if not selected:
            self.lbl_resolvers.set_text("Automatic")
            self.resolvers_row.set_subtitle("None selected: dnscrypt-proxy picks any server that meets the requirements")
        elif effective is None:
            self.lbl_resolvers.set_text(f"{len(selected)} selected")
            self.resolvers_row.set_subtitle("Resolver list is loading…")
        else:
            self.lbl_resolvers.set_text(f"{len(effective)} of {len(selected)} usable")
            if len(effective) < len(selected):
                skipped = [n for n in selected if n not in effective]
                self.resolvers_row.set_subtitle("Skipped: " + ", ".join(skipped) + ". See the Resolvers page")
                self.resolvers_row.add_css_class("warning")
            else:
                self.resolvers_row.set_subtitle(", ".join(selected))

        active = sum(1 for r in self.cfg.rules if r.enabled)
        self.lbl_rules.set_text(f"{active} active")
        self.rules_row.set_subtitle(f"{len(self.cfg.rules)} total. Queries they match are sent as plain DNS")

    # Actions

    def _on_requirement_toggled(self, row, _pspec, attr):
        if self._loading:
            return
        setattr(self.cfg, attr, row.get_active())
        self.win.config_changed()

    def _on_restart_clicked(self, btn):
        btn.set_sensitive(False)

        def done(result):
            ok, err = result
            btn.set_sensitive(True)
            self.win.show_toast("dnscrypt-proxy restarted" if ok else err)
            self.win.refresh_status()

        run_in_thread(self.win.service_mgr.restart, done)

    def _on_test_clicked(self, btn):
        btn.set_sensitive(False)
        self.test_row.set_subtitle("Querying…")
        self.upstream_row.set_subtitle("Querying…")

        def done(result):
            lookup, upstream = result
            btn.set_sensitive(True)
            host, port = probe_target(self.cfg.listen_addresses)
            if lookup.ok and lookup.rcode == 0 and lookup.addresses:
                self.test_row.set_subtitle(f"cloudflare.com → {lookup.addresses[0]} in {lookup.latency_ms:.1f} ms via {host}:{port}")
            elif lookup.ok:
                self.test_row.set_subtitle(f"Answered with error code {lookup.rcode} in {lookup.latency_ms:.1f} ms")
            else:
                self.test_row.set_subtitle(f"Failed: {lookup.error}")
            if upstream.ok and upstream.rcode in (0, 3):
                self.upstream_row.set_subtitle(f"{upstream.latency_ms:.1f} ms")
            elif upstream.ok:
                self.upstream_row.set_subtitle(f"Upstream answered with error code {upstream.rcode}")
            else:
                self.upstream_row.set_subtitle(f"Failed: {upstream.error}")

        run_in_thread(lambda: self.win.service_mgr.test_resolution(self.cfg.listen_addresses), done)

    def _on_fix_clicked(self, _):
        host, port = probe_target(self.cfg.listen_addresses)
        dialog = Adw.AlertDialog(
            heading="Route all DNS through dnscrypt-proxy?",
            body=(
                f"This will:\n"
                f"• point systemd-resolved at dnscrypt-proxy ({host}:{port}) for every domain and turn off its fallback servers\n"
                f"• stop NetworkManager from handing DHCP/VPN DNS servers to systemd-resolved\n"
                f"• make /etc/resolv.conf use the systemd-resolved stub (127.0.0.53)\n\n"
                f"VPN-provided DNS servers will no longer be used; add Domain Rules for internal VPN domains instead. "
                f"If dnscrypt-proxy stops, name resolution stops too. Use Undo on this page to revert."
            ),
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("fix", "Route DNS")
        dialog.set_response_appearance("fix", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_d, response):
            if response != "fix":
                return
            self.btn_fix.set_sensitive(False)
            addr = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

            def done(result):
                self.btn_fix.set_sensitive(True)
                if result.get("ok"):
                    self.win.show_toast(result.get("message", "Done"))
                else:
                    self.win.show_message("Could not change system DNS", result.get("message", "Unknown error"))
                self.win.refresh_status()

                run_in_thread(lambda: self.win.service_mgr.setup_system_dns(addr), done)

        dialog.connect("response", on_response)
        dialog.present(self.win)

    def _on_undo_clicked(self, btn):
        btn.set_sensitive(False)

        def done(result):
            btn.set_sensitive(True)
            if result.get("ok"):
                self.win.show_toast(result.get("message", "Done"))
            else:
                self.win.show_message("Could not undo DNS routing", result.get("message", "Unknown error"))
            self.win.refresh_status()

        run_in_thread(self.win.service_mgr.undo_system_dns, done)
