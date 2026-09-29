"""
Main Application and Window for DNSCrypt UI.
Provides a Libadwaita desktop interface for managing dnscrypt-proxy,
split-DNS forwarding rules, encrypted upstream resolvers, system DNS routing,
and live query logging.
"""

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from . import __version__
from .backend import resolver_db
from .backend.config_manager import ConfigManager
from .backend.query_monitor import QueryMonitor
from .backend.service_manager import RoutingStatus, ServiceManager, ServiceStatus
from .util import run_in_thread
from .views.query_log_view import QueryLogView
from .views.resolvers_view import ResolversView
from .views.rules_view import RulesView
from .views.settings_view import SettingsView
from .views.status_view import StatusView

APP_CSS = """
.dns-badge {
    font-size: 0.73rem;
    font-weight: 600;
    padding: 3px 9px;
    border-radius: 9999px;
    background-color: alpha(currentColor, 0.08);
    border: 1px solid alpha(currentColor, 0.15);
}
.dns-badge-doh { background-color: alpha(@accent_bg_color, 0.15); color: @accent_color; border-color: alpha(@accent_bg_color, 0.35); }
.dns-badge-dnscrypt { background-color: alpha(#9141ac, 0.15); color: #c061cb; border-color: alpha(#9141ac, 0.35); }
.dns-badge-security,
.dns-badge-allowed { background-color: alpha(@success_bg_color, 0.15); color: @success_color; border-color: alpha(@success_bg_color, 0.35); }
.dns-badge-privacy,
.dns-badge-warning { background-color: alpha(@warning_bg_color, 0.15); color: @warning_color; border-color: alpha(@warning_bg_color, 0.35); }
.dns-badge-blocked { background-color: alpha(@error_bg_color, 0.15); color: @error_color; border-color: alpha(@error_bg_color, 0.35); }
.dns-badge-neutral { background-color: alpha(currentColor, 0.08); border-color: alpha(currentColor, 0.15); }
.dns-stat-pill {
    font-size: 0.85rem;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 9999px;
    background-color: alpha(currentColor, 0.08);
}
"""


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application):
        super().__init__(application=app, title="DNSCrypt UI")
        self.set_default_size(980, 720)

        self.config_mgr = ConfigManager()
        self.service_mgr = ServiceManager()
        self.query_monitor = QueryMonitor(str(self.config_mgr.query_log_path))
        self.query_monitor.start()

        self.catalog = resolver_db.load_cached()
        self.catalog_state = "cached" if self.catalog else "loading"
        self.service_status = ServiceStatus(installed=True, active=False, status_str="unknown")
        self.routing = RoutingStatus(protected=False, checked=False)
        self._heartbeat_busy = False

        self._updating_switch = False
        self.connect("close-request", self._on_close_request)

        self._build_ui()
        self.refresh_catalog()
        self.refresh_status()
        self._heartbeat_id = GLib.timeout_add_seconds(5, self._on_heartbeat)

    def _on_close_request(self, _):
        if self._heartbeat_id:
            GLib.source_remove(self._heartbeat_id)
            self._heartbeat_id = 0
        self.query_monitor.stop()
        return False

    def _build_ui(self):
        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        toolbar_view = Adw.ToolbarView()
        self.toast_overlay.set_child(toolbar_view)

        header_bar = Adw.HeaderBar()
        toolbar_view.add_top_bar(header_bar)

        self.view_stack = Adw.ViewStack()
        switcher = Adw.ViewSwitcher(stack=self.view_stack, policy=Adw.ViewSwitcherPolicy.WIDE)
        header_bar.set_title_widget(switcher)

        self.btn_apply = Gtk.Button(label="Apply")
        self.btn_apply.add_css_class("suggested-action")
        self.btn_apply.set_tooltip_text("Write pending changes and restart dnscrypt-proxy")
        self.btn_apply.connect("clicked", self._on_apply_clicked)
        self.btn_apply.set_visible(False)
        header_bar.pack_end(self.btn_apply)

        menu = Gio.Menu()
        menu.append("Refresh Status", "app.refresh")
        menu.append("Discard Changes", "app.discard")
        menu.append("About DNSCrypt UI", "app.about")
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        header_bar.pack_end(menu_btn)

        self.quick_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.quick_switch.set_tooltip_text("Start or stop dnscrypt-proxy")
        self.quick_switch.connect("state-set", self._on_quick_switch_state_set)
        header_bar.pack_start(self.quick_switch)

        self.status_view = StatusView(self)
        self.rules_view = RulesView(self)
        self.resolvers_view = ResolversView(self)
        self.query_log_view = QueryLogView(self)
        self.settings_view = SettingsView(self)

        for view, name, title, icon in (
            (self.status_view, "status", "Dashboard", "network-wired-symbolic"),
            (self.rules_view, "rules", "Domain Rules", "view-list-bullet-symbolic"),
            (self.resolvers_view, "resolvers", "Resolvers", "network-server-symbolic"),
            (self.query_log_view, "query_log", "Query Log", "document-open-recent-symbolic"),
            (self.settings_view, "settings", "Settings", "preferences-system-symbolic"),
        ):
            page = self.view_stack.add_titled(view, name, title)
            page.set_icon_name(icon)

        toolbar_view.set_content(self.view_stack)

        switcher_bar = Adw.ViewSwitcherBar(stack=self.view_stack)
        toolbar_view.add_bottom_bar(switcher_bar)

        breakpoint = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 700sp"))
        breakpoint.add_setter(switcher_bar, "reveal", True)
        breakpoint.add_setter(switcher, "visible", False)
        self.add_breakpoint(breakpoint)

        if self.config_mgr.load_error:
            self.show_toast(self.config_mgr.load_error)

    # Shared state updates

    def config_changed(self):
        """Called by views after they modify config_mgr."""
        self.btn_apply.set_visible(self.config_mgr.is_dirty)
        self.status_view.update_summary()
        self.resolvers_view.refresh_eligibility()

    def reload_views(self):
        for view in (self.status_view, self.rules_view, self.resolvers_view, self.settings_view, self.query_log_view):
            view.reload()
        self.query_monitor.set_log_path(str(self.config_mgr.query_log_path))
        self.btn_apply.set_visible(self.config_mgr.is_dirty)

    def refresh_catalog(self):
        self.catalog_state = "loading" if not self.catalog else "refreshing"
        self.resolvers_view.update_catalog_state()

        def work():
            try:
                return resolver_db.fetch_catalog(self.config_mgr.toml_path), ""
            except RuntimeError as e:
                return None, str(e)

        def done(result):
            catalog, error = result
            if catalog:
                self.catalog = catalog
                self.catalog_state = "fresh"
            else:
                self.catalog_state = f"error: {error}"
            self.resolvers_view.reload()
            self.status_view.update_summary()

        run_in_thread(work, done)

    def refresh_status(self):
        if self._heartbeat_busy:
            return
        self._heartbeat_busy = True

        def work():
            status = self.service_mgr.get_status()
            routing = self.service_mgr.check_routing(self.config_mgr.listen_addresses)
            return status, routing

        def done(result):
            self._heartbeat_busy = False
            self.service_status, self.routing = result
            self._sync_quick_switch()
            self.status_view.update_status()
            self.query_log_view.update_state()

        run_in_thread(work, done)

    def _on_heartbeat(self) -> bool:
        self.refresh_status()
        return GLib.SOURCE_CONTINUE

    # Apply

    def _on_apply_clicked(self, _):
        effective = resolver_db.effective_servers(self.catalog, self.config_mgr)
        if effective is not None and not effective:
            self.show_message(
                "No usable resolvers",
                "None of the selected resolvers can be used with the current requirements "
                "(DNSSEC, no-log, no-filter, protocols). dnscrypt-proxy would fail to resolve anything.\n\n"
                "Select another resolver or relax the requirements on the Dashboard.",
            )
            return

        self.btn_apply.set_sensitive(False)
        self.btn_apply.set_label("Applying…")
        staged = self.config_mgr.get_staged_files()
        run_in_thread(lambda: self.service_mgr.apply(staged), self._finish_apply)

    def _finish_apply(self, result: dict):
        self.btn_apply.set_sensitive(True)
        self.btn_apply.set_label("Apply")
        if result.get("ok"):
            self.config_mgr.load()
            self.reload_views()
            msg = "Configuration applied and dnscrypt-proxy restarted"
            if not result.get("answering", True):
                msg = "Applied, but dnscrypt-proxy is not answering queries yet"
            self.show_toast(msg)
            self.refresh_status()
        else:
            body = result.get("message", "Unknown error")
            if result.get("output"):
                body += "\n\n" + result["output"]
            self.show_message("Could not apply configuration", body)
            self.refresh_status()

    # Service toggle

    def _on_quick_switch_state_set(self, switch, state):
        if self._updating_switch:
            return False
        if state == self.service_status.active:
            return False
        switch.set_sensitive(False)
        action = self.service_mgr.start if state else self.service_mgr.stop
        run_in_thread(action, lambda r: self._finish_toggle(r, state))
        return True  # keep the old state until the service confirms

    def _finish_toggle(self, result, requested: bool):
        ok, err = result
        self.quick_switch.set_sensitive(True)
        if ok:
            self.show_toast("dnscrypt-proxy started" if requested else "dnscrypt-proxy stopped")
        elif err:
            self.show_toast(err)
        self.refresh_status()
        self._sync_quick_switch()

    def _sync_quick_switch(self):
        self._updating_switch = True
        try:
            self.quick_switch.set_state(self.service_status.active)
            self.quick_switch.set_active(self.service_status.active)
        finally:
            self._updating_switch = False
        self.quick_switch.set_sensitive(self.service_status.installed)

    # Helpers

    def show_toast(self, text: str):
        toast = Adw.Toast.new(text)
        toast.set_timeout(4)
        self.toast_overlay.add_toast(toast)

    def show_message(self, heading: str, body: str):
        dialog = Adw.AlertDialog(heading=heading, body=body)
        dialog.set_body_use_markup(False)
        dialog.add_response("ok", "Close")
        dialog.present(self)

    def discard_changes(self):
        self.config_mgr.load()
        self.reload_views()
        self.show_toast("Discarded unsaved changes")


class DNSCryptUIApp(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id="io.github.shovon.DNSCryptUI",
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.window = None
        self.connect("startup", self._on_startup)

    def _on_startup(self, _):
        css_provider = Gtk.CssProvider()
        css_provider.load_from_string(APP_CSS)
        display = Gdk.Display.get_default()
        if display:
            Gtk.StyleContext.add_provider_for_display(
                display, css_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    def do_activate(self):
        if not self.window:
            self.window = MainWindow(self)
            self._setup_actions()
        self.window.present()

    def _setup_actions(self):
        for name, callback in (
            ("refresh", lambda *_: (self.window.refresh_status(), self.window.refresh_catalog())),
            ("discard", lambda *_: self.window.discard_changes()),
            ("about", self._show_about),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

    def _show_about(self, *_):
        about = Adw.AboutDialog()
        about.set_application_name("DNSCrypt UI")
        about.set_application_icon("io.github.shovon.DNSCryptUI")
        about.set_developer_name("Shovon")
        about.set_version(__version__)
        about.set_comments(
            "A GNOME interface for dnscrypt-proxy with split-DNS domain rules, "
            "encrypted upstream resolvers, leak detection, and live query inspection."
        )
        about.set_website("https://github.com/DNSCrypt/dnscrypt-proxy")
        about.set_license_type(Gtk.License.GPL_3_0)
        about.present(self.window)


def main():
    app = DNSCryptUIApp()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
