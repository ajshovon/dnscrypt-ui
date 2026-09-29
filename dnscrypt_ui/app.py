"""
Main Application and Window for DNSCrypt UI.
Provides a modern Libadwaita desktop interface for managing dnscrypt-proxy,
split-DNS domain routing rules (YogaDNS style), DoH/DNSCrypt upstream resolvers,
and real-time query logging.
"""

import sys
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib, GObject, Gdk

from .backend.config_manager import ConfigManager
from .backend.service_manager import ServiceManager
from .backend.query_monitor import QueryMonitor
from .views.status_view import StatusView
from .views.rules_view import RulesView
from .views.resolvers_view import ResolversView
from .views.query_log_view import QueryLogView
from .views.settings_view import SettingsView

APP_CSS = """
.dns-badge {
    font-size: 0.73rem;
    font-weight: 600;
    padding: 3px 9px;
    border-radius: 9999px;
    background-color: alpha(currentColor, 0.08);
    border: 1px solid alpha(currentColor, 0.15);
}
.dns-badge-doh {
    background-color: alpha(#3584e4, 0.15);
    color: #3584e4;
    border-color: alpha(#3584e4, 0.35);
}
.dns-badge-dnscrypt {
    background-color: alpha(#9141ac, 0.15);
    color: #c061cb;
    border-color: alpha(#9141ac, 0.35);
}
.dns-badge-security {
    background-color: alpha(#2ec27e, 0.15);
    color: #2ec27e;
    border-color: alpha(#2ec27e, 0.35);
}
.dns-badge-privacy {
    background-color: alpha(#e5a50a, 0.15);
    color: #f6d32d;
    border-color: alpha(#e5a50a, 0.35);
}
.dns-badge-allowed {
    background-color: alpha(#2ec27e, 0.15);
    color: #2ec27e;
    border-color: alpha(#2ec27e, 0.35);
}
.dns-badge-blocked {
    background-color: alpha(#e01b24, 0.15);
    color: #e01b24;
    border-color: alpha(#e01b24, 0.35);
}
.dns-badge-neutral {
    background-color: alpha(currentColor, 0.08);
    border-color: alpha(currentColor, 0.15);
}
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
        self.set_default_size(950, 700)

        # Initialize Backend
        self.config_mgr = ConfigManager()
        self.service_mgr = ServiceManager()
        self.query_monitor = QueryMonitor(log_path=self.config_mgr.query_log_file)
        self.query_monitor.start()

        self._updating_switch = False
        self.connect("close-request", self._on_close_request)

        self._build_ui()

        # Periodic status refresh
        self._heartbeat_id = GLib.timeout_add_seconds(4, self._on_status_heartbeat)

    def _on_close_request(self, _):
        if hasattr(self, "_heartbeat_id") and self._heartbeat_id:
            GLib.source_remove(self._heartbeat_id)
            self._heartbeat_id = 0
        if hasattr(self, "query_monitor"):
            self.query_monitor.stop()
        return False

    def _build_ui(self):
        # Toast Overlay for app notifications
        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        # Main Toolbar View
        self.toolbar_view = Adw.ToolbarView()
        self.toast_overlay.set_child(self.toolbar_view)

        # 1. Header Bar
        header_bar = Adw.HeaderBar()
        self.toolbar_view.add_top_bar(header_bar)

        # View Switcher Title
        self.view_stack = Adw.ViewStack()
        self.view_title = Adw.ViewSwitcherTitle()
        self.view_title.set_stack(self.view_stack)
        self.view_title.set_title("DNSCrypt UI")
        header_bar.set_title_widget(self.view_title)

        # Apply & Restart Button (in HeaderBar end)
        self.btn_apply = Gtk.Button(label="Apply & Restart")
        self.btn_apply.set_icon_name("emblem-ok-symbolic")
        self.btn_apply.add_css_class("suggested-action")
        self.btn_apply.set_tooltip_text("Save pending changes and restart dnscrypt-proxy")
        self.btn_apply.connect("clicked", self._on_apply_clicked)
        self.btn_apply.set_visible(False)
        header_bar.pack_end(self.btn_apply)

        # Quick Toggle Switch
        self.quick_switch = Gtk.Switch()
        self.quick_switch.set_valign(Gtk.Align.CENTER)
        self.quick_switch.set_tooltip_text("Quick toggle dnscrypt-proxy service")
        self.quick_switch.connect("state-set", self._on_quick_switch_state_set)
        header_bar.pack_end(self.quick_switch)

        # Primary Menu Button
        menu = Gio.Menu()
        menu.append("Refresh Status", "app.refresh")
        menu.append("Discard Changes", "app.discard")
        menu.append("About DNSCrypt UI", "app.about")

        menu_btn = Gtk.MenuButton()
        menu_btn.set_icon_name("open-menu-symbolic")
        menu_btn.set_menu_model(menu)
        header_bar.pack_end(menu_btn)

        # 2. Add Views to ViewStack
        self.status_view = StatusView(self.service_mgr, self.config_mgr, self._on_config_changed)
        page1 = self.view_stack.add_titled(self.status_view, "status", "Dashboard")
        page1.set_icon_name("network-wired-symbolic")

        self.rules_view = RulesView(self.config_mgr, self._on_config_changed)
        page2 = self.view_stack.add_titled(self.rules_view, "rules", "Domain Rules")
        page2.set_icon_name("view-list-bullet-symbolic")

        self.resolvers_view = ResolversView(self.config_mgr, self._on_config_changed)
        page3 = self.view_stack.add_titled(self.resolvers_view, "resolvers", "Resolvers")
        page3.set_icon_name("cloud-symbolic")

        self.query_log_view = QueryLogView(self.config_mgr, self.query_monitor)
        page4 = self.view_stack.add_titled(self.query_log_view, "query_log", "Query Log")
        page4.set_icon_name("utilities-system-monitor-symbolic")

        self.settings_view = SettingsView(self.config_mgr, self.service_mgr, self._on_config_changed)
        page5 = self.view_stack.add_titled(self.settings_view, "settings", "Settings")
        page5.set_icon_name("preferences-system-symbolic")

        self.toolbar_view.set_content(self.view_stack)

        # 3. Bottom View Switcher Bar (for compact/mobile mode)
        self.switcher_bar = Adw.ViewSwitcherBar()
        self.switcher_bar.set_stack(self.view_stack)
        self.view_title.bind_property(
            "title-visible",
            self.switcher_bar,
            "reveal",
            GObject.BindingFlags.SYNC_CREATE,
        )
        self.toolbar_view.add_bottom_bar(self.switcher_bar)

        self._update_quick_switch()

    def _on_config_changed(self):
        is_dirty = self.config_mgr.is_dirty
        self.btn_apply.set_visible(is_dirty)

    def _on_apply_clicked(self, _):
        self.btn_apply.set_sensitive(False)
        staged = self.config_mgr.get_staged_files()

        def do_apply():
            ok, err = self.service_mgr.apply_and_restart(staged)
            GLib.idle_add(self._finish_apply, ok, err)

        import threading
        threading.Thread(target=do_apply, daemon=True).start()

    def _finish_apply(self, ok: bool, err: str):
        self.btn_apply.set_sensitive(True)
        if ok:
            self.config_mgr.load()  # reload cleanly
            self.btn_apply.set_visible(False)
            self.show_toast("Configuration saved and dnscrypt-proxy restarted!")
            self.status_view.refresh_status()
            self._update_quick_switch()
        else:
            self.show_toast(f"Apply failed: {err[:80]}")

    def _on_quick_switch_state_set(self, switch, state):
        if self._updating_switch:
            return False

        status = self.service_mgr.get_status()
        if not status.installed:
            self.show_toast("dnscrypt-proxy is not installed")
            return True

        if state == status.active:
            return False

        def do_toggle():
            if state:
                ok, err = self.service_mgr.start()
            else:
                ok, err = self.service_mgr.stop()
            GLib.idle_add(self._finish_toggle, ok, err, state)

        import threading
        threading.Thread(target=do_toggle, daemon=True).start()
        return True  # prevent immediate switch snap until confirmed

    def _finish_toggle(self, ok: bool, err: str, requested_state: bool):
        self.status_view.refresh_status()
        status = self.service_mgr.get_status()
        self._updating_switch = True
        try:
            self.quick_switch.set_active(status.active)
        finally:
            self._updating_switch = False
        if ok:
            action = "started" if requested_state else "stopped"
            self.show_toast(f"DNSCrypt-Proxy {action}")
        else:
            self.show_toast(f"Failed to change state: {err[:60]}")

    def _update_quick_switch(self):
        status = self.service_mgr.get_status()
        self._updating_switch = True
        try:
            self.quick_switch.set_active(status.active)
        finally:
            self._updating_switch = False
        self.quick_switch.set_sensitive(status.installed)

    def _on_status_heartbeat(self) -> bool:
        status = self.service_mgr.get_status()
        if self.quick_switch.get_active() != status.active:
            self._updating_switch = True
            try:
                self.quick_switch.set_active(status.active)
            finally:
                self._updating_switch = False
        return True

    def show_toast(self, text: str):
        toast = Adw.Toast.new(text)
        toast.set_timeout(3)
        self.toast_overlay.add_toast(toast)

    def discard_changes(self):
        self.config_mgr.load()
        self.rules_view.reload_rules()
        self.resolvers_view.reload_resolvers()
        self.btn_apply.set_visible(False)
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
        css_provider.load_from_data(APP_CSS.encode("utf-8"))
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
        # Refresh action
        refresh_action = Gio.SimpleAction.new("refresh", None)
        refresh_action.connect("activate", lambda *_: self.window.status_view.refresh_status())
        self.add_action(refresh_action)

        # Discard action
        discard_action = Gio.SimpleAction.new("discard", None)
        discard_action.connect("activate", lambda *_: self.window.discard_changes())
        self.add_action(discard_action)

        # About action
        about_action = Gio.SimpleAction.new("about", None)
        about_action.connect("activate", self._show_about)
        self.add_action(about_action)

    def _show_about(self, *_):
        about = Adw.AboutDialog()
        about.set_application_name("DNSCrypt UI")
        about.set_application_icon("network-wired-symbolic")
        about.set_developer_name("Shovon")
        about.set_version("1.0.0")
        about.set_comments(
            "A modern GNOME / Libadwaita interface for dnscrypt-proxy with YogaDNS-style split DNS domain routing, DoH/DNSCrypt resolvers, and live query inspection."
        )
        about.set_website("https://github.com/DNSCrypt/dnscrypt-proxy")
        about.set_license_type(Gtk.License.GPL_3_0)
        about.present(self.window)


def main():
    app = DNSCryptUIApp()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
