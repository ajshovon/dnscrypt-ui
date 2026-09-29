#!/usr/bin/env bash
# Installs DNSCrypt UI for the current user, plus the root-owned privileged
# helper and its polkit action (needs sudo; skip with --user-only).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
HELPER_DEST="/usr/local/libexec/dnscrypt-ui-helper"
POLICY_DEST="/usr/share/polkit-1/actions/io.github.shovon.DNSCryptUI.policy"

USER_ONLY=0
[[ "${1:-}" == "--user-only" ]] && USER_ONLY=1

echo "==> Installing DNSCrypt UI for $(whoami)..."
mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR"

chmod +x "$SCRIPT_DIR/bin/dnscrypt-ui"
ln -sf "$SCRIPT_DIR/bin/dnscrypt-ui" "$BIN_DIR/dnscrypt-ui"
echo "  [✓] Linked $BIN_DIR/dnscrypt-ui"

cp "$SCRIPT_DIR/data/icons/io.github.shovon.DNSCryptUI.svg" "$ICON_DIR/"
echo "  [✓] Installed icon"

sed "s|^Exec=.*|Exec=$BIN_DIR/dnscrypt-ui|" \
    "$SCRIPT_DIR/data/io.github.shovon.DNSCryptUI.desktop" > "$APP_DIR/io.github.shovon.DNSCryptUI.desktop"
echo "  [✓] Installed desktop entry"

command -v update-desktop-database >/dev/null && update-desktop-database "$APP_DIR" || true
command -v gtk4-update-icon-cache >/dev/null && gtk4-update-icon-cache -q -t -f "$HOME/.local/share/icons/hicolor" || true

if [[ $USER_ONLY -eq 0 ]]; then
    echo "==> Installing the privileged helper (sudo)..."
    # Root-owned copy outside your home, so other programs running as you
    # cannot change what pkexec runs as root.
    sudo install -D -o root -g root -m 0755 "$SCRIPT_DIR/helper/dnscrypt-ui-helper" "$HELPER_DEST"
    sudo install -D -o root -g root -m 0644 "$SCRIPT_DIR/data/io.github.shovon.DNSCryptUI.policy" "$POLICY_DEST"
    command -v restorecon >/dev/null && sudo restorecon "$HELPER_DEST" "$POLICY_DEST" || true
    echo "  [✓] Installed $HELPER_DEST and polkit action"
else
    echo "  [!] Skipped the privileged helper; the app will run it from $SCRIPT_DIR/helper"
fi

echo ""
echo "==> Done. Launch 'DNSCrypt UI' from the app grid or run 'dnscrypt-ui'."
