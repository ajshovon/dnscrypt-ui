#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"

echo "==> Installing DNSCrypt UI for user $(whoami)..."

# Ensure directories exist
mkdir -p "$BIN_DIR"
mkdir -p "$APP_DIR"
mkdir -p "$ICON_DIR"

# 1. Symlink binary
chmod +x "$SCRIPT_DIR/bin/dnscrypt-ui"
ln -sf "$SCRIPT_DIR/bin/dnscrypt-ui" "$BIN_DIR/dnscrypt-ui"
echo "  [✓] Linked executable to $BIN_DIR/dnscrypt-ui"

# 2. Install icon
cp "$SCRIPT_DIR/data/icons/io.github.shovon.DNSCryptUI.svg" "$ICON_DIR/io.github.shovon.DNSCryptUI.svg"
echo "  [✓] Installed icon to $ICON_DIR"

# 3. Install desktop entry with updated Exec path
sed "s|^Exec=.*|Exec=$BIN_DIR/dnscrypt-ui|" "$SCRIPT_DIR/data/io.github.shovon.DNSCryptUI.desktop" > "$APP_DIR/io.github.shovon.DNSCryptUI.desktop"
chmod +x "$APP_DIR/io.github.shovon.DNSCryptUI.desktop"
echo "  [✓] Installed desktop entry to $APP_DIR"

# 4. Update desktop & icon caches
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR" || true
fi
if command -v gtk4-update-icon-cache >/dev/null 2>&1; then
    gtk4-update-icon-cache "$HOME/.local/share/icons/hicolor" -t -f || true
fi

echo ""
echo "==> Installation complete! You can now launch 'DNSCrypt UI' from your GNOME app drawer or run 'dnscrypt-ui' in terminal."
