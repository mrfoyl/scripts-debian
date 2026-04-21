#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/ufw-manager.py"
LINK="/usr/local/bin/ufw-manager"

usage() {
    echo "Usage: $0 [--uninstall]"
    echo "  (no args)     Install ufw-manager to $LINK"
    echo "  --uninstall   Remove the symlink from $LINK"
    exit 1
}

# ── root check ─────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

# ── uninstall ──────────────────────────────────────────────────────────────────

if [[ "${1:-}" == "--uninstall" ]]; then
    if [[ -L "$LINK" ]]; then
        rm "$LINK"
        echo "Removed $LINK"
    elif [[ -e "$LINK" ]]; then
        echo "Error: $LINK exists but is not a symlink created by this installer."
        exit 1
    else
        echo "$LINK is not installed."
    fi
    exit 0
fi

[[ $# -gt 0 ]] && usage

# ── dependency checks ──────────────────────────────────────────────────────────

if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found.  Install with: apt install python3"
    exit 1
fi

if ! python3 -c "import curses" 2>/dev/null; then
    echo "Error: Python 'curses' module not available.  Install with: apt install python3"
    exit 1
fi

if ! command -v ufw &>/dev/null; then
    echo "Error: ufw not found.  Install with: apt install ufw"
    exit 1
fi

# ── install ────────────────────────────────────────────────────────────────────

chmod +x "$SOURCE"

if [[ -L "$LINK" ]]; then
    ln -sf "$SOURCE" "$LINK"
    echo "Updated:   $LINK → $SOURCE"
elif [[ -e "$LINK" ]]; then
    echo "Error: $LINK already exists and is not a symlink. Remove it manually."
    exit 1
else
    ln -s "$SOURCE" "$LINK"
    echo "Installed: $LINK → $SOURCE"
fi

echo "Run with:  ufw-manager"
echo "Remove with: sudo bash $0 --uninstall"
