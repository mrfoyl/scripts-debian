# ufw-manager

Interactive TUI for managing UFW firewall rules on Debian. Navigate with arrow keys, toggle rules on/off, add and delete rules — all without typing raw `ufw` commands.

## Requirements

- Python 3
- UFW (`apt install ufw`)
- Root / sudo access

## Install

```bash
sudo bash install.sh
```

This creates a symlink at `/usr/local/bin/ufw-manager` pointing to `ufw-manager.py`.  
Updates to the script are picked up immediately — no reinstall needed.

## Run

```bash
ufw-manager
```

The tool will re-launch itself with `sudo` if not already root.

## Keyboard shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate rules |
| `Space` | Toggle selected rule on / off |
| `A` | Add a new rule (guided dialog) |
| `C` | Edit comment on selected rule |
| `D` / `Del` | Delete selected rule permanently |
| `E` | Enable UFW firewall |
| `X` | Disable UFW firewall |
| `R` | Refresh rule list |
| `Q` | Quit |

## How rule toggling works

UFW has no native per-rule enable/disable. This tool implements it by:

1. **Disabling** a rule deletes it from UFW and saves it to `.ufw_disabled.json` in the same directory.
2. **Re-enabling** reads from that file and adds the rule back to UFW.

Disabled rules stay visible in the list (greyed out, marked `[OFF]`) so you can find and restore them easily. Pressing `D` on a disabled rule removes it from the saved list permanently.

## Visual indicators

| Colour | Meaning |
|--------|---------|
| Green `ALLOW` | Traffic allowed |
| Red `DENY` / `REJECT` | Traffic blocked |
| Yellow `LIMIT` | Rate-limited |
| Grey `[OFF]` | Rule disabled (not active in UFW) |
| Green badge `● ACTIVE` | UFW is running |
| Red badge `○ INACTIVE` | UFW is off |
