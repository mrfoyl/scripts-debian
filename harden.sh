#!/usr/bin/env bash
# Debian 13 desktop hardening script
# Tailored for: single user, outbound SSH only, VMs (QEMU/KVM), Citrix, network tools
#
# Usage:
#   sudo bash harden.sh            — preview changes (dry run)
#   sudo bash harden.sh --apply    — apply all changes
#
# Log output is written to /var/log/harden.log (apply mode only).
# Reboot after applying to activate all kernel/sysctl settings.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0 [--apply]" >&2
    exit 1
fi

# Default to dry run unless --apply is passed
APPLY=false
if [[ "${1:-}" == "--apply" ]]; then
    APPLY=true
fi

# ── Helpers ──────────────────────────────────────────────────────────────────

# run: execute a command in apply mode, or print it in dry-run mode
run() {
    if $APPLY; then
        "$@"
    else
        echo "    would run: $*"
    fi
}

# write_file: show a diff of what would be written vs current content, then write in apply mode
write_file() {
    local path="$1"
    local content="$2"

    if $APPLY; then
        echo "$content" > "$path"
    else
        if [[ -f "$path" ]]; then
            echo "    would update: $path"
            diff <(cat "$path") <(echo "$content") | sed 's/^/      /' || true
        else
            echo "    would create: $path"
            echo "$content" | head -20 | sed 's/^/      /'
            local total
            total=$(echo "$content" | wc -l)
            [[ $total -gt 20 ]] && echo "      ... ($total lines total)"
        fi
    fi
}

# append_if_missing: show or apply a line append
append_if_missing() {
    local file="$1"
    local line="$2"
    if grep -qF "$line" "$file" 2>/dev/null; then
        echo "    already set in $file — no change"
    else
        if $APPLY; then
            echo "$line" >> "$file"
        else
            echo "    would append to $file: $line"
        fi
    fi
}

# check_service: report service state and whether it would be disabled
check_service() {
    local svc="$1"
    if systemctl list-unit-files --state=enabled 2>/dev/null | grep -q "^${svc}"; then
        if $APPLY; then
            systemctl disable --now "$svc" 2>/dev/null \
                && echo "  [+] Disabled: $svc" \
                || echo "  [!] Could not disable: $svc"
        else
            local status
            status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            echo "  would disable: $svc (currently $status)"
        fi
    else
        echo "  not enabled, skip: $svc"
    fi
}

# ── Header ───────────────────────────────────────────────────────────────────

if $APPLY; then
    LOG=/var/log/harden.log
    exec > >(tee -a "$LOG") 2>&1
    echo "=== Debian 13 Hardening — APPLY — $(date) ==="
else
    echo ""
    echo "=== Debian 13 Hardening — DRY RUN (no changes will be made) ==="
    echo "=== Run with --apply to apply all changes                    ==="
    echo ""
fi

# ─────────────────────────────────────────────
# 1. FIREWALL
# Installs UFW and sets a default-deny-inbound policy.
# All outbound traffic is allowed so normal internet use is unaffected.
# ─────────────────────────────────────────────
echo "[1] Firewall (UFW)"
if ! command -v ufw &>/dev/null; then
    if $APPLY; then
        apt-get install -y ufw
    else
        echo "    would install: ufw"
    fi
else
    echo "    ufw already installed"
fi

CURRENT_DEFAULT_IN=$(ufw status verbose 2>/dev/null | grep "Default:" | grep -o 'deny (incoming)\|allow (incoming)\|reject (incoming)' || echo "unknown")
CURRENT_DEFAULT_OUT=$(ufw status verbose 2>/dev/null | grep "Default:" | grep -o 'deny (outgoing)\|allow (outgoing)\|reject (outgoing)' || echo "unknown")
UFW_STATUS=$(ufw status 2>/dev/null | head -1 || echo "Status: unknown")

echo "    current UFW status : $UFW_STATUS"
echo "    current default in : ${CURRENT_DEFAULT_IN:-unknown}"
echo "    current default out: ${CURRENT_DEFAULT_OUT:-unknown}"
echo "    target  default in : deny"
echo "    target  default out: allow"

if $APPLY; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
    echo "  [+] UFW configured"
fi

# ─────────────────────────────────────────────
# 2. SSH SERVER — disable (no inbound needed)
# This machine only connects outbound via SSH (e.g. to Kali VMs).
# The SSH server daemon is not needed and exposes an attack surface.
# ─────────────────────────────────────────────
echo "[2] SSH server"
for svc in ssh sshd; do
    if systemctl list-units --all 2>/dev/null | grep -q "^.*${svc}.service"; then
        local_status=$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")
        if $APPLY; then
            systemctl disable --now "$svc" 2>/dev/null && echo "  [+] Disabled $svc" || true
        else
            echo "    would disable: $svc (currently $local_status)"
        fi
    else
        echo "    not found, skip: $svc"
    fi
done

# ─────────────────────────────────────────────
# 3. SSH CLIENT HARDENING (outbound SSH)
# Restricts the SSH client to modern, strong algorithms only.
# Drops legacy ciphers (3DES, arcfour), weak MACs (MD5/SHA1), and old KEX.
# ForwardAgent/X11 disabled to prevent credential and display leakage.
# ─────────────────────────────────────────────
echo "[3] SSH client config"
SSH_CLIENT_CONF=/etc/ssh/ssh_config.d/99-hardened.conf
run mkdir -p /etc/ssh/ssh_config.d
write_file "$SSH_CLIENT_CONF" "Host *
    Protocol 2
    HashKnownHosts yes                          # store known_hosts as hashes, not plain hostnames
    HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256
    KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    ServerAliveInterval 60                      # send keepalive every 60s
    ServerAliveCountMax 3                       # drop connection after 3 missed keepalives
    StrictHostKeyChecking ask                   # prompt on unknown host keys, never auto-accept
    VisualHostKey yes                           # show ASCII art fingerprint for easier visual verification
    ForwardAgent no                             # never forward SSH agent to remote host
    ForwardX11 no                               # never forward X11 display"

# ─────────────────────────────────────────────
# 4. KERNEL / NETWORK SYSCTL
# Applies hardened kernel parameters at runtime via sysctl.
# Settings persist across reboots via /etc/sysctl.d/99-hardening.conf.
# ─────────────────────────────────────────────
echo "[4] Sysctl hardening"
SYSCTL_CONF=/etc/sysctl.d/99-hardening.conf
write_file "$SYSCTL_CONF" "# --- Network: anti-spoofing & redirect protection ---
# rp_filter: drop packets whose source address has no return route (spoofed)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Ignore ICMP redirects — could be used to hijack routing
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Do not send ICMP redirects (this is not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Disable source-routed packets (attacker-controlled routing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# --- Network: ICMP ---
# Ignore broadcast pings — prevents smurf amplification attacks
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Suppress bogus ICMP error responses from filling logs
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Network: SYN flood protection ---
# SYN cookies: respond to SYN floods without filling the connection table
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
# RFC 1337: drop RST packets for connections in TIME_WAIT (prevents hijacking)
net.ipv4.tcp_rfc1337 = 1

# --- Network: logging ---
# Log packets with impossible source addresses (martians) for intrusion detection
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Network: forwarding ---
# Disabled — this is not a router.
# NOTE: If VMs use bridged networking or NAT, set net.ipv4.ip_forward = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- IPv6: disable router advertisements ---
# Prevents rogue routers on the LAN from changing the default gateway
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- Kernel hardening ---
# dmesg_restrict: prevent unprivileged users from reading kernel ring buffer
kernel.dmesg_restrict = 1
# kptr_restrict: hide kernel symbol addresses from /proc (prevents KASLR bypass)
kernel.kptr_restrict = 2
# Full ASLR: randomize memory layout of stack, heap, and mmap regions
kernel.randomize_va_space = 2
# Disable SysRq key — prevents local users triggering kernel commands
kernel.sysrq = 0

# --- Core dumps ---
# Prevent setuid programs from creating core dumps (could expose secrets)
fs.suid_dumpable = 0
# Route core dumps to /bin/false instead of writing them to disk
kernel.core_pattern = |/bin/false"

if $APPLY; then
    sysctl --system > /dev/null
    echo "  [+] Sysctl applied"
fi

# ─────────────────────────────────────────────
# 5. CORE DUMPS — disable at PAM and systemd level
# Three layers: sysctl (above), PAM limits, and systemd.
# All three are needed because different processes respect different limits.
# ─────────────────────────────────────────────
echo "[5] Core dumps"
write_file /etc/security/limits.d/no-coredump.conf "* hard core 0
* soft core 0"

run mkdir -p /etc/systemd/coredump.conf.d
write_file /etc/systemd/coredump.conf.d/disable.conf "[Coredump]
Storage=none
ProcessSizeMax=0"

# ─────────────────────────────────────────────
# 6. APPARMOR
# AppArmor confines processes to a defined set of allowed actions.
# Already included in Debian 13 — this ensures it's active and enforcing.
# ─────────────────────────────────────────────
echo "[6] AppArmor"
if ! dpkg -l apparmor apparmor-utils &>/dev/null; then
    if $APPLY; then
        apt-get install -y apparmor apparmor-utils
    else
        echo "    would install: apparmor apparmor-utils"
    fi
else
    echo "    apparmor already installed"
fi

AA_STATUS=$(aa-status --pretty-print 2>/dev/null | grep -E "^[0-9]+ profiles" | head -3 || echo "    (aa-status not available)")
echo "    $AA_STATUS"
if $APPLY; then
    systemctl enable --now apparmor
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    echo "  [+] AppArmor enforcing"
else
    echo "    would enable and set all profiles to enforce mode"
fi

# ─────────────────────────────────────────────
# 7. AUTOMATIC SECURITY UPDATES
# Applies security-only updates daily without requiring manual intervention.
# Auto-reboot is disabled — reboot manually at a convenient time.
# ─────────────────────────────────────────────
echo "[7] Unattended upgrades"
if ! dpkg -l unattended-upgrades &>/dev/null; then
    if $APPLY; then
        apt-get install -y unattended-upgrades apt-listchanges
    else
        echo "    would install: unattended-upgrades apt-listchanges"
    fi
else
    echo "    unattended-upgrades already installed"
fi

write_file /etc/apt/apt.conf.d/50unattended-upgrades 'Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";'

write_file /etc/apt/apt.conf.d/20auto-upgrades 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'

# ─────────────────────────────────────────────
# 8. DISABLE UNUSED SERVICES
# Each of these services increases attack surface without providing value
# on a single-user desktop with no printer, mobile modem, or local discovery needs.
# ─────────────────────────────────────────────
echo "[8] Unused services"
SERVICES=(
    bluetooth                # no Bluetooth devices in use
    avahi-daemon             # mDNS/Bonjour — not needed on single-user desktop
    cups                     # printing — remove from list if you have a printer
    cups-browsed             # network printer discovery via mDNS
    ModemManager             # mobile broadband modems — not needed
)
for svc in "${SERVICES[@]}"; do
    svc="${svc%% *}"         # strip inline comments from array entries
    check_service "$svc"
done

# ─────────────────────────────────────────────
# 9. SECURE SHARED MEMORY
# /dev/shm is world-writable by default — mounting with noexec/nosuid
# prevents attackers from staging and executing payloads there.
#
# NOTE: noexec can break QEMU/KVM shared memory (vhost, memfd).
#       If VMs fail to start after this, change noexec to exec in /etc/fstab.
# ─────────────────────────────────────────────
echo "[9] Secure /dev/shm"
FSTAB_LINE="tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
if grep -q '/dev/shm' /etc/fstab; then
    CURRENT_SHM=$(grep '/dev/shm' /etc/fstab)
    if [[ "$CURRENT_SHM" == "$FSTAB_LINE" ]]; then
        echo "    /dev/shm already hardened in /etc/fstab — no change"
    else
        echo "    current /etc/fstab entry : $CURRENT_SHM"
        echo "    target  /etc/fstab entry : $FSTAB_LINE"
        if $APPLY; then
            sed -i 's|.*\s/dev/shm\s.*|'"$FSTAB_LINE"'|' /etc/fstab
            mount -o remount /dev/shm 2>/dev/null || echo "  [!] Remount failed — will apply on next boot"
            echo "  [+] /dev/shm secured"
        fi
    fi
else
    echo "    no /dev/shm entry in /etc/fstab"
    echo "    would add: $FSTAB_LINE"
    if $APPLY; then
        echo "$FSTAB_LINE" >> /etc/fstab
        mount -o remount /dev/shm 2>/dev/null || echo "  [!] Remount failed — will apply on next boot"
        echo "  [+] /dev/shm secured"
    fi
fi

# ─────────────────────────────────────────────
# 10. UMASK
# Default Debian umask is 022 (world-readable files).
# 027 makes new files unreadable by other users on the system.
# ─────────────────────────────────────────────
echo "[10] Umask"
for f in /etc/profile /etc/bash.bashrc; do
    append_if_missing "$f" "umask 027"
done

# ─────────────────────────────────────────────
# 11. RESTRICT su TO WHEEL/SUDO GROUP
# Prevents any local user from attempting to switch to root via su.
# Only members of the sudo group are permitted.
# ─────────────────────────────────────────────
echo "[11] Restrict su"
PAM_SU=/etc/pam.d/su
if grep -q '#.*pam_wheel' "$PAM_SU"; then
    echo "    pam_wheel is commented out — would enable it in $PAM_SU"
    if $APPLY; then
        sed -i 's/^#\(.*pam_wheel.*\)/\1/' "$PAM_SU"
        echo "  [+] su restricted to sudo group"
    fi
else
    echo "    pam_wheel already configured or not present — no change"
fi

# ─────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────
echo ""
if $APPLY; then
    echo "=== Hardening complete. Log: $LOG ==="
    echo ""
    echo "Action items:"
    echo "  - Reboot to apply all kernel/sysctl settings fully"
    echo "  - If VMs (QEMU/KVM) fail to start: check /dev/shm noexec and ip_forward in /etc/sysctl.d/99-hardening.conf"
    echo "  - If you have a printer: re-enable cups with: systemctl enable --now cups"
else
    echo "=== Dry run complete — no changes were made ==="
    echo "=== Run with --apply to apply all changes above ==="
fi
