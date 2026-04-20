#!/usr/bin/env bash
# Debian 13 desktop hardening script
# Tailored for: single user, outbound SSH only, VMs (QEMU/KVM), Citrix, network tools
#
# Run as root: sudo bash harden.sh
# Log output is written to /var/log/harden.log
# Reboot after running to apply all kernel/sysctl settings.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

LOG=/var/log/harden.log
# Tee all output to log file and stdout simultaneously
exec > >(tee -a "$LOG") 2>&1
echo "=== Debian 13 Hardening - $(date) ==="

# ─────────────────────────────────────────────
# 1. FIREWALL
# Installs UFW and sets a default-deny-inbound policy.
# All outbound traffic is allowed so normal internet use is unaffected.
# ─────────────────────────────────────────────
echo "[*] Firewall..."
apt-get install -y ufw
ufw --force reset                  # clear any existing rules
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
echo "[+] UFW: deny incoming, allow outgoing"

# ─────────────────────────────────────────────
# 2. SSH SERVER — disable (no inbound needed)
# This machine only connects outbound via SSH (e.g. to Kali VMs).
# The SSH server daemon is not needed and exposes an attack surface.
# ─────────────────────────────────────────────
echo "[*] SSH server..."
for svc in ssh sshd; do
    if systemctl list-units --all | grep -q "^.*${svc}.service"; then
        systemctl disable --now "$svc" 2>/dev/null && echo "[+] Disabled $svc" || true
    fi
done

# ─────────────────────────────────────────────
# 3. SSH CLIENT HARDENING (outbound SSH)
# Restricts the SSH client to modern, strong algorithms only.
# Drops legacy ciphers (3DES, arcfour), weak MACs (MD5/SHA1), and old KEX.
# ForwardAgent/X11 disabled to prevent credential and display leakage.
# ─────────────────────────────────────────────
echo "[*] SSH client config..."
mkdir -p /etc/ssh/ssh_config.d
cat > /etc/ssh/ssh_config.d/99-hardened.conf << 'EOF'
Host *
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
    ForwardX11 no                               # never forward X11 display
EOF
echo "[+] SSH client hardened"

# ─────────────────────────────────────────────
# 4. KERNEL / NETWORK SYSCTL
# Applies hardened kernel parameters at runtime via sysctl.
# Settings persist across reboots via /etc/sysctl.d/99-hardening.conf.
# ─────────────────────────────────────────────
echo "[*] Sysctl hardening..."
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# --- Network: anti-spoofing & redirect protection ---
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
kernel.core_pattern = |/bin/false
EOF
sysctl --system > /dev/null
echo "[+] Sysctl applied"

# ─────────────────────────────────────────────
# 5. CORE DUMPS — disable at PAM and systemd level
# Three layers: sysctl (above), PAM limits, and systemd.
# All three are needed because different processes respect different limits.
# ─────────────────────────────────────────────
echo "[*] Core dumps..."
cat > /etc/security/limits.d/no-coredump.conf << 'EOF'
* hard core 0
* soft core 0
EOF
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
echo "[+] Core dumps disabled"

# ─────────────────────────────────────────────
# 6. APPARMOR
# AppArmor confines processes to a defined set of allowed actions.
# Already included in Debian 13 — this ensures it's active and enforcing.
# ─────────────────────────────────────────────
echo "[*] AppArmor..."
apt-get install -y apparmor apparmor-utils
systemctl enable --now apparmor
# Set all loaded profiles to enforce mode (errors are non-fatal — some profiles may be unconfined by design)
aa-enforce /etc/apparmor.d/* 2>/dev/null || true
echo "[+] AppArmor enforcing"

# ─────────────────────────────────────────────
# 7. AUTOMATIC SECURITY UPDATES
# Applies security-only updates daily without requiring manual intervention.
# Auto-reboot is disabled — reboot manually at a convenient time.
# ─────────────────────────────────────────────
echo "[*] Unattended upgrades..."
apt-get install -y unattended-upgrades apt-listchanges
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";  // security updates only
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";     // recover from interrupted installs
Unattended-Upgrade::Remove-Unused-Dependencies "true"; // clean up orphaned packages
Unattended-Upgrade::Automatic-Reboot "false";          // never reboot automatically
EOF
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";    // refresh package lists daily
APT::Periodic::Unattended-Upgrade "1";      // apply upgrades daily
EOF
echo "[+] Auto security updates enabled (no auto-reboot)"

# ─────────────────────────────────────────────
# 8. DISABLE UNUSED SERVICES
# Each of these services increases attack surface without providing value
# on a single-user desktop with no printer, mobile modem, or local discovery needs.
# ─────────────────────────────────────────────
echo "[*] Disabling unused services..."
SERVICES=(
    bluetooth                # no Bluetooth devices in use
    avahi-daemon             # mDNS/Bonjour — not needed on single-user desktop
    cups                     # printing — remove from list if you have a printer
    cups-browsed             # network printer discovery via mDNS
    ModemManager             # mobile broadband modems — not needed
)
for svc in "${SERVICES[@]}"; do
    svc="${svc%% *}"         # strip inline comments from array entries
    if systemctl list-unit-files --state=enabled 2>/dev/null | grep -q "^${svc}"; then
        systemctl disable --now "$svc" 2>/dev/null \
            && echo "  [+] Disabled: $svc" \
            || echo "  [!] Could not disable: $svc"
    else
        echo "  [-] Not enabled (skipping): $svc"
    fi
done

# ─────────────────────────────────────────────
# 9. SECURE SHARED MEMORY
# /dev/shm is world-writable by default — mounting with noexec/nosuid
# prevents attackers from staging and executing payloads there.
#
# NOTE: noexec can break QEMU/KVM shared memory (vhost, memfd).
#       If VMs fail to start after this, change noexec to exec in /etc/fstab.
# ─────────────────────────────────────────────
echo "[*] /dev/shm..."
if grep -q '/dev/shm' /etc/fstab; then
    sed -i 's|.*\s/dev/shm\s.*|tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0|' /etc/fstab
else
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
fi
mount -o remount /dev/shm 2>/dev/null || echo "  [!] Remount failed — will apply on next boot"
echo "[+] /dev/shm: noexec,nosuid,nodev"

# ─────────────────────────────────────────────
# 10. UMASK
# Default Debian umask is 022 (world-readable files).
# 027 makes new files unreadable by other users on the system.
# ─────────────────────────────────────────────
echo "[*] Umask..."
for f in /etc/profile /etc/bash.bashrc; do
    if ! grep -q 'umask 027' "$f"; then
        echo 'umask 027' >> "$f"
    fi
done
echo "[+] Default umask set to 027"

# ─────────────────────────────────────────────
# 11. RESTRICT su TO WHEEL/SUDO GROUP
# Prevents any local user from attempting to switch to root via su.
# Only members of the sudo group are permitted.
# ─────────────────────────────────────────────
echo "[*] Restricting su..."
PAM_SU=/etc/pam.d/su
if grep -q '#.*pam_wheel' "$PAM_SU"; then
    sed -i 's/^#\(.*pam_wheel.*\)/\1/' "$PAM_SU"
    echo "[+] su restricted to sudo group"
else
    echo "  [-] pam_wheel already configured or not found — check $PAM_SU manually"
fi

# ─────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────
echo ""
echo "=== Hardening complete. Log: $LOG ==="
echo ""
echo "Action items:"
echo "  - Reboot to apply all kernel/sysctl settings fully"
echo "  - If VMs (QEMU/KVM) fail to start: check /dev/shm noexec and ip_forward in /etc/sysctl.d/99-hardening.conf"
echo "  - If you have a printer: re-enable cups with: systemctl enable --now cups"
