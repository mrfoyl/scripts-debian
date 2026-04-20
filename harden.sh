#!/usr/bin/env bash
# Debian 13 desktop hardening script
# Tailored for: single user, outbound SSH only, VMs (QEMU/KVM), Citrix, network tools
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

LOG=/var/log/harden.log
exec > >(tee -a "$LOG") 2>&1
echo "=== Debian 13 Hardening - $(date) ==="

# ─────────────────────────────────────────────
# 1. FIREWALL
# ─────────────────────────────────────────────
echo "[*] Firewall..."
apt-get install -y ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
echo "[+] UFW: deny incoming, allow outgoing"

# ─────────────────────────────────────────────
# 2. SSH SERVER — disable (no inbound needed)
# ─────────────────────────────────────────────
echo "[*] SSH server..."
for svc in ssh sshd; do
    if systemctl list-units --all | grep -q "^.*${svc}.service"; then
        systemctl disable --now "$svc" 2>/dev/null && echo "[+] Disabled $svc" || true
    fi
done

# ─────────────────────────────────────────────
# 3. SSH CLIENT HARDENING (outbound SSH)
# ─────────────────────────────────────────────
echo "[*] SSH client config..."
mkdir -p /etc/ssh/ssh_config.d
cat > /etc/ssh/ssh_config.d/99-hardened.conf << 'EOF'
Host *
    Protocol 2
    HashKnownHosts yes
    HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256
    KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    ServerAliveInterval 60
    ServerAliveCountMax 3
    StrictHostKeyChecking ask
    VisualHostKey yes
    ForwardAgent no
    ForwardX11 no
EOF
echo "[+] SSH client hardened"

# ─────────────────────────────────────────────
# 4. KERNEL / NETWORK SYSCTL
# ─────────────────────────────────────────────
echo "[*] Sysctl hardening..."
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# --- Network: anti-spoofing & redirect protection ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# --- Network: ICMP ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Network: SYN flood protection ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_rfc1337 = 1

# --- Network: logging ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Network: forwarding
# NOTE: If VMs use bridged networking or NAT, set net.ipv4.ip_forward = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- IPv6: disable router advertisements ---
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- Kernel hardening ---
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
kernel.sysrq = 0

# --- Core dumps ---
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
EOF
sysctl --system > /dev/null
echo "[+] Sysctl applied"

# ─────────────────────────────────────────────
# 5. CORE DUMPS — disable at PAM and systemd level
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
# ─────────────────────────────────────────────
echo "[*] AppArmor..."
apt-get install -y apparmor apparmor-utils
systemctl enable --now apparmor
# Enforce all loaded profiles (skips unconfined gracefully)
aa-enforce /etc/apparmor.d/* 2>/dev/null || true
echo "[+] AppArmor enforcing"

# ─────────────────────────────────────────────
# 7. AUTOMATIC SECURITY UPDATES
# ─────────────────────────────────────────────
echo "[*] Unattended upgrades..."
apt-get install -y unattended-upgrades apt-listchanges
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
echo "[+] Auto security updates enabled (no auto-reboot)"

# ─────────────────────────────────────────────
# 8. DISABLE UNUSED SERVICES
# ─────────────────────────────────────────────
echo "[*] Disabling unused services..."
SERVICES=(
    bluetooth
    avahi-daemon   # mDNS/service discovery — not needed on single-user desktop
    cups           # printing — remove from list if you have a printer
    cups-browsed
    ModemManager   # mobile modem management — not needed
)
for svc in "${SERVICES[@]}"; do
    # Strip comments
    svc="${svc%% *}"
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
# NOTE: noexec on /dev/shm can break QEMU/KVM shared memory.
#       If VMs fail to start after this, remove the noexec flag.
# ─────────────────────────────────────────────
echo "[*] /dev/shm..."
if grep -q '/dev/shm' /etc/fstab; then
    # Update existing entry
    sed -i 's|.*\s/dev/shm\s.*|tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0|' /etc/fstab
else
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
fi
mount -o remount /dev/shm 2>/dev/null || echo "  [!] Remount failed — will apply on next boot"
echo "[+] /dev/shm: noexec,nosuid,nodev"

# ─────────────────────────────────────────────
# 10. UMASK
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
