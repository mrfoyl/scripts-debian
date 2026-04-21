# Debian Scripts

Shell scripts for Debian 13 system administration.

---

## harden.sh

Hardening script for a Debian 13 desktop. Tailored for a single-user machine running network tools, Citrix, and QEMU/KVM virtual machines, with outbound SSH only and no inbound remote access.

### What it does

| # | Area | Action |
|---|------|--------|
| 1 | Firewall (UFW) | Deny all inbound, allow all outbound |
| 2 | SSH server | Disable sshd (no inbound needed) |
| 3 | SSH client | Enforce modern ciphers/KEX/MACs for outbound SSH |
| 4 | Kernel / sysctl | Anti-spoofing, SYN flood protection, ASLR, restrict dmesg |
| 5 | Core dumps | Disabled via PAM limits and systemd |
| 6 | AppArmor | Ensure enabled and enforcing |
| 7 | Auto updates | Unattended security-only updates, no auto-reboot |
| 8 | Services | Disable bluetooth, avahi-daemon, cups, ModemManager |
| 9 | /dev/shm | Mounted with noexec, nosuid, nodev |
| 10 | Umask | Default set to 027 |
| 11 | su | Restricted to sudo group via pam_wheel |

### Usage

```bash
sudo bash harden.sh
```

Log is written to `/var/log/harden.log`. Reboot after running to apply all kernel settings.

### What it doesn't cover

Some hardening measures can't be applied to a running system and must be decided at install time or require significant manual effort:

- **Partition scheme** — separate `/tmp`, `/var/tmp`, `/home`, `/var` mounts with `noexec`/`nosuid`/`nodev` flags must be set up during OS installation. `/dev/shm` is the exception and is handled by this script (section 9).
- **GRUB/boot password** — prevents tampering with boot parameters from the console; requires manual setup.
- **Intrusion detection** — file integrity monitoring (AIDE, rkhunter) requires baseline snapshots and scheduled checks; too site-specific to automate here.
- **Audit logging** — `auditd` with custom rules is workload-dependent and not included.

### Known caveats

**QEMU/KVM virtual machines**
- `/dev/shm` is mounted `noexec` — if VMs fail to start, remove that flag from `/etc/fstab`
- IP forwarding is disabled — if VMs use bridged or NAT networking, set `net.ipv4.ip_forward = 1` in `/etc/sysctl.d/99-hardening.conf` and run `sysctl -p`

**Printer**
- `cups` is disabled. Re-enable with:
  ```bash
  sudo systemctl enable --now cups
  ```
