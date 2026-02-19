#!/usr/bin/env bash
# RedCheck Host Setup Script
# Run as root on a fresh Kali/Linux host to bootstrap the RedCheck environment.
# Usage: sudo bash setup_host.sh
set -euo pipefail

REDCHECK_USER="redcheck"
CODE_DIR="/opt/redcheck"
EVIDENCE_DIR="/var/lib/redcheck/evidence"
LOG_DIR="/var/log/redcheck"

echo "=== RedCheck Host Bootstrap ==="

# --- 1. Install pinned packages ---
echo "[1/6] Installing system packages..."
apt-get update -qq
apt-get install -y \
  python3 python3-pip python3-venv \
  git \
  docker.io \
  gnupg2 openssl \
  cryptsetup \
  nmap masscan \
  tcpdump tshark \
  jq \
  auditd audispd-plugins \
  aide

# Optional: KVM support
if [ "${INSTALL_KVM:-0}" = "1" ]; then
  apt-get install -y qemu-kvm libvirt-daemon-system virtinst
  systemctl enable libvirtd
fi

# --- 2. Create runtime user ---
echo "[2/6] Creating runtime user '${REDCHECK_USER}'..."
if ! id "$REDCHECK_USER" &>/dev/null; then
  useradd -r -m -s /bin/bash -d "$CODE_DIR" "$REDCHECK_USER"
fi

# Limited sudo rights (container + crypto mount only)
cat > /etc/sudoers.d/redcheck << 'SUDOERS'
redcheck ALL=(root) NOPASSWD: /usr/bin/docker
redcheck ALL=(root) NOPASSWD: /usr/bin/podman
redcheck ALL=(root) NOPASSWD: /sbin/cryptsetup luksOpen /dev/sd*
redcheck ALL=(root) NOPASSWD: /sbin/cryptsetup luksClose redcheck-*
SUDOERS
chmod 440 /etc/sudoers.d/redcheck

# --- 3. Harden SSH ---
echo "[3/6] Hardening SSH..."
cat > /etc/ssh/sshd_config.d/redcheck.conf << 'SSHCONF'
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers redcheck
MaxAuthTries 3
AllowAgentForwarding no
X11Forwarding no
SSHCONF
systemctl restart sshd || true

# Auditd rules for SSH
auditctl -w /etc/ssh/sshd_config -p wa -k sshd_config_change 2>/dev/null || true
auditctl -w /home/redcheck/.ssh/ -p wa -k ssh_key_access 2>/dev/null || true
systemctl enable auditd

# --- 4. Create directory layout ---
echo "[4/6] Creating directory layout..."
mkdir -p "$CODE_DIR"/{bin,lib,conf,scripts}
mkdir -p "$EVIDENCE_DIR"/{engagements,keys,audit}
mkdir -p "$LOG_DIR"

# Permissions
chown -R root:redcheck "$CODE_DIR"
chmod -R 750 "$CODE_DIR"

chown -R redcheck:redcheck "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"

chown -R redcheck:redcheck "$LOG_DIR"
chmod 750 "$LOG_DIR"

# --- 5. Set up Python virtualenv ---
echo "[5/6] Setting up Python virtualenv..."
su - "$REDCHECK_USER" -c "python3 -m venv ${CODE_DIR}/lib/venv"
su - "$REDCHECK_USER" -c "${CODE_DIR}/lib/venv/bin/pip install --upgrade pip"

if [ -f "${CODE_DIR}/requirements.txt" ]; then
  su - "$REDCHECK_USER" -c "${CODE_DIR}/lib/venv/bin/pip install -r ${CODE_DIR}/requirements.txt"
fi

# --- 6. Initialize AIDE integrity baseline ---
echo "[6/6] Initializing host integrity monitoring (AIDE)..."
aideinit 2>/dev/null || true
if [ -f /var/lib/aide/aide.db.new ]; then
  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi
# Daily integrity check at 03:00
echo "0 3 * * * root /usr/bin/aide --check | mail -s 'AIDE Report' root" > /etc/cron.d/aide-check

echo ""
echo "=== RedCheck host bootstrap complete ==="
echo "  Code dir:     $CODE_DIR"
echo "  Evidence dir: $EVIDENCE_DIR (mount encrypted volume here)"
echo "  Log dir:      $LOG_DIR"
echo "  User:         $REDCHECK_USER"
echo ""
echo "Next steps:"
echo "  1. Set up encrypted LUKS2 volume and mount to $EVIDENCE_DIR"
echo "  2. Generate GPG keys for evidence signing"
echo "  3. Configure filebeat to forward $LOG_DIR to your aggregator"
echo "  4. Deploy RedCheck code to $CODE_DIR and install requirements"
