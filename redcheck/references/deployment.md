# Deployment & Bootstrap (Kali/Linux)

## Table of Contents

1. [Overview](#overview)
2. [Minimal Runtime Components](#minimal-runtime-components)
3. [Pinned Package Manifests](#pinned-package-manifests)
4. [Host Configuration](#host-configuration)
5. [Directory Layout](#directory-layout)
6. [Host Integrity Monitoring](#host-integrity-monitoring)

---

## Overview

Make RedCheck runnable from a hardened Kali/Linux host while keeping evidence, keys, and execution environments isolated and auditable.

All packages are pinned for reproducibility. Installers and package versions are tracked in the repo.

---

## Minimal Runtime Components

Install and pin all of the following:

| Category | Packages | Purpose |
|----------|----------|---------|
| Agent runtime | `python3`, `pip`, `virtualenv` | Core agent execution |
| Code sync | `git` | Repository management |
| Isolation | `docker` / `podman` | Disposable containers for test runs |
| Deep isolation (optional) | `qemu-kvm`, `libvirt` | VM snapshots for deeper isolation |
| Crypto | `gpg`, `openssl` | Evidence encryption and signing |
| Encrypted storage | `cryptsetup` (LUKS2) | Encrypted evidence volumes (or managed Vault/HSM) |
| Network recon | `nmap`, `masscan` | Asset inventory, non-intrusive mode |
| Packet capture | `tcpdump`, `tshark` | Network capture for staging environments |
| Data processing | `jq`, `yq` | JSON/YAML processing |
| Logging | `filebeat` (or equivalent) | Central log forwarding to secured aggregator |

---

## Pinned Package Manifests

### APT Manifest (apt-packages.txt)

```
python3=3.11.*
python3-pip
python3-venv
git
docker.io
qemu-kvm
libvirt-daemon-system
gnupg2
openssl
cryptsetup
nmap
masscan
tcpdump
tshark
jq
filebeat
```

Install with:
```bash
xargs -a apt-packages.txt sudo apt-get install -y
```

### Python Requirements (requirements.txt)

```
pyyaml==6.0.1
cryptography==42.0.0
paramiko==3.4.0
requests==2.31.0
jinja2==3.1.3
python-nmap==0.7.1
scapy==2.5.0
```

Install with:
```bash
pip install -r requirements.txt
```

### yq Installation

```bash
# Install yq (YAML processor)
wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 \
  -O /usr/local/bin/yq && chmod +x /usr/local/bin/yq
```

---

## Host Configuration

### 1. Create Dedicated Runtime User

```bash
# Create redcheck user with minimal privileges
useradd -r -m -s /bin/bash -d /opt/redcheck redcheck

# Grant limited sudo rights (snapshot/rollback only)
cat > /etc/sudoers.d/redcheck << 'EOF'
redcheck ALL=(root) NOPASSWD: /usr/bin/docker, /usr/bin/podman
redcheck ALL=(root) NOPASSWD: /sbin/cryptsetup luksOpen /dev/sd*
redcheck ALL=(root) NOPASSWD: /sbin/cryptsetup luksClose redcheck-*
redcheck ALL=(root) NOPASSWD: /usr/bin/virsh snapshot-*
EOF
chmod 440 /etc/sudoers.d/redcheck
```

### 2. Harden SSH

```bash
# /etc/ssh/sshd_config.d/redcheck.conf
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers redcheck
MaxAuthTries 3
AllowAgentForwarding no
X11Forwarding no
```

Enable auditd for SSH session logging:
```bash
systemctl enable auditd
auditctl -w /etc/ssh/sshd_config -p wa -k sshd_config_change
auditctl -w /home/redcheck/.ssh/ -p wa -k ssh_key_access
```

---

## Directory Layout

```
/opt/redcheck/                    # Code (read-only except during update)
  ├── bin/                        # Agent executables and entry points
  ├── lib/                        # Python packages (virtualenv)
  ├── conf/                       # Configuration files
  └── scripts/                    # Operational scripts

/var/lib/redcheck/evidence/       # Encrypted evidence mount (LUKS2)
  ├── engagements/                # Per-engagement evidence directories
  ├── keys/                       # GPG/age keys (authorizer-only access)
  └── audit/                      # Access audit logs

/var/log/redcheck/                # Agent logs (forwarded to central aggregator)
  ├── agent.log                   # Operational logs
  ├── engagement.log              # Per-engagement activity
  └── anomaly.log                 # Anomaly detection events
```

### Set Permissions

```bash
# Code directory: read-only
chown -R root:redcheck /opt/redcheck
chmod -R 750 /opt/redcheck
chmod -R a-w /opt/redcheck  # read-only, writeable only during updates

# Evidence mount: redcheck user only
mkdir -p /var/lib/redcheck/evidence
chown -R redcheck:redcheck /var/lib/redcheck/evidence
chmod 700 /var/lib/redcheck/evidence

# Logs: writable by agent, readable by log forwarder
mkdir -p /var/log/redcheck
chown -R redcheck:redcheck /var/log/redcheck
chmod 750 /var/log/redcheck
```

### Set Up Encrypted Evidence Volume (LUKS2)

```bash
# Create and format encrypted volume
cryptsetup luksFormat --type luks2 /dev/sdX
cryptsetup luksOpen /dev/sdX redcheck-evidence
mkfs.ext4 /dev/mapper/redcheck-evidence
mount /dev/mapper/redcheck-evidence /var/lib/redcheck/evidence
```

---

## Host Integrity Monitoring

Enforce integrity monitoring to detect tampering on the agent host.

### Option A: AIDE

```bash
apt-get install aide
aideinit
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# Schedule daily checks
echo "0 3 * * * root /usr/bin/aide --check" >> /etc/crontab
```

### Option B: osquery

```bash
apt-get install osquery
# Monitor critical paths
cat > /etc/osquery/osquery.conf << 'EOF'
{
  "schedule": {
    "file_integrity": {
      "query": "SELECT * FROM file WHERE path LIKE '/opt/redcheck/%' OR path LIKE '/etc/ssh/%';",
      "interval": 300
    }
  },
  "file_paths": {
    "redcheck": ["/opt/redcheck/%%", "/etc/ssh/%%"]
  }
}
EOF
systemctl enable osqueryd
```

### Option C: Tripwire

```bash
apt-get install tripwire
tripwire --init
# Configure policy to monitor /opt/redcheck and /var/lib/redcheck
```

Any detected tampering triggers an alert to the sole authorizer and pauses all active engagements.
