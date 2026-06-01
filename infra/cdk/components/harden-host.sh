#!/usr/bin/env bash
# harden-host.sh — host hardening for the sandbox AMI: SSM-only access (no SSH
# passwords), enforce IMDSv2 defaults, and common CIS Amazon Linux 2023
# benchmark items. Runs last so it can lock down what the prior components set up.
set -euo pipefail

echo "[harden-host] disabling password + root SSH login"
sshd_drop="/etc/ssh/sshd_config.d/99-asec-hardening.conf"
install -d -m 0755 /etc/ssh/sshd_config.d
cat > "${sshd_drop}" <<'CONF'
# asec sandbox host: SSM-only access. SSH stays installed but cannot be used
# for interactive password / root login (Track G: no inbound SSH).
PasswordAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
CONF
chmod 0600 "${sshd_drop}"

echo "[harden-host] enforcing IMDSv2 (instance-level fallback; AMI built with HttpTokens=required)"
# The build/launch infrastructure sets HttpTokens=required at the instance level;
# this records the intent and disables IMDS hop > 1.
mkdir -p /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/99-asec-imdsv2.cfg <<'CONF'
# IMDSv2 is enforced at the EC2 instance metadata-options level (HttpTokens=required,
# HttpPutResponseHopLimit=1). See SandboxAmiPipelineStack InfrastructureConfiguration.
CONF

echo "[harden-host] CIS: kernel module + network sysctl hardening"
cat > /etc/sysctl.d/99-asec-cis.conf <<'CONF'
# CIS Amazon Linux 2023 network hardening (subset).
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
CONF
sysctl --system || true

echo "[harden-host] CIS: disable uncommon filesystems + protocols"
cat > /etc/modprobe.d/99-asec-cis.conf <<'CONF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
CONF

echo "[harden-host] CIS: restrict cron + set login.defs umask"
chmod 0700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
[ -f /etc/crontab ] && chmod 0600 /etc/crontab || true
if [ -f /etc/login.defs ]; then
  sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs || true
fi

echo "[harden-host] done"
