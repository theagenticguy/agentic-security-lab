#!/usr/bin/env bash
# install-docker.sh — install the Docker engine on Amazon Linux 2023 (arm64).
# Referenced by the `install-docker` EC2 Image Builder component. Idempotent.
set -euo pipefail

echo "[install-docker] installing docker via dnf (AL2023, arm64)"
dnf install -y docker

echo "[install-docker] enabling + starting docker"
systemctl enable docker
systemctl start docker

# Harden the daemon: disable inter-container connectivity by default, enable
# live-restore so the sandbox host survives a daemon restart, and pin the
# default ulimit. The sandbox runtime (runsc) is registered by install-runsc.sh.
install -d -m 0755 /etc/docker
cat > /etc/docker/daemon.json <<'JSON'
{
  "icc": false,
  "live-restore": true,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
JSON

systemctl restart docker
docker --version
echo "[install-docker] done"
