#!/usr/bin/env bash
# install-tinyproxy.sh — install tinyproxy for the deny-default egress allowlist
# sidecar (whitepaper section 07 / Track C section 7). The per-sandbox config is
# rendered at runtime by EgressProxy; this only stages the binary in the AMI.
set -euo pipefail

echo "[install-tinyproxy] installing tinyproxy via dnf"
dnf install -y tinyproxy

# Do NOT enable the host-level tinyproxy service: egress proxying runs inside a
# per-sandbox sidecar container, never as a host daemon. Disable + mask so a
# stray host proxy can never become an unintended egress path.
systemctl disable --now tinyproxy 2>/dev/null || true
systemctl mask tinyproxy 2>/dev/null || true

tinyproxy -v
echo "[install-tinyproxy] done"
