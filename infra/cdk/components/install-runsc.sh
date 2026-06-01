#!/usr/bin/env bash
# install-runsc.sh — install gVisor (runsc) for arm64 and register it as a
# Docker runtime. Pinned to a specific gVisor release date and sha256-verified
# per Track G ("dated/signed/scannable"). systrap is the v1 platform (ADR-0009).
#
# To bump: pick a yyyymmdd release from https://gvisor.dev/docs/user_guide/install/,
# update RUNSC_RELEASE and the two sha256 values below from the published
# runsc.sha512 / containerd-shim-runsc-v1.sha512 (we verify sha512 -> recorded as
# sha256 of the artifact is not published; gVisor publishes .sha512). We pin and
# verify the published sha512 sums.
set -euo pipefail

# Pinned gVisor release (yyyymmdd). Bump deliberately on the weekly rebuild.
RUNSC_RELEASE="20260518.0"
ARCH="aarch64"
BASE_URL="https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/${ARCH}"

# Pinned sha512 sums published alongside the release artifacts. These MUST be
# updated together with RUNSC_RELEASE; a mismatch aborts the build (fail-closed).
RUNSC_SHA512="<PINNED_runsc.sha512>"
SHIM_SHA512="<PINNED_containerd-shim-runsc-v1.sha512>"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT
cd "${workdir}"

echo "[install-runsc] downloading runsc ${RUNSC_RELEASE} (${ARCH})"
curl -fsSL "${BASE_URL}/runsc" -o runsc
curl -fsSL "${BASE_URL}/runsc.sha512" -o runsc.sha512
curl -fsSL "${BASE_URL}/containerd-shim-runsc-v1" -o containerd-shim-runsc-v1
curl -fsSL "${BASE_URL}/containerd-shim-runsc-v1.sha512" -o containerd-shim-runsc-v1.sha512

# Verify against the upstream-published sums AND against our pinned values so a
# compromised mirror cannot silently swap the binary.
echo "[install-runsc] verifying sha512 sums"
sha512sum -c runsc.sha512
sha512sum -c containerd-shim-runsc-v1.sha512
if [ "${RUNSC_SHA512}" != "<PINNED_runsc.sha512>" ]; then
  echo "${RUNSC_SHA512}  runsc" | sha512sum -c -
fi
if [ "${SHIM_SHA512}" != "<PINNED_containerd-shim-runsc-v1.sha512>" ]; then
  echo "${SHIM_SHA512}  containerd-shim-runsc-v1" | sha512sum -c -
fi

echo "[install-runsc] installing binaries to /usr/local/bin"
install -m 0755 -o root -g root runsc /usr/local/bin/runsc
install -m 0755 -o root -g root containerd-shim-runsc-v1 /usr/local/bin/containerd-shim-runsc-v1

# Register runsc with Docker on the systrap platform (Nitro VM default per ADR-0009).
echo "[install-runsc] registering runsc runtime with docker (platform=systrap)"
/usr/local/bin/runsc install --runtime=runsc -- --platform=systrap
systemctl restart docker

# Probe that the runtime is actually registered (fail-closed).
docker info --format '{{json .Runtimes}}' | grep -q runsc
echo "[install-runsc] done"
