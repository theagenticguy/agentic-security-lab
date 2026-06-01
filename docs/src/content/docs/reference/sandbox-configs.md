---
title: Sandbox configurations
description: Copy-paste-ready sandbox definitions, least to most isolated.
---

Copy-paste-ready sandbox definitions, ordered from least to most isolated.
Grounded in current Docker, `mise`, devcontainer-spec, Canonical Workshop, and
Firecracker documentation. These back the `asec-sandbox` package and enforce
[E3](/agentic-security-lab/concepts/ears-invariants/#e3) (`--network=none`
default) and [E12](/agentic-security-lab/concepts/ears-invariants/#e12)
(Write-Once-Read-Many — WORM — audit log).

The isolation comparison table at the bottom is the single most useful page on
this site for picking a backend. Code-block bodies collapse so the comparison
fits on screen first.

## Isolation comparison

| Property | Docker (hardened) | LXD / Workshop | Firecracker | Full VM (KVM/QEMU) |
|---|---|---|---|---|
| Boot time | ~50–200 ms | ~0.5–2 s | ~125 ms | 10–30 s |
| Blast radius | Shared host kernel (gVisor narrows the syscall surface) | Shared kernel, unprivileged user namespaces | Own guest kernel; minimal Virtual Machine Monitor (VMM) | Own kernel + full device model |
| Build complexity | Low | Low–medium | Medium | High |
| Per-instance memory | 10–50 MiB | 30–80 MiB | ~5 MiB VMM + guest RAM | 200+ MiB + guest RAM |
| Parallel ceiling | Thousands | Hundreds–thousands | Thousands (Lambda-proven) | Tens–low hundreds |

Linux Container Daemon (LXD) is Canonical's system-container manager. KVM is the
Kernel-based Virtual Machine; QEMU is the Quick Emulator user-space VMM that
typically drives KVM.

## Dockerfile — agentic-security image

<details>
<summary>Show Dockerfile</summary>

```dockerfile
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PATH=/root/.local/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl git ca-certificates build-essential pkg-config \
      gdb lldb clang llvm libclang-rt-dev \
      ripgrep python3 python3-venv python3-pip openjdk-17-jre-headless \
 && rm -rf /var/lib/apt/lists/*
# mise (tool/version manager) + uv (Python)
RUN curl -fsSL https://mise.run | sh && curl -LsSf https://astral.sh/uv/install.sh | sh
# Supply-chain scanners
RUN curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin \
 && curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
 && curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# SAST: semgrep, codeql, frida; DAST: OWASP ZAP
RUN uv tool install semgrep && uv tool install frida-tools \
 && curl -fsSLo /tmp/ql.zip https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip \
 && unzip -q /tmp/ql.zip -d /opt && ln -s /opt/codeql/codeql /usr/local/bin/codeql && rm /tmp/ql.zip
RUN curl -fsSLo /tmp/zap.tar.gz https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_LINUX.tar.gz \
 && tar xf /tmp/zap.tar.gz -C /opt && ln -s /opt/ZAP*/zap.sh /usr/local/bin/zap && rm /tmp/zap.tar.gz
# Agent SDK (clang/ASan via -fsanitize=address at compile time)
RUN uv pip install --system claude-agent-sdk
RUN useradd -m -u 10001 agent
USER agent
WORKDIR /work
ENTRYPOINT ["mise","exec","--"]
```

Non-root `agent` (User Identifier — UID — 10001), tools on `PATH`.
AddressSanitizer (ASan) is invoked at build time (`clang -fsanitize=address`),
not a package.

</details>

## `mise.toml` — pinned toolchain + tasks

<details>
<summary>Show mise.toml</summary>

```toml
[tools]
python = "3.12"
node   = "22"
rust   = "1.83"
go     = "1.23"
"cargo:cargo-fuzz" = "latest"
"pipx:semgrep"     = "latest"

[env]
_.python.venv = { path = ".venv", create = true }
ASAN_OPTIONS  = "detect_leaks=1:abort_on_error=1"

[tasks.scan]
description = "SAST + dep + container scan"
run = [
  "semgrep --config auto --error src/",
  "grype dir:. --fail-on high",
  "trivy fs --severity HIGH,CRITICAL .",
]

[tasks.fuzz]
description = "Build + run libFuzzer/ASan target"
run = "cargo fuzz run target -- -max_total_time=300"

[tasks."harness-gen"]
description = "Generate a fuzz harness via the agent SDK"
run = "uv run python tools/gen_harness.py --src src/ --out fuzz/"
```

`mise run scan|fuzz|harness-gen`. Version pins make the environment reproducible
across machines. The Python version pinned in this snippet is illustrative; the
repo's actual `mise.toml` pins Python 3.13.

</details>

## `devcontainer.json` — hardened `runArgs`

<details>
<summary>Show devcontainer.json</summary>

```jsonc
{
  "name": "agentic-security",
  "image": "agentic-security:latest",
  "runArgs": [
    "--cap-drop=ALL",
    "--security-opt", "no-new-privileges",
    "--security-opt", "seccomp=default.json",
    "--read-only",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
    "--tmpfs", "/work/.scratch:rw,nosuid,size=1g",
    "--pids-limit", "512",
    "--memory", "4g", "--cpus", "2",
    "--network", "none"
  ],
  "mounts": [
    "source=${localWorkspaceFolder},target=/work,type=bind,consistency=cached"
  ],
  "containerUser": "agent",
  "overrideCommand": true,
  "postCreateCommand": "mise install"
}
```

`runArgs` are passed verbatim to `docker run`. `--read-only` root plus writable
`tmpfs` scratch means any agent-written payload is wiped on teardown. Network
is off by default; see the egress allowlist below to add scoped egress.

</details>

## `workshop.yaml` — Canonical Workshop environment

<details>
<summary>Show workshop.yaml</summary>

```yaml
# Unprivileged LXD system container (LXD >= 6.8).
name: agentic-security
description: Sandboxed environment for the security research agent
image: ubuntu:24.04
resources:
  cpu: 4
  memory: 8GiB
sdks:
  - mise          # toolchain manager
  - opencode      # agent runtime
  - clang-asan    # sanitizer toolchain
interfaces:
  - name: ssh-agent     # forward host SSH agent (scoped, snapd-style)
  - name: network-egress
    config:
      allow:
        - bedrock-runtime.us-east-1.amazonaws.com:443
        - github.com:443
  # GUI/display deliberately NOT requested -> no host display access
provision:
  - mise install
  - mise run scan
```

Workshop runs each environment in an unprivileged LXD container; the
snapd-inspired `interfaces` system grants only the host resources explicitly
listed, so omitting a `display` interface denies graphical-display access
entirely.

</details>

## Firecracker — no-network microVM with vsock

<details>
<summary>Show Firecracker boot script</summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
API=/tmp/fc.sock; rm -f "$API"
firecracker --api-sock "$API" &
put(){ curl -fsS -X PUT --unix-socket "$API" --data "$2" "http://localhost/$1"; }
put boot-source '{"kernel_image_path":"vmlinux-6.1","boot_args":"console=ttyS0 reboot=k panic=1 pci=off"}'
put drives/rootfs '{"drive_id":"rootfs","path_on_host":"rootfs.ext4","is_root_device":true,"is_read_only":true}'
put machine-config '{"vcpu_count":2,"mem_size_mib":2048}'
# vsock host<->guest channel (CID 3) — the ONLY communication path
put vsock '{"vsock_id":"v1","guest_cid":3,"uds_path":"/tmp/fc.vsock"}'
# NOTE: no network-interfaces PUT -> microVM has zero network egress.
put actions '{"action_type":"InstanceStart"}'
```

Read-only root filesystem, no `network-interfaces` call (so no virtual network
interface card at all), and a single virtio-socket Unix Domain Socket (vsock UDS)
for control. Firecracker boots in ~125 ms with ~5 MiB VMM overhead.

</details>

## Egress allowlist

<details>
<summary>Show tinyproxy + allowlist + docker run invocation</summary>

```ini
# tinyproxy.conf  (sidecar; agent container joins its netns)
Port 8888
Listen 127.0.0.1
Timeout 30
Allow 127.0.0.1
FilterDefaultDeny Yes
Filter "/etc/tinyproxy/allow"
```

```text
# /etc/tinyproxy/allow  (regex, anchored)
^bedrock-runtime\.us-east-1\.amazonaws\.com$
^bedrock\.us-east-1\.amazonaws\.com$
^github\.com$
^codeload\.github\.com$
```

```bash
docker run --network=none \
  -e HTTPS_PROXY=http://127.0.0.1:8888 -e HTTP_PROXY=http://127.0.0.1:8888 \
  agentic-security
```

`FilterDefaultDeny Yes` makes the allowlist authoritative.

</details>

## WORM audit-log line

A single line of the hash-chained JSON Lines audit log
([E12](/agentic-security-lab/concepts/ears-invariants/#e12)). The chain format is
fixed in [ADR-005](/agentic-security-lab/adrs/0005-worm-audit-hash-chain/).

<details>
<summary>Show example audit-log entry</summary>

```json
{"ts":"2026-05-29T14:03:21.778Z","seq":4412,"session":"sec-agent-7f3a","actor":"agent:claude","sandbox":{"kind":"firecracker","id":"fc-9b21","net":"none"},"action":"tool_call","tool":"Bash","args":{"cmd":"cargo fuzz run target -- -max_total_time=300"},"egress":[],"exit_code":0,"duration_ms":300214,"artifacts":["fuzz/crash-a1b2"],"prev_hash":"sha256:6f1c…d09","hash":"sha256:b740…e22"}
```

</details>
