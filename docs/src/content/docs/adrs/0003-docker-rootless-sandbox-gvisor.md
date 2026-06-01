---
title: "ADR-003: Docker rootless sandbox behind the `Sandbox` protocol"
description: "The substrate runs experiments against untrusted target code (E3–E6): it must execute"
---

# ADR-003: Docker rootless sandbox behind the `Sandbox` protocol

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** AI Engineering NAMER

## Context

The substrate runs experiments against untrusted target code (E3–E6): it must execute
attacker-influenced programs to verify hypotheses, then throw the environment away. That
demands a real isolation boundary with deny-by-default networking, dropped capabilities, a
read-only root, bounded resources, and artifacts copied *out* rather than bind-mounted out.
The orchestrator must depend on the isolation *contract*, not on any one backend, so the
boundary can harden over time without rippling upward. This ADR fixes the sandbox seam and
its v1 default.

## Decision

We will define **`Sandbox` as an async `Protocol`** (`start`/`exec`/`collect_artifacts`/
`teardown`, mirroring `asec_core.SandboxPort`) with two adapters: **`LocalSandbox`** (a
no-isolation passthrough, *tests and bootstrapping only*) and **`DockerSandbox`**, the real
backend. `DockerSandbox` launches a long-lived hardened container — `--cap-drop=ALL`,
`--security-opt no-new-privileges`, `--read-only` root, tmpfs scratch, `--pids-limit` /
`--memory` / `--cpus` caps, and `--network=none` by default — with the target repo
bind-mounted read-only at `/work`. **gVisor `runsc --platform=systrap` is the v1 default**
isolation runtime; Docker rootless `runc` is the fallback when `runsc` is not registered
(`allow_fallback=True`, recorded as a WORM `gate_decision`), otherwise an unavailable
`runsc` is a hard error. `GVisorSandbox` is a thin subclass that defaults `kind="gvisor"`,
because runsc is a runtime flag, not a class. When a spec requests `allowlist` networking,
the only egress path is an `internal=true` Docker network plus a tinyproxy sidecar enforcing
an anchored-regex host allowlist (deny-default). See ADR-009 for the gVisor/EC2 substrate.

## Alternatives Considered

- **Full VM per experiment (Firecracker/QEMU).** Rejected for v1: strongest boundary but
  heavy to operate; kept in the `SandboxKind` enum (`firecracker`) for a future tier.
- **bubblewrap / firejail.** Rejected: namespace/seccomp sandboxes share the host kernel
  syscall surface directly — a weaker boundary than gVisor's userspace kernel.
- **Bare Docker without runsc.** Rejected as the default: a shared host kernel means a
  container escape has a host-wide blast radius. runsc interposes a userspace kernel.

## Rationale

gVisor systrap gives a strong syscall boundary on any Nitro VM without needing
virtualization extensions, while the Protocol keeps the orchestrator backend-agnostic.
Deny-by-default network + read-only root + cap-drop satisfy E3/E4 structurally rather than
by policy.

## Consequences

### Positive

- A container escape must first defeat gVisor's userspace kernel before reaching the host.
- New isolation tiers (Firecracker, AgentCore) slot in behind the same Protocol.

### Negative

- gVisor adds syscall-interception overhead and incompatibility for exotic syscalls.
  **Mitigated** by the `runc` fallback and per-spec opt-out. Split trigger: a workload that
  runsc cannot run correctly forces a per-experiment runtime choice.
