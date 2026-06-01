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

- A guest-syscall-driven container escape must first defeat gVisor's userspace kernel
  (the *Sentry*) before reaching a host syscall, narrowing the host kernel attack
  surface to what the Sentry intentionally exposes.
- New isolation tiers (Firecracker, AgentCore) slot in behind the same Protocol.

### Residual attack surface

This ADR does not claim more isolation than gVisor itself claims; see the
[gVisor security model](https://gvisor.dev/docs/architecture_guide/security/).
Specifically, gVisor:

- Mediates guest syscalls into a userspace re-implementation, so direct exploitation
  of seldom-audited Linux kernel subsystems (e.g. obscure netfilter, exotic filesystems)
  from inside the sandbox is not reachable.
- Does **not** eliminate bugs in the Sentry itself — the Sentry is a Go program with
  its own attack surface and CVE history.
- Does **not** replace defense-in-depth: the substrate still runs `--cap-drop=ALL`,
  `--read-only`, a default seccomp profile on the host, `--network=none` by default,
  and rootless Docker, so an escape must defeat the Sentry **and** the layered host
  policy.
- Does **not** protect against side channels, hardware vulnerabilities, or
  misconfigurations of the egress allowlist (E4, E6).

Switching `--platform=systrap` to `--platform=kvm` changes the boundary *mechanism*
(virtualization extensions vs. seccomp `SECCOMP_RET_TRAP`), not the threat model —
both run the same Sentry.

### Negative

- gVisor adds syscall-interception overhead and incompatibility for exotic syscalls.
  **Mitigated** by the `runc` fallback and per-spec opt-out. Split trigger: a workload
  that runsc cannot run correctly forces a per-experiment runtime choice.
