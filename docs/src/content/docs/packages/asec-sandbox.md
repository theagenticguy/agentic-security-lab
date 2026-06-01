---
title: asec-sandbox
description: Isolated target-code execution and the hash-chained WORM audit-log writer.
---

## Purpose

`asec-sandbox` runs target-code experiments in throwaway isolation and writes the
tamper-evident audit log. It owns the two structural invariants of the codebase
([E3](/agentic-security-lab/concepts/ears-invariants/#e3) and
[E12](/agentic-security-lab/concepts/ears-invariants/#e12)). See
[Sandbox configurations](/agentic-security-lab/reference/sandbox-configs/) for
the copy-paste-ready isolation definitions and
[ADR-003](/agentic-security-lab/adrs/0003-docker-rootless-sandbox-gvisor/) for
the gVisor decision and its threat model.

## Public types

- `SandboxSpec` — `kind: Literal["docker","firecracker","agentcore"]`,
  `network="none"` default, egress allowlist, resource limits.
- `Sandbox(Protocol)` — `start` / `exec` / `collect_artifacts` / `teardown`.
- `DockerSandbox` — rootless, `--cap-drop=ALL`, `--read-only`, seccomp, tmpfs,
  non-root user (UID 10001).
- `WormAuditWriter.append(entry) -> str` — SHA-256 `prev_hash`-chained JSON
  Lines. The canonicalization conforms to a documented subset of RFC 8785;
  see [ADR-005](/agentic-security-lab/adrs/0005-worm-audit-hash-chain/).
- Firecracker and AgentCore sandboxes are stubs in v1.

## EARS invariants owned

- [**E3**](/agentic-security-lab/concepts/ears-invariants/#e3) — every experiment
  runs in a throwaway sandbox launched with `--network=none` by default.
- [**E4**](/agentic-security-lab/concepts/ears-invariants/#e4),
  [**E5**](/agentic-security-lab/concepts/ears-invariants/#e5),
  [**E6**](/agentic-security-lab/concepts/ears-invariants/#e6) — egress
  allowlist, wall-clock time-box, blocked-attempt logging.
- [**E12**](/agentic-security-lab/concepts/ears-invariants/#e12) — every tool
  call, lifecycle event, and gate decision appends to the WORM log.
- [**E13**](/agentic-security-lab/concepts/ears-invariants/#e13) — chain
  verification halts a run if tampering is detected.

## Dependencies

`pydantic`, `anyio`, `structlog`, `opentelemetry-api`. `boto3` extra for the S3
Object Lock path.
