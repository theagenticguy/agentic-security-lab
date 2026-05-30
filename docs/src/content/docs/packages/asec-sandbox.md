---
title: asec-sandbox
description: Isolated target-code execution and the hash-chained WORM audit writer.
---

## Purpose

`asec-sandbox` runs target-code experiments in throwaway isolation and writes the
tamper-evident audit log. It owns the two governing invariants of the whole lab (E3, E12).
See [Sandbox configs](/agentic-security-lab/reference/sandbox-configs/) for the
copy-paste-ready isolation definitions.

## Public types

- `SandboxSpec` — `kind: Literal["docker","firecracker","agentcore"]`, `network="none"`
  default, egress allowlist, resource limits.
- `Sandbox(Protocol)` — `start` / `exec` / `collect_artifacts` / `teardown`.
- `DockerSandbox` — rootless, `--cap-drop=ALL`, `--read-only`, seccomp, tmpfs, UID 10001.
- `WormAuditWriter.append(entry) -> str` — SHA-256 `prev_hash` chained JSONL.
- Firecracker / AgentCore sandboxes are stubs in v1.

## EARS invariants owned

- **E3** — all experiments run in a throwaway sandbox launched `--network=none` by default.
- **E4, E5, E6** — isolation hardening (caps, read-only root, limits).
- **E12** — every tool call, lifecycle event, and gate decision appends to the WORM log.
- **E13** — tamper-evident chain (canonical JSON, `prev_hash`, CI chain-verification gate).

## Dependencies

`pydantic`, `anyio`, `structlog`, `opentelemetry-api`; `boto3` extra (S3 Object Lock).
