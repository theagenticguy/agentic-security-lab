---
title: asec-core
description: Orchestrator, provider-abstract AgentRuntime seam, and governance.
---

## Purpose

`asec-core` is the orchestration hub and the provider-abstract model seam. It merges the
whitepaper's `governance` foundation. Every other package depends on it; it depends on no
other `asec-*` package. It re-exports the Protocols (`SandboxPort`, `LedgerPort`,
`SkillLoaderPort`) that the rest of the substrate is wired against.

## Public types

- `AgentRuntime(Protocol)` — `query`, `stream`, `spawn_subagents`, `register_hook`.
- `ClaudeAgentRuntime` — the only v1 adapter; wraps `ClaudeSDKClient`. A future
  `StrandsRuntime` satisfies the same Protocol without inheritance.
- `Orchestrator.run(scope) -> ReviewResult`.
- `Settings(BaseSettings)`.
- `ScopeArtifact`, `KillSwitch`, `GovernanceGate`.
- Re-exported ports: `SandboxPort`, `LedgerPort`, `SkillLoaderPort`.

## EARS invariants owned

- **E14, E15, E16** — orchestration lifecycle and dispatch.
- **E18 (dispatch)** — routing confidence-scored work; scoring itself lives in `asec-confidence`.
- **E19** — governance / kill-switch enforcement.

## Dependencies

`claude-agent-sdk`, `pydantic`, `structlog`, `opentelemetry-api`, `cyclopts` (CLI
entrypoint), `cryptography` (scope signing).
