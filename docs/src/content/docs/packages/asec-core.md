---
title: asec-core
description: Orchestrator, agent-runtime Protocol, and governance / kill-switch enforcement.
---

## Purpose

`asec-core` is the orchestration hub and the agent-runtime boundary. It folds in
the design's `governance` foundation. Every other package depends on it; it
depends on no other `asec-*` package. It re-exports the `typing.Protocol` types
(`SandboxPort`, `LedgerPort`, `SkillLoaderPort`) the rest of the codebase is
written against. See
[ADR-002](/agentic-security-lab/adrs/0002-agent-runtime-protocol/) for the
runtime-swap mechanism.

## Public types

- `AgentRuntime(Protocol)` — `query`, `stream`, `spawn_subagents`,
  `register_hook`. The only v1 implementation is `ClaudeAgentRuntime`, wrapping
  `ClaudeSDKClient`. A future adapter (`OpenAIAgentsRuntime`,
  `DeepAgentsRuntime`, `OpenCodeRuntime`) satisfies the same Protocol without
  inheritance.
- `Orchestrator.run(scope) -> ReviewResult`.
- `Settings(BaseSettings)`.
- `ScopeArtifact`, `KillSwitch`, `GovernanceGate`.
- Re-exported ports: `SandboxPort`, `LedgerPort`, `SkillLoaderPort`.

## EARS invariants owned

- [**E14**](/agentic-security-lab/concepts/ears-invariants/#e14) — budget
  enforcement.
- [**E15**](/agentic-security-lab/concepts/ears-invariants/#e15) — kill-switch
  termination + audit-log seal.
- [**E16**](/agentic-security-lab/concepts/ears-invariants/#e16) — human gate on
  externally visible actions.
- [**E18**](/agentic-security-lab/concepts/ears-invariants/#e18) (dispatch) —
  routing confidence-scored work; the score itself lives in `asec-confidence`.
- [**E19**](/agentic-security-lab/concepts/ears-invariants/#e19) — runtime
  tool-authorship governance.

## Dependencies

`claude-agent-sdk`, `pydantic`, `structlog`, `opentelemetry-api`, `cyclopts`
(command-line interface entrypoint), `cryptography` (scope signing).
