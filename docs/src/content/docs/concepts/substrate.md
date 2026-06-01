---
title: Architecture
description: Six Python packages, the seam each one owns, and how they depend on each other.
sidebar:
  order: 1
---

The `asec-*` packages are the runtime, sandbox, ledger, and audit-log layers a
code-analysis agent depends on. They are designed for a Claude Opus 4.8 agent on
Amazon Bedrock today, but the agent-runtime boundary is a `typing.Protocol` so a
different runtime is a swap rather than a rewrite
(see [ADR-001](/agentic-security-lab/adrs/0001-adopt-claude-agent-sdk/) and
[ADR-002](/agentic-security-lab/adrs/0002-agent-runtime-protocol/)).

The mapping from the design's eight foundations to v1's six packages is at
[Eight foundations → six packages](/agentic-security-lab/concepts/eight-foundations/).
The full list of [EARS invariants](/agentic-security-lab/concepts/ears-invariants/)
the layers enforce is on its own page.

## High-level architecture

```mermaid
flowchart TD
    App[apps/pr-reviewer] --> Core[asec-core: Orchestrator + AgentRuntime + governance]
    Core -->|SkillLoaderPort| Skills[asec-skills: SKILL.md loader + PreToolUse gate]
    Core -->|SandboxPort| Sandbox[asec-sandbox: isolated exec + WORM audit]
    Core -->|LedgerPort| Memory[asec-memory: hypothesis board + ledger + SARIF]
    Core --> TM[asec-threat-model: pydantic threat-model artifacts]
    Core --> Conf[asec-confidence: three-axis scorer]
    Core -->|InvokeModel| Bedrock[(Amazon Bedrock — Claude Opus 4.8)]
    Sandbox -->|hash-chained JSONL| Worm[(WORM audit log)]
    Memory -->|SARIF v2.1 + asec property bag| Sarif[(findings.sarif)]
```

## Dependency direction

Strict and one-way: `apps → packages → asec-core`. No package imports another's
concrete class; cross-package coupling is via `typing.Protocol` re-exported from
`asec-core` (`SandboxPort`, `LedgerPort`, `SkillLoaderPort`). An alternate
agent-runtime adapter (e.g. `OpenAIAgentsRuntime`, `DeepAgentsRuntime`,
`OpenCodeRuntime`) can satisfy the `AgentRuntime` Protocol without inheritance
coupling — see ADR-002.

## Why six packages, not eight or four

Three options were considered while folding the design's eight foundations into
the v1 codebase:

- **Eight packages** — over-splits: `asec-output` and `asec-governance` each have
  exactly one v1 consumer, so a separate package for each adds boundary cost
  without buying isolation.
- **Four packages** — over-merges: folding `threat-model` and `confidence` into
  `core` erases two seams that own distinct EARS invariants
  ([E1/E2](/agentic-security-lab/concepts/ears-invariants/#e1),
  [E18](/agentic-security-lab/concepts/ears-invariants/#e18)) and are
  independently testable as pure-logic units.
- **Six packages** — chosen. Keep every seam that owns an invariant; merge only
  the two pure plumbing foundations (`output` → `memory`, `governance` → `core`).

Each merge is recorded with a *split trigger* — the condition under which the
merged package would be split back out. Public APIs are re-exported so a future
split is mechanical, not a rewrite.
