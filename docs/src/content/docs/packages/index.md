---
title: Packages
description: The six asec-* packages and what each one owns.
---

The codebase is six `asec-*` Python packages. Each owns a distinct seam and a
set of [EARS invariants](/agentic-security-lab/concepts/ears-invariants/).
Dependency direction is strict: `apps → packages → asec-core`, with cross-package
coupling only via `typing.Protocol` types re-exported from `asec-core`.

| Package | One-line description |
|---|---|
| [`asec-core`](/agentic-security-lab/packages/asec-core/) | Orchestrator + `AgentRuntime` Protocol seam + governance gate. |
| [`asec-sandbox`](/agentic-security-lab/packages/asec-sandbox/) | Isolated target-code execution + hash-chained Write-Once-Read-Many (WORM) audit-log writer. |
| [`asec-memory`](/agentic-security-lab/packages/asec-memory/) | Hypothesis board + findings ledger + Static Analysis Results Interchange Format (SARIF) v2.1 output. |
| [`asec-skills`](/agentic-security-lab/packages/asec-skills/) | `SKILL.md` loader + deny-by-default PreToolUse permission gate. |
| [`asec-threat-model`](/agentic-security-lab/packages/asec-threat-model/) | Phase-Zero Pydantic threat-model artifacts + diff. |
| [`asec-confidence`](/agentic-security-lab/packages/asec-confidence/) | Three-axis (pattern, recall, reachability) confidence scorer. |

## Shared conventions

- All public types are Pydantic v2 (`frozen=True` for value objects).
- All input/output is async.
- Every module gets `structlog.get_logger()` plus an OpenTelemetry span at
  entry points.
- Every package ships `py.typed`; tests live in each package's `tests/`.
