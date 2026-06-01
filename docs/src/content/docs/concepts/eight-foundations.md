---
title: Foundations and packages
description: Eight design-document foundations mapped to the six asec-* packages that implement them.
sidebar:
  order: 4
---

The whitepaper-v1.3 design lists eight foundations the agent depends on:

1. **Sandbox** — isolated, throwaway execution; `--network=none` default;
   egress-allowlist sidecar.
2. **Memory** — per-session hypothesis board (append-only), durable findings
   ledger, false-positive memory.
3. **Skills** — `SKILL.md` discovery; `allowed-tools` contract enforced by a
   PreToolUse hook.
4. **Threat-model artifact** — `threat-model.yaml` + `assets.yaml` + data-flow
   diagram, agent-authored in Phase Zero.
5. **Confidence scorer** — three-axis (pattern × recall × reachability),
   drives orchestration tiering.
6. **Orchestrator** — drives the agent runtime; programmatic subagent
   fan-out under the confidence gate.
7. **Output** — Static Analysis Results Interchange Format (SARIF) v2.1
   with the `asec` property bag; per-persona reports (Executive,
   Engineering, Auditor).
8. **Governance** — signed scope artifact, time-boxed credentials, kill
   switch, OWASP LLM01/06 controls.

The v1 codebase implements those foundations across **six** `asec-*`
packages. The two single-consumer plumbing foundations are merged into
their closest siblings: `output` into `memory`, `governance` into `core`.
Every other seam stays distinct.

| Foundation | Package (owner) |
|---|---|
| Sandbox | `asec-sandbox` |
| Audit log *(part of sandbox)* | `asec-sandbox` |
| Memory: hypothesis board + findings ledger | `asec-memory` |
| SARIF output *(merged into memory)* | `asec-memory` |
| Skill loader + permission gate | `asec-skills` |
| Threat-model artifact | `asec-threat-model` |
| Confidence scorer | `asec-confidence` |
| Orchestrator | `asec-core` |
| Governance *(merged into core)* | `asec-core` |

Each merge is recorded with a *split trigger* — the condition under which
the merge would be reversed (for example, "split when a second consumer of
the merged interface appears"). Public types are re-exported from the
merged package so a future split is a file move, not an Application
Programming Interface (API) change. See
[ADR-001](/agentic-security-lab/adrs/0001-adopt-claude-agent-sdk/).

## What each package guarantees

The structural-invariants table is on the
[EARS invariants page](/agentic-security-lab/concepts/ears-invariants/). The
two that govern v1 day-to-day are:

- The sandbox launches with `--network=none` by default — every target-code
  experiment runs in throwaway isolation. (Owned by `asec-sandbox`.)
- Every tool call, sandbox lifecycle event, and gate decision appends to a
  hash-chained Write-Once-Read-Many (WORM) audit log (Amazon S3 Object Lock
  or `chattr +a`). (Owned by `asec-sandbox`.)
