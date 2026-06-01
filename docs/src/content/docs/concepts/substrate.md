---
title: How it works
description: The read-run-verify loop, the three faculties, and the six asec-* packages that implement them.
sidebar:
  order: 1
---

The agent's job is to **find security vulnerabilities, prove them with
working exploits, and propose patches**. v1 implements that as a closed
loop:

1. **Read.** Claude Opus 4.8 reads the target repo, the seed
   `threat-model.yaml`, and the diff under review. It authors hypotheses —
   "this `account_api` handler may be vulnerable to Insecure Direct Object
   Reference (CWE-639)" — and prioritizes them by reachability from
   untrusted entry points.
2. **Run.** The orchestrator dispatches each hypothesis to a per-experiment
   Docker / gVisor sandbox (`--network=none` by default). The agent
   compiles, runs, fuzzes, and exploits the target code in isolation.
3. **Verify.** A hypothesis is confirmed only if the sandbox produces a
   working Proof of Concept (PoC) — an attacker input that triggers the
   defect and an observed effect that proves exploitability. Confirmed
   vulnerabilities land in a durable ledger and are emitted as Static
   Analysis Results Interchange Format (SARIF) v2.1 with URIs to the PoC,
   a proposed patch, and the audit-log entry.

This trades a Static Application Security Testing (SAST) flood for an
exploit-verified loop. The agent earns each finding by observing the
behavior, not by pattern-matching alone. False positives are suppressed by
name in the false-positive memory; **variants** of confirmed bugs are
tracked across sessions, so a hit on `account_api` triggers a Big-Sleep-
style sweep for the same shape elsewhere on the next nightly run.

## The three faculties

| Faculty | What it is | Implemented in |
|---|---|---|
| Eyes | Claude Opus 4.8 on Amazon Bedrock — lexical + abstract syntax tree (AST) + cross-reference search; Phase-Zero threat-model authoring; hypothesis generation | `asec-core` (`AgentRuntime` Protocol + `ClaudeAgentRuntime`) |
| Hands | A per-experiment sandbox: Docker rootless or gVisor `runsc`, `--cap-drop=ALL`, `--read-only`, deny-default networking, optional egress allowlist sidecar. Compiles, runs, fuzzes, exploits | `asec-sandbox` |
| Memory | An append-only hypothesis board, a durable findings ledger (SQLite locally, Postgres in cloud), false-positive suppressions, a hash-chained audit log of every tool call and gate decision | `asec-memory` (board + ledger) and `asec-sandbox` (audit log) |

## High-level architecture

```mermaid
flowchart TD
    App[apps/pr-reviewer] --> Core[asec-core: orchestrator + AgentRuntime + governance]
    Core -->|SkillLoaderPort| Skills[asec-skills: SKILL.md loader + PreToolUse gate]
    Core -->|SandboxPort| Sandbox[asec-sandbox: isolated exec + WORM audit]
    Core -->|LedgerPort| Memory[asec-memory: hypothesis board + ledger + SARIF]
    Core --> TM[asec-threat-model: Pydantic threat-model artifacts]
    Core --> Conf[asec-confidence: three-axis scorer]
    Core -->|InvokeModel| Bedrock[(Amazon Bedrock — Claude Opus 4.8)]
    Sandbox -->|hash-chained JSONL| Worm[(WORM audit log)]
    Memory -->|SARIF v2.1 + asec property bag| Sarif[(findings.sarif)]
```

## Confidence dispatch

Not every candidate vulnerability deserves the same effort. `asec-confidence`
scores each one on three axes — pattern match, memory recall, reachability —
and the orchestrator picks the cheapest mode whose confidence band is
sufficient:

| Score | Mode | What runs |
|---|---|---|
| ≥ 0.85 | Specialized worker | One focused agent built for that vulnerability class (e.g. SQLi, deserialization) |
| ≥ 0.70 | Parallel shell | A few specialists in parallel; first confirmation wins |
| ≥ 0.40 | Swarm | Broad fan-out across hypothesis families |
| < 0.40 | Runtime tool authorship | The agent writes a custom probe and gates it through the same `allowed-tools` contract |

Cheap deterministic paths run first; expensive autonomy is earned, not
default. Scoring math is fixed in
[ADR-008](/agentic-security-lab/adrs/0008-pluggable-confidence-strategy-bm25/);
dispatch lives in `asec-core`.

## Patch proposal and the human gate

A confirmed vulnerability ships with a proposed patch (a unified diff the
agent generates from the PoC and the surrounding code). The patch is
attached to the SARIF result by URI, not inlined. **No patch is applied,
no PR comment is posted, and no public action is taken without explicit
human approval** — see
[E16](/agentic-security-lab/concepts/ears-invariants/#e16). The agent
proposes; a human disposes.

## Phase Zero: agent authors its own threat model

When a new repository has no `threat-model.yaml`, the agent writes one
(boundaries, assets, data-flow diagram, STRIDE threats) **before**
dispatching any audit worker. The threat model is a first deliverable the
agent owns, not a prerequisite a human has to draft. This is what unlocks
autonomous onboarding on an unfamiliar repo. v1 ships with a hand-written
fixture; Phase Zero authoring is wired but not exercised end-to-end yet.

## Adversarial CI: re-audit the agent

The agent itself is software with skills, prompts, and tool calls — it is
an attack surface in its own right. A continuous-integration job runs four
planted-canary classes against a hermetic fake `AgentRuntime` on every
change to skills, prompts, or the orchestrator, and blocks deploy on any
miss. Details: [Adversarial CI in the README](https://github.com/theagenticguy/agentic-security-lab#adversarial-ci).

## Why six packages

The eight foundations from the design document collapse into six packages.
v1 merges the two single-consumer plumbing pieces — `output` into `memory`
and `governance` into `core` — and keeps every other seam distinct.

- **Eight packages** would over-split: `asec-output` and `asec-governance`
  each have exactly one v1 consumer.
- **Four packages** would over-merge: folding `threat-model` and
  `confidence` into `core` erases two seams that own distinct invariants
  and are independently testable as pure-logic units.
- **Six packages** is the minimum that keeps every distinct boundary.

Each merge is recorded with a *split trigger* — the condition under which
the merge would be reversed. Public types are re-exported so a future split
is a file move, not an Application Programming Interface (API) change.

## Dependency direction

Strict and one-way: `apps → packages → asec-core`. No package imports
another's concrete class; cross-package coupling is via `typing.Protocol`
re-exported from `asec-core` (`SandboxPort`, `LedgerPort`,
`SkillLoaderPort`). An alternate agent-runtime adapter (e.g.
`OpenAIAgentsRuntime`, `DeepAgentsRuntime`, `OpenCodeRuntime`) can satisfy
the `AgentRuntime` Protocol without inheritance coupling — see
[ADR-002](/agentic-security-lab/adrs/0002-agent-runtime-protocol/).

## Substrate contract

The behaviors above — sandbox isolation, deny-by-default tool gating,
append-only memory, hash-chained audit, human gate on externally visible
actions — are formalized as 19
[Easy Approach to Requirements Syntax (EARS) invariants](/agentic-security-lab/concepts/ears-invariants/).
Each `asec-*` package owns a subset and tests against it directly. The
invariants are the security contract; this page is the design overview.
