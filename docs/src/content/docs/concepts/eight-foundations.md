---
title: Eight foundations → six packages
description: Each foundation in the v1.3 design and the asec-* package that owns it, with EARS invariants.
sidebar:
  order: 2
---

The v1.3 design lists eight foundations. The v1 codebase implements them across
six `asec-*` packages: the two single-consumer foundations (`output` and
`governance`) are merged into the closest sibling package, and the rest stay
distinct. Every Easy Approach to Requirements Syntax (EARS) invariant linked
below is the verbatim "The system shall…" requirement from the
[EARS invariants page](/agentic-security-lab/concepts/ears-invariants/).

| Foundation | Package (owner) | EARS invariants owned |
|---|---|---|
| Sandbox isolation | `asec-sandbox` | [E3](/agentic-security-lab/concepts/ears-invariants/#e3), [E4](/agentic-security-lab/concepts/ears-invariants/#e4), [E5](/agentic-security-lab/concepts/ears-invariants/#e5), [E6](/agentic-security-lab/concepts/ears-invariants/#e6) |
| Write-Once-Read-Many (WORM) audit log | `asec-sandbox` | [E12](/agentic-security-lab/concepts/ears-invariants/#e12), [E13](/agentic-security-lab/concepts/ears-invariants/#e13) |
| Memory: hypothesis board + findings ledger | `asec-memory` | [E9](/agentic-security-lab/concepts/ears-invariants/#e9), [E10](/agentic-security-lab/concepts/ears-invariants/#e10), [E11](/agentic-security-lab/concepts/ears-invariants/#e11) |
| SARIF output *(merged into memory)* | `asec-memory` | [E10](/agentic-security-lab/concepts/ears-invariants/#e10) (SARIF emission), [E11](/agentic-security-lab/concepts/ears-invariants/#e11) |
| Skill loader + permission gate | `asec-skills` | [E7](/agentic-security-lab/concepts/ears-invariants/#e7), [E8](/agentic-security-lab/concepts/ears-invariants/#e8) |
| Threat-model artifact | `asec-threat-model` | [E1](/agentic-security-lab/concepts/ears-invariants/#e1), [E2](/agentic-security-lab/concepts/ears-invariants/#e2) |
| Confidence scorer | `asec-confidence` | [E18](/agentic-security-lab/concepts/ears-invariants/#e18) (scoring) |
| Orchestrator | `asec-core` | [E14](/agentic-security-lab/concepts/ears-invariants/#e14), [E15](/agentic-security-lab/concepts/ears-invariants/#e15), [E16](/agentic-security-lab/concepts/ears-invariants/#e16), [E19](/agentic-security-lab/concepts/ears-invariants/#e19) |
| Governance *(merged into core)* | `asec-core` | [E18](/agentic-security-lab/concepts/ears-invariants/#e18) (dispatch), [E19](/agentic-security-lab/concepts/ears-invariants/#e19) |

## The two structural invariants

Two of the 19 invariants are enforced *structurally* — by the deny-default
networking and append-only file format — rather than by policy:

- [**E3**](/agentic-security-lab/concepts/ears-invariants/#e3) — every target-code
  experiment runs inside a throwaway sandbox launched with `--network=none` by
  default. Owned by `asec-sandbox`.
- [**E12**](/agentic-security-lab/concepts/ears-invariants/#e12) — every tool call,
  sandbox lifecycle event, and gate decision appends to a hash-chained WORM audit
  log (Amazon S3 Object Lock or `chattr +a`). Owned by `asec-sandbox`.

## Merge discipline

Each merge is recorded in
[ADR-001](/agentic-security-lab/adrs/0001-adopt-claude-agent-sdk/) with its
*split trigger* — the condition under which the merge would be reversed (for
example, "split when a second consumer of the merged interface appears"). Public
types are re-exported from the merged package so a future split is a file move,
not an API change.
