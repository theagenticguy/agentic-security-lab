---
title: Eight foundations → six packages
description: Mapping each whitepaper foundation to its package and the EARS invariants it owns.
---

The whitepaper names eight foundations. The table maps each to the package that owns it
in v1, plus the EARS invariants that package is responsible for. The two plumbing
foundations (SARIF output, governance) are folded into `asec-memory` and `asec-core`.

| Foundation | Package (owner) | EARS invariants |
|---|---|---|
| Sandbox (isolated execution) | `asec-sandbox` | E3, E4, E5, E6 |
| WORM audit log | `asec-sandbox` | E12, E13 |
| Memory: hypothesis board + findings ledger | `asec-memory` | E9, E10, E11 |
| SARIF output *(folded into memory)* | `asec-memory` | E9 (SARIF emission) |
| Skill loader + permission gate | `asec-skills` | E7, E8 |
| Threat-model artifact | `asec-threat-model` | E1, E2 |
| Confidence scorer | `asec-confidence` | E18 (scoring) |
| Orchestrator | `asec-core` | E14, E15, E16, E19 |
| Governance *(folded into core)* | `asec-core` | E18 (dispatch), E19 |

## The two governing invariants

These two are the ones the substrate exists to guarantee, verbatim from the product
framing:

- **E3** — "The system shall execute all target-code experiments inside a throwaway
  sandbox launched with `--network=none` by default." Owned by `asec-sandbox`.
- **E12** — "The system shall append every tool call, sandbox lifecycle event, and gate
  decision to a hash-chained WORM audit log (S3 Object Lock or `chattr +a`)." Owned by
  `asec-sandbox`.

## Merge discipline

Each merge is recorded in ADR-0001 with its split trigger ("split when a second consumer
appears"). Public APIs are re-exported so a future split is mechanical, not a rewrite.
