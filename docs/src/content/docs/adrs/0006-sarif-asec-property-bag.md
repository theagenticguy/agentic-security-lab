---
title: "ADR-006: Own pydantic SARIF v2.1 + `asec` property bag"
description: "Findings must leave the substrate in a format that existing security tooling — GitHub code"
---

# ADR-006: Own pydantic SARIF v2.1 + `asec` property bag

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** AI Engineering NAMER

## Context

Findings must leave the substrate in a format that existing security tooling — GitHub code
scanning, IDEs, dashboards — already ingests, while also carrying the substrate's own
signals: whether a defect is reachable ([E18](/agentic-security-lab/concepts/ears-invariants/#e18)), how exploitable it is, the asset weight, the
derived priority, and pointers to the evidence (PoC, patch, audit log). SARIF v2.1.0 is the
OASIS standard those tools speak, and §3.8 of the spec reserves `properties` bags exactly for
tool-specific extension data. This ADR fixes how we emit SARIF and where our signals live.


<details>
<summary>Decision, alternatives, rationale, consequences</summary>

## Decision

We will **emit SARIF v2.1.0 from our own pydantic models** and attach the substrate's signals
in a single namespaced **`properties.asec`** bag on every result. The bag is the validated
`AsecProperties` value object — `schemaVersion: "asec.v1"`, `reachability`, `exploitability`,
`asset` weight, derived `priority`/`confidence`, and `variants_of`/`hypothesis_id`
correlation links — modeled `frozen=True` with `extra="forbid"` so unknown `asec.*` fields
are rejected rather than silently dropped. Each result also duplicates the reachability
verdict, asset tier, and a bare `asec` marker into the SARIF `tags` array so SARIF-only
consumers can filter without parsing the bag. Crucially, the bag carries **pointers, not
payloads**: URIs to the PoC, the proposed patch, and the audit-log entry — never the blobs
themselves.

## Alternatives Considered

- **Roll our own JSON schema.** Rejected: a bespoke format throws away the entire SARIF tool
  ecosystem (code scanning, viewers) and forces every consumer to learn our shape.
- **Depend on a `sarif-tools`/`sarif-om` library only.** Rejected: we author our own pydantic
  models for type safety, `extra="forbid"` validation of the `asec` contract, and a zero
  third-party dependency on our output surface — the substrate owns its output contract. We
  emit plain dicts conforming to the schema directly.

## Rationale

Per OASIS SARIF v2.1.0 §3.8, property bags are the sanctioned place for tool-specific data,
so `properties.asec` is standards-compliant rather than an abuse of the format: SARIF-aware
tools ignore the bag, while substrate-aware consumers read it. Pointers-not-payloads keeps
SARIF logs small and shifts the heavy evidence to the durable ledger and WORM audit (ADR-005).

## Consequences

### Positive

- Findings flow straight into GitHub code scanning and SARIF viewers with no adapter.
- The `asec.v1` bag is a versioned, validated contract; schema drift fails loudly.

### Negative

- We own the mapping from our models to the SARIF shape as the spec evolves. **Mitigated** by
  the small, centralized `to_sarif_*` functions. Split trigger: SARIF v2.2 or a consumer that
  needs richer `result` fields than we currently emit.


</details>
