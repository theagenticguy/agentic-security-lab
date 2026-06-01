---
title: "ADR-004: SQLite + DynamoDB single-table ledger"
description: "`asec-memory` owns the durable home for findings, hypotheses, and false-positive"
---

# ADR-004: SQLite + DynamoDB single-table ledger

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** AI Engineering NAMER

## Context

`asec-memory` owns the durable home for findings, hypotheses, and false-positive
suppressions (E9–E11). Local dev must stay zero-install (clone, `mise run test`, done), and
the cloud path needs a backend that fans out across orchestrator workers and feeds the WORM
audit pipeline. The orchestrator depends only on a `LedgerPort` Protocol, so the backend can
swap without changing the contract. This ADR fixes the Protocol's access patterns and names
the candidate backends; ADR-010 supersedes the *cloud default* choice (it picks asyncpg
Postgres over DynamoDB), so this ADR records the DynamoDB single-table design as the
in-scope-but-deferred alternative and freezes the shared access patterns.

## Decision

We will keep **`LedgerPort` as the Protocol** (`add_finding` / `get_finding` /
`list_findings` / `add_hypothesis` / `add_suppression` / `find_similar`). The **default and
only shipped adapter is `SQLiteLedger`** (aiosqlite, WAL mode for concurrent fan-out writers,
single versioned file, JSON payload columns rehydrated through Pydantic). A **`DynamoLedger`
adapter is deferred but in scope**, designed against a **single-table model**: `PK` =
entity-scoped partition key (e.g. `FINDING#<id>`, `HYPO#<session>`), `SK` = sort key for
range reads, and a **GSI1 keyed on `status`** to serve the open-hypotheses and
suppression-by-rule reads without table scans. The access patterns are frozen here:
finding-by-id, findings-by-priority (descending), suppressions-by-(rule, location), and
hypotheses-by-status. Adapter selection is via `Settings`; the Protocol is unchanged across
backends.

## Alternatives Considered

- **A fully relational schema (many tables, foreign keys).** Rejected: the payloads are
  self-contained JSON value objects with a handful of queryable indexes — a normalized
  relational model over-models data we read back whole.
- **Pure SQLite for the cloud too.** Rejected: a single-writer file does not fan out across
  cloud workers; replication is another moving piece.
- **Aurora Serverless v2 via asyncpg.** This is the chosen cloud default — see **ADR-010**,
  which picks Postgres over DynamoDB because the `asec.v1` SARIF bag is JSONB-shaped data
  Postgres serves natively. DynamoDB stays available behind the same Protocol for compliance
  postures that rule out RDS.

## Rationale

SQLite-first keeps local dev fast and dependency-free; freezing the access patterns now means
any future backend (DynamoDB single-table or Postgres) is a query-mapping exercise, not a
contract change.

## Consequences

### Positive

- Zero new Python deps in v1; cloud drivers arrive behind a dependency group when needed.
- A frozen access-pattern list makes the DynamoDB single-table design a mechanical port.

### Negative

- A DynamoDB single-table design is unforgiving once access patterns drift. **Mitigated** by
  freezing them here. Split trigger: a new read pattern that GSI1 cannot serve forces a
  schema (and ADR) revision.
