---
title: asec-memory
description: Hypothesis board, findings ledger, and SARIF v2.1 emission.
---

## Purpose

`asec-memory` holds the agent's working memory and the durable store for
findings, and emits results as Static Analysis Results Interchange Format (SARIF)
v2.1. It also folds in the design's `output` foundation, so SARIF emission lives
next to the ledger that produced it. The local-default ledger is SQLite; the
cloud path is PostgreSQL via `asyncpg`. See
[ADR-010](/agentic-security-lab/adrs/0010-ledger-backends/) for the backend
decision and [ADR-006](/agentic-security-lab/adrs/0006-sarif-asec-property-bag/)
for the SARIF property-bag schema.

## Public types

- `Finding`, `Hypothesis`, `Suppression` (Pydantic value objects, `frozen=True`).
- `LedgerPort` implementations:
  - `SQLiteLedger` (`aiosqlite`) — local default; zero external dependencies.
  - `PostgresLedger` (`asyncpg`) — cloud path against managed PostgreSQL
    (Aurora Serverless v2 or RDS).
  - `DynamoLedger` — deferred behind the same Protocol; design frozen in
    [ADR-004](/agentic-security-lab/adrs/0004-sqlite-and-dynamodb-single-table-ledger/).
- `HypothesisBoard` — append-only.
- `to_sarif(findings) -> SarifReport` — SARIF v2.1 with the `asec` property bag.
- `ReportAgent(Protocol)` — Executive / Engineering / Auditor report personas.

## EARS invariants owned

- [**E9**](/agentic-security-lab/concepts/ears-invariants/#e9) — hypothesis board
  is append-only.
- [**E10**](/agentic-security-lab/concepts/ears-invariants/#e10) — every confirmed
  finding is persisted durably and emitted as SARIF v2.1 with the `asec`
  property bag.
- [**E11**](/agentic-security-lab/concepts/ears-invariants/#e11) — at end of run,
  every SARIF result carries a confidence score and a back-reference to its
  originating hypothesis-board entry.

## Dependencies

`pydantic`, `aiosqlite`, `structlog`, `opentelemetry-api`, `sarif-tools` (ingest
only). `aioboto3` extra for the deferred DynamoDB adapter; `asyncpg` extra for
the cloud Postgres adapter.
