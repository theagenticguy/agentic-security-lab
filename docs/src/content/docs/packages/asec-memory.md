---
title: asec-memory
description: Hypothesis board, findings ledger, and SARIF output.
---

## Purpose

`asec-memory` holds the agent's working memory and the findings store, and emits SARIF.
It merges the whitepaper's `output` foundation.

## Public types

- `Finding`, `Hypothesis`, `Suppression` (pydantic value objects).
- `LedgerPort` implementations: `SQLiteLedger` (aiosqlite, default) and `DynamoLedger`
  (single-table; stub → real on Day 4).
- `HypothesisBoard` — append-only.
- `to_sarif(findings) -> SarifReport` — SARIF v2.1 with the `x-bonk` extension.
- `ReportAgent(Protocol)` — Executive / Engineering / Auditor report personas.

## EARS invariants owned

- **E9** — findings persistence + SARIF emission.
- **E10, E11** — hypothesis board append-only semantics and ledger integrity.

## Dependencies

`pydantic`, `aiosqlite`, `structlog`, `opentelemetry-api`, `sarif-tools` (ingest only);
`aioboto3` extra (DynamoDB).
