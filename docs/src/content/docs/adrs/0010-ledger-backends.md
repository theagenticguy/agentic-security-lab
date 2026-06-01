---
title: "ADR-010: Ledger backends — SQLite local, asyncpg Postgres cloud, PGlite as docs reference"
description: "`asec-memory` ships a `LedgerPort` Protocol — the durable home for findings,"
---

# ADR-010: Ledger backends — SQLite local, asyncpg Postgres cloud, PGlite as docs reference

- **Status:** Accepted
- **Date:** 2026-05-31
- **Deciders:** AI Engineering NAMER

## Context

`asec-memory` ships a `LedgerPort` Protocol — the durable home for findings,
hypotheses, and false-positive suppressions. Day 2 landed the SQLite implementation
(`SQLiteLedger`, aiosqlite) and proves the round-trip from finding → SARIF → ledger →
back works. We need a cloud-grade backend for the AWS path, and we need to be honest
about the role of [PGlite](https://pglite.dev), which surfaced as a candidate.

The asks competing here:

1. Local dev must remain zero-install — clone, `mise run test`, done.
2. Cloud deployments need a managed Postgres so multiple orchestrator instances and
   the WORM audit pipeline share state.
3. `LedgerPort` should not change shape between local and cloud — only the adapter swaps.
4. Engineers running JS-side tooling (the docs site, future Workshop sandboxes,
   browser-based dashboards) might want to rehearse the schema without standing up
   a full Postgres.

## Decision

Ship **two production `LedgerPort` adapters**, plus a third documentation-only path:

1. **`SQLiteLedger`** (default; already shipped) — `aiosqlite`, single-file DB at
   `~/.cache/asec/ledger.db` by default, schema-versioned, indexed. The local-dev
   default and the substrate the apps tests run against. No external dependencies.

2. **`PostgresLedger`** (new, to be implemented) — `asyncpg` driver against a managed
   Postgres (Aurora Serverless v2 in the AWS path, plain RDS or any compatible
   Postgres elsewhere). Same schema as SQLite, generated from the same SQL with a
   small dialect-shim layer. Connection pool sized from `Settings`. Used by the
   cloud orchestrator deployment and by CI integration tests against a throwaway
   container Postgres.

3. **PGlite** is **not a Python runtime backend** — it is a JS/TS-only WASM Postgres
   build. We do not link it into `asec-memory`. We do document it in
   `docs/reference/local-postgres.md` as the right choice for two specific cases:
   (a) JS-side rehearsals of the ledger schema in a browser dev tool, and (b)
   ephemeral CI runners where a JS toolchain already exists. The schema we ship is
   Postgres-compatible enough that PGlite consumes it unchanged, which is the
   payoff for the dialect shim.

The `LedgerPort` Protocol is unchanged. Adapter selection is via `Settings` — set
`ASEC_LEDGER_DRIVER=sqlite|postgres` and the corresponding DSN.

## Alternatives Considered

- **SQLite for everything, including cloud.** Rejected: a single-writer file does not
  fan out across cloud orchestrator workers, and `litestream`-style replication is
  another moving piece without solving the multi-writer story.

- **DynamoDB single-table** (originally floated in PLAN §13). Deferred, not killed.
  We keep the option open behind the same `LedgerPort` Protocol; a `DynamoLedger`
  adapter would land in a follow-up if a customer's compliance posture rules out
  RDS or if cost modeling tilts that way. Postgres is the better v1 default because
  the `asec` SARIF property bag is JSONB-shaped data with a few queryable indexes,
  which Postgres serves natively without schema gymnastics.

- **PGlite-py / embedded-postgres-py** Python wrappers around Postgres binaries.
  Rejected: heavier than SQLite, less battle-tested than asyncpg-against-managed,
  no real win in either dev or prod.

## Rationale

SQLite + asyncpg-Postgres is the standard "two-tier" pattern that keeps local dev
fast and cloud deployments boring. The `LedgerPort` Protocol means the orchestrator
never sees the difference, and the test suite runs the same exercises against both
adapters in CI. PGlite earns a docs page, not a dependency: it solves a real problem
for JS-side engineers but creates none for Python.

## Consequences

### Positive

- Zero new Python deps in v1: SQLite ships with the runtime; asyncpg arrives only
  when the cloud adapter does, behind a dependency group.
- Schema rehearsal in a browser via PGlite is a nice-to-have engineers can adopt
  without our buy-in.
- DynamoDB stays available as a future swap; nothing in v1 forecloses on it.

### Negative

- A small dialect-shim layer is needed (SQLite vs. Postgres differ on JSON1 vs.
  JSONB, default UUIDs, returning-clauses). Mitigated by keeping the schema flat
  and using SQL the both dialects speak, with adapter-private overrides for the
  diverging bits.
- The ADR's "PGlite is documentation only" stance must hold: if someone ports the
  ledger to PGlite-via-Pyodide, we will own that complexity. The split trigger is
  any PR that adds PGlite as a runtime dependency to a Python package.
