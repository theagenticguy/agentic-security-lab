---
title: Local Postgres rehearsal — PGlite
description: When (and how) to use PGlite to rehearse the asec-memory schema in a browser or JS-only CI runner.
sidebar:
  order: 30
---

The findings ledger ships with two production backends — `SQLiteLedger` (local
default) and `PostgresLedger` (cloud, asyncpg) — under the same `LedgerPort`
Protocol. Neither is the right answer for engineers working from the docs site
or a JS-only runner who want to *try the schema* without spinning up Postgres.
That niche is what [**PGlite**](https://pglite.dev) covers.

PGlite is a WASM Postgres build packaged as a TypeScript/JavaScript library
(`@electric-sql/pglite`). It runs in the browser, Node, and Bun. It is **not**
a runtime dependency of any Python package in this monorepo — see
[ADR-010](/agentic-security-lab/adrs/0010-ledger-backends/) for the decision.

## When this page applies to you

- You are iterating on the JS-side docs tooling and want a Postgres-compatible
  store backing a sample dashboard without a Docker dependency.
- You are running CI in a runner that already has Node but not a Postgres
  service container.
- You want a 60-second sanity check that our SQL applies cleanly under
  Postgres semantics (JSONB, UUID defaults) before opening a PR that touches
  the schema.

For all other cases — running tests, running `apps/pr-reviewer`, running the
cloud orchestrator — use SQLite or the real Postgres.

## Spin up

```bash
pnpm add @electric-sql/pglite
```

```ts
import { PGlite } from "@electric-sql/pglite";

const db = new PGlite();           // in-memory; pass "idb://name" for IndexedDB
await db.exec(await fetch("/agentic-security-lab/schema/postgres.sql").then(r => r.text()));
const result = await db.query("SELECT count(*) FROM findings");
console.log(result.rows);
```

## Caveats

- Single-connection only — fine for rehearsal, not for emulating concurrent
  writers.
- WASM startup cost. Cache the `db` instance.
- pgvector / extensions need to be loaded explicitly; the asec schema does not
  use them today.
- We do not version PGlite. If you hit a divergence between PGlite and the real
  Postgres adapter, the real adapter is the source of truth.

## What lives where

| Surface | Adapter | Used by |
|---|---|---|
| Local dev (`mise run test`) | `SQLiteLedger` | All apps + tests |
| Cloud orchestrator | `PostgresLedger` (asyncpg) | `apps/pr-reviewer` cloud profile |
| Browser docs / JS CI rehearsal | PGlite | Docs site demos, JS-only runners |
| Future: DynamoDB | `DynamoLedger` (deferred) | Compliance-constrained AWS deployments |

The dialect shim in `asec-memory` keeps the SQLite and Postgres SQL surface
narrow enough that PGlite consumes our exported schema without modification.
That is the payoff for the small abstraction.
