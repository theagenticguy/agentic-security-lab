---
title: Architecture Decision Records
description: ADRs are source-of-truth in /adr and mirrored read-only into the docs.
---

ADRs are the **source of truth** for architectural decisions. They live in the repo's
top-level [`/adr`](https://github.com/lalsaado/agentic-security-lab/tree/main/adr)
directory in MADR format.

:::note[Read-only mirror]
The pages under this section are a **read-only mirror** generated from `/adr` by
`scripts/sync_adrs.py` (run via `mise run docs:sync`, and automatically in the
docs-deploy workflow). Do not edit ADR content here — edit the source file in `/adr` and
re-run the sync. Concept and how-to pages must never duplicate ADR content.
:::

## The first ten ADRs

1. Adopt Claude Agent SDK on Bedrock
2. `AgentRuntime` Protocol + adapter (runtime swap: OpenAI Agents / DeepAgents / OpenCode)
3. Docker rootless sandbox behind the `Sandbox` protocol
4. SQLite + DynamoDB single-table findings ledger
5. Hash-chained WORM audit (`chattr +a` / S3 Object Lock)
6. Own pydantic SARIF v2.1 + `asec` property bag
7. Deny-by-default skill gate via PreToolUse hook
8. Pluggable `ConfidenceStrategy` with `bm25s` recall
9. gVisor platform + EC2 instance type + storage tiers
10. Ledger backends: SQLite (local) + asyncpg Postgres (cloud) + PGlite (docs reference)

## How the mirror works

```bash
# regenerate the mirror from /adr
mise run docs:sync
```

The script reads each `adr/NNNN-*.md`, normalizes frontmatter for Starlight, and writes
the result into this directory.
