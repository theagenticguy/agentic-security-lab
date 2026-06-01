---
title: Architecture Decision Records
description: ADRs are source-of-truth in /adr and mirrored read-only into the docs.
---

Architecture Decision Records (ADRs) are the source of truth for architectural
decisions. They live in the repository's top-level
[`/adr`](https://github.com/lalsaado/agentic-security-lab/tree/main/adr)
directory in MADR (Markdown Any Decision Records) format.

The pages under this section are a read-only mirror generated from `/adr` by
`scripts/sync_adrs.py` (run via `mise run docs:sync`, and automatically in the
documentation-deploy workflow). The mirror script also rewrites EARS invariant
references like `E12` to anchor links on the
[EARS invariants](/agentic-security-lab/concepts/ears-invariants/) page, and
folds each ADR's Decision / Alternatives / Rationale / Consequences sections into
a `<details>` element so the page shows context first.

:::note[Read-only mirror]
Do not edit ADR content under `docs/`. Edit the source file under `/adr` and
re-run `mise run docs:sync`. The concept and how-to pages must never duplicate
ADR content.
:::

## The first ten ADRs

1. [Adopt the Claude Agent SDK on Amazon Bedrock](/agentic-security-lab/adrs/0001-adopt-claude-agent-sdk/)
2. [`AgentRuntime` Protocol + adapter](/agentic-security-lab/adrs/0002-agent-runtime-protocol/) — runtime swap for OpenAI Agents, DeepAgents, OpenCode.
3. [Docker rootless sandbox + gVisor](/agentic-security-lab/adrs/0003-docker-rootless-sandbox-gvisor/) behind the `Sandbox` Protocol.
4. [SQLite + DynamoDB single-table findings ledger](/agentic-security-lab/adrs/0004-sqlite-and-dynamodb-single-table-ledger/).
5. [Hash-chained WORM audit](/agentic-security-lab/adrs/0005-worm-audit-hash-chain/) — `chattr +a` and Amazon S3 Object Lock.
6. [Own Pydantic SARIF v2.1 + `asec` property bag](/agentic-security-lab/adrs/0006-sarif-asec-property-bag/).
7. [Deny-by-default skill gate via PreToolUse hook](/agentic-security-lab/adrs/0007-deny-by-default-skill-permission-gate/).
8. [Pluggable `ConfidenceStrategy` with BM25 recall](/agentic-security-lab/adrs/0008-pluggable-confidence-strategy-bm25/).
9. [gVisor platform + EC2 instance type + storage tiers](/agentic-security-lab/adrs/0009-gvisor-ec2-storage/).
10. [Ledger backends](/agentic-security-lab/adrs/0010-ledger-backends/) — SQLite local, asyncpg Postgres cloud, PGlite as docs reference.

## How the mirror works

```bash
# regenerate the mirror from /adr
mise run docs:sync
```

The script reads each `adr/NNNN-*.md`, prepends Starlight frontmatter (title,
description), rewrites EARS invariant references to anchor links, and wraps the
Decision / Alternatives / Rationale / Consequences sections in `<details>`.
