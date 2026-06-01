---
title: Command-line interface
description: Command-line surface of the substrate and the pr-reviewer app.
sidebar:
  badge:
    text: Roadmap
    variant: caution
  order: 95
---

:::caution[Roadmap page]
The full command-line interface is generated from `cyclopts` entrypoints in
`asec-core`. This reference will be auto-generated once the surface stabilizes.
The one command below is stable in v1.
:::

## `pr-reviewer review`

Run the pull-request reviewer loop over a target directory.

```bash
uv run pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo
```

| Argument | Description |
|---|---|
| `<target>` | Path to the repo or diff corpus to review. |

Outputs: `findings.sarif`, one hash-chained Write-Once-Read-Many (WORM)
audit-log line per tool call, SQLite ledger rows, and an engineering report
(markdown table plus PASS/FAIL gate).
