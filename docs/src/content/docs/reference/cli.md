---
title: CLI reference
description: Command-line surface of the substrate and the pr-reviewer app.
---

:::caution[Placeholder]
The CLI is generated from `cyclopts` entrypoints in `asec-core`. This reference will be
auto-generated once the CLI surface stabilizes. The one command below is stable.
:::

## `pr-reviewer review`

Run the PR-reviewer loop over a target directory.

```bash
uv run pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo
```

| Argument | Description |
|---|---|
| `<target>` | Path to the repo/diff corpus to review. |

Outputs a `findings.sarif`, a hash-chained WORM audit line, SQLite ledger rows, and an
Engineering report (markdown table + PASS/FAIL gate).
