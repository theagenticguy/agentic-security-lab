---
title: Getting started
description: Clone, install with mise, run the tests, and run the dev loop.
---

## Prerequisites

- [`mise`](https://mise.jdx.dev/) — installs the Python 3.13, `uv`, and Node 22
  versions pinned in the repo's `mise.toml`.
- AWS credentials with `bedrock:InvokeModel` access to
  `global.anthropic.claude-opus-4-8`. The bootstrap smoke test verifies this;
  the end-to-end loop will not run without it.
- Docker — only needed for the hardened `DockerSandbox` path. The default
  `LocalSandbox` passthrough needs nothing.

## Quickstart

```bash
git clone https://github.com/lalsaado/agentic-security-lab
cd agentic-security-lab

# mise installs Python 3.13, uv, and Node 22, then uv sync builds the .venv
mise install

# run the full test suite across all six packages
mise run test

# run the one E2E app (PR-reviewer) over the committed tiny-repo fixture
mise run dev
```

`mise run dev` expands to:

```bash
uv run pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo
```

## What you get

- A green `uv sync` resolves the whole six-package workspace into one `.venv`.
- `mise run test` runs `uv run pytest` across every package.
- `mise run dev` runs the pull-request reviewer loop end-to-end against the
  fixture corpus: `SKILL.md` → orchestrator → Bedrock Opus 4.8 → `Finding` →
  SQLite ledger → `findings.sarif` + a Write-Once-Read-Many (WORM) audit-log
  line.

## Useful tasks

| Task | Command |
|---|---|
| Install / sync | `mise run install` |
| Lint | `mise run lint` |
| Format | `mise run format` |
| Typecheck (pyright strict) | `mise run typecheck` |
| Test | `mise run test` |
| Security scan | `mise run security:scan` |
| Docs dev server | `mise run docs:dev` |
| Synthesize CDK | `mise run cdk:synth` |

:::caution
`apps/pr-reviewer` is the v1 fixture-driven exercise of every package boundary.
It is not a production review service.
:::
