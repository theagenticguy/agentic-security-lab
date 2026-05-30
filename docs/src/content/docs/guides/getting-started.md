---
title: Getting started
description: Clone, install with mise, run the tests, and run the dev loop.
---

## Prerequisites

- [`mise`](https://mise.jdx.dev/) (manages Python 3.13, `uv`, and Node 22 per the repo `mise.toml`)
- AWS credentials with `bedrock:InvokeModel` access to `global.anthropic.claude-opus-4-8`
  (a Day-1 smoke test verifies this; it is an E2E precondition)
- Docker (only needed for the hardened `DockerSandbox` path; the default `LocalSandbox`
  passthrough needs nothing)

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
- `mise run dev` runs the PR-reviewer loop: SKILL.md → Orchestrator → Bedrock Opus 4.8 →
  `Finding` → SQLite ledger → `findings.sarif` + a WORM audit line, over the fixture.

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
`apps/pr-reviewer` is a substrate proof, **not** production-grade. It exists to exercise
every primitive interface end-to-end on a tiny corpus.
:::
