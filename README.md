# agentic-security-lab

## Overview

A trustworthy **substrate** for agentic security review: the eight foundation pieces a
Claude Opus 4.8 agent (Bedrock) needs to read code semantically, run experiments in a
closed sandbox, and verify hypotheses in a loop. This is the substrate, not a product —
concrete CWE skills and the human-review surface are explicitly out of scope for v1.

Two invariants govern everything:

- **E3** — all target-code experiments run inside a throwaway sandbox launched with
  `--network=none` by default.
- **E12** — every tool call, sandbox lifecycle event, and gate decision is appended to a
  hash-chained WORM audit log (S3 Object Lock or `chattr +a`).

## Eight Foundations -> Six Packages

| Foundation                         | Package             | EARS invariants     |
| ---------------------------------- | ------------------- | ------------------- |
| Orchestrator                       | `asec-core`         | E14, E15, E16, E19  |
| Governance / kill-switch           | `asec-core`         | E16, E19            |
| Sandbox (isolated execution)       | `asec-sandbox`      | E3, E4, E5, E6      |
| WORM audit log                     | `asec-sandbox`      | E12, E13            |
| Memory: board + ledger             | `asec-memory`       | E9, E10             |
| SARIF output                       | `asec-memory`       | E11                 |
| Skill loader + permission gate     | `asec-skills`       | E7, E8              |
| Threat-model artifact              | `asec-threat-model` | E1, E2              |
| Confidence scorer                  | `asec-confidence`   | E18                 |

(Eight whitepaper foundations collapse to six packages: `asec-output` folds into
`asec-memory`, `asec-governance` folds into `asec-core` — the two single-consumer
plumbing pieces.)

## Quickstart

```sh
git clone <repo-url> agentic-security-lab
cd agentic-security-lab
mise install        # python 3.13 + uv + node 22
mise run install    # uv sync -> one .venv across the workspace
mise run test       # uv run pytest
```

Run the one end-to-end proof app over the committed fixture:

```sh
mise run dev        # pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo
```

## Layout

```
agentic-security-lab/
├── packages/            # six asec-* libraries (constraints, port discipline)
│   ├── asec-core/       # orchestrator + AgentRuntime seam + governance
│   ├── asec-sandbox/    # isolated exec + WORM audit writer
│   ├── asec-memory/     # board + ledger + SARIF
│   ├── asec-skills/     # SKILL.md loader + PreToolUse gate
│   ├── asec-threat-model/  # pydantic threat artifacts (E1/E2)
│   └── asec-confidence/    # three-axis scorer (E18)
├── apps/pr-reviewer/    # the one E2E app; wiring only, NOT production-grade
├── infra/cdk/           # Python CDK + CDK Nag; one substrate stack
├── adr/                 # source-of-truth ADRs (mirrored to docs)
├── docs/                # Astro Starlight (pnpm-isolated)
└── scripts/             # repo automation (ADR sync, etc.)
```

Strict dependency direction: `apps -> packages -> asec-core`. No package imports
another's concrete class — only Protocols re-exported from `asec-core`.

## Status

**Alpha — foundations only.** This repo is the substrate scaffold. The `pr-reviewer`
app is a wiring demo and is explicitly **not** production-grade.
