# agentic-security-lab

[![CI](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/codeql.yml)
[![Security](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/security.yml)
[![Adversarial CI](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/adversarial-ci.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/adversarial-ci.yml)
[![Documentation](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/docs-deploy.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/docs-deploy.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/theagenticguy/agentic-security-lab/badge)](https://scorecard.dev/viewer/?uri=github.com/theagenticguy/agentic-security-lab)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/release/python-3130/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Runtime, sandbox, findings ledger, and audit-log layers for a code-analysis
agent on Amazon Bedrock. The v1 agent is Claude Opus 4.8
(`global.anthropic.claude-opus-4-8`); the layers are written so a different
agent runtime can replace it without changes elsewhere
(see [ADR-002](adr/0002-agent-runtime-protocol.md)).

The contract these layers enforce is a list of 19
[Easy Approach to Requirements Syntax (EARS) invariants][ears-page]. Two
govern v1 day-to-day:

- **E3** — every target-code experiment runs inside a throwaway sandbox
  launched with `--network=none` by default.
- **E12** — every tool call, sandbox lifecycle event, and gate decision appends
  to a hash-chained Write-Once-Read-Many (WORM) audit log (Amazon S3 Object
  Lock or `chattr +a`).

[ears-page]: https://theagenticguy.github.io/agentic-security-lab/concepts/ears-invariants/

## Quickstart

```sh
git clone https://github.com/theagenticguy/agentic-security-lab
cd agentic-security-lab
mise install        # installs Python 3.13, uv, Node 22 per mise.toml
mise run install    # uv sync — one .venv across the workspace
mise run test       # uv run pytest
```

Run the one end-to-end app over the committed fixture corpus:

```sh
mise run dev        # pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo
```

Output: a `findings.sarif` (Static Analysis Results Interchange Format v2.1
with the `asec` property bag), one hash-chained WORM audit-log line per tool
call, SQLite ledger rows, and an engineering report.

### Prerequisites

- [`mise`](https://mise.jdx.dev/) — manages Python, `uv`, and Node versions
  pinned in `mise.toml`.
- AWS credentials with `bedrock:InvokeModel` access to
  `global.anthropic.claude-opus-4-8`. The bootstrap smoke test verifies this.
- Docker — only needed for the hardened `DockerSandbox` path; the default
  `LocalSandbox` passthrough needs nothing.

## Layout

```
agentic-security-lab/
├── packages/
│   ├── asec-core/          # orchestrator + AgentRuntime Protocol + governance
│   ├── asec-sandbox/       # isolated execution + WORM audit-log writer
│   ├── asec-memory/        # hypothesis board + findings ledger + SARIF
│   ├── asec-skills/        # SKILL.md loader + deny-by-default PreToolUse gate
│   ├── asec-threat-model/  # Pydantic threat-model artifacts (E1, E2)
│   └── asec-confidence/    # three-axis (pattern, recall, reachability) scorer
├── apps/pr-reviewer/       # the one end-to-end app (fixture-driven, not prod)
├── infra/cdk/              # Python AWS CDK stacks; CDK Nag in CI
├── adr/                    # source-of-truth ADRs (mirrored to docs)
├── docs/                   # Astro Starlight site (pnpm-isolated)
├── scripts/                # repo automation (ADR sync, etc.)
└── tests/adversarial/      # §16 canary corpus (honey-bugs, prompt-injection,
                            #   honey-secret, tool-call canaries)
```

Strict dependency direction: `apps → packages → asec-core`. No package imports
another's concrete class — only `typing.Protocol` types re-exported from
`asec-core` (`SandboxPort`, `LedgerPort`, `SkillLoaderPort`).

## Packages

| Package | Owns | EARS invariants |
|---|---|---|
| [`asec-core`](packages/asec-core/) | Orchestrator + `AgentRuntime` Protocol + governance gate | E14, E15, E16, E18 (dispatch), E19 |
| [`asec-sandbox`](packages/asec-sandbox/) | Isolated execution + hash-chained WORM audit writer | E3, E4, E5, E6, E12, E13 |
| [`asec-memory`](packages/asec-memory/) | Hypothesis board + findings ledger + SARIF v2.1 emission | E9, E10, E11 |
| [`asec-skills`](packages/asec-skills/) | `SKILL.md` loader + deny-by-default PreToolUse permission gate | E7, E8 |
| [`asec-threat-model`](packages/asec-threat-model/) | Pydantic threat-model artifacts + diff | E1, E2 |
| [`asec-confidence`](packages/asec-confidence/) | Three-axis confidence scorer (pluggable strategies, BM25 recall) | E18 (scoring) |

Eight design-document foundations collapse to six packages: `asec-output` folds
into `asec-memory` and `asec-governance` folds into `asec-core` — the two
single-consumer plumbing pieces. Each merge is recorded with a *split trigger*
in [ADR-001](adr/0001-adopt-claude-agent-sdk.md).

## Common tasks

| Task | Command |
|---|---|
| Install / sync | `mise run install` |
| Lint (`ruff`) | `mise run lint` |
| Format (`ruff format`) | `mise run format` |
| Typecheck (`pyright` strict) | `mise run typecheck` |
| Test (`pytest`) | `mise run test` |
| Adversarial canary corpus | `mise run adversarial` |
| Security scan (`bandit`, `pip-audit`, `trivy fs`) | `mise run security:scan` |
| Secret scan (`gitleaks`) | `mise run security:gitleaks` |
| CDK synth | `mise run cdk:synth` |
| CDK Nag (`checkov`) | `mise run cdk:nag` |
| Docs dev server | `mise run docs:dev` |
| Sync ADR mirror into docs | `mise run docs:sync` |

## CI workflows

| Workflow | Triggers | What it runs |
|---|---|---|
| **CI** | push, PR | `mise install` → `uv sync` → ruff lint → pyright strict → pytest + coverage |
| **CodeQL Analysis** | push, PR, weekly | GitHub CodeQL static analysis on the Python tree (fixtures and adversarial corpus excluded) |
| **Security** | push, PR, weekly | `gitleaks`, dependency review, `bandit`, `pip-audit`, `osv-scanner`, `trivy fs` (SARIF upload) |
| **Adversarial CI** | push, PR, weekly | §16 canary corpus: honey-bugs, prompt-injection, honey-secret, tool-call canaries — see ["What is Adversarial CI?"](#what-is-adversarial-ci) |
| **CDK Nag** | push, PR (infra changes) | `cdk synth` + `checkov` |
| **OpenSSF Scorecard** | push, PR, weekly | Supply-chain best-practices score (publish gated to default branch) |
| **Documentation** | push (`adr/**`, `docs/**`) | Astro Starlight build → GitHub Pages deploy |
| **Release** | tag push | `commitizen` bump + changelog |

## What is Adversarial CI?

A hermetic self-test gate. The harness injects a fake `AgentRuntime` (no
Bedrock call), runs the orchestrator against four planted-canary classes, and
asserts each safety property:

| Class | Asserts |
|---|---|
| Honey-bugs (5 files, CWE-89/79/22/502/639) | Recall = 5/5 |
| Prompt injection (magic comments, fake tool output) | No `<exfiltrate>` token, only expected event types in WORM audit |
| Honey-secret (planted `AKIAIOSFODNN7EXAMPLE`) | Flagged as a finding **and** never appears in any `tool_call` argument |
| Tool canaries (`git push`, `curl`, `nc`, `rm -rf`, …) | Every coerced out-of-scope call denied via `GateDecision` |

Source: `tests/adversarial/`. Runner: `tests/adversarial/runner.py`.

## Documentation

- Site: <https://theagenticguy.github.io/agentic-security-lab/>
  (Astro Starlight; deployed by the `Documentation` workflow.)
- ADRs: source of truth in [`/adr`](adr/), mirrored into the docs by
  `scripts/sync_adrs.py`.
- EARS invariants: [concepts/ears-invariants/][ears-page].
- Glossary of acronyms: [reference/glossary/](https://theagenticguy.github.io/agentic-security-lab/reference/glossary/).

## Status

**Alpha — foundations only.** This repo implements the substrate primitives
listed in the *Packages* table; the `apps/pr-reviewer` app exercises every
package boundary against a small fixture corpus. It is not a production review
service.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
Vulnerability reporting: see [`SECURITY.md`](SECURITY.md).
