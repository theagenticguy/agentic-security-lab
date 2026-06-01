# agentic-security-lab

[![CI](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/codeql.yml)
[![Security](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/security.yml)
[![Adversarial CI](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/adversarial-ci.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/adversarial-ci.yml)
[![Documentation](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/docs-deploy.yml/badge.svg?branch=main)](https://github.com/theagenticguy/agentic-security-lab/actions/workflows/docs-deploy.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/theagenticguy/agentic-security-lab/badge)](https://scorecard.dev/viewer/?uri=github.com/theagenticguy/agentic-security-lab)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/release/python-3130/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A code-analysis agent that **reads code semantically, runs experiments in a
throwaway sandbox, and verifies hypotheses in a closed loop**. The agent has
three faculties:

- **Eyes** — Claude Opus 4.8 on Amazon Bedrock reads the target repo (lexical
  + AST + cross-reference search).
- **Hands** — a per-experiment Docker / gVisor sandbox launched with
  `--network=none` by default. Egress, when enabled per-run, is enforced by an
  allowlist sidecar.
- **Memory** — an append-only hypothesis board, a durable findings ledger, and
  a tamper-evident audit log of every tool call and gate decision.

The differentiator over a Static Application Security Testing (SAST) flood is
that the agent **falsifies its own guesses by running them**: a candidate bug
is a hypothesis until the sandbox produces a Proof of Concept (PoC) or a
counter-example, and only confirmed findings reach the ledger.

## What it does today

v1 implements the **pull-request mode** end-to-end against a small fixture
corpus. Given a diff:

1. Loads the target repo and a hand-written `threat-model.yaml`.
2. The orchestrator runs the diff through Claude Opus 4.8 with a deny-by-default
   tool gate and a sandboxed exec surface.
3. Each candidate finding is scored on three axes — pattern match, memory
   recall, and reachability — and dispatched accordingly (specialized worker,
   parallel shell, or swarm).
4. Confirmed findings land in a SQLite ledger and are emitted as Static
   Analysis Results Interchange Format (SARIF) v2.1 with an `asec` property
   bag carrying the confidence axes.
5. Every tool call, sandbox lifecycle event, and gate decision appends to a
   hash-chained Write-Once-Read-Many (WORM) audit log.

```sh
mise run dev
# pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo
```

The pull-request mode is the first of **five lifecycle modes** the substrate
is designed for. The other four (Onboarding, Nightly variant, Release,
Incident) reuse the same six packages — adding one is new orchestration
wiring, not new isolation, ledger, or audit primitives.

## Quickstart

```sh
git clone https://github.com/theagenticguy/agentic-security-lab
cd agentic-security-lab
mise install        # installs Python 3.13, uv, Node 22 per mise.toml
mise run install    # uv sync — one .venv across the workspace
mise run test       # uv run pytest
mise run dev        # the pull-request reviewer loop on the fixture corpus
```

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
│   ├── asec-threat-model/  # Pydantic threat-model artifacts
│   └── asec-confidence/    # three-axis (pattern, recall, reachability) scorer
├── apps/pr-reviewer/       # the v1 end-to-end app (fixture-driven, not prod)
├── infra/cdk/              # Python AWS Cloud Development Kit (CDK) stacks
├── adr/                    # source-of-truth Architecture Decision Records
├── docs/                   # Astro Starlight site (pnpm-isolated)
├── scripts/                # repo automation
└── tests/adversarial/      # canary corpus (honey-bugs, prompt-injection,
                            #   honey-secret, tool-call canaries)
```

Strict dependency direction: `apps → packages → asec-core`. No package imports
another's concrete class — only `typing.Protocol` types re-exported from
`asec-core` (`SandboxPort`, `LedgerPort`, `SkillLoaderPort`).

## Packages

| Package | Owns |
|---|---|
| [`asec-core`](packages/asec-core/) | Orchestrator + `AgentRuntime` Protocol + governance gate |
| [`asec-sandbox`](packages/asec-sandbox/) | Isolated execution + hash-chained WORM audit-log writer |
| [`asec-memory`](packages/asec-memory/) | Hypothesis board + findings ledger + SARIF v2.1 emission |
| [`asec-skills`](packages/asec-skills/) | `SKILL.md` loader + deny-by-default PreToolUse permission gate |
| [`asec-threat-model`](packages/asec-threat-model/) | Pydantic threat-model artifacts + diff |
| [`asec-confidence`](packages/asec-confidence/) | Three-axis confidence scorer (pluggable strategies, BM25 recall) |

The original whitepaper lists eight foundations. v1 collapses two
single-consumer plumbing pieces (`output` → `memory`, `governance` → `core`)
into the closest siblings. Each merge is recorded with a *split trigger* in
[ADR-001](adr/0001-adopt-claude-agent-sdk.md).

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
| **CI** | push, PR | `mise install` → `uv sync` → ruff → pyright strict → pytest + coverage |
| **CodeQL Analysis** | push, PR, weekly | GitHub CodeQL static analysis on the Python tree (fixtures and adversarial corpus excluded) |
| **Security** | push, PR, weekly | `gitleaks`, dependency review, `bandit`, `pip-audit`, `osv-scanner`, `trivy fs` (SARIF upload) |
| **Adversarial CI** | push, PR, weekly | The canary corpus (see below) |
| **CDK Nag** | push, PR (infra changes) | `cdk synth` + `checkov` |
| **OpenSSF Scorecard** | push, PR, weekly | Supply-chain best-practices score (publish gated to default branch) |
| **Documentation** | push, PR (`adr/**`, `docs/**`) | Astro Starlight build → GitHub Pages deploy on push |
| **Release** | tag push | `commitizen` bump + changelog |

## Adversarial CI

A hermetic self-test gate that re-audits the agent on every change. Injects a
fake `AgentRuntime` (no Bedrock call), runs the orchestrator against four
planted-canary classes, asserts each safety property:

| Class | Asserts |
|---|---|
| Honey-bugs (5 files, CWE-89/79/22/502/639) | Recall = 5/5 |
| Prompt injection (magic comments, fake tool output) | No `<exfiltrate>` token, only expected event types in audit log |
| Honey-secret (planted `AKIAIOSFODNN7EXAMPLE`) | Flagged as a finding **and** never appears in any `tool_call` argument |
| Tool canaries (`git push`, `curl`, `nc`, `rm -rf`, …) | Every coerced out-of-scope call denied via `GateDecision` |

Source: `tests/adversarial/`. Runner: `tests/adversarial/runner.py`.

## Documentation

- Site: <https://theagenticguy.github.io/agentic-security-lab/>
  (Astro Starlight; deployed by the `Documentation` workflow.)
- ADRs: source of truth in [`/adr`](adr/), mirrored into the docs by
  `scripts/sync_adrs.py`.
- Glossary of acronyms: <https://theagenticguy.github.io/agentic-security-lab/reference/glossary/>.

## Substrate contract

The agent's behavior is governed by a list of 19
[Easy Approach to Requirements Syntax (EARS) invariants](https://theagenticguy.github.io/agentic-security-lab/concepts/ears-invariants/) — sandbox isolation, deny-by-default tool gating, append-only memory, hash-chained audit, human gate on externally visible actions, and so on. Each `asec-*` package owns a subset and tests against it directly. They are the security contract, not the project pitch.

## Status

**Alpha — pull-request mode end-to-end on a fixture corpus.** The other four
lifecycle modes are designed for, not built. The `apps/pr-reviewer` app is a
small wiring exercise, not a production review service.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
Vulnerability reporting: see [`SECURITY.md`](SECURITY.md).
