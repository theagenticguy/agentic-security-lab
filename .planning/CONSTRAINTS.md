# agentic-security-lab — Constraints (May 2026)

## North-star
Build the substrate the v1.3 whitepaper describes (`.planning/whitepaper-summary.md`).
**Foundations first. No specific audit scope.** v1 is the substrate, not a finished product.

## Hard constraints (non-negotiable)
- Path: `~/workplace/agentic-security-lab/`
- License: Apache-2.0, internal-only audience for now
- Repo shape: **lab monorepo** — uv workspace (no pnpm workspace; pnpm only for docs site)
- Package layout: `packages/` for shared libs · `apps/` for runnable lifecycle modes · `infra/cdk/` for AWS · `docs/` Astro Starlight · `experiments/` scratch · `adr/` source-of-truth ADRs
- Python: **3.13**
- AWS infra: **CDK Python** + **CDK Nag** (must pass with documented suppressions)
- Default model wiring: Claude Opus 4.8 via Bedrock (`global.anthropic.claude-opus-4-8`)
- Default agent SDK: **Claude Agent SDK (Python)** — but `asec-core` keeps the model layer abstract so Strands is a swap, not a rewrite
- Tooling: **mise + uv + lefthook + ruff + pyright + commitizen** (no poetry, no pip-tools, no black, no make)
- Docs: **Astro Starlight** in `docs/`, mirroring `adr/` to `docs/src/content/docs/adrs/`
- Commits: Conventional Commits, enforced via lefthook commit-msg + commitizen
- CI: GitHub Actions, action SHAs pinned, OpenSSF baseline (scorecard, dependency-review, codeql, gitleaks)

## Whitepaper v1.3 → repo mapping (the foundations only)
Foundation pieces to ship in v1:
1. **Sandbox primitive** (`packages/asec-sandbox`) — Docker / Firecracker abstraction; `--network=none` default; egress-allowlist sidecar; WORM audit JSONL writer.
2. **Hypothesis board + findings ledger** (`packages/asec-memory`) — SQLite for local; Postgres adapter; SARIF v2.1 + Bonk extension serializer.
3. **Skill loader + permission gate** (`packages/asec-skills`) — load `SKILL.md` from `.claude/skills/`; PreToolUse hook scaffold; deny-by-default `editor`/`load_tool` gate.
4. **Threat-model artifact** (`packages/asec-threat-model`) — pydantic models for `threat-model.yaml` + `assets.yaml`; round-trip + diff.
5. **Confidence scorer** (`packages/asec-confidence`) — three-axis (pattern-match × memory recall × reachability); pluggable.
6. **Orchestrator core** (`packages/asec-core`) — Agent SDK orchestrator with the SKILL.md→subagent→hook wiring; provider-abstract for Strands swap.
7. **One end-to-end app** (`apps/pr-reviewer`) — proves the orchestrator + sandbox + memory + skills loop on a tiny corpus. NOT production-grade.
8. **CDK stack** (`infra/cdk/`) — Bedrock IAM role + S3 Object Lock audit bucket + DynamoDB ledger + CloudFront-fronted dashboard placeholder. Nothing customer-facing yet.

Out of scope for v1 (defer):
- All concrete CWE-specific skills beyond a stub
- Mythos integration (no public access)
- Full lifecycle five-pack (only PR mode in v1)
- Adversarial CI corpus content (scaffold only, no honey-bugs yet)

## Methodology directives from operator
- Use **HMW (How Might We)** to frame the fuzzy product surface
- Use **EARS** for any agent contract specs (Event-driven, State-driven, Unwanted-behavior, Required-behavior)
- Don't over-rotate on specific audit scope engineering stuff
- Foundations first

## Style / "dressed to the nines" 2026 stance
- Type-safe everywhere (pyright strict, pydantic v2)
- Async-first I/O
- Polars for any tabular data; Altair for any chart
- structlog + OpenTelemetry from day one
- pre-commit lefthook with parallel hooks
- CDK Nag in CI with explicit suppressions list
