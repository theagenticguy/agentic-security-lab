# Plan B — SPEED-FIRST v1

**Thesis:** time-to-running beats durable shape. Get one E2E loop (`apps/pr-reviewer` → real Agent SDK call → SQLite ledger → SARIF out) green by **Day 3**, then harden. Merge primitives aggressively now; A can re-split later behind stable public APIs.

---

## 1. Smallest meaningful skeleton

```
agentic-security-lab/
├── pyproject.toml            # uv workspace root
├── uv.lock
├── mise.toml                 # python=3.13, tasks: test/lint/scan/docs
├── lefthook.yml              # commit-msg (commitizen) + pre-commit (ruff,pyright)
├── packages/
│   ├── asec-core/            # orchestrator + model abstraction + confidence + threat-model
│   ├── asec-sandbox/         # docker runner stub + WORM JSONL writer
│   ├── asec-memory/          # SQLite ledger + hypothesis board + SARIF serializer
│   └── asec-skills/          # SKILL.md loader + PreToolUse permission gate
├── apps/
│   └── pr-reviewer/          # the one E2E app
├── infra/cdk/                # one stack file + CDK Nag
├── docs/                     # Astro Starlight (pnpm, isolated)
├── adr/                      # ADR-001 only
└── .github/workflows/        # ci.yml, security.yml, cdk.yml, docs.yml
```

**Deleted vs. A (the 4 merges):** A spins up 8 packages. I ship **4**. `asec-threat-model` + `asec-confidence` collapse into `asec-core` (both are pure-pydantic + pure-function modules consumed only by the orchestrator — no external consumer in v1, so a sub-module not a package). `experiments/` is omitted entirely on day one (an empty scratch dir adds no running code; add it Day 5 if needed). No `asec-output` package — SARIF lives in `asec-memory` (findings already live there; serialization is a method, not a package). **Net: 4 packages, not 8.**

---

## 2. uv workspace layout (4 packages)

Root `pyproject.toml` declares `[tool.uv.workspace] members = ["packages/*", "apps/*"]`. Each package is `uv init --lib`; `pr-reviewer` is `uv init` (app). Shared dev deps (ruff, pyright, pytest, pytest-asyncio) in root `[dependency-groups].dev`. Python pinned 3.13 via `mise.toml` + `requires-python = ">=3.13"`. Internal deps via `[tool.uv.sources] asec-core = { workspace = true }`.

The whitepaper's primitive boundaries are still respected at the **module** level inside `asec-core` (`asec_core.threat_model`, `asec_core.confidence`, `asec_core.orchestrator`, `asec_core.model`). Boundaries are import-discipline, not package-count. A can promote any module to a package later with zero call-site churn if the public API stays `from asec_core import ...` re-exported.

---

## 3. Package contracts (terse)

- **asec-core** — orchestrator + provider-abstract model layer + threat-model + confidence. Public: `Orchestrator`, `ModelProvider` (protocol; `BedrockClaudeProvider` default impl), `ThreatModel` (pydantic). Submodule `confidence.score(pattern, recall, reach) -> float`.
- **asec-sandbox** — isolated tool execution + tamper-evident audit. Public: `Sandbox` (protocol), `DockerSandbox` (real-ish; stub-OK Day 1), `WormLog` (hash-chained JSONL append).
- **asec-memory** — durable findings + per-session hypotheses + SARIF. Public: `Ledger` (SQLite, async via aiosqlite), `Finding` (pydantic), `to_sarif(findings) -> dict` (SARIF v2.1).
- **asec-skills** — load `SKILL.md`, gate tools. Public: `SkillLoader`, `Skill` (frontmatter model), `permission_gate(input, ...)` (PreToolUse hook fn, deny-by-default `editor`/`load_tool`).

---

## 4. The one E2E app — `apps/pr-reviewer`

**First thing that runs end-to-end (Day 3).** `uv run pr-reviewer review ./fixtures/tiny-repo` →:

1. Loads a single project `SKILL.md` (`security-code-review`, from Track D §4) via `asec-skills`.
2. `asec-core.Orchestrator` builds `ClaudeAgentOptions(model="global.anthropic.claude-opus-4-8", permission_mode="plan", allowed_tools=["Read","Grep","Glob"], hooks={"PreToolUse":[permission_gate]})` and runs **one** `query()` over a ~3-file fixture corpus (committed in `apps/pr-reviewer/fixtures/`).
3. Findings parsed into `asec-memory.Finding`, written to SQLite `Ledger`.
4. `to_sarif()` emits `findings.sarif`; each tool call appends to `WormLog`.

**Real on Day 3:** Agent SDK call against Bedrock (`CLAUDE_CODE_USE_BEDROCK=1`), SKILL.md loading, permission gate hook, SQLite write, SARIF + WORM output.
**Stubbed on Day 3:** `DockerSandbox` is a **passthrough** (`LocalSandbox` runs the SDK in-process, WORM still logs) — no container yet. Confidence scorer returns a fixed `0.5` constant. No per-CWE fan-out / subagents (single query). No Postgres adapter. Threat model loaded from a hand-written `fixtures/threat-model.yaml`, not agent-generated.

This proves the **loop topology** is sound before any piece is production-grade — the whole point of speed-first.

---

## 5. CDK stack (minimum)

One file `infra/cdk/app.py` → one `AsecFoundationStack`:

- **S3** audit bucket, Object Lock (COMPLIANCE/governance), versioned, SSE-KMS, public access blocked — WORM destination.
- **DynamoDB** `findings-ledger`, on-demand billing, PITR on, the durable analog of the SQLite ledger.
- **IAM** Bedrock invoke role: `bedrock:InvokeModel`, `InvokeModelWithResponseStream`, inference-profile read, scoped to the Opus 4.8 profile ARN; S3 put-only to the bucket; DDB read/write to the table.

`uv run --with aws-cdk-lib python infra/cdk/app.py` synths. **CDK Nag** (`AwsSolutionsChecks`) wired in synth; failures break `cdk.yml` CI. A documented **v1-baseline suppression set** (`infra/cdk/suppressions.py`) in plain language:

- *"No access logs on the audit bucket — v1 is single-bucket; access logging is a Day-N follow-up, tracked in ADR backlog."*
- *"IAM has a wildcard on inference-profile read because Bedrock profile ARNs are region/account-templated; scoped to the bedrock action set, not `*`."*
- *"No CloudFront/WAF — dashboard is a deferred placeholder, nothing is internet-facing in v1."*

Every suppression carries a one-sentence justification and an ADR-backlog pointer; none suppress encryption or public-access controls.

---

## 6. Docs (3 pages Day 1)

`pnpm create astro@latest docs -- --template starlight` (pnpm isolated to `docs/`, never the uv workspace). Day-one content:

1. **README** (repo root, also surfaced as docs index) — what the lab is, the 8 foundations → 4 packages mapping, quickstart.
2. **getting-started.md** — `mise install` → `uv sync` → set Bedrock env → `uv run pr-reviewer review ./fixtures/tiny-repo`.
3. **adrs/adr-001.md** — "4-package merge & speed-first slice": records the threat-model+confidence→core and SARIF→memory merges, why, and the promotion path. Sourced from `adr/ADR-001.md`, mirrored into `docs/src/content/docs/adrs/` by a `mise run docs:sync` task (simple copy in v1, not a build plugin).

---

## 7. CI (4 load-bearing workflows)

All actions pinned by SHA; OpenSSF baseline.

1. **ci.yml** — `mise install` → `uv sync` → `uv run ruff check` + `uv run pyright` + `uv run pytest` (incl. the one E2E test, mocked SDK). The gate that protects the loop.
2. **security.yml** — gitleaks + dependency-review + CodeQL (Python). Non-negotiable per CONSTRAINTS.
3. **cdk.yml** — `cdk synth` + CDK Nag (fails on un-suppressed findings).
4. **docs.yml** — Starlight build (catches broken ADR mirror / links).

**Deferred to Day-N:** OpenSSF Scorecard workflow (add Day 5 — it's a scheduled scan, not a per-PR gate, so it doesn't block the running slice). Release/commitizen-bump workflow deferred. Adversarial-CI corpus: scaffold dir only, no workflow.

---

## 8. Day-by-day timeline

**The ordering trick:** build the *thinnest vertical slice* that exercises every primitive interface, stubbing the expensive internals — so integration risk surfaces Day 3, not Day 5.

- **Day 1 — skeleton + tooling green.** `uv init` workspace + 4 package skeletons; `mise.toml`, `lefthook.yml`, ruff/pyright/commitizen config; `ci.yml` + `security.yml` passing on empty packages; Starlight scaffold + 3 docs pages; ADR-001 written. *Exit:* `uv run pytest` (trivial), lint, commit hooks all green.
- **Day 2 — primitive stubs with real interfaces.** `asec-memory.Ledger` (real SQLite + `Finding` + `to_sarif`); `asec-sandbox.WormLog` (real hash chain) + `LocalSandbox` passthrough; `asec-skills.SkillLoader` (real frontmatter parse) + `permission_gate` (real deny-by-default); `asec-core.ModelProvider` protocol + `BedrockClaudeProvider`; `confidence.score` returns constant. *Exit:* each package has a unit test.
- **Day 3 — E2E loop runs (the milestone).** Wire `apps/pr-reviewer`: SKILL.md → `Orchestrator.query()` → Bedrock Opus 4.8 → `Finding` → `Ledger` → `findings.sarif` + WORM line, over the committed fixture repo. Add the one E2E test (SDK mocked in CI, live-run documented). *Exit:* `uv run pr-reviewer review ./fixtures/tiny-repo` produces real SARIF.
- **Day 4 — infra + harden.** `AsecFoundationStack` (S3 Object Lock + DDB + IAM); CDK Nag + suppressions; `cdk.yml`. Replace `LocalSandbox` passthrough with a thin `DockerSandbox` (`--network=none`, non-root, from Track C §1/§3). structlog + OTel wiring in `asec-core`. *Exit:* `cdk synth` Nag-clean; sandbox runs a real container.
- **Day 5 — second axis of value + polish.** Real three-axis `confidence.score`; per-CWE subagent fan-out (`AgentDefinition`, Track A) gated on confidence; `docs.yml`; OpenSSF Scorecard; `experiments/` + adversarial-CI corpus scaffold; backfill EARS contracts for the orchestrator in ADR-002. *Exit:* fan-out demo + full CI suite green.

---

## 9. Three speed-anchor decisions

1. **4 packages, not 8 (merge threat-model + confidence into core; SARIF into memory).** A would package every whitepaper primitive 1:1. But v1 has exactly one consumer (the orchestrator) for threat-model and confidence, and exactly one producer (memory) for SARIF. Packaging them now buys version-boundary ceremony with zero present benefit. Module boundaries + re-exports preserve the promotion path; net days saved: ~1.5.
2. **`LocalSandbox` passthrough before `DockerSandbox`.** The Track C Docker image (CodeQL, ZAP, semgrep, Frida) takes hours to build/debug and gates nothing in the loop *topology*. Ship the `Sandbox` protocol + `WormLog` real on Day 2, run in-process, swap to a container Day 4. The interface is what matters for proving the loop; the isolation is a Day-4 hardening pass.
3. **Single `query()` over per-CWE swarm fan-out.** The orchestrator's hard-to-debug surface is subagent fan-out. v1 proves the *loop* (read→reason→ledger→SARIF) with one query first; fan-out is additive on Day 5 behind the same `Orchestrator` API. We refuse to let the most complex feature block the first runnable artifact.

---

## 10. Risks + mitigations (top 5 — fast-mover failure modes)

1. **Bedrock auth/model-access blocks Day 3.** Opus 4.8 profile not enabled in-account, or IAM gap. *Mitigate:* verify `bedrock:InvokeModel` against `global.anthropic.claude-opus-4-8` on **Day 1** with a 5-line smoke script; make it the first E2E precondition, not a Day-3 surprise.
2. **Merges become permanent (tech debt by accident).** Speed merges silently calcify. *Mitigate:* ADR-001 records each merge *with* its promotion trigger ("split when a second consumer appears"); re-export public API so the split is mechanical, not a rewrite.
3. **Stub-to-real swap leaks (LocalSandbox assumptions bake in).** Day-3 code assumes in-process execution. *Mitigate:* `Sandbox` is a protocol from Day 2; `pr-reviewer` depends only on the protocol, never on `LocalSandbox` concretely — Day-4 swap is one DI line.
4. **CDK Nag suppressions over-broad / hide real gaps.** Speed pressure tempts blanket suppressions. *Mitigate:* suppressions are per-rule with plain-language justification + ADR-backlog ID; encryption/public-access rules may **never** be suppressed (CI assert).
5. **Mocked E2E test passes while live path is broken.** CI mocks the SDK, so a real Bedrock regression hides. *Mitigate:* keep a separate `pytest -m live` job (manual/nightly trigger) hitting real Bedrock against the fixture; document it in getting-started so it runs before any release.
