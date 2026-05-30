# agentic-security-lab — Unified v1 Plan

> Composed from Plan A (architectural), Plan B (speed), Plan C (simple), the tech-stack report, and the product framing. Per-decision attribution: (A)/(B)/(C)/merged. Foundations only. v1 is the substrate, not a product.

## 1 — North star

We are building the **substrate** the v1.3 whitepaper describes: eight foundation pieces — sandbox, memory (board + ledger), skill loader + permission gate, threat-model artifact, confidence scorer, orchestrator, SARIF output, governance — that let a Claude Opus 4.8 agent (Bedrock, `global.anthropic.claude-opus-4-8`) read code semantically, run experiments in a closed sandbox, and verify hypotheses in a loop. One thin proof app (`apps/pr-reviewer`) wires them on a tiny corpus. We are **not** building concrete CWE skills, the human review UI/dashboard, the full five-mode lifecycle, Mythos integration, or any public-facing surface. Now, because the substrate must be trustworthy *before* the fuzzy audit content can be iterated safely on top of it.

Two invariants govern everything, verbatim from the product framing:

- **E3:** "The system shall execute all target-code experiments inside a throwaway sandbox launched with `--network=none` by default."
- **E12:** "The system shall append every tool call, sandbox lifecycle event, and gate decision to a hash-chained WORM audit log (S3 Object Lock or `chattr +a`)."

## 2 — Repo skeleton (final, attributed)

**Package count: 6** (C's count). A's 8 over-splits — `asec-output` and `asec-governance` each have exactly one v1 consumer; B's 4 over-merges — folding `threat-model` and `confidence` into `core` erases two seams that own distinct EARS invariants (E1/E2, E18) and are independently testable pure-logic units. Six keeps every whitepaper *seam* the substrate must preserve, while collapsing the two packages that are pure plumbing.

```
agentic-security-lab/
├── pyproject.toml  uv.lock  mise.toml  lefthook.yml          # workspace root (B)
├── ruff.toml  pyrightconfig.json  .editorconfig  .gitignore  .gitattributes
├── README.md  CONTRIBUTING.md  SECURITY.md  LICENSE  CHANGELOG.md
├── adr/                          # source-of-truth ADRs (C) — mirrored to docs
│   ├── 0000-template.md
│   └── 0001-adopt-claude-agent-sdk.md
├── packages/                     # shared libs (constraints)
│   ├── asec-core/                # (merged A+C) orchestrator + AgentRuntime seam + governance
│   ├── asec-sandbox/             # (A) isolated exec + WORM audit writer
│   ├── asec-memory/              # (merged B) board + ledger + SARIF/Bonk
│   ├── asec-skills/              # (A) SKILL.md loader + PreToolUse gate
│   ├── asec-threat-model/        # (C) pydantic artifacts; kept separate — owns E1/E2
│   └── asec-confidence/          # (C) three-axis scorer; kept separate — owns E18
├── apps/
│   └── pr-reviewer/              # (B) the one E2E app; src/ + fixtures/ + .claude/skills/
├── infra/cdk/                    # (A) Python CDK + CDK Nag; one stack v1
├── docs/                         # (all) Astro Starlight, pnpm-isolated
├── experiments/                  # (A/C) scratch; gitignored outputs
└── .github/workflows/            # (A) pinned-SHA actions, OpenSSF baseline
```

`src/` layout per package (A): every package ships `py.typed`; tests in per-package `tests/`. Rejected C's tests-beside-code — strict `src/` keeps import hygiene and pyright-strict scoping clean across a workspace.

## 3 — uv workspace + pyproject.toml (canonical)

Root `pyproject.toml` (workspace root, not publishable):

```toml
[project]
name = "agentic-security-lab"
version = "0.1.0"
requires-python = ">=3.13"

[tool.uv.workspace]
members = ["packages/*", "apps/*", "infra/cdk"]

[tool.uv.sources]
asec-core         = { workspace = true }
asec-sandbox      = { workspace = true }
asec-memory       = { workspace = true }
asec-skills       = { workspace = true }
asec-threat-model = { workspace = true }
asec-confidence   = { workspace = true }

[dependency-groups]
dev = ["pytest", "pytest-asyncio", "pytest-cov", "hypothesis",
       "atheris", "pyright", "ruff", "commitizen"]
security = ["bandit", "pip-audit", "checkov", "osv-scanner"]

[tool.ruff]
target-version = "py313"

[tool.pyright]
typeCheckingMode = "strict"
```

Representative member `packages/asec-confidence/pyproject.toml`:

```toml
[project]
name = "asec-confidence"
version = "0.1.0"
requires-python = ">=3.13"
dependencies = ["pydantic>=2.7", "structlog", "opentelemetry-api"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/asec_confidence"]
```

`uv sync` resolves the whole graph into one `.venv`; `uv.lock` committed. Strict dependency direction: `apps → packages → asec-core`; no package imports another's concrete class — only Protocols re-exported from `asec-core` (A's port discipline).

## 4 — mise.toml (canonical)

```toml
[tools]
python = "3.13"
uv     = "latest"
node   = "22"          # docs only

[env]
_.python.venv = { path = ".venv", create = true }
CLAUDE_CODE_USE_BEDROCK = "1"
ANTHROPIC_DEFAULT_OPUS_MODEL = "global.anthropic.claude-opus-4-8"

[tasks.install]   run = "uv sync"
[tasks.dev]       run = "uv run pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo"
[tasks.test]      run = "uv run pytest"
[tasks.lint]      run = "uv run ruff check ."
[tasks.format]    run = "uv run ruff format ."
[tasks.typecheck] run = "uv run pyright"
[tasks."security:scan"]  run = ["uv run bandit -r packages apps", "uv run pip-audit", "trivy fs ."]
[tasks."security:gitleaks"] run = "gitleaks detect --no-banner"
[tasks."cdk:synth"]  run = "uv run --package infra-cdk cdk synth"
[tasks."cdk:nag"]    run = ["uv run --package infra-cdk cdk synth", "uv run checkov -d infra/cdk/cdk.out"]
[tasks."docs:dev"]   dir = "docs"  run = "pnpm dev"
[tasks."docs:build"] dir = "docs"  run = "pnpm build"
[tasks."docs:sync"]  run = "uv run python scripts/sync_adrs.py"
[tasks."release:bump"] run = "uv run cz bump --changelog"
```

## 5 — Package contracts

All public types are Pydantic v2 (`frozen=True` for value objects); all I/O is async; every module gets `structlog.get_logger()` + an OTel span at entry points. Cross-package coupling is via `typing.Protocol` owned by `asec-core` (A).

**asec-core** — Orchestrator + provider-abstract model seam + governance (merged A's `asec-governance`). Public: `AgentRuntime(Protocol)` (`query`, `stream`, `spawn_subagents`, `register_hook`), `ClaudeAgentRuntime` (only v1 adapter, wraps `ClaudeSDKClient`), `Orchestrator.run(scope) -> ReviewResult`, `Settings(BaseSettings)`, `ScopeArtifact` + `KillSwitch` + `GovernanceGate`. Re-exports ports `SandboxPort`, `LedgerPort`, `SkillLoaderPort`. **Owns:** E14, E15, E16, E18 (dispatch), E19. Deps: `claude-agent-sdk`, pydantic, structlog, otel, cyclopts (CLI entrypoint), cryptography (scope signing).

**asec-sandbox** — Isolated execution + WORM audit. Public: `SandboxSpec` (kind `Literal["docker","firecracker","agentcore"]`, `network="none"` default, egress allowlist, limits), `Sandbox(Protocol)` (`start`/`exec`/`collect_artifacts`/`teardown`), `DockerSandbox` (rootless, `--cap-drop=ALL`, `--read-only`, seccomp, tmpfs, UID 10001), `WormAuditWriter.append(entry) -> str` (SHA-256 `prev_hash` JSONL). Firecracker/AgentCore = stubs. **Owns:** E3, E4, E5, E6, E12, E13. Deps: pydantic, anyio, structlog, otel; boto3 extra.

**asec-memory** — Hypothesis board + findings ledger + SARIF (merged B's `asec-output`). Public: `Finding`, `Hypothesis`, `Suppression` (pydantic), `LedgerPort` impls `SQLiteLedger` (aiosqlite, default) / `DynamoLedger` (single-table, stub-real day 4), `HypothesisBoard` (append-only), `to_sarif(findings) -> SarifReport` (SARIF v2.1 + `x-bonk` extension), `ReportAgent(Protocol)` (Executive/Engineering/Auditor). **Owns:** E9, E10, E11. Deps: pydantic, aiosqlite, structlog, otel, sarif-tools (ingest only); aioboto3 extra.

**asec-skills** — `SKILL.md` loader + permission gate. Public: `Skill` (frontmatter: name, description, `allowed_tools`), `SkillLoader.discover(root) -> list[Skill]`, `PolicyRegistry`, `permission_gate(...)` (PreToolUse hook, deny-by-default `editor`/`load_tool`). **Owns:** E7, E8. Deps: pydantic, pyyaml, structlog, otel, claude-agent-sdk (`HookMatcher`).

**asec-threat-model** — Phase-Zero artifacts. Public: `Asset`, `Threat`, `ThreatModel` (pydantic), `load(path)`, `dump(tm, path)` (round-trip stable), `diff(a, b) -> ThreatModelDiff`. **Owns:** E1, E2. Deps: pydantic, pyyaml, structlog, otel.

**asec-confidence** — Three-axis scorer. Public: `ConfidenceInputs` (pattern, recall, reachability 0–1), `ConfidenceStrategy(Protocol)`, `BaselineStrategy` (deterministic, `weights` tuple), `LLMJudgeStrategy` (opt-in), `bm25s` lexical recall. **Owns:** E18 (scoring). Deps: pydantic, bm25s, structlog, otel.

## 6 — The one E2E app (apps/pr-reviewer)

A single `src/pr_reviewer/main.py` (<300 lines), five named functions read top-to-bottom (C's legibility): `load_target` → `build_threat_model` (loads fixture `threat-model.yaml`) → `run_review` → `score_and_store` → `report`. Invoked `uv run pr-reviewer review ./fixtures/tiny-repo`.

| Aspect | v1 status |
|---|---|
| Agent SDK call to Bedrock Opus 4.8 | **Real** |
| SKILL.md load + PreToolUse gate | **Real** |
| Reads a tiny example diff (3-file corpus) | **Real** |
| Generates a finding, scores it | **Real** (confidence: constant day 3, three-axis day 5) |
| Writes SARIF + WORM line, persists in SQLite ledger | **Real** |
| Report Agent (Engineering) summary | **Real** (markdown table + PASS/FAIL gate) |
| Sandbox | `LocalSandbox` passthrough day 3 → `DockerSandbox` day 4 (B) |
| Threat model | Hand-written fixture, not agent-authored |
| Per-CWE subagent fan-out | Single `query()` day 3; fan-out day 5 (B) |

App depends only on the six `asec-*` packages — no logic of its own beyond wiring. README marks it NOT production-grade.

## 7 — CDK stack (Python + CDK Nag)

One `AsecSubstrateStack` (A; split later). Constructs: **VPC** (2 AZ, isolated subnets) + interface endpoint `BEDROCK_RUNTIME` + gateway endpoints `S3`/`DYNAMODB`; **S3 audit bucket** — `objectLockEnabled`, COMPLIANCE retention, SSE-KMS, `enforceSSL`, versioned, `blockPublicAccess=BLOCK_ALL`; **DynamoDB findings ledger** — single-table `TableV2`, `billing=on-demand`, PITR, KMS-CMK, `stream=NEW_AND_OLD_IMAGES`; **KMS key** (rotation on) shared by S3+DDB; **Bedrock IAM role** — scoped `bedrock:InvokeModel*` + inference-profile read, ledger RW, audit-bucket put-only (no delete).

**Single-table key shape:** `PK`/`SK` — `FINDING#<id>`/`META`, `SESSION#<id>`/`HYP#<seq>`, `LEDGER#<repo>`/`FINDING#<id>`; GSI1 on `status` for FP-suppression queries. Access patterns frozen in ADR-004 before first write.

```python
class AsecSubstrateStack(Stack):
    def __init__(self, scope, id, **kw):
        super().__init__(scope, id, **kw)
        key = kms.Key(self, "AsecKey", enable_key_rotation=True)
        audit = s3.Bucket(self, "AuditBucket", object_lock_enabled=True,
            encryption=s3.BucketEncryption.KMS, encryption_key=key,
            enforce_ssl=True, versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL)
        ledger = dynamodb.TableV2(self, "FindingsLedger",
            partition_key=dynamodb.Attribute(name="PK", type=STRING),
            sort_key=dynamodb.Attribute(name="SK", type=STRING),
            billing=dynamodb.Billing.on_demand(),
            encryption=dynamodb.TableEncryptionV2.customer_managed_key(key),
            point_in_time_recovery=True,
            dynamo_stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES)
        # vpc, endpoints, bedrock role omitted for brevity
```

CDK Nag (`AwsSolutionsChecks`) via `Aspects.of(app).add(...)`; suppressions centralized in `infra/cdk/cdk-nag-suppressions.md` with per-rule plain-language justification + ADR-backlog pointer. Encryption and public-access rules may **never** be suppressed (CI assert, B). `mise run cdk:nag` fails on un-suppressed findings.

## 8 — Docs (Astro Starlight)

```
docs/src/content/docs/
├── index.mdx
├── concepts/      (substrate, eight-foundations, lifecycle-modes)
├── guides/        (getting-started, run-pr-reviewer)
├── packages/      (one page per asec-* package)
├── adrs/          (generated mirror of /adr via scripts/sync_adrs.py)
└── reference/     (cli, settings, sandbox-configs)
```

pnpm isolated to `docs/`. Mermaid via `astro-mermaid`. `docs/CLAUDE.md` scope: concept + how-to pages only — never duplicate ADR content (ADRs are source-of-truth in `/adr`, mirrored read-only); every page opens with a runnable example before reference tables; max H3 depth (C discipline).

**First 8 ADRs:** 1 — Adopt Claude Agent SDK on Bedrock; 2 — `AgentRuntime` Protocol + adapter (Strands swap); 3 — Docker rootless sandbox behind `Sandbox` protocol; 4 — SQLite + DynamoDB single-table ledger; 5 — Hash-chained WORM audit (`chattr +a` / S3 Object Lock); 6 — Own pydantic SARIF v2.1 + Bonk models; 7 — Deny-by-default skill gate via PreToolUse hook; 8 — Pluggable `ConfidenceStrategy` with `bm25s` recall.

## 9 — CI workflows (`.github/workflows/`)

All third-party actions pinned by SHA; OpenSSF baseline.

| File | Does |
|---|---|
| `ci.yml` | `mise run lint` + `typecheck` + `test` (per-package matrix, coverage); the gate protecting the loop |
| `codeql.yml` | CodeQL Python SAST |
| `scorecard.yml` | OpenSSF Scorecard → SARIF upload |
| `dependency-review.yml` | PR dependency-diff gate |
| `docs-deploy.yml` | Starlight build + ADR sync + Pages deploy |
| `release.yml` | commitizen version bump + CHANGELOG + tag |
| `cdk-nag.yml` | `cdk synth` + CDK Nag report + checkov; fails on un-suppressed findings |
| `security.yml` | gitleaks, semgrep, trivy fs, syft+grype, bandit, osv-scanner, pip-audit |

## 10 — Bootstrap order (day-by-day)

**The ordering trick (B):** build the thinnest vertical slice that exercises every primitive *interface*, stubbing expensive internals — so integration risk surfaces Day 3, not Day 5.

- **Day 1 — skeleton + tooling green.** uv workspace + 6 package skeletons (`__init__.py` + `pyproject.toml` + one passing test each); mise/lefthook/ruff/pyright/commitizen; `ci.yml` + `security.yml` green on empty packages; Starlight scaffold + 3 pages; ADR-0001. **Precondition smoke test:** verify `bedrock:InvokeModel` against `global.anthropic.claude-opus-4-8` (B's Day-1 de-risk).
- **Day 2 — primitives with real interfaces.** `asec-memory` (real SQLite `Ledger` + `Finding` + `to_sarif`); `asec-sandbox` (real `WormAuditWriter` hash chain + `LocalSandbox` passthrough); `asec-skills` (real frontmatter parse + `permission_gate`); `asec-core` `AgentRuntime` Protocol + `ClaudeAgentRuntime`; `asec-threat-model` + `asec-confidence` (pure, fastest to finish — A). Each gets a unit test.
- **Day 3 — E2E loop runs (the milestone).** Wire `apps/pr-reviewer`: SKILL.md → `Orchestrator` → Bedrock Opus 4.8 → `Finding` → SQLite → `findings.sarif` + WORM line, over the committed fixture. One E2E test (SDK mocked in CI; live run documented).
- **Day 4 — infra + harden.** `AsecSubstrateStack` (VPC + endpoints + S3 Object Lock + DDB single-table + KMS + IAM); CDK Nag + suppressions; `cdk-nag.yml`. Swap `LocalSandbox` → real `DockerSandbox` (`--network=none`, non-root). structlog + OTel wiring.
- **Day 5 — second axis + polish.** Real three-axis `confidence`; per-CWE subagent fan-out gated on confidence; `docs-deploy.yml` + `scorecard.yml` + `release.yml`; `experiments/` + adversarial-CI corpus scaffold; ADRs 2–8.

**End-state Day 5:** `mise run test` green · `mise run cdk:synth` green with Nag · `apps/pr-reviewer` runs hello-world E2E on a sample diff.

## 11 — Three load-bearing decisions where the plans disagreed

1. **Package count.** A=8, B=4, C=6. **Winner: 6 (C)** — keep every whitepaper seam (sandbox isolation, WORM, gate, provider, threat-model/E1, confidence/E18), merge only the two single-consumer plumbing packages (`output`→`memory`, `governance`→`core`).
2. **Model-provider seam shape.** B/C want a plain `make_options()` function; A wants a `Protocol` + adapter. **Winner: Protocol + adapter (A, tech-stack ADR-002)** — the SDK's async-generator surface needs normalizing and a future `StrandsRuntime` must satisfy the same shape without inheritance coupling; a bare function leaks SDK types into the orchestrator.
3. **Sandbox-first vs loop-first.** A builds `DockerSandbox` before the loop; B ships `LocalSandbox` passthrough and swaps to Docker on Day 4. **Winner: loop-first (B)** — the `Sandbox` *protocol* is what proves loop topology; isolation is a Day-4 hardening pass behind one DI line, so integration risk surfaces two days earlier.

## 12 — Risks + mitigations (top 5)

1. **Bedrock auth/model-access blocks Day 3** → Day-1 5-line smoke test against the Opus profile, made an E2E precondition.
2. **Docker shared-kernel blast radius** → `--network=none` default + egress allowlist + seccomp + read-only root; Firecracker upgrade path designed behind the `Sandbox` protocol.
3. **Speed merges calcify into accidental debt** → ADR-0001 records each merge with its split trigger ("split when a second consumer appears"); public API re-exported so a split is mechanical.
4. **WORM `prev_hash` bug silently breaks tamper evidence** → canonical-JSON serialization pinned; chain-verification is a CI gate; golden-file tests on the writer.
5. **CDK Nag / checkov friction on Object Lock + KMS** → reviewed suppression list with rationale in `cdk-nag-suppressions.md`; encryption/public-access rules never suppressed (CI assert); every other finding a blocker.

## 13 — Day-1 commit checklist

Files the scaffolder writes in the first commit:

- `pyproject.toml` (workspace root, §3), `uv.lock`, `mise.toml` (§4), `lefthook.yml` (commit-msg→commitizen; pre-commit→ruff+pyright, parallel)
- `ruff.toml`, `pyrightconfig.json` (strict), `.editorconfig`, `.gitignore`, `.gitattributes`
- `README.md` (skeleton: lab purpose, 8 foundations→6 packages map, quickstart), `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE` (Apache-2.0), `CHANGELOG.md`
- `adr/0000-template.md` (MADR-style), `adr/0001-adopt-claude-agent-sdk.md`
- Per package (×6): `packages/<name>/pyproject.toml`, `src/<pkg>/__init__.py`, `src/<pkg>/py.typed`, `tests/test_<pkg>.py` (one passing assertion)
- `apps/pr-reviewer/pyproject.toml`, `src/pr_reviewer/__init__.py`, `fixtures/tiny-repo/` placeholder, `.claude/skills/security-code-review/SKILL.md` (stub)
- `infra/cdk/pyproject.toml`, `app.py` (skeleton importing `AsecSubstrateStack`), `cdk.json`, `stacks/__init__.py`, `cdk-nag-suppressions.md` (header only)
- `docs/` Starlight skeleton (`package.json`, `astro.config.mjs` with `astro-mermaid`, `src/content/docs/index.mdx`), `docs/CLAUDE.md`
- `scripts/sync_adrs.py` (ADR mirror)
- `.github/workflows/ci.yml` (minimal: `mise install` → lint → typecheck → test), `.github/workflows/security.yml` (gitleaks + dependency-review + codeql)
