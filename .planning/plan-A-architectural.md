# Plan A — Architectural-First v1 (agentic-security-lab)

Durable shape over quick win. Contracts before implementations; ports/adapters so Bedrock/Strands/Postgres/Firecracker are swaps, not rewrites.

## 1. Repo skeleton (`tree -L 3`)

```
agentic-security-lab/
├── mise.toml  pyproject.toml  uv.lock  ruff.toml  pyrightconfig.json
├── lefthook.yml  .editorconfig  .gitignore  .gitattributes
├── README.md  CONTRIBUTING.md  CHANGELOG.md  SECURITY.md  LICENSE
├── adr/
│   ├── 0000-template.md
│   └── 0001..0005-*.md
├── packages/
│   ├── asec-core/        {pyproject.toml, src/asec_core/, tests/}
│   ├── asec-sandbox/     {pyproject.toml, src/asec_sandbox/, tests/}
│   ├── asec-memory/      {pyproject.toml, src/asec_memory/, tests/}
│   ├── asec-skills/      {pyproject.toml, src/asec_skills/, tests/}
│   ├── asec-threat-model/{pyproject.toml, src/asec_threat_model/, tests/}
│   ├── asec-confidence/  {pyproject.toml, src/asec_confidence/, tests/}
│   ├── asec-output/      {pyproject.toml, src/asec_output/, tests/}
│   └── asec-governance/  {pyproject.toml, src/asec_governance/, tests/}
├── apps/
│   └── pr-reviewer/      {pyproject.toml, src/pr_reviewer/, .claude/skills/, tests/}
├── infra/cdk/            {pyproject.toml, app.py, stacks/, cdk.json, cdk_nag_suppressions.py}
├── docs/                 (Astro Starlight; pnpm)
├── experiments/          (scratch; gitignored outputs)
└── .github/workflows/
```

`src/` layout everywhere (no flat packages). Every package ships `py.typed`.

## 2. uv workspace layout

Root `pyproject.toml` is the workspace root, not a publishable package:

```toml
[tool.uv.workspace]
members = ["packages/*", "apps/*", "infra/cdk"]

[tool.uv.sources]
asec-core = { workspace = true }
asec-sandbox = { workspace = true }   # ...one line per package

[dependency-groups]
dev = ["pytest","pytest-asyncio","pytest-cov","ruff","pyright","commitizen","cdk-nag"]
```

Each member `pyproject.toml`: `requires-python = ">=3.13"`, `build-system = hatchling`, deps on sibling `asec-*` via `workspace = true`. Shared baseline in every package: `pydantic>=2.7`, `structlog`, `opentelemetry-api`. `uv sync` resolves the whole graph into one `.venv`; `uv.lock` committed.

## 3. Package contracts (8 foundations)

All public types are `pydantic.BaseModel` (frozen where it's a value object); all I/O boundaries are `async`; every module gets a `structlog.get_logger()` and an OTel span at entry points. Cross-package coupling is via `typing.Protocol` ports defined in `asec-core` only.

**asec-core** — Orchestrator + provider-abstract model layer + shared ports.
- `class ModelProvider(Protocol)`: `async def query(prompt, opts) -> AsyncIterator[Message]`
- `class BedrockProvider(ModelProvider)` (wraps Claude Agent SDK `query`/`ClaudeSDKClient`)
- `class Orchestrator`: `async def run(scope: ScopeArtifact) -> ReviewResult`
- `class Settings(BaseSettings)` (env: model id, region, sandbox kind)
- Ports re-exported: `SandboxPort`, `MemoryPort`, `SkillLoaderPort`, `OutputPort`.
- deps: `claude-agent-sdk`, pydantic, structlog, otel.

**asec-sandbox** — Isolated execution + WORM audit.
- `class SandboxSpec(BaseModel)`: kind `Literal["docker","firecracker"]`, network default `"none"`, egress_allow, limits.
- `class Sandbox(Protocol)`: `async def exec(cmd) -> ExecResult`, `async def teardown()`
- `class DockerSandbox` / `FirecrackerSandbox`
- `class WormAuditWriter`: `async def append(entry) -> str` (hash-chained JSONL → local or S3 Object Lock)
- deps: pydantic, anyio, structlog, otel; boto3 optional extra.

**asec-memory** — Hypothesis board + findings ledger + FP memory.
- `class Finding(BaseModel)`, `class Hypothesis(BaseModel)`, `class Suppression(BaseModel)`
- `class LedgerStore(Protocol)`: `upsert_finding`, `list_findings`, `record_suppression`
- `class SQLiteLedger` / `PostgresLedger` / `DynamoLedger` (single-table)
- deps: pydantic, sqlalchemy[asyncio], structlog, otel; psycopg/aioboto3 extras.

**asec-skills** — SKILL.md loader + permission gate.
- `class SkillManifest(BaseModel)` (frontmatter: name, description, allowed_tools, hooks, context)
- `class SkillLoader`: `def discover(root) -> list[SkillManifest]`
- `class PermissionGate`: `async def __call__(input_data, tool_use_id, ctx) -> HookResult` (deny-by-default `Edit`/`load_tool`)
- deps: pydantic, pyyaml, structlog, otel.

**asec-threat-model** — `threat-model.yaml` + `assets.yaml` artifacts.
- `class Asset(BaseModel)`, `class Threat(BaseModel)`, `class ThreatModel(BaseModel)`
- `def load(path) -> ThreatModel` / `def dump(tm, path)` (round-trip stable)
- `def diff(a, b) -> ThreatModelDiff`
- deps: pydantic, pyyaml, structlog, otel.

**asec-confidence** — Three-axis scorer.
- `class ConfidenceInputs(BaseModel)`: pattern_match, memory_recall, reachability (0–1)
- `class ConfidenceScorer(Protocol)`: `def score(inputs) -> ConfidenceScore`
- `class WeightedScorer` (pluggable weights) → drives orchestration tier.
- deps: pydantic, structlog, otel.

**asec-output** — SARIF + Bonk extension + report agents.
- `class SarifReport(BaseModel)` (SARIF v2.1 subset + `x-bonk` extension)
- `def to_sarif(findings) -> SarifReport`
- `class ReportAgent(Protocol)`: `async def render(findings, audience) -> str` (Executive/Engineering/Auditor)
- deps: pydantic, jsonschema, structlog, otel.

**asec-governance** — Scope artifact, STS time-box, kill switch.
- `class ScopeArtifact(BaseModel)` (signed: repos, paths, expiry)
- `class GovernanceGate`: `def validate(scope) -> None`, `def expired(scope) -> bool`
- `class KillSwitch`: `async def tripped() -> bool` (OWASP LLM01/06 controls)
- deps: pydantic, cryptography, structlog, otel.

## 4. The one E2E app — `apps/pr-reviewer`

CLI (`pr-reviewer review --diff <ref>`). Composition flow: load `ScopeArtifact` via **governance** → `SkillLoader` discovers `.claude/skills/security-code-review` + installs `PermissionGate` as a `PreToolUse` hook → `Orchestrator` (core) spins a `DockerSandbox` (sandbox, `--network=none`) → per-CWE `AgentDefinition` fan-out gated by `ConfidenceScorer` tier → findings written to `SQLiteLedger` (memory) → `to_sarif` + Engineering `ReportAgent` (output). App depends only on the eight `asec-*` packages — no logic of its own beyond wiring. Tiny fixture corpus under `tests/corpus/` (one seeded SQLi). Marked NOT production-grade in README.

## 5. CDK stack (`infra/cdk/`, Python)

Single `SubstrateStack` (split later). Constructs:
- `aws_ec2.Vpc` (2 AZ, isolated subnets) + `InterfaceVpcEndpoint` for `BEDROCK_RUNTIME`, `aws_ec2.GatewayVpcEndpoint` for `S3` + `DYNAMODB`.
- `aws_s3.Bucket` audit: `objectLockEnabled=True`, `ObjectLockConfiguration` GOVERNANCE retention, `encryption=KMS`, `enforceSSL=True`, `versioned`, `blockPublicAccess=BLOCK_ALL`.
- `aws_dynamodb.TableV2` findings ledger: single-table, PK `pk`/SK `sk`, `billing=on-demand`, PITR on, KMS-CMK encryption, `stream=NEW_AND_OLD_IMAGES`.
- `aws_kms.Key` (rotation enabled) shared by S3+DDB.
- `aws_iam.Role` agent role: scoped `bedrock:InvokeModel*` + inference-profile reads, ledger RW, audit-bucket put-only (no delete).
- `cdk_nag.AwsSolutionsChecks` via `Aspects.of(app).add(...)`; suppressions centralized in `cdk_nag_suppressions.py` with per-rule justification strings. CloudFront-fronted dashboard placeholder (origin = empty S3 site).

## 6. Docs — Astro Starlight (`docs/`, pnpm)

```
docs/src/content/docs/
├── index.mdx
├── concepts/        (substrate, eight-foundations, lifecycle-modes)
├── guides/          (getting-started, run-pr-reviewer)
├── packages/        (one page per asec-* contract)
├── adrs/            (generated mirror of /adr via sync script)
└── reference/       (cli, settings, sandbox-configs)
```
`adr/0000-template.md` (MADR-style: Context, Decision, Status, Consequences). First 5 ADRs:
1. uv workspace monorepo over multi-repo
2. Ports & adapters for provider/storage/sandbox abstraction
3. WORM audit via hash-chained JSONL + S3 Object Lock
4. DynamoDB single-table findings-ledger design
5. Deny-by-default skill permission gate via PreToolUse hooks

## 7. CI workflows (`.github/workflows/`)

All third-party actions pinned by SHA; OpenSSF baseline.
- `ci.yml` — `mise run lint` (ruff) + `mise run typecheck` (pyright strict) + `mise run test` (pytest matrix per package, coverage gate).
- `cdk-nag.yml` — `cdk synth` + Nag must pass; fails on un-suppressed findings.
- `codeql.yml` — CodeQL python.
- `scorecard.yml` — OpenSSF Scorecard → SARIF upload.
- `dependency-review.yml` — PR dependency diff gate.
- `gitleaks.yml` — secret scan.
- `docs-deploy.yml` — Starlight build + ADR sync + Pages deploy.
- `release.yml` — commitizen version bump + CHANGELOG + tag.

## 8. Bootstrap sequence (day 1 → N)

1. **Day 1 (complete):** root scaffold — mise.toml, root pyproject `[tool.uv.workspace]`, ruff.toml, pyrightconfig (strict), lefthook.yml, all root meta files, LICENSE (Apache-2.0), ADR 0001–0002.
2. **Day 2 (complete):** `asec-core` ports + `Settings` + `Message` types; CI `ci.yml` green on empty packages. *This unblocks everyone — ports first.*
3. **Day 3 (complete):** `asec-threat-model` + `asec-confidence` (pure, no I/O — fastest to finish + test).
4. **Day 4 (complete):** `asec-memory` SQLite adapter; `asec-output` SARIF (Postgres/Dynamo adapters = **stubs** raising `NotImplementedError`).
5. **Day 5 (complete):** `asec-skills` loader + `PermissionGate`; `asec-governance` scope + kill switch.
6. **Day 6 (complete-local / stub-microVM):** `asec-sandbox` DockerSandbox + WormAuditWriter complete; **FirecrackerSandbox = stub**.
7. **Day 7 (complete):** `asec-core` `BedrockProvider` + `Orchestrator`; `apps/pr-reviewer` wiring + corpus fixture.
8. **Day 8 (complete):** `infra/cdk` SubstrateStack + Nag suppressions; `cdk-nag.yml`.
9. **Day 9 (complete):** docs site + remaining CI (codeql/scorecard/dep-review/gitleaks/release/docs-deploy); ADR 0003–0005.

Stubs: Postgres/Dynamo ledgers, Firecracker, CloudFront dashboard, all CWE skills beyond the one review skill.

## 9. Three architectural anchors I'd defend

1. **Ports & adapters with all `Protocol`s owned by `asec-core`.** No `asec-*` package imports another's concrete class — only the port. Bedrock→Strands and SQLite→Dynamo become adapter swaps with zero call-site churn. This is the line speed/simple branches will cut; it's the one that survives v2.
2. **WORM audit is a first-class package contract, not an app concern.** `WormAuditWriter` hash-chains every tool call at the sandbox boundary so tamper-evidence is structural, not bolted on. Governance/compliance depend on it existing day 1.
3. **Confidence scorer is a separate pluggable package driving orchestration tier — not inline heuristics.** Decoupling the score from the orchestrator lets us tune/replace the three-axis model without touching fan-out logic, and makes it independently testable.

## 10. Risks + mitigations

1. **Over-abstraction slows v1.** → Cap ports at the 5 named; concrete adapters may be stubs but ports are frozen day 2.
2. **Claude Agent SDK requires CLI on PATH; brittle in CI.** → Pin SDK + CLI in mise.toml + sandbox image; provider is mocked in unit tests.
3. **CDK Nag noise stalls CI.** → Suppressions file with mandatory justification; PR review required to add one.
4. **uv workspace + 9 members = slow resolve / circular deps.** → Strict dependency direction (apps→packages→core only); `uv lock` in CI catches drift.
5. **Single-table DDB design hard to evolve.** → ADR 0004 fixes access patterns up front; local SQLite is the dev default so schema iterates cheaply.
