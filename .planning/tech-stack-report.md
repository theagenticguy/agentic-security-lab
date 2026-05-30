# agentic-security-lab — v1 Tech Stack Report

**Audience:** AWS Principal Eng + AGS field · **Date:** May 2026 · **Scope:** v1 substrate (foundations only) per `CONSTRAINTS.md`. Settled defaults (Python 3.13, uv, mise, lefthook, ruff, pyright, commitizen, pytest, pydantic v2, structlog, OpenTelemetry, polars+altair, CDK Python + CDK Nag, Astro Starlight, GitHub Actions w/ pinned SHAs, OpenSSF Scorecard, Conventional Commits, Apache-2.0) are assumed, not re-justified.

---

## Section 1 — Stack at a glance

| Layer | Choice | Why | ADR |
|---|---|---|---|
| Agent SDK | Claude Agent SDK (Python), Bedrock backend | Whitepaper mandates `ClaudeSDKClient` + programmatic subagents; native hooks/forks | ADR-001 |
| Model seam | `AgentRuntime` **Protocol** + adapter | Strands becomes a swap, not a rewrite; matches Cyber-AutoAgent precedent | ADR-002 |
| Sandbox runtime | Docker rootless (day 1); Firecracker / AgentCore (v2) | Lowest build cost; track-c hardened `runArgs`; substrate behind `Sandbox` protocol | ADR-003 |
| Memory store | SQLite (local) + DynamoDB single-table (cloud), `Repository` protocol | Zero-dep local, serverless cloud, no Postgres ops | ADR-004 |
| Hypothesis board | Same `Repository` protocol; JSONL local, DDB+Streams cloud | Ephemeral per-session; Streams fan-out for orchestration | ADR-005 |
| WORM audit | JSONL `prev_hash` chain; `chattr +a` local, S3 Object Lock+KMS cloud | Tamper-evident, matches track-c §8 | ADR-006 |
| Findings format | SARIF v2.1 pydantic models + Bonk extension | Type-safe round-trip; `sarif-tools` for read/merge only | ADR-007 |
| Skill loader | Own loader over `.claude/skills/SKILL.md` | Deny-by-default gate + provider independence | ADR-008 |
| Hook pattern | `HookMatcher` wrapped in thin policy registry | One indirection for testability, no framework | ADR-009 |
| Confidence scorer | Three-axis `ConfidenceStrategy` protocol; `bm25s` recall | Deterministic baseline + LLM judge; no vector infra in v1 | ADR-010 |
| Diagrams | Mermaid via `astro-mermaid` | Matches ai-gateway | ADR-011 |
| HTTP client | `httpx` async | Async-first I/O | ADR-012 |
| CLI | `cyclopts` | Preferred-lib default, type-hint native | ADR-013 |
| Test harness | pytest + hypothesis + atheris | Property + fuzz, matches ai-gateway | ADR-014 |
| Tracing | otel-api/sdk + ADOT Collector → X-Ray | Vendor-neutral SDK, AWS-managed export | ADR-015 |
| Container build | uv on `python:3.13-slim`, multi-stage, UID 10001 | Mirrors track-c non-root agent | ADR-016 |
| Security CI gates | semgrep, gitleaks, trivy fs, syft+grype, checkov, bandit, osv-scanner, pip-audit | Mirror ai-gateway exactly | ADR-017 |

---

## Section 2 — Decisions

### 2.1 Agent SDK abstraction (ADR-001, ADR-002)

**Decision.** Default to the Claude Agent SDK (Python) on the Bedrock backend (`global.anthropic.claude-opus-4-8`). Wrap it behind an `AgentRuntime` **Protocol** in `asec-core` (`query()`, `stream()`, `spawn_subagents()`, `register_hook()`), with a `ClaudeAgentRuntime` adapter as the only v1 implementation.

**Rationale.** The whitepaper's orchestrator is defined in SDK-native terms — `ClaudeSDKClient`, `AgentDefinition` fan-out, the 10 hook events, session fork for parallel hypothesis testing. A Protocol (structural typing, pyright-strict-friendly, zero inheritance coupling) lets a future `StrandsRuntime` satisfy the same shape without touching orchestration. Cyber-AutoAgent proved the Strands+Bedrock swarm/Report-Agent pattern at 85% XBOW; an ABC would force Strands into Anthropic's class hierarchy, whereas a Protocol + adapter keeps each runtime idiomatic. Adapter (not bare Protocol) because the SDK's async-generator surface needs normalizing to our internal message envelope.

**Alternatives.** ABC (rejected: inheritance coupling, harder mocking); direct SDK calls (rejected: no Strands seam, violates `CONSTRAINTS.md` line 15). **Consequences.** One adapter to maintain per runtime; orchestrator tests mock the Protocol, never the network.

### 2.2 Sandbox runtime (ADR-003)

**Decision.** Docker rootless on day 1 with track-c hardened `runArgs` (`--cap-drop=ALL`, `--read-only`, `--network=none`, seccomp, tmpfs scratch, UID 10001). Define a `Sandbox` protocol (`start`, `exec`, `collect_artifacts`, `teardown`) so Firecracker microVM and Bedrock AgentCore Code Interpreter drop in for v2 without orchestrator changes.

**Rationale.** Docker has the lowest boot/build cost (~50–200 ms, track-c §6) and runs anywhere a reviewer sits. The blast-radius gap (shared kernel) is acceptable for v1 because egress is off by default and a tinyproxy sidecar gates the allowlist. The `Sandbox` protocol plus a `SandboxFactory` keyed on a `kind` enum (`docker|firecracker|agentcore`) is the v2 extension point; the WORM audit writer records `sandbox.kind`/`id`/`net` so substrate swaps stay observable.

**Alternatives.** Firecracker day 1 (rejected: KVM/bare-metal requirement blocks laptop dev); AgentCore-only (rejected: couples v1 to a managed service before the primitive is proven). **Consequences.** Hardening lives in code, not docs; v2 substrates inherit the audit + egress contracts for free.

### 2.3 Memory store (ADR-004)

**Decision.** SQLite for local dev, DynamoDB **single-table** for cloud, both behind a `Repository[T]` protocol in `asec-memory`. The findings ledger is the durable store.

**Rationale.** SQLite is zero-dependency, file-portable, and fast for the single-writer local loop; DynamoDB is serverless (no instance to patch, on-demand billing) and Streams-native for the hypothesis board. Single-table design (`PK`/`SK` with `FINDING#<id>`, `SESSION#<id>`, `LEDGER#<repo>` partitions, a GSI on `status` for FP-suppression queries) fits the access patterns — write-once findings, point reads, session range scans — without join needs. Postgres was rejected: it adds an always-on instance, VPC, and patch surface that `CONSTRAINTS.md` ("foundations first," serverless-leaning) does not want in v1. SQLite mirrors the relational shape locally; the protocol hides the divergence.

**Alternatives.** Postgres adapter (deferred, not removed — the constraints doc names it as an option); pure-file local (rejected: no query). **Consequences.** Two backends to test; single-table demands disciplined key design documented in the ADR.

### 2.4 Hypothesis board (ADR-005)

**Decision.** Same `Repository` protocol as the ledger, distinct entity type. Local: append-only JSONL per session. Cloud: DynamoDB with **Streams** enabled, TTL on session rows.

**Rationale.** The board is per-session and ephemeral (whitepaper foundation 2), so it shares the storage abstraction but not durability semantics — TTL expires it, the ledger persists. Streams is the key difference: a hypothesis state-change event drives confidence-gated orchestration (promote to parallel-shell / swarm) without polling. JSONL locally gives the same append-event semantics a Stream provides, so the orchestrator's reactive code is identical across environments.

**Alternatives.** Separate protocol (rejected: needless duplication — entity differs, contract does not); SQS instead of Streams (rejected: Streams is co-located with the data, no extra resource). **Consequences.** Cloud orchestrator subscribes to a Stream; local subscribes to a file tailer — one adapter each.

### 2.5 WORM audit (ADR-006)

**Decision.** Append-only JSONL, each line hash-chained via `prev_hash` (SHA-256 over the canonical prior line), matching track-c §8. Local: file opened append-only, hardened with `chattr +a`. Cloud: S3 Object Lock (COMPLIANCE mode) + SSE-KMS.

**Rationale.** Hash chaining gives tamper *evidence* even where the OS cannot enforce immutability; `chattr +a` and Object Lock give tamper *resistance* at the two tiers. This satisfies whitepaper governance (foundation 8) and OWASP LLM06 audit expectations. The writer is a single class emitting the exact track-c line shape (`ts`, `seq`, `session`, `actor`, `sandbox`, `action`, `egress[]`, `prev_hash`, `hash`), so a verifier can replay the chain offline. CDK Nag will flag the bucket; suppress with documented rationale tied to Object Lock.

**Alternatives.** QLDB (rejected: deprecated direction, over-engineered for v1); CloudTrail-only (rejected: doesn't capture agent tool-call semantics). **Consequences.** Chain verification is a CI test; KMS key rotation policy documented in the stack.

### 2.6 Findings format (ADR-007)

**Decision.** Roll our own **pydantic v2** models for SARIF v2.1 + the Bonk extension (in `propertyBag`). Use `sarif-tools` only for reading/merging third-party SARIF (semgrep, codeql, trivy) into our model.

**Rationale.** `sarif-tools` is read/aggregate-oriented and not a strict pydantic emitter; our findings must round-trip type-safely (pyright strict) and carry the Bonk extension fields (confidence triple, reachability, hypothesis-id) the whitepaper requires. Hand-written pydantic models give validation, JSON-schema export for the SDK's `output_format`, and a clean `.to_sarif()`/`.from_sarif()` boundary. We still consume `sarif-tools` to ingest scanner output rather than reparsing each tool's dialect.

**Alternatives.** `jschema-to-python`/`sarif-om` (rejected: unmaintained, not pydantic); fully wrap `sarif-tools` (rejected: can't model the extension cleanly). **Consequences.** We own the SARIF spec subset we emit; covered by golden-file + hypothesis round-trip tests.

### 2.7 Skill loader (ADR-008)

**Decision.** Build our own loader in `asec-skills` that reads `SKILL.md` (front-matter: `name`, `description`, `allowed-tools`) from `.claude/skills/`, validates with pydantic, and feeds a deny-by-default PreToolUse gate. Do **not** wrap Claude Code's internal loader.

**Rationale.** The Agent SDK exposes hooks and `allowed_tools` but not a stable public skill-loading API; coupling to Claude Code internals would break the Strands seam (ADR-002). Our loader is ~150 lines, gives a typed `Skill` model, and lets the permission gate (`editor`/`load_tool` deny-by-default, foundation 3) live in our code where CI can test it. Provider-independent by construction.

**Alternatives.** Wrap Claude Code (rejected: private API, provider lock-in). **Consequences.** We track the `SKILL.md` schema ourselves; one parser to maintain.

### 2.8 Hook pattern (ADR-009)

**Decision.** Use `claude_agent_sdk.HookMatcher` as the only mechanism, wrapped in a thin `PolicyRegistry` that maps `(HookEvent, matcher) → list[callable]`. No layered hook framework.

**Rationale.** The SDK's 10 events + `HookMatcher` already cover deterministic policy enforcement (the threat-model edit-gate in track-a is the canonical case). A registry adds exactly one indirection: it makes hooks unit-testable in isolation and lets the Strands adapter re-expose the same registered policies. A bespoke framework would duplicate SDK plumbing for no gain in v1.

**Alternatives.** Bare `HookMatcher` lists inline (rejected: untestable, scattered); full framework (rejected: YAGNI). **Consequences.** Policies are pure functions registered once; the registry is the seam the adapter binds to.

### 2.9 Confidence scorer (ADR-010)

**Decision.** A `ConfidenceStrategy` **Protocol** scoring the three axes (pattern-match × memory-recall × reachability). v1 ships a deterministic `BaselineStrategy` plus an optional `LLMJudgeStrategy`. Memory-recall uses **`bm25s`** for lexical similarity against prior findings.

**Rationale.** Pluggability is mandated (foundation 5). `bm25s` is pure-Python, fast, dependency-light, and needs no embedding model, vector index, or extra service — correct for v1 where the FP-memory corpus is small and ops simplicity wins. `lancedb`/`chromadb` introduce a vector store and an embedding call per query: real infrastructure we defer until corpus size justifies semantic recall (noted as a v2 swap, trivial behind the protocol). The deterministic baseline keeps scoring reproducible for CI; the LLM judge is opt-in to control cost/latency.

**Alternatives.** `lancedb` (deferred: embedded vector DB, v2 when recall quality demands it); `chromadb` (rejected for v1: server/client surface). **Consequences.** Recall is lexical in v1; the protocol makes the embedding upgrade a one-class change.

### 2.10 Confirmations (ADR-011 → ADR-016)

- **Diagrams (ADR-011):** Mermaid via `astro-mermaid` in Starlight — confirmed, matches ai-gateway.
- **HTTP (ADR-012):** `httpx` async client — confirmed (async-first constraint).
- **CLI (ADR-013):** `cyclopts` — confirmed. Stub in §4.
- **Test harness (ADR-014):** pytest + hypothesis (property) + atheris (coverage-guided fuzz of parsers/serializers) — confirmed.
- **Tracing (ADR-015):** `opentelemetry-api` + `opentelemetry-sdk`, exported to **ADOT Collector** → X-Ray. Chosen over the direct X-Ray exporter so the SDK stays vendor-neutral and the collector owns batching/sampling/credentials; ADOT is the AWS-supported OTel distro.
- **Container (ADR-016):** multi-stage `python:3.13-slim`; builder stage runs `uv sync --frozen`, runtime stage copies the venv, drops to non-root UID 10001, mirrors track-c.

### 2.11 Security CI gates (ADR-017)

Mirror ai-gateway exactly: **semgrep** (SAST), **gitleaks** (secrets), **trivy fs** (deps/IaC), **syft + grype** (SBOM + container CVE), **checkov** (CDK synth output), **bandit** (Python SAST), **osv-scanner** + **pip-audit** (dependency vulns). All as GitHub Actions with pinned SHAs, on top of the OpenSSF baseline (Scorecard, dependency-review, CodeQL). Every non-zero exit is a blocker per global tenets.

---

## Section 3 — ADR titles to file

1. **ADR-001** — Adopt Claude Agent SDK (Python) on Bedrock as the default agent runtime
2. **ADR-002** — Define `AgentRuntime` Protocol + adapter to keep Strands a swap
3. **ADR-003** — Docker rootless sandbox v1 behind a `Sandbox` protocol; Firecracker/AgentCore v2
4. **ADR-004** — SQLite + DynamoDB single-table findings ledger via `Repository` protocol
5. **ADR-005** — Hypothesis board on the shared `Repository` protocol with DynamoDB Streams
6. **ADR-006** — Hash-chained WORM audit: `chattr +a` local, S3 Object Lock + KMS cloud
7. **ADR-007** — Own pydantic SARIF v2.1 + Bonk-extension models; `sarif-tools` for ingest
8. **ADR-008** — Custom `SKILL.md` loader with deny-by-default permission gate
9. **ADR-009** — `HookMatcher` wrapped in a thin `PolicyRegistry`
10. **ADR-010** — Pluggable `ConfidenceStrategy` protocol; `bm25s` recall in v1
11. **ADR-011** — Mermaid diagrams via `astro-mermaid`
12. **ADR-012** — `httpx` async HTTP client
13. **ADR-013** — `cyclopts` CLI framework
14. **ADR-014** — pytest + hypothesis + atheris test harness
15. **ADR-015** — OpenTelemetry SDK exporting via ADOT Collector to X-Ray
16. **ADR-016** — Multi-stage `python:3.13-slim` container, non-root UID 10001
17. **ADR-017** — Security CI gate suite mirroring ai-gateway

---

## Section 4 — `pyproject.toml` & `mise.toml` shape

**`pyproject.toml` (workspace root, abbreviated):**

```toml
[project]
name = "agentic-security-lab"
requires-python = ">=3.13"

[tool.uv.workspace]
members = ["packages/*", "apps/*", "infra/cdk"]

[tool.uv.sources]
asec-core       = { workspace = true }
asec-memory     = { workspace = true }
asec-sandbox    = { workspace = true }

[dependency-groups]
dev = ["pytest", "hypothesis", "atheris", "pyright", "ruff", "commitizen"]

# core runtime deps (added via `uv add`, never hand-edited):
#   claude-agent-sdk, pydantic, structlog, httpx, cyclopts,
#   opentelemetry-api, opentelemetry-sdk, boto3, bm25s, sarif-tools

[tool.ruff]
target-version = "py313"
[tool.pyright]
typeCheckingMode = "strict"
```

**`mise.toml` (root):**

```toml
[tools]
python = "3.13"
uv     = "latest"

[env]
_.python.venv = { path = ".venv", create = true }
CLAUDE_CODE_USE_BEDROCK = "1"
ANTHROPIC_DEFAULT_OPUS_MODEL = "global.anthropic.claude-opus-4-8"

[tasks.test]
run = "uv run pytest"
[tasks.lint]
run = ["uv run ruff check .", "uv run pyright"]
[tasks.scan]
description = "Local security gate"
run = ["uv run bandit -r packages apps", "uv run pip-audit", "trivy fs ."]
[tasks.synth]
run = "uv run cdk synth && uv run checkov -d infra/cdk/cdk.out"
```

**`cyclopts` entrypoint stub (`apps/cli/asec.py`):**

```python
import cyclopts

app = cyclopts.App(name="asec", help="agentic-security-lab CLI")

@app.command
async def review(repo: str, *, mode: str = "pr") -> None:
    """Run the orchestrator review loop over a repo."""
    from asec_core import build_runtime
    runtime = build_runtime()  # returns AgentRuntime (Claude adapter)
    await runtime.review(repo, mode=mode)

if __name__ == "__main__":
    app()
```

---

## Section 5 — Risks (top 5)

1. **Agent SDK API churn.** The Claude Agent SDK is young; hook signatures and `ClaudeAgentOptions` fields move. *Mitigation:* the `AgentRuntime` adapter is the only contact point — churn is contained to one file, regression-tested against pinned SDK versions.
2. **Docker shared-kernel blast radius.** v1 runs untrusted target code in a shared-kernel container. *Mitigation:* `--network=none` default + egress allowlist + seccomp + read-only root; Firecracker upgrade path already designed behind the `Sandbox` protocol (ADR-003).
3. **Single-table DynamoDB modeling lock-in.** Wrong key design forces a painful migration. *Mitigation:* access patterns enumerated and frozen in ADR-004 before first write; `Repository` protocol lets the Postgres adapter take over if patterns outgrow DDB.
4. **WORM chain integrity gaps.** A bug in `prev_hash` computation silently breaks tamper evidence. *Mitigation:* canonical-JSON serialization pinned, chain-verification is a CI gate, golden-file tests on the writer.
5. **CDK Nag / checkov friction on the Object Lock bucket + KMS.** Security gates may block synth on legitimately-suppressed findings. *Mitigation:* maintain an explicit, reviewed suppression list with rationale (CONSTRAINTS line 13); treat every other finding as a blocker.
