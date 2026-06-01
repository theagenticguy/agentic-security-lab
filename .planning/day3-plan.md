# Day 3 — E2E loop runs (the milestone)

Substrate goes from "tests pass" to "produces a real `Finding` from real source code via Bedrock Opus 4.8." Day-2 primitives are all real (ledger, WORM, gate, threat-model, confidence, `LocalSandbox`, `EventEmitter`). `claude-agent-sdk` 0.2.87 is installed. Today wires them.

## 1. End-state of Day 3
`mise run dev` (= `uv run pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo`) loads the 3-file tiny-repo + its `threat-model.yaml`, discovers `security-code-review/SKILL.md`, and runs `Orchestrator.run(scope)` — which builds `ClaudeAgentOptions` from `Settings`, registers `permission_gate` as a PreToolUse hook, and streams a real Bedrock Opus 4.8 `query()` over the corpus. The agent emits ≥3 findings (CWE-89/79/22), each scored by `BaselineStrategy`, persisted to `SQLiteLedger`, and serialized to `findings.sarif` with an `asec.v1` property bag; every phase boundary emits a typed `ProgressEvent` hash-chained into the WORM audit. Finally `ReportAgentImpl` reads the ledger and writes `REPORT_EXEC.md` / `REPORT_ENG.md` / `REPORT_AUDIT.md`. CI runs the same loop with a mocked Bedrock client — no network — asserting the SARIF schema, finding count, WORM chain, event set, and property bags.

## 2. The fixture corpus — `apps/pr-reviewer/fixtures/tiny-repo/`
Three deliberately vulnerable files (small, demo-obvious):
- `src/api/users.py` — **CWE-89**: `cursor.execute(f"SELECT * FROM users WHERE name='{name}'")` (f-string SQL).
- `src/web/render.py` — **CWE-79**: returns `f"<div>{request.args['q']}</div>"` unescaped to the browser.
- `src/files/download.py` — **CWE-22**: `open(os.path.join(BASE, request.args['p']))` with no normalization/containment check.

- `threat-model.yaml` — matches `asec_threat_model.models.ThreatModel`: `version: 1`, `generated_by`, `generated_at`, 3 `assets` (note `class:` alias, e.g. user-PII `HIGH`), 3 `threats` (STRIDE `I`/`T`/`I`, each `element_id` pointing at a file), one small `attack_trees` node. Must round-trip through `io.load`.
- `apps/pr-reviewer/.claude/skills/security-code-review/SKILL.md` — extend the existing stub: keep `allowed_tools: [Read, Grep, Glob, Bash]`, add per-CWE detection guidance + an explicit "emit findings as a JSON array of {rule_id, message, severity, cwe, uri, start_line, snippet}" output contract so the orchestrator can parse the final assistant message deterministically.
- `apps/pr-reviewer/tests/golden/findings.sarif` — golden snapshot for the **mocked** run (deterministic mock → stable SARIF). Compared structurally (rule_ids, locations, `asec` bag shape), not byte-exact on timestamps/ids.

## 3. ClaudeAgentRuntime — stub → real
Edit `packages/asec-core/src/asec_core/runtime.py` (currently raises at `runtime.py:85`,`:95`). Docs: https://docs.claude.com/en/api/agent-sdk/python.
- `query()` builds `ClaudeAgentOptions` and delegates to `claude_agent_sdk.query(prompt=..., options=...)`, yielding each SDK message normalized into a small typed `RuntimeMessage` (text / tool_use / tool_result / result) — never leak raw SDK types upward.
- **Settings → options map:** `model=settings.model_id`; `permission_mode=settings.permission_mode`; `allowed_tools` from the loaded `Skill.allowed_tools`; `hooks={"PreToolUse": [HookMatcher(hooks=[h]) for h in self._hooks["PreToolUse"]]}` from buffered `register_hook`. Bedrock backend is selected by env (`CLAUDE_CODE_USE_BEDROCK=1`, set in `mise.toml:105`) — the SDK reads it; no explicit option needed. `setting_sources=[]` so the SDK doesn't auto-load host config.
- **SDK → ProgressEvent bridge:** the runtime yields normalized messages; the *Orchestrator* (not the runtime) maps them to `asec_sandbox.events` `ProgressEvent`s and emits them. Keeps the runtime provider-pure.
- `spawn_subagents` stays a single-`query` shim (fan-out is Day 5 per PLAN §6); raise-free but unused on Day 3.
- Update `protocols.py:22` `AgentRuntime.query` signature (currently `-> str`) to the async-iterator shape `runtime.py` already uses, so the Protocol and adapter agree. Fix this divergence in the same change.

## 4. Orchestrator — new file
`packages/asec-core/src/asec_core/orchestrator.py`:
- `class Orchestrator` composing `AgentRuntime`, `SandboxPort`, `LedgerPort`, `EventEmitter`, `GovernanceGate`, `KillSwitch`, plus loaded `Skill` + `ThreatModel`. Injected via `__init__` (DI — `LocalSandbox` today, `DockerSandbox` Day 4 behind one line).
- `async def run(scope: ScopeArtifact) -> ReviewResult`:
  1. `gate.check()` → emit `GateDecision`; deny ⇒ abort.
  2. emit `PhaseTransition(recon→find)`; assemble prompt = SKILL body + threat-model summary + corpus file contents.
  3. `async for msg in runtime.query(prompt, options=...)`: bridge `tool_use`→`GateDecision`, model claims→`HypothesisOpened`, parse the final JSON result block into `Finding`s, emit `FindingEmitted` per finding. Budget tracked from message usage → `BudgetWarning` at 50/80/100% of `settings.max_budget_usd`; `kill.triggered` short-circuits.
  4. `to_sarif_log(findings)`; emit `RunComplete`. Return result.
- `async def run_pr(diff_path: Path) -> ReviewResult` — same loop, prompt seeded from a unified diff instead of full files.
- `ReviewResult` (frozen pydantic): `findings: list[Finding]`, `sarif: dict`, `audit_head_hash: str`, `events: list[ProgressEvent]`. Export `Orchestrator`, `ReviewResult` from `asec_core/__init__.py`.

## 5. apps/pr-reviewer rewrite (~200–300 lines)
Replace the 5 `NotImplementedError` stubs in `main.py`:
- `load_target(path)` → `TargetCorpus`: read every file under `target/src`, discover the SKILL via `SkillLoader.discover([Path("apps/pr-reviewer/.claude/skills")])`, pick `security-code-review`.
- `build_threat_model(corpus)` → `asec_threat_model.io.load(target/"threat-model.yaml")`.
- `run_review(corpus, tm)` → build `Settings()`, `LocalSandbox`, `SQLiteLedger(...).init()`, `WormAuditWriter`+`EventEmitter`, a self-signed dev `ScopeArtifact` (`sign_scope` with an ephemeral key) + `GovernanceGate`, register `permission_gate` (bound to `skill.allowed_tools`, denied-paths `[".env","*.pem"]`) as PreToolUse, instantiate `Orchestrator`, `await .run(scope)`.
- `score_and_store(result)` → for each finding run `BaselineStrategy().score(ConfidenceInputs(...))`, fold tier/score into `AsecProperties` (`model_copy`), `ledger.add_finding`.
- `report(scored)` → write `findings.sarif`, instantiate `ReportAgentImpl(ledger, tm)`, write 3 reports, print Engineering PASS/FAIL gate.
- cyclopts entrypoint unchanged; wrap the async body in `anyio.run`.

## 6. ReportAgent — new
`packages/asec-memory/src/asec_memory/report.py`. Promote the `ReportAgent(Protocol)` (PLAN §5) and add `ReportAgentImpl`:
- ctor `(ledger: LedgerPort, threat_model, out_dir: Path)`; `async def generate() -> dict[str,Path]`.
- Reads `ledger.list_findings()` only (idempotent, ledger-as-input per §13). Day-3 templates are deterministic Python string-builders (no second LLM pass yet — keeps CI hermetic):
  - `REPORT_EXEC.md` — top-5 by `priority` (Reachability×Exploitability×Asset), plain prose.
  - `REPORT_ENG.md` — one card per HIGH/error finding: `uri:line`, snippet, suggested patch placeholder, regression-test path; deferred MED/LOW section.
  - `REPORT_AUDIT.md` — threat-model coverage table, model id, skill name, WORM head hash range. Export from `asec_memory/__init__.py`.

## 7. Tests
- `apps/pr-reviewer/tests/test_e2e.py` (CI, no network): inject a **fake `AgentRuntime`** whose `query()` yields a canned tool_use stream + a final JSON block of 3 findings (mirrors the real model contract — single mock seam keeps drift small). Assert: (a) SARIF validates against the v2.1 schema (use `jsonschema` against the bundled SARIF schema, dev dep); (b) `len(findings) >= 3`; (c) `verify_chain(worm_path)` returns clean; (d) the emitted event set ⊇ `{PhaseTransition, GateDecision, FindingEmitted, RunComplete}`; (e) each finding's `properties.asec` has `reachability`, `confidence`, `priority`; (f) golden `findings.sarif` structural match.
- `apps/pr-reviewer/tests/test_e2e_live.py` marked `@pytest.mark.live` (register marker in root `pyproject.toml`): real `ClaudeAgentRuntime`+Bedrock, skipped unless `RUN_LIVE_BEDROCK=1`. Add `-m "not live"` to the default pytest addopts so CI never hits it; engineers run `RUN_LIVE_BEDROCK=1 uv run pytest -m live`.

## 8. Branching + parallelism
Three worktrees off `main` (`git worktree add`):
- `day3/orchestrator` — `asec-core/orchestrator.py` + real `ClaudeAgentRuntime` + `protocols.py` signature fix + `ReviewResult`. Owns the runtime↔event bridge.
- `day3/report-agent` — `asec-memory/report.py` `ReportAgentImpl` + its unit test (pure, ledger-only — no dependency on orchestrator).
- `day3/pr-reviewer` — fixture corpus + SKILL.md + `main.py` rewrite + `test_e2e.py`/`test_e2e_live.py` + golden SARIF.

**Merge order:** `orchestrator` first (everything depends on `Orchestrator`/`ReviewResult`) → `report-agent` (independent, mergeable in parallel, land second) → `pr-reviewer` last (consumes both). **Integration step:** on `main` after all three, run the full §9 gate; resolve the one expected conflict (`asec_memory/__init__.py` exports) and the golden SARIF regenerated against the merged code.

## 9. Day 3 acceptance criteria (all must exit 0)
- `mise run install`
- `mise run lint`
- `uv run ruff format --check .`
- `mise run typecheck` (pyright strict — including the new `orchestrator.py`, `report.py`)
- `mise run test` (includes `test_e2e.py`; `-m "not live"`)
- `mise run dev` (mocked path in CI; live path produces real Bedrock findings locally)
- `mise run security:scan` (bandit must not flag the fixtures — they live under `fixtures/`, add a `# nosec` carve-out or bandit `exclude_dirs` for the intentionally-vulnerable corpus, justified in-file)
- `mise run cdk:nag` (unchanged from Day 1 scaffold; stays green — no infra changes today)

## 10. Risks (top 5)
1. **Mock vs live Bedrock divergence** — the fake runtime's message shape drifts from the real SDK stream. Mitigate: one normalization seam (`RuntimeMessage`); the live test (manually run before merge) is the contract check; mock is built from a captured real transcript.
2. **claude-agent-sdk API drift** (0.2.87) — `ClaudeAgentOptions`/`HookMatcher`/`query` signatures. Mitigate: ground in the docs URL before coding; pin the SDK version in `uv.lock`; one thin adapter file isolates blast radius.
3. **SARIF schema validator** — strict v2.1 validators reject minor shape issues. Mitigate: validate against the bundled OASIS schema in `test_e2e.py`; keep `to_sarif` output minimal and spec-clean (already does).
4. **Ledger concurrent-write under fan-out** — `SQLiteLedger` opens a new connection per call; future parallel subagents could contend. Day 3 is single-`query` so safe; note WAL-mode/serialized-writer as a Day-5 prerequisite before fan-out lands.
5. **Fixture-corpus authenticity** — patterns too toy ⇒ model won't "find" them naturally, or security:scan flags our own repo. Mitigate: real-looking idioms (Flask-style handlers), corpus isolated under `fixtures/` and excluded from bandit, golden file proves the mock detects all three.
