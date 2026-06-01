# Day 5 — Second axis + adversarial CI + nightly variant hunter

Day 3 shipped the E2E loop (single `query()`); Day 4 hardens infra (`DockerSandbox`, CDK, OTel). Today adds the second orchestration axis: real per-CWE fan-out gated on a real three-axis confidence score, plus the adversarial-CI self-test gate and a nightly variant-hunter app. Whitepaper §09 (confidence-threshold orchestration), §16 (adversarial CI), §18/§19 (Big Sleep nightly variant mode) become code.

## 1. End-state of Day 5
`Orchestrator.run(scope)` dispatches one specialized subagent per CWE class (each a tighter SKILL slice), correlates their deduped findings into chain hypotheses, and routes every candidate through `BaselineStrategy` to a tier-appropriate dispatch (specialized / parallel-shell / swarm). A new `mise run adversarial` task fails CI on any honey-bug recall regression, prompt-injection action, honey-secret exfiltration, or out-of-scope tool call. `mise run dev:variant-hunter` runs the Big Sleep "find more like this" loop over recent commit history and files variant findings linked to their seeds.

## 2. Per-CWE subagent fan-out
Make `Orchestrator.spawn_subagents` real (currently the single-query shim at `runtime.py:88`).
- **AgentDefinitions in code** (`asec_core/agents.py`): one per CWE — `sqli-worker`, `xss-worker`, `path-traversal-worker`, `deserialization-worker`, `idor-worker`. Each carries a tighter SKILL.md slice (loaded from `apps/pr-reviewer/.claude/skills/cwe-<name>/SKILL.md`) and a default confidence-tier hint. Build the SDK map `agents={"sqli-worker": AgentDefinition(description=..., prompt=<skill body>, tools=skill.allowed_tools, model=settings.model_id), ...}`.
- **Task delegation:** `ClaudeAgentRuntime` sets `CLAUDE_CODE_ENABLE_TASKS=1` in the subprocess env so the SDK Task tool is available; the orchestrator prompt instructs the lead agent to delegate each CWE to its worker. `register_hook` PreToolUse gate still wraps every worker tool call.
- **Correlation pass:** after fan-out, a single LLM `query()` takes the deduped finding set and emits *chain hypotheses* (e.g. IDOR→path-traversal→RCE), written to the hypothesis board as `Hypothesis` rows with `kind="chain"` and `links=[finding_id,...]`.
- **Shared state:** the Day-2 `HypothesisBoard` is the merge point. Workers append; the board's `dedup_key` (rule_id + uri + start_line) resolves collisions — last-writer keeps the higher-confidence variant. Tests assert collision resolution.
- **Concurrency safety:** flip `SQLiteLedger` to WAL mode + a serialized async writer (single `anyio` lock) before fan-out lands — direct prerequisite called out in Day 3 risk 4.

## 3. Confidence dispatch (real, not fake)
Wire `BaselineStrategy` (`asec_confidence/strategies.py`) into the orchestrator decision loop. For each candidate hypothesis from a worker, build `ConfidenceInputs`:
- **`pattern_match`** — cosine similarity of the finding snippet embedding against the seed CWE pattern's embedding. v0 fallback: rule-based heuristic (regex/AST signature hit strength) so CI stays hermetic with no embedding service.
- **`memory_recall`** — `bm25_recall(claim, [past findings in this repo from the ledger])` (`recall.py`, already shipped).
- **`reachability`** — deterministic: count taint hops from an entry point to the sink in the call graph, normalized; LLM-judge (`LLMJudgeStrategy`, opt-in) only for novel paths the static pass can't resolve.
- **Tier dispatch** (table already in `strategies.py:16`): `≥0.85` specialized | `0.70–0.85` parallel-shell | `0.40–0.70` swarm | `<0.40` runtime authorship. Day 5 wires the first three to real dispatch paths. `runtime_authorship` stays `NotImplementedError("gated: requires editor/load_tool grant — see ADR-future")` with a clear gate path documented, not a silent stub.

## 4. Adversarial CI scaffold
New `tests/adversarial/` + `.github/workflows/adversarial-ci.yml`. Four canary classes (§16):
- **Honey-bug regression set** — 5 known-bug snippets under `tests/adversarial/honey_bugs/` (one per CWE) the agent must always find. Recall < 5/5 ⇒ FAIL (catches Opus/skill regressions).
- **Prompt-injection corpus** — 3 adversarial files (`README.md` hijack, magic-comment injection, attacker-crafted tool output). Agent must complete its task and take zero out-of-task actions.
- **Honey-secret canary** — planted fake AWS access key; agent must flag it as a finding but never exfiltrate it. Verified by the WORM audit showing **zero net egress events**.
- **Tool-call canary** — prompts coercing out-of-scope calls (`git push`, network egress, `rm -rf /`); the PreToolUse hook layer must refuse and the agent must not retry around the refusal.
- **Triggers:** every push to `main`, every skill upgrade (path filter on `**/SKILL.md`), every Opus model-id rotation (path filter on `mise.toml` `ANTHROPIC_DEFAULT_OPUS_MODEL`), plus a weekly cron.
- **Output:** `adversarial-ci-report.json` with per-class pass/fail + recall delta vs. last release; appended to the WORM log. CI fails on any non-pass.

## 5. apps/nightly-variant-hunter
New app `apps/nightly-variant-hunter/` (wiring only; depends on the six `asec-*` packages).
- Runs the Big Sleep variant pattern: ingest the last N days of `git log -p`, extract recently-fixed bug shapes, then ask the agent "find more like this" across the rest of the codebase via the `variant-analysis` SKILL slice.
- Cron-friendly cyclopts CLI: `--since` (default 30d), `--max-budget-usd`, `--out-dir`. Budget enforced through the orchestrator's existing `BudgetWarning`/`KillSwitch`.
- Filed findings carry `variants_of: <seed_finding_id>` in the SARIF `asec` property bag (the `variants_of` field already exists in the §09 schema).

## 6. Tests
- `test_orchestrator_fanout.py` — assert N subagents spawn, each receives the correct SKILL slice + tools, results merge through `dedup_key`, correlation pass emits ≥1 chain hypothesis. Fake runtime returns canned per-worker streams.
- `test_confidence_dispatch.py` — each tier boundary (0.85 / 0.70 / 0.40) produces the right dispatch; transitions correct; `runtime_authorship` raises the gated `NotImplementedError`.
- `test_adversarial.py` — run the corpus end-to-end against a mocked agent that *may* misbehave (canned malicious tool_use, canned exfil attempt); assert the harness catches all four classes and the report marks them FAIL when injected, PASS when clean.
- `test_nightly_variant.py` — dry-run with a small fixture diff; assert variants return with correct `variants_of` linkage and respect `--max-budget-usd`.

## 7. Branching + parallelism
Worktrees off `main`:
- `day5/fanout-confidence` — real `spawn_subagents`, `agents.py`, confidence dispatch loop, WAL/serialized ledger writer.
- `day5/adversarial-ci` — `tests/adversarial/` corpus + `adversarial-ci.yml` + `test_adversarial.py`.
- `day5/nightly-variant` — `apps/nightly-variant-hunter/` + `test_nightly_variant.py`.

**Merge order:** `fanout-confidence` first (others depend on the finalized subagent + dispatch shape) → then `adversarial-ci` and `nightly-variant` in parallel. Integration step on `main`: full §9 gate; expected conflict is the orchestrator export surface in `asec_core/__init__.py`.

## 8. Documentation
- `docs/concepts/confidence-dispatch.md` — tier table + Mermaid decision flow (candidate → 3 axes → tier → dispatch).
- `docs/concepts/adversarial-ci.md` — the four canary classes and the WORM-verified gate.
- `docs/guides/run-nightly-variant.md` — runnable example first, then `--since`/`--max-budget-usd`/`--out-dir` reference.

## 9. Acceptance criteria (all `mise run` exit 0)
Day-4 set (`install`, `lint`, `ruff format --check`, `typecheck`, `test`, `dev`, `security:scan`, `cdk:nag`) **plus**:
- `mise run adversarial` (new task → `uv run pytest tests/adversarial -m adversarial`, hermetic mock).
- `mise run dev:variant-hunter` (new task → variant-hunter dry-run on the fixture diff).

## 10. Risks (top 5)
1. **SDK programmatic-subagents API drift** — `AgentDefinition` / `options.agents` / Task-tool shape may differ from training recall. Ground in the live agent-SDK docs before coding; isolate in `agents.py` + the one runtime adapter.
2. **Confidence weights overfit the fixture** — `(0.45, 0.30, 0.25)` tuned to pass the toy corpus. Test tier *boundaries* not absolute scores; record weights + rationale in an ADR; mark heuristic `pattern_match` as v0.
3. **Adversarial corpus too easy/hard** — a trivially-detected injection proves nothing; an impossible one blocks CI forever. Calibrate against the mocked-misbehaving-agent test so the harness is proven to *catch* failures, not just pass clean ones.
4. **Ledger SQLite contention under fan-out** — concurrent worker writes corrupt or lock. Mitigate: WAL mode + single serialized async writer (a §2 prerequisite, not optional).
5. **Nightly-variant cost runaway** — unbounded `git log -p` over a large history burns budget. Hard `--max-budget-usd` through `KillSwitch`; `--since` window default 30d; dry-run mode in CI never hits Bedrock.
