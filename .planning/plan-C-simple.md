# Plan C — SIMPLE-FIRST v1

> Branch C of Ultraplan. Optimizes for **legibility**: a sharp engineer who joined yesterday reads the whole repo and groks it in 30 minutes. Where A optimizes structure and B optimizes speed, C optimizes *concept count*. The bias throughout: plain functions over classes, one obvious file over a clever abstraction, and "extract later when it hurts" over "abstract now in case."

## 1. Minimal mental model (the 5 sentences a new hire reads)

1. An **orchestrator** asks Claude Opus 4.8 (via Bedrock) to review a target repo, dispatching one read-only subagent per CWE class.
2. Every tool the agent runs is gated by a **deny-by-default hook** and executed inside a **`--network=none` sandbox** that writes a tamper-evident audit log.
3. The agent's procedural know-how lives in **Skills** (`SKILL.md` files), loaded on demand.
4. Findings land in a **ledger** (SQLite locally, DynamoDB in AWS) serialized as **SARIF**, each scored by a **three-axis confidence** number.
5. One app, **`apps/pr-reviewer`**, wires all of that into a single loop you can run end-to-end on a tiny corpus.

That is the entire system. Six nouns, one verb (review), one app.

## 2. Repo tree (flat, predictable)

We keep the **one-package-per-whitepaper-noun** decomposition the constraints mandate — but each package is deliberately *thin* (one module + `__init__`, not a class hierarchy). The decomposition is justified because the whitepaper invariants (sandbox isolation, WORM audit, deny-by-default gate, provider-abstract model layer) are *seams the substrate must preserve*; collapsing them into one package would erase the seams. So: many packages, but each is small enough to read in two minutes.

```
agentic-security-lab/
├── packages/
│   ├── asec-sandbox/        # run a command in an isolated, no-net box + WORM log
│   ├── asec-memory/         # hypothesis board + findings ledger + SARIF
│   ├── asec-skills/         # load SKILL.md + the PreToolUse permission gate
│   ├── asec-threat-model/   # pydantic models for threat-model.yaml / assets.yaml
│   ├── asec-confidence/     # one function: score(pattern, memory, reachability)
│   └── asec-core/           # orchestrator + the model-provider seam
├── apps/
│   └── pr-reviewer/         # the one E2E app (<300 lines, one module)
├── infra/cdk/               # one stack file
├── docs/                    # Astro Starlight
├── adr/                     # source-of-truth ADRs (mirrored into docs)
├── experiments/             # scratch, gitignored outputs
├── .claude/skills/          # project skills (security-code-review stub)
├── pyproject.toml           # uv workspace root
├── uv.lock
├── mise.toml
└── lefthook.yml
```

No `src/` nesting gymnastics, no per-package `tests/` scattered — tests live beside code as `test_*.py`. A new hire opens any package and sees: `__init__.py`, one or two modules, tests. That's the whole pattern, repeated six times.

## 3. uv workspace (minimum)

Root `pyproject.toml` declares `[tool.uv.workspace] members = ["packages/*", "apps/*"]`. Each member has its own tiny `pyproject.toml` naming only its direct deps. `asec-core` depends on the other five packages via `[tool.uv.sources] asec-sandbox = { workspace = true }` etc. One `uv.lock` at the root. Python pinned to 3.13 in `mise.toml`; `_.python.venv = { path = ".venv", create = true }` so mise+uv share one venv. Bootstrap is literally `mise install && uv sync`. No extras, no optional-dependency matrices in v1.

## 4. Package contracts (one plain-English paragraph each)

**asec-sandbox** — Give it a command and a working directory; it runs that command in a hardened Docker container (`--network=none`, `--read-only` root, writable tmpfs scratch, non-root UID 10001) and returns exit code, stdout, and the list of artifacts written. As a side effect it appends one hash-chained JSON line per call to a WORM audit log. Public surface: `run(cmd, workdir) -> SandboxResult` and `audit_log(path)`. Firecracker is a *documented future backend*, not v1 code — the function signature is the seam.

**asec-memory** — Two stores behind two plain dataclasses. `HypothesisBoard` is per-session scratch (add/list/resolve hypotheses). `FindingsLedger` is durable (add/list findings). Locally both back onto SQLite; a `DynamoLedger` with the same three methods is the AWS adapter. A `to_sarif(findings) -> dict` function emits SARIF v2.1 with the Bonk extension. No ORM — raw `sqlite3` with typed row helpers.

**asec-skills** — `load_skills(dir) -> list[Skill]` parses each `SKILL.md` (frontmatter + body) into a `Skill` dataclass. `permission_gate(allowed_tools) -> hook` returns a PreToolUse hook function that denies any tool not on the allowlist (deny-by-default) and blocks edits to threat-model-protected files. That hook is the *only* enforcement primitive; the orchestrator wires it into `ClaudeAgentOptions.hooks`.

**asec-threat-model** — Pydantic v2 models for `threat-model.yaml` and `assets.yaml`, plus `load(path)`, `dump(model)`, and `diff(a, b)`. Round-trip safe (load→dump→load is identity). This is data, not behavior — no methods beyond validation.

**asec-confidence** — One pure function: `score(pattern_match: float, memory_recall: float, reachability: float) -> float`, returning a 0–1 blend. "Pluggable" means you pass a `weights` tuple, not that you register strategy classes. Forty lines including the docstring that explains each axis.

**asec-core** — The orchestrator. `review(target_dir, cwes) -> list[Finding]` builds `ClaudeAgentOptions` (Bedrock Opus 4.8, `permission_mode="plan"`, read-only tools, the skills gate hook), defines one `AgentDefinition` subagent per CWE, runs the SDK `query()`, parses findings, scores them via `asec-confidence`, and writes them to the ledger. The **model-provider seam** is a single function `make_options(model_id) -> ClaudeAgentOptions`; swapping to Strands means rewriting that one function, not the orchestrator.

## 5. The one E2E app — `apps/pr-reviewer`

A single module `main.py`, under 300 lines, structured as five named functions read top to bottom:

1. `load_target(path)` — read the tiny corpus diff.
2. `build_threat_model(target)` — call `asec-threat-model.load` (corpus ships a `threat-model.yaml`).
3. `run_review(target, threat_model)` — call `asec_core.review(...)` inside `asec_sandbox.run(...)`.
4. `score_and_store(findings)` — confidence scores → `FindingsLedger` → `to_sarif`.
5. `report(sarif)` — print a markdown table + PASS/FAIL gate (FAIL on CRITICAL/HIGH).

`main()` calls them in sequence. No framework, no plugin system, no DI container — just function composition you can trace with your finger. Invoked via `uv run pr-reviewer ./corpus/sample-repo`.

## 6. CDK stack (one file, four named constructs)

`infra/cdk/stack.py` defines `AsecLabStack` with exactly four constructs, each explainable to a junior in one minute:

- **`AuditBucket`** — S3 bucket with Object Lock (WORM) for the audit JSONL. "Append-only, can't be deleted."
- **`FindingsTable`** — DynamoDB table, partition key `finding_id`. "The cloud version of the SQLite ledger."
- **`BedrockRole`** — IAM role granting `bedrock:InvokeModelWithResponseStream` on the Opus inference profile, nothing else. "The agent's only AWS power."
- **`DashboardPlaceholder`** — CloudFront distribution over an empty S3 origin. "A door we'll hang a UI on later."

CDK Nag runs in `app.py` with a short, commented suppressions list (e.g., CloudFront placeholder has no WAF yet — documented, time-boxed). One stack, one environment, no nested stacks or stage abstractions in v1.

## 7. Docs (Starlight + documentation discipline)

Scaffold Astro Starlight in `docs/` with pnpm (the *only* pnpm use). Sidebar mirrors the repo: one page per package, one page per app, plus `adrs/` mirrored from `/adr`. **Discipline rules, enforced in review:** (a) max one page per concept — if a concept needs two pages it's two concepts; (b) no headings deeper than H3; (c) every page opens with a runnable example *before* any reference table. A `sync-adrs` mise task copies `adr/*.md` into `docs/src/content/docs/adrs/` so ADRs have one source of truth.

## 8. CI (exactly enough to enforce simplicity)

GitHub Actions, action SHAs pinned, three jobs:

1. **lint** — `ruff check`, `ruff format --check`, `pyright` (strict), commitizen commit-msg check.
2. **test** — `uv run pytest` across the workspace.
3. **cdk-nag** — `uv run cdk synth` with Nag enabled; fails on un-suppressed findings.

Plus OpenSSF baseline (scorecard, dependency-review, codeql, gitleaks) as separate pinned actions. lefthook runs lint+test locally pre-push in parallel. That's the whole gate — no coverage thresholds, mutation testing, or perf budgets in v1. The simplicity is itself the thing CI protects: a PR that adds a class where a function would do shows up as a diff a reviewer can reject.

## 9. Bootstrap sequence (ordered, no dependency tangles)

1. `mise install` + `uv init` workspace root; commit `mise.toml`, root `pyproject.toml`, `lefthook.yml`.
2. Scaffold the six packages as empty modules with stubbed signatures (Section 4) — *signatures first, bodies later*.
3. Implement leaf packages with no internal deps: `asec-confidence`, `asec-threat-model`, `asec-skills`, `asec-memory`.
4. Implement `asec-sandbox` (depends on nothing internal; ships the Dockerfile from Track C).
5. Implement `asec-core` last (depends on all five).
6. Write `apps/pr-reviewer/main.py` against the now-real packages; add the `corpus/sample-repo`.
7. `infra/cdk/stack.py` + Nag suppressions.
8. Starlight scaffold + ADR mirror task.
9. Wire CI jobs; turn the gate red, make it green.

Dependency order is a strict DAG: leaves → sandbox → core → app → infra → docs → CI. Nothing earlier imports anything later.

## 10. Three simplicity-anchor decisions

**A. Reject the strategy/registry pattern for confidence and providers.** The whitepaper says "pluggable" scorer and "provider-abstract" model layer. We honor both with *plain functions and parameters*, not abstract base classes with registries. `score(...)` takes a `weights` tuple; `make_options(model_id)` is one function. Justification: there is exactly one scorer and one provider in v1; a registry serving one entry is pure ceremony. The seam is the function signature.

**B. Collapse the sandbox abstraction to one function with one backend.** Track C lists five isolation tiers. v1 ships *only hardened Docker*, behind `run(cmd, workdir) -> SandboxResult`. Firecracker/LXD stay as documented configs in `docs/`, not as a `SandboxBackend` interface with one implementation. Justification: an interface with a single implementor is a guess about the future; the function signature already lets us add a `backend=` param the day we need a second box.

**C. No event bus / message types between packages — direct calls only.** The orchestrator calls `sandbox.run`, `ledger.add`, `score`. No pub/sub, no domain events, no mediator. Justification: the data flow is linear (read → run → score → store → report); an event system would hide that line behind indirection a new hire can't trace. We use dataclasses as the lingua franca, passed by value.

## 11. Risks + mitigations (failure modes of over-simplifying)

| # | Risk (we cut too deep) | Line in the sand → mitigation |
|---|---|---|
| 1 | **Single sandbox backend** can't isolate strongly enough for hostile targets. | Line: the day we audit untrusted/exploit-bearing code. Mitigation: `run()` signature already accepts `backend=`; Firecracker config is pre-written in docs, so it's a wiring job, not a redesign. |
| 2 | **Plain-function provider seam** leaks SDK types into `asec-core`, making the Strands swap harder than promised. | Line: any `claude_agent_sdk` import outside `make_options`. Mitigation: a CI grep test asserts the SDK is imported in exactly one module; violations fail the build. |
| 3 | **Raw SQLite, no migrations** breaks when the findings schema changes. | Line: the second schema change. Mitigation: ship a one-file `schema_version` table + a `migrate()` function now (cheap insurance); defer a migration *framework*. |
| 4 | **One app proves the loop but hides orchestration gaps** (no confidence-gated fan-out tiers from the whitepaper). | Line: when a second lifecycle mode (nightly/release) lands. Mitigation: document the four orchestration tiers as a non-code ADR so the gap is visible, not forgotten. |
| 5 | **Thin packages tempt premature merging** ("why six packages for 800 lines?"). | Line: any PR that merges two packages. Mitigation: the whitepaper-invariant seams (isolation, audit, gate, provider) are documented per-package as "why this is separate"; reviewers reject merges that erase a seam. |

---

**Net:** six thin packages, one app, one stack, one gate. Every abstraction is a function until pain proves it should be a class. A new hire reads `apps/pr-reviewer/main.py` top to bottom, follows five function calls into six small packages, and understands the whole substrate before their coffee gets cold.
