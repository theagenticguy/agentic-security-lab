# Track D: Claude Code Skills — Deep Reference + Security Skill Landscape

Companion to Track A (Agent SDK), B (Opus 4.8), and C (sandbox configs). Grounded in current Claude Code / Agent Skills docs and live registry data (skills.sh, anthropics/skills, trailofbits/skills, awesome lists), captured 2026-05-29.

## 1. What a Skill is, technically

A Skill is a directory whose entrypoint is a `SKILL.md` file: YAML frontmatter plus a Markdown body, optionally bundling reference files and executable scripts. Claude Code follows the [Agent Skills open standard](https://agentskills.io). Custom commands have been merged into skills — `.claude/commands/deploy.md` and `.claude/skills/deploy/SKILL.md` both create `/deploy`.

**Frontmatter fields** (all optional; `description` recommended). Source: https://code.claude.com/docs/en/skills

| Field | Purpose |
|---|---|
| `name` | Display label; defaults to directory name |
| `description` | What it does + when to use it; drives auto-invocation (capped 1,536 chars) |
| `when_to_use` | Extra trigger phrases, appended to description |
| `allowed-tools` | Tools pre-approved without prompting while skill active |
| `disallowed-tools` | Tools removed from the pool while active (clears next message) |
| `disable-model-invocation` | `true` = manual `/name` only; removes from auto-context |
| `user-invocable` | `false` = Claude-only background knowledge |
| `model` / `effort` | Override session model / effort while active |
| `context: fork` + `agent` | Run skill in an isolated subagent of the given type |
| `hooks` | Hooks scoped to the skill's lifecycle |
| `paths` | Glob patterns gating auto-activation |

**Where skills live** (closer scope wins; enterprise > personal > project; plugins namespaced `plugin:skill`):

| Scope | Path |
|---|---|
| Enterprise (managed) | managed settings |
| Personal | `~/.claude/skills/<name>/SKILL.md` |
| Project | `.claude/skills/<name>/SKILL.md` (loaded from CWD up to repo root, plus nested on demand) |
| Plugin | `<plugin>/skills/<name>/SKILL.md` |

**Discovery & invocation.** Level-1 metadata (`name`+`description`, ~100 tokens each) loads at startup into the system prompt. When a request matches, Claude reads the full `SKILL.md` via the `Skill` tool / bash; bundled files and scripts load only when referenced. This **progressive disclosure** (metadata → instructions → resources) keeps idle skills near-zero cost. Claude Code watches skill dirs for live changes within a session.

**Skills vs other primitives.** Skills = on-demand procedural knowledge + bundled code, in the main context. **Agents/subagents** = separate context windows and tool sets for delegated work. **Slash commands** = now a subset of skills. **MCP servers** = external tool/data providers over a protocol. **Hooks** = deterministic shell callbacks on lifecycle events (no model judgment). A skill can compose all four: it can set `allowed-tools`, fork to an `agent`, call MCP tools, and carry scoped `hooks`.

**Recent improvements.** Custom-commands→skills merger; `context: fork` subagent execution; dynamic context injection via `` !`cmd` ``; `${CLAUDE_SKILL_DIR}` / `$ARGUMENTS` substitution; per-skill `hooks`; auto-compaction that re-attaches invoked skills (25k-token budget); `skillOverrides` settings; plugin distribution via `/plugin` marketplaces; `disableSkillShellExecution` managed kill-switch.

## 2. The skills landscape — marketplaces + registries

- **skills.sh** — community registry, ~583k skills indexed across 20+ agent platforms (Claude Code, Cursor, Copilot, Gemini, Cline, Windsurf). Trending leaders are dev/design (vercel-labs `find-skills` ~1.8M installs, anthropics `frontend-design` ~477k, Azure cloud skills). Dedicated security skills are present but not top-ranked.
- **anthropics/skills** (https://github.com/anthropics/skills) — official demo repo, Apache-2.0 (docx/pdf/pptx/xlsx are source-available). 17 example skills incl. `webapp-testing`, `mcp-builder`, `skill-creator`. Register as marketplace: `/plugin marketplace add anthropics/skills` → `document-skills` / `example-skills`. No security-specific skills here.
- **anthropic.com/skills** — returns HTTP 404; no standalone public catalog at that path. The canonical catalog is the docs "Available Skills" list (pptx/xlsx/docx/pdf + open-source `claude-api`) at https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview.
- **Awesome lists** — `ComposioHQ/awesome-claude-skills` (~62k★), `hesreallyhim/awesome-claude-code` (~45k★), `coreyhaines31/marketingskills`, `jeremylongshore/claude-code-plugins-plus-skills` (425 plugins / 2,810 skills, incl. a 26-entry `security` category), `daymade/claude-code-skills`.
- **Security-curated** — `Eyadkelleh/awesome-claude-skills-security` (SecLists-derived offensive wordlists/payloads, installable via `/plugin marketplace add`); `RationalEyes/claude-skills-security-guide` → now **Claude Security Atlas** (12-vector SKILL.md prompt-injection threat taxonomy + defense skills).
- **Most authoritative for our playbook: `trailofbits/skills`** (~5.5k★) — "skills for security research, vulnerability detection, and audit workflows." Install: `/plugin marketplace add trailofbits/skills`. Also Codex-native via `.codex/skills/`.

## 3. Top security/defense skills currently published

Slotting into our agentic-security playbook (orchestrator → per-CWE workers, Track A/C sandbox):

**Secure code review / SAST**
- `trailofbits/static-analysis` — CodeQL + Semgrep + SARIF parsing toolkit. Core SAST worker.
- `trailofbits/semgrep-rule-creator` / `semgrep-rule-variant-creator` — author/port custom Semgrep rules. Per-CWE rule synthesis.
- `trailofbits/variant-analysis` — find similar bugs across a codebase from one seed finding. The "find more like this" stage after a primary hit.
- `trailofbits/c-review`, `insecure-defaults`, `constant-time-analysis`, `zeroize-audit` — targeted reviewers (C/C++ memory, crypto timing, secret zeroization).
- `daymade` `skill-reviewer` / OWASP-Top-10 QA skills — general review gates.

**Threat modeling** — No high-quality public STRIDE/PASTA generator confirmed on skills.sh or the major awesome lists (presence not confirmed). Closest are SDLC-orchestrator plugins (`avelikiy/great_cto`, with a `security-officer` subagent + 13 compliance frameworks). We author our own (§4).

**Pentest / red-team**
- `Eyadkelleh/awesome-claude-skills-security` — `security-fuzzing/payloads/webshells/usernames/passwords` + agents Pentest Advisor, CTF Assistant, Bug Bounty Hunter; commands `/sqli-test`, `/xss-test`, `/wordlist`.
- `jthack/ffuf_claude_skill` — drives the ffuf web fuzzer and analyzes results.
- `trailofbits/burpsuite-project-parser`, `entry-point-analyzer`.

**Secrets / dependency scanning**
- `daymade` `security_scan.py` (gitleaks gate, pre-commit).
- `trailofbits/supply-chain-risk-auditor` — dependency threat-landscape audit.
- `jeremylongshore` `dependency-checker`, `container-security-scanner` (Trivy/Snyk).

**Incident response / forensics / log analysis**
- `mhattingpete/claude-skills-marketplace` — `computer-forensics`, `file-deletion`, `metadata-extraction`.
- `jthack/threat-hunting-with-sigma-rules-skill` — hunt with Sigma detection rules.
- `trailofbits/agentic-actions-auditor` — audits GitHub Actions for agent-security flaws.

**Compliance (SOC2/HIPAA/PCI)**
- `jeremylongshore` `compliance-checker` (SOC2/HIPAA/PCI-DSS), `compliance-report-generator`.
- `avelikiy/great_cto` — 13 frameworks incl. GDPR/PCI-DSS/HIPAA/SOC2/ISO 27001.

**CTF** — `Eyadkelleh` CTF Assistant agent. No published HackingBuddy- or EnIGMA-style SKILL.md confirmed (presence not confirmed).

**Bug-bounty triage** — `Eyadkelleh` Bug Bounty Hunter agent; `trailofbits/variant-analysis` for dedup/expansion. No dedicated severity-triage skill confirmed (presence not confirmed).

Mutation/fuzz-adjacent from Trail of Bits: `mutation-testing`, `property-based-testing`, `testing-handbook-skills` (fuzzers, sanitizers, coverage).

## 4. Authoring a security skill — three SKILL.md examples

### `security-code-review`
```yaml
---
name: security-code-review
description: Review a git diff for vulnerabilities by running Semgrep and CodeQL, then
  emit structured findings. Use when the user asks for a security review of a diff/PR.
allowed-tools: Bash(semgrep *) Bash(codeql *) Bash(git diff *) Read Grep
disable-model-invocation: true
context: fork
agent: general-purpose
---

## Diff under review
!`git diff --merge-base origin/main`

## Task
1. Run `semgrep --config auto --sarif -o /tmp/semgrep.sarif $(git diff --name-only --merge-base origin/main)`.
2. If a CodeQL DB exists at .codeql/db, run `codeql database analyze .codeql/db --format sarifv2.1.0 -o /tmp/codeql.sarif <suite>`.
3. Merge SARIF; keep only findings on changed lines.
4. Emit one block per finding: file:line, CWE, severity (CRITICAL/HIGH/MED/LOW),
   evidence snippet, fix. End with a markdown summary table and a PASS/FAIL gate
   (FAIL if any CRITICAL/HIGH).
Do not modify source files. Report only.
```

### `threat-model-from-architecture`
```yaml
---
name: threat-model-from-architecture
description: Given an architecture description or diagram, produce a STRIDE threat
  model plus attack trees as YAML. Use when the user asks to threat model a system.
allowed-tools: Read Write Glob
argument-hint: [arch-file]
---

## Architecture
@$ARGUMENTS[0]

## Task
1. Extract trust boundaries, data flows, external entities, datastores, processes.
2. For each element, enumerate STRIDE categories (Spoofing, Tampering, Repudiation,
   Info-disclosure, DoS, Elevation). Skip categories that do not apply; justify.
3. For each HIGH-likelihood threat, build an attack tree (root goal -> AND/OR subgoals).
4. Map each threat to a mitigation and a control owner.
Emit `threat-model.yaml`:
  boundaries: [...]
  threats: [{id, element, stride, desc, likelihood, impact, mitigation}]
  attack_trees: [{goal, children: [...]}]
Then a short prose exec summary of the top 5 risks.
```

### `fuzz-harness-author`
```yaml
---
name: fuzz-harness-author
description: Read a target function signature and draft a libFuzzer/Jazzer/Atheris
  harness, then build and run it under coverage. Use when asked to fuzz a function.
allowed-tools: Read Write Bash(clang *) Bash(cargo fuzz *) Bash(python -m atheris *) Bash(java *)
argument-hint: [source-file] [function]
context: fork
agent: general-purpose
---

## Target
@$ARGUMENTS[0]  (function: $ARGUMENTS[1])

## Task
1. Identify language and input type of $ARGUMENTS[1].
2. Pick the engine: C/C++ -> libFuzzer (`LLVMFuzzerTestOneInput`, build with
   `clang -g -O1 -fsanitize=address,fuzzer`); Rust -> cargo-fuzz; Python -> Atheris
   (`atheris.Setup`); JVM -> Jazzer (`fuzzerTestOneInput`).
3. Write a harness that decodes FuzzedDataProvider bytes into typed args; guard
   against trivial early-exit. Save to fuzz/.
4. Build, then run 120s with coverage: libFuzzer `-max_total_time=120
   -print_final_stats=1`; cargo fuzz `run <t> -- -max_total_time=120`.
5. On crash, minimize and report the reproducer path + stack. Never run outside
   the sandbox (see Track C, network=none).
```

## 5. Skills + Agent SDK + sandbox interplay

- **Restricted tools via `allowed-tools`.** Inside the Track C Docker/Workshop image, a skill's `allowed-tools` whitelists exactly the scanner binaries it needs (e.g. `Bash(semgrep *)`), so a CWE worker can run its tool without prompting yet cannot reach `git push` or arbitrary egress. `disallowed-tools` strips dangerous tools (e.g. `AskUserQuestion` in an autonomous loop). Note: `allowed-tools` pre-approves but does not *cap* the pool — pair with permission **deny** rules for hard limits.
- **Deterministic gates via PreToolUse hooks.** Per-skill `hooks` enforce policy the model cannot talk its way past: a PreToolUse hook on `Bash` rejects any command touching the network, validates the sandbox is `network=none`, or blocks `rm -rf` outside `/work/.scratch`. Hooks are shell callbacks — judgment-free, auditable.
- **Programmatic subagents (Agent SDK).** An orchestrator built on the Agent SDK (Track A) dispatches one worker per CWE class. Each worker runs `context: fork` with a different security skill loaded: SQLi→`semgrep-rule-creator`, memory-safety→`c-review`/`zeroize-audit`, supply-chain→`supply-chain-risk-auditor`, then `variant-analysis` to expand confirmed hits. Forked contexts isolate noisy scanner output from the orchestrator's window.
- **Versioned + audited.** Skills are plain files: pin them in Git (plugin marketplaces carry `gitCommitSha`, e.g. our installed `personal-plugins@1.56.0`). Every skill-driven tool call appends to the Track C WORM log (hash-chained JSONL, S3 Object Lock / `chattr +a`), giving a tamper-evident record of which skill version ran which command in which sandbox.

## 6. Adoption patterns

- **`/plugin install` from a marketplace** — `/plugin marketplace add trailofbits/skills` then `/plugin install <name>@<marketplace>`. Pins a commit SHA; cleanest for vetted third-party security skills.
- **Clone into `~/.claude/skills/`** — drop a `SKILL.md` directory for personal, cross-project skills; live change detection picks it up mid-session.
- **Project-level `.claude/skills/`** (the playbook angle) — commit repo-specific review skills so every contributor and CI run inherits the same `security-code-review` gate. `allowed-tools` activates only after the workspace-trust dialog, so audit project skills before trusting a repo.
- **MDM / corp distribution** — push skills via **managed (enterprise) settings**, which override personal/project scope org-wide. Lock down with managed `disableSkillShellExecution: true` (kills `` !`cmd` `` injection) and `Skill(...)` permission allow/deny rules so only sanctioned security skills run. CI bakes the marketplace install into the Track C container image for reproducible, network-pinned runs.

> **Trust caveat (carry into the whitepaper's risk section):** a `SKILL.md` in `~/.claude/skills/` carries system-prompt-level authority with no review. Per Anthropic's docs, use skills only from trusted sources, audit all bundled scripts and external fetches, and treat installation like installing software. RationalEyes' Claude Security Atlas catalogs skills themselves as a prompt-injection attack surface — our defensive playbook must scan installed skills, not just target code.
