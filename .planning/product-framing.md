# Product Framing — agentic-security-lab v1 substrate

> Foundations only. HMW for the fuzzy surface, EARS for the agent contract. No concrete CWE skills.

## Section 1 — The fuzzy problem in one paragraph

v1 is **a substrate, not a product**: the eight foundation pieces (sandbox, memory, skills loader, threat-model artifact, confidence scorer, orchestrator, output/SARIF, governance) that let a Claude Opus 4.8 agent read code semantically, run experiments in a closed sandbox, and verify hypotheses in a loop — with one thin proof app (`apps/pr-reviewer`) wiring them together on a tiny corpus. What is genuinely unknown: *which* audit scopes will pay off, what the right confidence thresholds are, whether the three-axis scorer correlates with real findings, how adversarial-CI canaries should be tuned, and whether teams will trust an agent that authors its own threat model and its own runtime tools. We are deliberately not answering those yet. v1's job is to make the substrate **trustworthy enough that those questions can be asked safely** — bounded sandbox, append-only memory, hash-chained audit, human gate on any public action — so the fuzzy part (the audit content) can be iterated on top without rebuilding the floor.

## Section 2 — Five HMW questions

1. **HMW make the agent author its own threat model in Phase Zero, so that an audit never blocks on a human drafting one?**
   This reframes the threat model from a prerequisite input to a *first deliverable the agent owns*, which is what unlocks autonomous onboarding on an unfamiliar repo. It rules out designs that require a pre-existing `assets.yaml` or human-curated scope before the agent can start.

2. **HMW give the agent real hands (a throwaway, egress-closed sandbox) instead of static analysis alone, so that hypotheses are verified by execution rather than asserted by pattern match?**
   This commits us to a verify-by-running loop as the core differentiator over a SAST flood, making the sandbox primitive load-bearing rather than optional. It rules out a "lint-and-report" product that never executes target code and never falsifies its own guesses.

3. **HMW encode every agent capability as a permission-gated skill, so that what the agent *can* do is auditable, deny-by-default, and version-pinned in Git?**
   This makes the security boundary a data artifact (`allowed-tools` + PreToolUse hook) rather than trust in the model's judgment, which is the only way an autonomous security agent is itself defensible. It rules out giving the orchestrator an open tool pool or letting model reasoning be the last line of defense.

4. **HMW prove the *agent itself* is trustworthy via adversarial CI (honey-bugs, prompt-injection, secret + tool-call canaries) before it ships, so that we re-audit the auditor on every change?**
   This treats the agent as an attack surface — its skills, its prompts, its tool calls — and gates deploy on catching planted failures, not just green unit tests. It rules out shipping orchestration or skill changes on code-coverage confidence alone.

5. **HMW route work by confidence (specialized → parallel → swarm → runtime tool authorship), so that cheap deterministic paths run first and expensive autonomy is earned, not default?**
   This makes the confidence scorer the spine of orchestration and keeps cost/blast-radius proportional to ambiguity. It rules out a one-size swarm that burns budget on findings a single specialized worker would have settled.

## Section 3 — EARS contract — agent invariants

**Phase Zero / threat model**
- E1 (Event-driven): When a new repository is presented with no `threat-model.yaml`, the system shall author one (boundaries, assets, DFD, STRIDE threats) before dispatching any audit worker.
- E2 (State-driven): While operating, the system shall treat the agent-authored `threat-model.yaml` and `assets.yaml` as the scope of record and shall not act outside their declared boundaries.

**Sandbox isolation**
- E3 (Ubiquitous): The system shall execute all target-code experiments inside a throwaway sandbox launched with `--network=none` by default.
- E4 (Optional): Where egress is explicitly enabled for a run, the system shall route it through the egress-allowlist sidecar and deny all destinations not on the allowlist.
- E5 (State-driven): While a sandbox is running, the system shall enforce a wall-clock time-box and terminate and discard the sandbox when it expires.
- E6 (Unwanted): If a sandboxed process attempts a network connection that is not on the active allowlist, then the system shall block the connection and record the attempt to the audit log.

**Skill permission contract**
- E7 (Ubiquitous): The system shall deny every tool not listed in the active skill's `allowed-tools` (deny-by-default), enforced by a PreToolUse hook independent of model reasoning.
- E8 (Unwanted): If a tool call is rejected by a PreToolUse hook, then the system shall surface the denial to the orchestrator and continue without the call rather than escalating privileges.

**Hypothesis board**
- E9 (Ubiquitous): The system shall treat the hypothesis board as append-only; entries may be added or superseded but never deleted or mutated in place.

**Findings ledger + SARIF**
- E10 (Ubiquitous): The system shall persist every confirmed finding durably in the findings ledger and shall emit results as SARIF v2.1 with the Bonk extension.
- E11 (Event-driven): When an audit run completes, the system shall write a SARIF report whose entries each carry a confidence score and a reference to the originating hypothesis-board entry.

**WORM audit log**
- E12 (Ubiquitous): The system shall append every tool call, sandbox lifecycle event, and gate decision to a hash-chained WORM audit log (S3 Object Lock or `chattr +a`).
- E13 (Unwanted): If the audit-log hash chain fails verification, then the system shall halt the run and refuse to emit findings as authoritative.

**Cost / budget**
- E14 (State-driven): While a run is active, the system shall track spend against `max_budget_usd` and shall stop dispatching new workers once the cap is reached.

**Kill switch**
- E15 (Event-driven): When the kill switch is triggered, the system shall terminate all sandboxes and in-flight workers and seal the audit log within the time-box window.

**Human gate**
- E16 (Ubiquitous): The system shall require explicit human approval before any externally visible action (PR comment, issue, push, public artifact); no public action shall occur autonomously.

**Adversarial CI**
- E17 (Event-driven): When the agent's skills, prompts, or orchestrator change, CI shall run the canary suite — honey-bug (must detect), prompt-injection (must refuse), secret canary (must not exfiltrate), tool-call canary (must not invoke disallowed tools) — and shall block deploy on any failure.

**Confidence dispatch**
- E18 (State-driven): While orchestrating, the system shall select the execution mode by confidence band (specialized < parallel < swarm < runtime tool authorship) and shall escalate to a higher-autonomy mode only when the lower mode's confidence is insufficient.

**Runtime tool authorship governance**
- E19 (Optional): Where the agent authors a tool at runtime, the system shall subject that tool to the same `allowed-tools` gate, sandbox confinement, and WORM logging as a pre-installed skill, with no exemption.

## Section 4 — Four customer journeys

**1. Onboarding — first run on a new repo.** A user points the agent at an unfamiliar repository and gets back a threat model plus a triaged first-pass finding set, with zero pre-authored scope. The agent reads the code, authors `threat-model.yaml`, and only then dispatches workers — so the human reviews a draft instead of writing one. *Protected by:* E1, E2, E3, E16.

**2. PR review — agent comments on a PR with findings.** On a pull request, the agent reviews the diff in a forked context, verifies candidate bugs in the sandbox, and posts findings as a comment — but only after a human approves the comment. Confidence scores ride along so reviewers can sort signal from noise. *Protected by:* E10, E11, E16, E18.

**3. Re-auditing the agent — adversarial CI before deploy.** Before any change to skills/prompts/orchestrator ships, CI runs the canary suite and blocks on any miss, so the auditor is re-audited every time. This is what keeps a self-modifying security agent from regressing into an unsafe one. *Protected by:* E7, E8, E17, E19.

**4. Incident handoff — a human takes over mid-session.** A responder hits the kill switch or pauses a live session and inherits a complete, tamper-evident picture: append-only hypotheses, durable findings, and a verifiable audit chain — enough to resume or override without trusting the agent's memory. *Protected by:* E9, E12, E13, E15.

## Section 5 — Anti-product list

1. **v1 does not own the human inbox / review UI.** Findings land as SARIF + a PR comment; we do not build a triage dashboard, notification system, or ticket workflow (CloudFront placeholder only).
2. **v1 does not auto-merge or push to protected branches.** No public/write action happens without the human gate (E16); the agent proposes, a human disposes.
3. **v1 does not ship concrete CWE skills.** Only a stub skill and the loader/gate; the per-CWE worker library is iterated on top of the substrate later.
4. **v1 does not run untrusted code with open egress.** `--network=none` is the default; egress is opt-in, allowlisted, and logged — never wide-open for convenience.
5. **v1 does not integrate Mythos or any public-facing distribution.** Internal-only, Apache-2.0, no public access surface; multi-mode lifecycle stays at PR mode.

## Section 6 — North-star metric proposals

1. **Verified-finding ratio** — confirmed-by-sandbox findings ÷ total reported findings. *Catches:* the SAST-flood failure mode where the agent asserts pattern matches it never executed, drowning reviewers in unverified noise.
2. **Canary catch rate** — fraction of adversarial-CI canaries (honey-bug, injection, secret, tool-call) caught per deploy gate, trended over time. *Catches:* silent degradation of the agent-as-attack-surface — a skill or prompt change that quietly weakens detection or opens an exfiltration path.
3. **Audit-chain integrity rate** — fraction of runs whose WORM hash chain verifies end-to-end and reconstructs the full tool-call timeline. *Catches:* the trust failure mode where a run "succeeded" but produced an unprovable, tamper-suspect record — making findings and incident handoff worthless.
