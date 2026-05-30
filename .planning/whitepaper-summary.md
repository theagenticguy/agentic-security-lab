# Whitepaper v1.3 — One-page summary for planners

The agent **reads** code semantically, runs experiments on a real **VM**, and **verifies** hypotheses in a closed loop. Three faculties: eyes (Opus 4.8), hands (sandbox), memory (ledger + FP memory).

## Eight foundations to build (v1 substrate)
1. **Sandbox** — Docker/Firecracker; `--network=none` default; egress-allowlist sidecar; WORM audit.
2. **Memory** — Hypothesis board (per-session) + findings ledger (durable) + FP memory (suppression).
3. **Skills** — Load `SKILL.md` directories; PreToolUse hook gate; allowed-tools contract.
4. **Threat model artifact** — `threat-model.yaml` + `assets.yaml` + DFD; agent-authored in Phase Zero.
5. **Confidence scorer** — Three-axis: pattern × memory × reachability. Drives orchestration.
6. **Orchestrator** — Agent SDK ClaudeSDKClient with programmatic subagents; per-CWE fan-out under confidence gate.
7. **Output** — SARIF v2.1 + Bonk extension; Report Agent (Executive / Engineering / Auditor).
8. **Governance** — Signed scope artifact, time-boxed STS, kill switch, OWASP LLM01/06 controls.

## What the substrate enables
- Phase Zero: agent generates threat model from repo
- Reachability ranking to filter SAST flood
- Confidence-threshold orchestration (specialized | parallel shell | swarm | runtime authorship)
- Adversarial CI of the agent itself
- Five lifecycle modes (onboarding / pre-commit / PR / nightly variant / release / incident)

## Prior art the design draws from
- Cyber-AutoAgent (Strands+Bedrock, 85% XBOW, archived) — runtime tool authorship, swarm fan-out, Report Agent pattern
- Big Sleep — variant analysis on patched diffs
- AIxCC CRSes — orchestrator + heterogeneous workers + falsifiable findings + auto-patch
- Claude Code `/security-review` — lowest-friction PR-time entry
