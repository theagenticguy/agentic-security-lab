---
title: EARS invariants
description: The 19 Easy Approach to Requirements Syntax (EARS) invariants the substrate enforces, with their normative text.
sidebar:
  order: 5
---

EARS — Easy Approach to Requirements Syntax — is a constrained-natural-language
template for software requirements (Mavin et al., 2009). Each invariant uses one
of five forms: ubiquitous (`shall`), event-driven (`when`), state-driven
(`while`), unwanted (`if … then`), or optional (`where`).

The 19 invariants below are the substrate's normative contract. They are the
single source of truth: every package owns a subset, every test references one,
every Architecture Decision Record (ADR) cites the ones it satisfies.
Source: [`/PLAN.md`](https://github.com/lalsaado/agentic-security-lab/blob/main/PLAN.md)
and [`/.planning/product-framing.md`](https://github.com/lalsaado/agentic-security-lab/blob/main/.planning/product-framing.md)
§3.

## Phase Zero / threat model

- <a id="e1"></a>**E1 (event-driven)** — When a new repository is presented with no `threat-model.yaml`, the system shall author one (boundaries, assets, data-flow diagram, STRIDE threats) before dispatching any audit worker.
- <a id="e2"></a>**E2 (state-driven)** — While operating, the system shall treat the agent-authored `threat-model.yaml` and `assets.yaml` as the scope of record and shall not act outside their declared boundaries.

## Sandbox isolation

- <a id="e3"></a>**E3 (ubiquitous)** — The system shall execute all target-code experiments inside a throwaway sandbox launched with `--network=none` by default.
- <a id="e4"></a>**E4 (optional)** — Where egress is explicitly enabled for a run, the system shall route it through the egress-allowlist sidecar and deny all destinations not on the allowlist.
- <a id="e5"></a>**E5 (state-driven)** — While a sandbox is running, the system shall enforce a wall-clock time-box and terminate and discard the sandbox when it expires.
- <a id="e6"></a>**E6 (unwanted)** — If a sandboxed process attempts a network connection that is not on the active allowlist, then the system shall block the connection and record the attempt to the audit log.

## Skill permission contract

- <a id="e7"></a>**E7 (ubiquitous)** — The system shall deny every tool not listed in the active skill's `allowed-tools` (deny-by-default), enforced by a PreToolUse hook independent of model reasoning.
- <a id="e8"></a>**E8 (unwanted)** — If a tool call is rejected by a PreToolUse hook, then the system shall surface the denial to the orchestrator and continue without the call rather than escalating privileges.

## Hypothesis board

- <a id="e9"></a>**E9 (ubiquitous)** — The system shall treat the hypothesis board as append-only; entries may be added or superseded but never deleted or mutated in place.

## Findings ledger and SARIF output

- <a id="e10"></a>**E10 (ubiquitous)** — The system shall persist every confirmed finding durably in the findings ledger and shall emit results as Static Analysis Results Interchange Format (SARIF) v2.1 with the `asec` property bag (see ADR-006).
- <a id="e11"></a>**E11 (event-driven)** — When an audit run completes, the system shall write a SARIF report whose entries each carry a confidence score and a reference to the originating hypothesis-board entry.

## Write-Once-Read-Many (WORM) audit log

- <a id="e12"></a>**E12 (ubiquitous)** — The system shall append every tool call, sandbox lifecycle event, and gate decision to a hash-chained WORM audit log (Amazon S3 Object Lock or `chattr +a`).
- <a id="e13"></a>**E13 (unwanted)** — If the audit-log hash chain fails verification, then the system shall halt the run and refuse to emit findings as authoritative.

## Cost / budget

- <a id="e14"></a>**E14 (state-driven)** — While a run is active, the system shall track spend against `max_budget_usd` and shall stop dispatching new workers once the cap is reached.

## Kill switch

- <a id="e15"></a>**E15 (event-driven)** — When the kill switch is triggered, the system shall terminate all sandboxes and in-flight workers and seal the audit log within the time-box window.

## Human gate

- <a id="e16"></a>**E16 (ubiquitous)** — The system shall require explicit human approval before any externally visible action (pull-request comment, issue, push, public artifact); no public action shall occur autonomously.

## Adversarial CI

- <a id="e17"></a>**E17 (event-driven)** — When the agent's skills, prompts, or orchestrator change, continuous integration shall run the canary suite — honey-bug (must detect), prompt-injection (must refuse), secret canary (must not exfiltrate), tool-call canary (must not invoke disallowed tools) — and shall block deploy on any failure.

## Confidence dispatch

- <a id="e18"></a>**E18 (state-driven)** — While orchestrating, the system shall select the execution mode by confidence band (specialized < parallel < swarm < runtime tool authorship) and shall escalate to a higher-autonomy mode only when the lower mode's confidence is insufficient.

## Runtime tool-authorship governance

- <a id="e19"></a>**E19 (optional)** — Where the agent authors a tool at runtime, the system shall subject that tool to the same `allowed-tools` gate, sandbox confinement, and WORM logging as a pre-installed skill, with no exemption.

## References

- Mavin, A., Wilkinson, P., Harwood, A., Novak, M. (2009). _Easy Approach to Requirements Syntax (EARS)._ 17th IEEE International Requirements Engineering Conference. [IEEE Xplore](https://ieeexplore.ieee.org/document/5328509).
- OASIS. (2020). _Static Analysis Results Interchange Format (SARIF) Version 2.1.0._ [docs.oasis-open.org](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html). §3.8 covers property bags.
- IETF. (2020). _RFC 8785: JSON Canonicalization Scheme (JCS)._ [datatracker.ietf.org/doc/html/rfc8785](https://datatracker.ietf.org/doc/html/rfc8785). The hash-chain canonicalization (ADR-005) is RFC 8785-compatible.
