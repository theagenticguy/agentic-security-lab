---
name: threat-model-diff
description: Compare two threat-model.yaml revisions and report what changed — added or
  removed assets/threats/mitigations and changed likelihood/impact. Use when the user asks
  to diff threat models or review the threat-model impact of a change.
allowed-tools: Read Bash(uv run *) Grep Glob
argument-hint: [old-threat-model.yaml] [new-threat-model.yaml]
---

## Inputs
- Baseline: @$ARGUMENTS[0]
- Revised:  @$ARGUMENTS[1]

## Task
1. Prefer the canonical implementation: run
   `uv run python -c "from asec_threat_model import load, diff; \
   d = diff(load('$ARGUMENTS[0]'), load('$ARGUMENTS[1]')); print(d.model_dump_json(indent=2))"`
   to get a `ThreatModelDiff`. The models are `frozen` and serialization is round-trip
   stable, so the diff is deterministic.
2. If the package is unavailable, fall back to a structural YAML comparison keyed on
   threat/asset `id`.
3. Classify each change: ADDED-THREAT, REMOVED-THREAT, ADDED-ASSET, REMOVED-ASSET,
   MITIGATION-CHANGED, LIKELIHOOD-CHANGED, IMPACT-CHANGED.
4. Flag risk regressions explicitly: any new HIGH threat, any removed mitigation, any
   likelihood/impact increase.

Emit a markdown table (change, location, before → after) and a short narrative of net
risk movement. End with a PASS/FAIL gate (FAIL if any risk regression is unmitigated).
Do not modify either file. Report only.
