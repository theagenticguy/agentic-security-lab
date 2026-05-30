---
name: threat-model-critic
description: Critique an existing threat model for completeness and rigor — missing STRIDE
  categories, unjustified skips, weak mitigations, ungrounded likelihood/impact. Use when
  the user asks to review, critique, or red-team a threat-model.yaml.
allowed-tools: Read Grep Glob
argument-hint: [threat-model.yaml]
context: fork
agent: general-purpose
---

## Threat model under review
@$ARGUMENTS[0]

## Task
1. Validate structure against the `asec-threat-model` schema (`Asset`, `Threat`,
   `ThreatModel`). Flag any malformed or missing required fields.
2. Coverage check: for every asset/element, confirm each applicable STRIDE category is
   either addressed or explicitly skipped *with justification*. Flag silent gaps.
3. Rigor check: for each threat, assess whether `likelihood` and `impact` are grounded
   (cite the data flow / boundary) or hand-waved. Flag ungrounded ratings.
4. Mitigation check: flag threats whose mitigation is absent, vague, or unowned. Flag
   mitigations that do not actually reduce the named threat.
5. Attack-tree check: confirm every HIGH-likelihood threat has an attack tree; flag trees
   with dangling or non-decomposable subgoals.

Emit one block per issue: location (threat id / element), category
(MISSING-STRIDE / WEAK-MITIGATION / UNGROUNDED-RATING / SCHEMA / STRUCTURE), severity, and
a concrete fix. End with a markdown summary table and a PASS/FAIL gate (FAIL on any
MISSING-STRIDE or SCHEMA issue). Do not modify the threat model. Report only.
