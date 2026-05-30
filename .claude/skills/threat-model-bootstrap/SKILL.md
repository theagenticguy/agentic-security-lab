---
name: threat-model-bootstrap
description: Given an architecture description, diagram, or repo, produce a Phase-Zero
  STRIDE threat model plus attack trees as YAML conforming to asec-threat-model schema.
  Use when the user asks to bootstrap or create a threat model for a system.
allowed-tools: Read Write Glob Grep
argument-hint: [arch-file-or-repo]
---

## Architecture
@$ARGUMENTS[0]

## Task
1. Extract trust boundaries, data flows, external entities, datastores, and processes.
   If given a repo, infer them from entrypoints, config, and dependency manifests.
2. For each element, enumerate STRIDE categories (Spoofing, Tampering, Repudiation,
   Info-disclosure, DoS, Elevation). Skip categories that do not apply; justify the skip.
3. For each HIGH-likelihood threat, build an attack tree (root goal -> AND/OR subgoals).
4. Map each threat to a mitigation and a control owner.

Emit `threat-model.yaml` conforming to the `asec-threat-model` schema (`Asset`, `Threat`,
`ThreatModel`), so `asec_threat_model.load()` round-trips it:
```yaml
assets: [{id, name, kind, trust_boundary}]
boundaries: [...]
threats:
  - {id, element, stride, desc, likelihood, impact, mitigation, owner}
attack_trees:
  - {goal, children: [...]}
```
Then a short prose exec summary of the top 5 risks. This artifact owns EARS invariants
E1/E2; keep serialization stable so `diff()` against a later revision is meaningful.
Do not modify source files. Write only `threat-model.yaml`.
