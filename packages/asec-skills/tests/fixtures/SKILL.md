---
name: threat-model-bootstrap
description: >-
  Given an architecture description or diagram, produce a STRIDE threat
  model plus attack trees as YAML. Use when the user asks to threat model a system.
allowed-tools: Read Write Glob Bash(git diff *)
argument-hint: [arch-file]
context: fork
agent: general-purpose
effort: high
---

## Architecture
@$ARGUMENTS[0]

## Task
1. Extract trust boundaries, data flows, external entities, datastores, processes.
2. For each element, enumerate STRIDE categories. Skip categories that do not apply; justify.
3. For each HIGH-likelihood threat, build an attack tree (root goal -> AND/OR subgoals).
4. Map each threat to a mitigation and a control owner.

Emit `threat-model.yaml` then a short prose exec summary of the top 5 risks.
