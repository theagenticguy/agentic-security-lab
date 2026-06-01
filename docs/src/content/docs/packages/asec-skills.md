---
title: asec-skills
description: SKILL.md loader and the deny-by-default PreToolUse permission gate.
---

## Purpose

`asec-skills` discovers `SKILL.md` files and runs the deterministic permission
gate that decides whether each tool call is allowed. The gate is a deny-by-default
PreToolUse hook — its decision is computed from the active skill's `allowed-tools`
list and the requested tool, independent of model output. See
[ADR-007](/agentic-security-lab/adrs/0007-deny-by-default-skill-permission-gate/)
for the threat model and design.

## Public types

- `Skill` — parsed frontmatter: `name`, `description`, `allowed_tools`.
- `SkillLoader.discover(root) -> list[Skill]`.
- `PolicyRegistry`.
- `permission_gate(...)` — PreToolUse hook; deny-by-default for `editor` and
  `load_tool`, plus path-glob denials for `Edit` and `Write`.

## EARS invariants owned

- [**E7**](/agentic-security-lab/concepts/ears-invariants/#e7) — every tool not
  in `allowed-tools` is denied (deny-by-default), enforced by a PreToolUse hook.
- [**E8**](/agentic-security-lab/concepts/ears-invariants/#e8) — denied calls
  surface to the orchestrator and the run continues without the call (no
  privilege escalation).

## Dependencies

`pydantic`, `pyyaml`, `structlog`, `opentelemetry-api`, `claude-agent-sdk`
(`HookMatcher`).
