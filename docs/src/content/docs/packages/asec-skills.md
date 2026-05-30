---
title: asec-skills
description: SKILL.md loader and the deny-by-default PreToolUse permission gate.
---

## Purpose

`asec-skills` discovers `SKILL.md` files and enforces the permission gate that the model
cannot talk its way past. The gate is a deny-by-default PreToolUse hook.

## Public types

- `Skill` — parsed frontmatter: `name`, `description`, `allowed_tools`.
- `SkillLoader.discover(root) -> list[Skill]`.
- `PolicyRegistry`.
- `permission_gate(...)` — PreToolUse hook; deny-by-default for `editor` / `load_tool`.

## EARS invariants owned

- **E7** — skills are discovered and their declared tool scope is parsed.
- **E8** — tool calls are gated deny-by-default; the model cannot escalate past the gate.

## Dependencies

`pydantic`, `pyyaml`, `structlog`, `opentelemetry-api`, `claude-agent-sdk`
(`HookMatcher`).
