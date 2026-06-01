---
title: "ADR-007: Deny-by-default skill gate via PreToolUse hook"
description: "The substrate hands a capable model real tools — a shell, file editors, dynamic tool loading"
---

# ADR-007: Deny-by-default skill gate via PreToolUse hook

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** AI Engineering NAMER

## Context

The substrate hands a capable model real tools — a shell, file editors, dynamic tool loading
— inside a sandbox that runs untrusted code. Prompt-level instructions about what a skill
"should" do are not a security boundary: they are non-deterministic and bypassable. We need a
*deterministic* enforcement point that decides, per tool call, whether the call is permitted,
and we need that decision to be auditable (E7, E8). The Claude Agent SDK exposes a PreToolUse
hook that fires before every tool invocation. This ADR fixes how we gate tool calls.

## Decision

We will implement a **deny-by-default `permission_gate`** — an async function shaped to the
SDK's PreToolUse hook signature (`(input_data, tool_use_id, context) -> dict | None`) but
taking only plain dicts so `asec-skills` carries **no dependency on the SDK**. It returns the
SDK deny payload (`permissionDecision: "deny"`) when the requested `tool_name` is not in the
skill's `allowed_tools`, and additionally denies file-writing tools (`Edit`/`Write`) whose
target path matches a denied-path glob (matched against both full path and bare filename, so
`*.env` blocks `/work/secrets/.env`). The **`allowed_tools` list parsed from SKILL.md
frontmatter is the enforcement contract**, not advisory guidance: the loader tokenizes specs
keeping `Bash(git push *)`-style argument groups intact, so a skill can permit `Bash(git
status)` while the gate denies `Bash(git push *)`, `editor`, `load_tool`, and everything else
not listed. Returning `None` allows the call.

## Alternatives Considered

- **Trust the model to self-restrict.** Rejected: not a boundary — a capable model under
  adversarial input will reach for tools regardless of instructions.
- **Prompt-only guardrails (system-prompt rules).** Rejected: non-deterministic and
  untestable; gives no auditable, per-call decision and degrades under prompt injection from
  the target code being analyzed.

## Rationale

A hook firing before *every* tool call is the only place to enforce policy deterministically
and emit a WORM `gate_decision` per call. Deny-by-default means a skill author must
explicitly list each capability, so the blast radius of a compromised or confused skill is
bounded by its own frontmatter. Keeping the gate SDK-free (plain dicts) preserves the
package-dependency direction and makes the gate unit-testable without a runtime.

## Consequences

### Positive

- Every tool call is screened deterministically and auditably; default posture is "no".
- The gate is testable in isolation and reusable behind any runtime that exposes a pre-call
  hook.

### Negative

- Skill authors must enumerate `allowed_tools` precisely, including parenthesized argument
  scopes; an under-specified list breaks a legitimate skill. **Mitigated** by clear deny
  reasons in the payload and logs. Split trigger: a need for richer policy than allow/deny
  globs (e.g. argument-value constraints) forces a policy-engine layer.
