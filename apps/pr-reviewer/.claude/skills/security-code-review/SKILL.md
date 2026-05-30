---
name: security-code-review
description: >-
  Review a code diff for security vulnerabilities grounded in the supplied threat model.
  Reads code semantically, forms hypotheses, verifies them in the sandbox, and emits
  scored findings. Deny-by-default: only the allowed_tools below are permitted.
allowed_tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Security Code Review

> Stub skill for the v1 substrate. Concrete CWE guidance is intentionally out of scope —
> this proves the SKILL.md load + PreToolUse gate path (E7/E8), not audit content.

## When to use

Use when reviewing a pull request or diff against a known threat model to surface and
verify security findings.

## Procedure

1. Load the threat model and the target diff.
2. Enumerate candidate hypotheses per asset/threat.
3. Verify each hypothesis with read-only inspection; run experiments only inside the
   sandbox (E3 — `--network=none` by default).
4. Emit findings with a three-axis confidence score (pattern, recall, reachability).

## Guardrails

- Never request a tool outside `allowed_tools`; the permission gate denies by default (E8).
- All target-code execution happens in the sandbox; every tool call and gate decision is
  appended to the hash-chained WORM audit log (E12).
