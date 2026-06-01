---
name: security-code-review
description: >-
  Review a code diff or corpus for security vulnerabilities grounded in the supplied
  threat model. Reads code semantically, forms hypotheses, verifies them, and emits
  scored findings as a single JSON code block. Deny-by-default: only the allowed_tools
  below are permitted.
allowed_tools:
  - Read
  - Grep
  - Glob
  - Bash
argument_hint: "[target-dir]"
---

# Security Code Review

Review the target corpus against the supplied threat model and emit machine-parseable
findings. Read code semantically — do not rely on a single regex. Prefer the
least-privilege tool: `Grep`/`Glob` to locate sinks, `Read` to confirm data flow, and
`Bash` only for read-only inspection.

## When to use

Use when reviewing a pull request, diff, or small corpus against a known threat model to
surface and verify security findings (CWE-89, CWE-79, CWE-22 are the focus here).

## Per-CWE detection guidance

### CWE-89 — SQL Injection
- Look for untrusted input (request params, headers, body, CLI args) flowing into a SQL
  string built by f-strings, `%`, `.format()`, or `+` concatenation.
- Confirm the value reaches a `cursor.execute(...)` / `session.execute(...)` sink without
  a parameterized placeholder (`?` / `%s` bind, or an ORM expression).
- Severity `error` when the sink is reachable from an HTTP handler.

### CWE-79 — Cross-Site Scripting (XSS)
- Look for untrusted input reflected into an HTTP/HTML response without escaping.
- Flag returned f-strings / concatenations that embed `request.args`, `request.form`, or
  similar directly into markup (`<div>...</div>`), bypassing an autoescaping template.
- Severity `error` for reflected, browser-rendered output.

### CWE-22 — Path Traversal
- Look for untrusted path components joined to a base directory via `os.path.join`,
  `pathlib`, or string concatenation with no normalization/containment check.
- Confirm the resolved path is then `open`/read/served. A missing `os.path.realpath`
  containment check under the base directory is the tell.
- Severity `error` when the traversal feeds a file read/serve sink.

## Procedure

1. Load the threat model and enumerate one candidate hypothesis per asset/threat.
2. Locate the candidate sink with `Grep`/`Glob`; confirm the data flow with `Read`.
3. Verify reachability with read-only inspection (sandbox-only for any execution; the
   sandbox defaults to `--network=none`, E3).
4. Emit a finding per confirmed hypothesis.

## Output contract

Emit findings as a single JSON code block containing an array of objects, each with the
keys below. Emit nothing else after the block:

```json
[
  {
    "rule_id": "CWE-89",
    "message": "SQL injection: request param interpolated into SELECT.",
    "severity": "error",
    "cwe": "CWE-89",
    "uri": "src/api/users.py",
    "start_line": 17,
    "end_line": 18,
    "snippet": "cursor.execute(f\"SELECT * FROM users WHERE name='{name}'\")"
  }
]
```

- `severity` is one of `error | warning | note | none`.
- `uri` is the target-relative path; `start_line`/`end_line` are 1-based.
- `cwe` mirrors `rule_id` (e.g. `CWE-89`).

## Guardrails

- Never request a tool outside `allowed_tools`; the permission gate denies by default (E8).
- All target-code execution happens in the sandbox; every tool call and gate decision is
  appended to the hash-chained WORM audit log (E12).
