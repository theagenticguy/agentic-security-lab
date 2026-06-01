---
name: variant-analysis
description: >-
  Big-Sleep variant analysis. Given a recently-fixed bug shape (the lines added/removed in
  a patch), find more code in the repository that has the same shape and is likely to carry
  the same defect. Reports variants linked to their seed. Deny-by-default: only the
  allowed_tools below are permitted.
allowed_tools:
  - Read
  - Grep
  - Glob
  - Bash
argument_hint: "[seed-shape]"
---

# Variant Analysis (Big Sleep "find more like this")

A bug was recently fixed. The patch hunk tells you the *shape* of the defect: the
vulnerable lines that were removed and the safe lines that replaced them. Your job is to
sweep the rest of the codebase for code with the same shape that was NOT fixed — these are
the variants.

## When to use

Use immediately after a security fix lands. The fix proves the pattern is exploitable in
this codebase; variants are the same pattern elsewhere that the fix did not reach.

## Procedure

1. Read the seed shape: the removed (vulnerable) lines and the CWE class they belong to.
2. Distil the shape into a search signature (the sink call, the tainted-input source, the
   missing guard) — not a literal string match.
3. `Grep`/`Glob` for the signature across the repo; `Read` each hit to confirm the same
   data flow and the same missing guard.
4. Emit one variant finding per confirmed hit. A hit that already has the guard the fix
   added is NOT a variant — skip it.

## Output contract

Emit variants as a single JSON code block: an array of objects with the keys below. Each
object MUST carry `variants_of` set to the seed finding id you were given. Emit nothing
after the block.

```json
[
  {
    "rule_id": "CWE-89",
    "message": "SQL injection variant: same f-string-into-execute shape as the seed fix.",
    "severity": "error",
    "cwe": "CWE-89",
    "uri": "src/api/orders.py",
    "start_line": 12,
    "end_line": 12,
    "snippet": "cursor.execute(f\"SELECT * FROM orders WHERE id={oid}\")",
    "variants_of": "<seed-finding-id>"
  }
]
```

- `severity` is one of `error | warning | note | none`.
- `uri` is the repo-relative path; lines are 1-based.
- `variants_of` is the seed finding id, verbatim.

## Guardrails

- Never request a tool outside `allowed_tools`; the permission gate denies by default (E8).
- Read-only inspection only; any execution happens in the network-isolated sandbox (E3).
- Every tool call and gate decision is appended to the hash-chained WORM audit log (E12).
