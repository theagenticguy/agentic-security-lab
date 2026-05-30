---
name: reachability-triage
description: Triage a candidate finding by deciding whether the vulnerable code is
  reachable from an untrusted entry point, producing the reachability axis (0-1) that
  feeds asec-confidence. Use when the user asks to triage a finding or assess exploitability.
allowed-tools: Read Grep Glob Bash(git diff *) Bash(semgrep *)
argument-hint: [finding-file-or-location]
context: fork
agent: general-purpose
---

## Finding under triage
@$ARGUMENTS[0]

## Task (v1.2 spec)
1. Identify the sink: the exact file:line and the dangerous operation (the candidate CWE).
2. Identify untrusted sources: external entry points (HTTP handlers, CLI args, deserialized
   input, message consumers). Enumerate them from entrypoints and route/handler registration.
3. Trace call paths from each source to the sink using Grep/Read (and `semgrep` taint
   queries when available). Record the shortest concrete path or prove none exists.
4. Classify reachability:
   - `1.0` — direct, unconditional path from an untrusted source to the sink.
   - `0.6-0.9` — reachable but guarded (auth, validation, feature flag); note the guard.
   - `0.1-0.5` — reachable only via an unlikely or internal-only path.
   - `0.0` — no path from any untrusted source (dead code, test-only, fully gated).
5. Note sanitizers/validators on the path that would neutralize the input, and whether
   they are complete.

Emit a JSON block matching the `reachability` field of `asec_confidence.ConfidenceInputs`:
```json
{"reachability": 0.0, "sink": "file:line", "sources": ["..."], "path": ["..."], "guards": ["..."], "rationale": "..."}
```
This axis is one of three (pattern, recall, reachability) the `BaselineStrategy` weights;
it owns the reachability portion of E18. Do not modify source files. Report only.
