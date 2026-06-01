---
title: "ADR-005: Hash-chained WORM audit (`chattr +a` / S3 Object Lock)"
description: "The substrate makes consequential, semi-autonomous decisions: which tools a skill may call,"
---

# ADR-005: Hash-chained WORM audit (`chattr +a` / S3 Object Lock)

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** AI Engineering NAMER

## Context

The substrate makes consequential, semi-autonomous decisions: which tools a skill may call,
when a gVisor fallback fires, which findings it confirms. We need a tamper-*evident* record
of those events ([E12](/agentic-security-lab/concepts/ears-invariants/#e12), [E13](/agentic-security-lab/concepts/ears-invariants/#e13)) that survives the orchestrator and lets a verifier prove, after
the fact, that no entry was altered, reordered, or removed. Ordinary application logs do not
provide that property. This ADR fixes the audit format and its at-rest enforcement.


<details>
<summary>Decision, alternatives, rationale, consequences</summary>

## Decision

We will write the audit as an **append-only JSON Lines (JSONL) log with a SHA-256
hash chain**. Each line is
`{ts, seq, session, actor, action, payload, prev_hash, hash}` where
`hash = sha256(canonical_json(line_without_hash))` and each line carries the previous
line's `hash` as its `prev_hash`; the first line uses the sentinel
`prev_hash="GENESIS"`. Writes serialize through an `asyncio.Lock` so concurrent
appends cannot interleave the chain. `verify_chain()` re-walks the file, recomputing
each hash and checking `prev_hash` linkage and monotonic `seq`. The file is enforced
WORM at rest: **`chattr +a`** (append-only) on the local host, and **Amazon S3 Object
Lock** in compliance mode for sealed segments in the cloud (never on ephemeral
instance store — see ADR-009).

Serialization follows a **subset of RFC 8785** (the JSON Canonicalization Scheme,
JCS): sorted UTF-8 keys, no insignificant whitespace, `ensure_ascii=False`. The
v1 implementation deviates from RFC 8785 in two known places, which we accept and
document rather than paper over:

1. **Number canonicalization** — RFC 8785 §3.2 mandates the I-JSON / ES6
   number-to-string algorithm. The v1 writer uses Python's default
   `json.dumps` numeric formatting, which matches RFC 8785 for integers and for
   most finite floats but is not bit-for-bit guaranteed for edge-case floats.
   The audit log carries no floating-point fields today; if one is added, the
   serializer must switch to a JCS-conformant number formatter.
2. **Non-ASCII escaping** — RFC 8785 §3.2.2.2 requires `\u` escaping of code
   points U+0000–U+001F and U+007F. `ensure_ascii=False` produces literal UTF-8
   bytes for code points above U+007F, which is *legal JSON* and round-trips
   identically, but is not byte-identical to a JCS encoder. Control characters
   below U+0020 are still `\u`-escaped by `json.dumps`.

An independent verifier therefore needs the spec **plus** these two deviations,
not the spec alone. A future move to a strict-JCS library (`json-canonical-form`
or equivalent) is mechanical and gated on the first deviation that bites.

## Alternatives Considered

- **Structured logging only (structlog/CloudWatch).** Rejected: searchable and useful for
  ops, but provides *no* tamper evidence — a privileged actor can edit or drop lines silently.
- **A Merkle tree / authenticated data structure.** Rejected as overkill: the audit is a
  strictly ordered append-only stream, so a linear hash chain gives full tamper evidence with
  O(1) append and O(n) verify; a Merkle tree's selective-proof benefit buys nothing here.

## Rationale

A linear hash chain is the minimal structure that makes any mutation detectable:
changing one line breaks every subsequent `prev_hash`. Canonical JSON makes the digest
reproducible across languages and runs, so an independent verifier needs the
canonicalization rules plus the documented deviations from RFC 8785, not our code.
`chattr +a` and Object Lock add an at-rest barrier so tampering requires both breaking
the chain *and* defeating the filesystem or bucket policy.

## Consequences

### Positive

- Any reorder, edit, or deletion is detected by `verify_chain` and at-rest WORM enforcement.
- Verification is portable: the canonicalization rules plus the two documented
  deviations from RFC 8785 are the only spec dependency.

### Negative

- Append must be serialized (the lock) and `_last_hash`/`_next_seq` re-read the tail, so the
  pure-file writer does not scale to very high append rates. **Mitigated** by segmenting and
  sealing to S3 Object Lock. Split trigger: append throughput becomes a bottleneck, forcing a
  segment-rotation or batched-append design.


</details>
