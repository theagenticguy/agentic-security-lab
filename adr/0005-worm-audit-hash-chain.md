# ADR-005: Hash-chained WORM audit (`chattr +a` / S3 Object Lock)

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** AI Engineering NAMER

## Context

The substrate makes consequential, semi-autonomous decisions: which tools a skill may call,
when a gVisor fallback fires, which findings it confirms. We need a tamper-*evident* record
of those events (E12, E13) that survives the orchestrator and lets a verifier prove, after
the fact, that no entry was altered, reordered, or removed. Ordinary application logs do not
provide that property. This ADR fixes the audit format and its at-rest enforcement.

## Decision

We will write the audit as an **append-only JSONL log with a sha256 hash chain**. Each line
is `{ts, seq, session, actor, action, payload, prev_hash, hash}` where
`hash = sha256(canonical_json(line_without_hash))` and each line carries the previous line's
`hash` as its `prev_hash`; the first line uses the sentinel `prev_hash="GENESIS"`. Serialization
is **RFC 8785-ish canonical JSON** (sorted keys, no insignificant whitespace, UTF-8, no
ASCII-escaping) so hashes are stable and content-addressable. Writes serialize through an
`asyncio.Lock` so concurrent appends cannot interleave the chain. `verify_chain()` re-walks
the file, recomputing each hash and checking `prev_hash` linkage and monotonic `seq`. The
file is enforced WORM at rest: **`chattr +a`** (append-only) on the local host, and **S3
Object Lock** in compliance mode for sealed segments in the cloud (never on ephemeral
instance store — see ADR-009).

## Alternatives Considered

- **Structured logging only (structlog/CloudWatch).** Rejected: searchable and useful for
  ops, but provides *no* tamper evidence — a privileged actor can edit or drop lines silently.
- **A Merkle tree / authenticated data structure.** Rejected as overkill: the audit is a
  strictly ordered append-only stream, so a linear hash chain gives full tamper evidence with
  O(1) append and O(n) verify; a Merkle tree's selective-proof benefit buys nothing here.

## Rationale

A linear hash chain is the minimal structure that makes any mutation detectable: changing one
line breaks every subsequent `prev_hash`. Canonical JSON makes the digest reproducible across
languages and runs, so an independent verifier needs only the spec, not our code. `chattr +a`
and Object Lock add an at-rest barrier so tampering requires both breaking the chain *and*
defeating the filesystem/bucket policy.

## Consequences

### Positive

- Any reorder, edit, or deletion is detected by `verify_chain` and at-rest WORM enforcement.
- Verification is portable: the canonical-JSON spec is the only dependency.

### Negative

- Append must be serialized (the lock) and `_last_hash`/`_next_seq` re-read the tail, so the
  pure-file writer does not scale to very high append rates. **Mitigated** by segmenting and
  sealing to S3 Object Lock. Split trigger: append throughput becomes a bottleneck, forcing a
  segment-rotation or batched-append design.
