# ADR-008: Pluggable `ConfidenceStrategy` with `bm25s` recall

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** AI Engineering NAMER

## Context

The orchestrator must decide *how hard* to work each candidate finding: a high-confidence hit
goes to a specialized worker, a marginal one fans out to a swarm or escalates to runtime
authorship (E18). That decision rides on a single confidence score combining a pattern-match
signal, a memory-recall signal (have we seen something like this before?), and a reachability
signal. We want the scoring math to be swappable as we learn, and we want the score to be
explainable and reproducible in v1. This ADR fixes the scoring seam, the v1 baseline, and the
recall mechanism.

## Decision

We will define **`ConfidenceStrategy` as a `Protocol`** (`async score(inputs) ->
ConfidenceScore`) so the scorer is pluggable. The v1 implementation is **`BaselineStrategy`,
a deterministic linear combination** of the three axes with weights **0.45 / 0.30 / 0.25**
over `(pattern_match, memory_recall, reachability)` (validated to sum to 1.0). The score maps
through a frozen tier table to a `Tier` and an orchestration `Dispatch`: `>=0.85 high ->
specialized`, `>=0.70 medium -> parallel_shell`, `>=0.40 low -> swarm`, else `very_low ->
runtime_authorship`. The **memory-recall axis is computed with `bm25s`**: an ephemeral BM25
index over the recalled corpus, top score squashed through a sigmoid into `[0, 1]`. `bm25s`
is chosen because it is light and pure-Python-friendly with **no native build dependencies**,
and all access to its untyped surface is funneled through one boundary cast.

## Alternatives Considered

- **scikit-learn `LogisticRegression` (or any learned model) for scoring.** Rejected for v1:
  a learned model is a black box that is hard to explain, needs labeled data we do not yet
  have, and pulls in a heavy dependency. The Protocol leaves the door open to add it later as
  a second strategy.
- **Embedding-based semantic recall.** Rejected for v1: stronger recall but requires an
  embedding model and a vector store to operate and maintain. BM25 lexical recall is enough
  for v1 and runs with no external service.

## Rationale

A deterministic linear baseline is fully explainable — you can read off why a finding landed
in its tier — and reproducible in tests, which matters while we are still calibrating the
dispatch table. The Protocol means swapping in a learned or embedding strategy later is a new
class, not a rewrite. `bm25s` keeps recall dependency-light so local dev stays zero-install.

## Consequences

### Positive

- Scores are explainable and deterministic; tier dispatch is unit-testable.
- A future learned or embedding strategy slots in behind the same Protocol with no
  orchestrator change.

### Negative

- Fixed linear weights and lexical-only recall will misrank some findings (synonymy,
  paraphrase). **Mitigated** by the swappable Protocol and the configurable weight tuple.
  Split trigger: calibration data shows the linear baseline materially mis-tiers findings,
  justifying a learned or embedding strategy.
