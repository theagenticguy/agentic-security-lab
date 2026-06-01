---
title: asec-confidence
description: Three-axis confidence scorer with pluggable strategies and Best-Match-25 (BM25) lexical recall.
---

## Purpose

`asec-confidence` scores a finding on three axes — pattern, recall, reachability —
via a pluggable strategy. It is kept separate from `asec-core` because it owns
[E18](/agentic-security-lab/concepts/ears-invariants/#e18) (the scoring half of
confidence dispatch) and is a pure, deterministic, independently testable unit.
The scoring math is fixed in
[ADR-008](/agentic-security-lab/adrs/0008-pluggable-confidence-strategy-bm25/);
the dispatch on the score lives in `asec-core`.

## Public types

- `ConfidenceInputs` — `pattern`, `recall`, `reachability` (each in `[0, 1]`).
- `ConfidenceStrategy(Protocol)`.
- `BaselineStrategy` — deterministic linear combination, weights tuple
  `(0.45, 0.30, 0.25)` over `(pattern, recall, reachability)`.
- `LLMJudgeStrategy` — opt-in second strategy.
- `bm25s` — pure-Python Best-Match-25 implementation; the lexical-recall axis
  uses an ephemeral BM25 index over the recalled corpus, with the top score
  squashed through a sigmoid into `[0, 1]`.

## EARS invariants owned

- [**E18**](/agentic-security-lab/concepts/ears-invariants/#e18) (scoring) —
  the deterministic three-axis confidence score the orchestrator dispatches on.

## Dependencies

`pydantic`, `bm25s`, `structlog`, `opentelemetry-api`.
