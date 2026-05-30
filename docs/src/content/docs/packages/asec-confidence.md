---
title: asec-confidence
description: Three-axis confidence scorer with pluggable strategies and bm25s recall.
---

## Purpose

`asec-confidence` scores a finding on three axes — pattern, recall, reachability — via a
pluggable strategy. Kept separate from `asec-core` because it owns E18 (scoring) and is a
pure, deterministic, independently testable unit.

## Public types

- `ConfidenceInputs` — `pattern`, `recall`, `reachability` (each 0–1).
- `ConfidenceStrategy(Protocol)`.
- `BaselineStrategy` — deterministic; `weights` tuple.
- `LLMJudgeStrategy` — opt-in.
- `bm25s` lexical recall component.

## EARS invariants owned

- **E18 (scoring)** — deterministic three-axis confidence score. Dispatch on the score
  lives in `asec-core`.

## Dependencies

`pydantic`, `bm25s`, `structlog`, `opentelemetry-api`.
