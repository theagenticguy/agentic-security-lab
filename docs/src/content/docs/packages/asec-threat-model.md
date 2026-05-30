---
title: asec-threat-model
description: Phase-Zero pydantic threat-model artifacts with stable round-trip and diff.
---

## Purpose

`asec-threat-model` defines the Phase-Zero threat-model artifacts as pure, independently
testable pydantic models. Kept separate from `asec-core` because it owns distinct EARS
invariants (E1/E2) and is a pure-logic unit.

## Public types

- `Asset`, `Threat`, `ThreatModel` (pydantic).
- `load(path)` / `dump(tm, path)` — round-trip stable serialization.
- `diff(a, b) -> ThreatModelDiff`.

## EARS invariants owned

- **E1, E2** — threat-model artifact structure and stable, comparable serialization.

## Dependencies

`pydantic`, `pyyaml`, `structlog`, `opentelemetry-api`.
