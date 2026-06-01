---
title: asec-threat-model
description: Phase-Zero pydantic threat-model artifacts with stable round-trip and diff.
---

## Purpose

`asec-threat-model` defines the Phase-Zero threat-model artifacts as pure,
independently testable Pydantic models. It is kept separate from `asec-core`
because it owns distinct EARS invariants
([E1](/agentic-security-lab/concepts/ears-invariants/#e1),
[E2](/agentic-security-lab/concepts/ears-invariants/#e2)) and is a pure-logic
unit with no I/O.

## Public types

- `Asset`, `Threat`, `ThreatModel` (Pydantic).
- `load(path)` / `dump(tm, path)` — round-trip stable serialization.
- `diff(a, b) -> ThreatModelDiff`.

## EARS invariants owned

- [**E1**](/agentic-security-lab/concepts/ears-invariants/#e1) — when a new repo
  has no `threat-model.yaml`, the system authors one (boundaries, assets,
  data-flow diagram, STRIDE threats) before dispatching any audit worker.
- [**E2**](/agentic-security-lab/concepts/ears-invariants/#e2) — while operating,
  the system treats `threat-model.yaml` and `assets.yaml` as the scope of record
  and does not act outside their declared boundaries.

## Dependencies

`pydantic`, `pyyaml`, `structlog`, `opentelemetry-api`.
