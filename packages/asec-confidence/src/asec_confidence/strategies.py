"""Confidence strategies: the deterministic baseline plus the Protocol seam."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import structlog
from opentelemetry import trace

from .models import ConfidenceInputs, ConfidenceScore, Dispatch, Tier

_log = structlog.get_logger(__name__)
_tracer = trace.get_tracer(__name__)

# (lower-inclusive threshold, tier, dispatch), highest first. Per PLAN §9.
_TIER_TABLE: tuple[tuple[float, Tier, Dispatch], ...] = (
    (0.85, "high", "specialized"),
    (0.70, "medium", "parallel_shell"),
    (0.40, "low", "swarm"),
    (0.0, "very_low", "runtime_authorship"),
)


def _classify(score: float) -> tuple[Tier, Dispatch]:
    for threshold, tier, dispatch in _TIER_TABLE:
        if score >= threshold:
            return tier, dispatch
    return "very_low", "runtime_authorship"


@runtime_checkable
class ConfidenceStrategy(Protocol):
    """A pluggable scorer mapping three axes to a tiered dispatch decision."""

    async def score(self, inputs: ConfidenceInputs) -> ConfidenceScore: ...


class BaselineStrategy:
    """A deterministic linear combination of the three axes.

    ``weights`` apply to ``(pattern_match, memory_recall, reachability)`` and
    must sum to 1.0 so the score stays within ``[0, 1]``.
    """

    def __init__(self, weights: tuple[float, float, float] = (0.45, 0.30, 0.25)) -> None:
        if abs(sum(weights) - 1.0) > 1e-9:
            raise ValueError(f"weights must sum to 1.0, got {sum(weights)}")
        self.weights = weights

    async def score(self, inputs: ConfidenceInputs) -> ConfidenceScore:
        with _tracer.start_as_current_span("BaselineStrategy.score"):
            wp, wm, wr = self.weights
            value = (
                wp * inputs.pattern_match
                + wm * inputs.memory_recall
                + wr * inputs.reachability
            )
            tier, dispatch = _classify(value)
            _log.info("confidence.score", score=value, tier=tier, dispatch=dispatch)
            return ConfidenceScore(score=value, tier=tier, dispatch=dispatch)
