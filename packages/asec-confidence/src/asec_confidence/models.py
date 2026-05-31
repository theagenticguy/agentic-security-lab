"""Pydantic value objects for the three-axis confidence scorer (E18)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Tier = Literal["very_low", "low", "medium", "high"]
Dispatch = Literal["specialized", "parallel_shell", "swarm", "runtime_authorship"]


class ConfidenceInputs(BaseModel):
    """The three normalised axes feeding the confidence score."""

    model_config = ConfigDict(frozen=True)

    pattern_match: float = Field(ge=0.0, le=1.0)
    memory_recall: float = Field(ge=0.0, le=1.0)
    reachability: float = Field(ge=0.0, le=1.0)
    context: dict[str, Any] | None = None


class ConfidenceScore(BaseModel):
    """The scored result plus its tier and the orchestration dispatch."""

    model_config = ConfigDict(frozen=True)

    score: float = Field(ge=0.0, le=1.0)
    tier: Tier
    dispatch: Dispatch
