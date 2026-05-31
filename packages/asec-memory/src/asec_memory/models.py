"""Pydantic v2 value objects for the findings ledger and the ``asec.v1`` SARIF bag.

All public models are ``frozen=True`` immutable value objects with ``extra="forbid"``
so that unknown ``asec.*`` fields are rejected rather than silently dropped — the
property bag is a versioned contract, not a free-form dict.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

ASEC_SCHEMA_VERSION = "asec.v1"

# A confidence/probability axis, clamped to the unit interval.
UnitFloat = Annotated[float, Field(ge=0.0, le=1.0)]


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class _Frozen(BaseModel):
    """Base for immutable, strict value objects."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ReachabilityVerdict(StrEnum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class AssetWeightTier(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingLocation(_Frozen):
    """Physical source location of a finding (SARIF physicalLocation analogue)."""

    uri: str
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    snippet: str | None = None


class Reachability(_Frozen):
    """Whether tainted data/control can actually reach the sink (E18 axis)."""

    verdict: ReachabilityVerdict = ReachabilityVerdict.UNKNOWN
    score: UnitFloat = 0.0
    rationale: str | None = None


class Exploitability(_Frozen):
    """How readily a reachable defect can be weaponized."""

    score: UnitFloat = 0.0
    rationale: str | None = None


class AssetWeight(_Frozen):
    """Threat-model importance of the asset the finding touches."""

    tier: AssetWeightTier = AssetWeightTier.MEDIUM
    score: UnitFloat = 0.5
    asset_id: str | None = None


class AsecProperties(_Frozen):
    """The ``asec.v1`` SARIF property bag attached to every result.

    Carries the substrate's reachability/exploitability/asset signals plus the
    derived ``priority``. ``schemaVersion`` must equal :data:`ASEC_SCHEMA_VERSION`.
    """

    schemaVersion: Literal["asec.v1"] = ASEC_SCHEMA_VERSION  # noqa: N815 (SARIF camelCase)
    reachability: Reachability = Reachability()
    exploitability: Exploitability = Exploitability()
    asset: AssetWeight = AssetWeight()
    priority: UnitFloat = 0.0
    confidence: UnitFloat = 0.0
    hypothesis_id: str | None = None


class Finding(_Frozen):
    """A single, durably persisted security finding."""

    id: str
    rule_id: str
    message: str
    severity: Literal["error", "warning", "note", "none"] = "warning"
    cwe: str | None = None
    location: FindingLocation
    asec: AsecProperties = AsecProperties()
    created_at: datetime = Field(default_factory=_utcnow)

    @property
    def priority(self) -> float:
        """Convenience accessor for the derived ``asec.priority`` score."""
        return self.asec.priority


class Hypothesis(_Frozen):
    """An in-flight, falsifiable claim on the per-session board (E9)."""

    id: str
    finding_id: str | None = None
    statement: str
    status: Literal["open", "confirmed", "refuted"] = "open"
    confidence: UnitFloat = 0.0
    created_at: datetime = Field(default_factory=_utcnow)


class Suppression(_Frozen):
    """A false-positive memory entry suppressing a (rule, location) pair (E11)."""

    id: str
    rule_id: str
    location_uri: str
    reason: str
    created_at: datetime = Field(default_factory=_utcnow)

    @property
    def dedup_key(self) -> str:
        """Stable identity used to deduplicate suppressions."""
        return f"{self.rule_id}::{self.location_uri}"
