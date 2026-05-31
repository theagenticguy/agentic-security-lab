"""ProgressEvent bus — the v1.5 structured progress channel (NOT token streaming).

This module carries *coarse-grained, typed lifecycle events* (phase transitions,
hypothesis open/verify, finding emission, gate decisions, worker-stuck signals, budget
warnings, run completion) — emphatically NOT model token streaming. There is no
character-by-character or chunk-by-chunk text channel here; raw model token streaming lives
behind `AgentRuntime.stream` in asec-core and is deliberately kept out of the audit/progress
path. Every emitted event fans out to subscribers and is durably recorded to the WORM audit.

`ProgressEvent` is a Pydantic discriminated union keyed on `event_type`; each variant
carries a typed payload. `EventEmitter.emit` is fail-soft for subscribers: a subscriber that
raises is logged and skipped, never allowed to take down the emitter or sibling subscribers.
"""

from __future__ import annotations

from typing import Annotated, Literal, Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from .audit import WormAuditWriter

logger = structlog.get_logger(__name__)


class _Event(BaseModel):
    model_config = ConfigDict(frozen=True)

    session: str


class PhaseTransition(_Event):
    event_type: Literal["phase_transition"] = "phase_transition"
    from_phase: str
    to_phase: str


class HypothesisOpened(_Event):
    event_type: Literal["hypothesis_opened"] = "hypothesis_opened"
    hypothesis_id: str
    statement: str


class HypothesisVerified(_Event):
    event_type: Literal["hypothesis_verified"] = "hypothesis_verified"
    hypothesis_id: str
    verdict: Literal["confirmed", "refuted", "inconclusive"]


class FindingEmitted(_Event):
    event_type: Literal["finding_emitted"] = "finding_emitted"
    finding_id: str
    severity: str
    cwe: str | None = None


class GateDecision(_Event):
    event_type: Literal["gate_decision"] = "gate_decision"
    gate: str
    decision: Literal["pass", "fail"]
    reason: str | None = None


class WorkerStuck(_Event):
    event_type: Literal["worker_stuck"] = "worker_stuck"
    worker_id: str
    detail: str


class BudgetWarning(_Event):
    event_type: Literal["budget_warning"] = "budget_warning"
    resource: str
    used: float
    limit: float


class RunComplete(_Event):
    event_type: Literal["run_complete"] = "run_complete"
    findings_count: int
    status: Literal["pass", "fail"]


ProgressEvent = Annotated[
    PhaseTransition
    | HypothesisOpened
    | HypothesisVerified
    | FindingEmitted
    | GateDecision
    | WorkerStuck
    | BudgetWarning
    | RunComplete,
    Field(discriminator="event_type"),
]

ProgressEventAdapter: TypeAdapter[ProgressEvent] = TypeAdapter(ProgressEvent)


@runtime_checkable
class EventSubscriber(Protocol):
    """A consumer of `ProgressEvent`s (e.g. a TUI, an SSE bridge)."""

    async def on_event(self, event: ProgressEvent) -> None:
        """Handle a single progress event."""
        ...


class EventEmitter:
    """Fans `ProgressEvent`s out to subscribers and records each to the WORM audit."""

    def __init__(self, *, audit: WormAuditWriter | None = None) -> None:
        self._subscribers: list[EventSubscriber] = []
        self._audit = audit

    def subscribe(self, subscriber: EventSubscriber) -> None:
        self._subscribers.append(subscriber)

    async def emit(self, event: ProgressEvent) -> None:
        """Record ``event`` to the WORM audit, then fan out to all subscribers (fail-soft)."""
        if self._audit is not None:
            await self._audit.append(
                actor="emitter",
                action=event.event_type,
                payload=event.model_dump(mode="json"),
                session=event.session,
            )
        for subscriber in self._subscribers:
            try:
                await subscriber.on_event(event)
            except Exception:
                logger.exception(
                    "event_subscriber.error",
                    subscriber=type(subscriber).__name__,
                    event_type=event.event_type,
                )
