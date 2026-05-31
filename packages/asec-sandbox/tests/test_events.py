from __future__ import annotations

from pathlib import Path

from asec_sandbox.audit import WormAuditWriter, verify_chain
from asec_sandbox.events import (
    BudgetWarning,
    EventEmitter,
    FindingEmitted,
    GateDecision,
    HypothesisOpened,
    HypothesisVerified,
    PhaseTransition,
    ProgressEvent,
    ProgressEventAdapter,
    RunComplete,
    WorkerStuck,
)

ALL_EVENTS: list[ProgressEvent] = [
    PhaseTransition(session="s", from_phase="zero", to_phase="recon"),
    HypothesisOpened(session="s", hypothesis_id="h1", statement="sqli in login"),
    HypothesisVerified(session="s", hypothesis_id="h1", verdict="confirmed"),
    FindingEmitted(session="s", finding_id="f1", severity="high", cwe="CWE-89"),
    GateDecision(session="s", gate="release", decision="fail", reason="open high"),
    WorkerStuck(session="s", worker_id="w1", detail="no progress 5m"),
    BudgetWarning(session="s", resource="tokens", used=0.9, limit=1.0),
    RunComplete(session="s", findings_count=3, status="fail"),
]


def test_every_event_type_roundtrips() -> None:
    for ev in ALL_EVENTS:
        dumped = ev.model_dump(mode="json")
        restored = ProgressEventAdapter.validate_python(dumped)
        assert restored == ev
        assert type(restored) is type(ev)


async def test_emit_fans_out_to_all_subscribers() -> None:
    seen_a: list[ProgressEvent] = []
    seen_b: list[ProgressEvent] = []

    class SubA:
        async def on_event(self, event: ProgressEvent) -> None:
            seen_a.append(event)

    class SubB:
        async def on_event(self, event: ProgressEvent) -> None:
            seen_b.append(event)

    emitter = EventEmitter()
    emitter.subscribe(SubA())
    emitter.subscribe(SubB())
    for ev in ALL_EVENTS:
        await emitter.emit(ev)
    assert seen_a == ALL_EVENTS
    assert seen_b == ALL_EVENTS


async def test_subscriber_raising_does_not_kill_emitter() -> None:
    good: list[ProgressEvent] = []

    class Bad:
        async def on_event(self, event: ProgressEvent) -> None:
            raise RuntimeError("boom")

    class Good:
        async def on_event(self, event: ProgressEvent) -> None:
            good.append(event)

    emitter = EventEmitter()
    emitter.subscribe(Bad())
    emitter.subscribe(Good())
    ev = RunComplete(session="s", findings_count=0, status="pass")
    await emitter.emit(ev)  # must not raise
    assert good == [ev]


async def test_worm_receives_every_emit(tmp_path: Path) -> None:
    audit = WormAuditWriter(tmp_path / "audit.jsonl")
    emitter = EventEmitter(audit=audit)
    for ev in ALL_EVENTS:
        await emitter.emit(ev)
    entries = verify_chain(audit.path)
    assert len(entries) == len(ALL_EVENTS)
    assert [e["action"] for e in entries] == [e.event_type for e in ALL_EVENTS]
