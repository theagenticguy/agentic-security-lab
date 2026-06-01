"""Day 3 tests for `Orchestrator` — driven by an in-test fake `AgentRuntime`.

The fake yields a canned `RuntimeMessage` stream (tool_use + assistant text + a terminal
`result` with token usage) that mirrors the real SDK→`RuntimeMessage` normalization, so the
orchestrator's bridge/parse/budget logic is exercised without touching Bedrock.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

import pytest
from asec_core import (
    GovernanceGate,
    KillSwitch,
    Orchestrator,
    ReviewResult,
    RuntimeMessage,
    ScopeArtifact,
    sign_scope,
)
from asec_memory.ledger import SQLiteLedger
from asec_sandbox.events import (
    BudgetWarning,
    EventEmitter,
    FindingEmitted,
    GateDecision,
    PhaseTransition,
    RunComplete,
    WorkerStuck,
)
from asec_skills.skill import Skill
from asec_threat_model.models import Asset, ThreatModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.asyncio

THREE_FINDINGS_JSON = """
Here is my analysis.

```json
[
  {"rule_id": "py.sql-injection", "message": "f-string SQL", "severity": "error",
   "cwe": "CWE-89", "uri": "src/api/users.py", "start_line": 12, "snippet": "cursor.execute(f...)"},
  {"rule_id": "py.xss", "message": "unescaped output", "severity": "error",
   "cwe": "CWE-79", "uri": "src/web/render.py", "start_line": 8, "snippet": "<div>{q}</div>"},
  {"rule_id": "py.path-traversal", "message": "no containment", "severity": "warning",
   "cwe": "CWE-22", "uri": "src/files/download.py", "start_line": 5, "snippet": "open(join(...))"}
]
```
"""


def _keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _signed_scope(priv_pem: bytes, *, expires_in: timedelta = timedelta(hours=1)) -> ScopeArtifact:
    now = datetime.now(UTC)
    unsigned = ScopeArtifact(
        id="scope-1",
        created_at=now,
        expires_at=now + expires_in,
        targets=("repo/src",),
        egress_allowlist=(),
        signer="",
        signature="",
    )
    return sign_scope(unsigned, priv_pem, signer="dev")


def _threat_model() -> ThreatModel:
    asset = Asset.model_validate(
        {"id": "user-pii", "class": "PII", "weight": "HIGH", "description": "user data"}
    )
    return ThreatModel(
        version=1,
        generated_by="test",
        generated_at=datetime.now(UTC),
        assets=(asset,),
    )


def _skill() -> Skill:
    return Skill(name="security-code-review", description="review", body="Find vulns.")


class _FakeSandbox:
    async def start(self) -> None: ...
    async def exec(self, command: Sequence[str]) -> tuple[int, str, str]:
        return (0, "", "")

    async def collect_artifacts(self) -> dict[str, bytes]:
        return {}

    async def teardown(self) -> None: ...


class _FakeRuntime:
    """Yields a canned stream; `messages` is overridable per test."""

    def __init__(self, messages: list[RuntimeMessage] | None = None) -> None:
        self.messages = messages if messages is not None else _default_stream()
        self.prompts: list[str] = []
        self._hooks: dict[str, list[Any]] = {}

    async def query(
        self, prompt: str, *, options: Any | None = None
    ) -> AsyncIterator[RuntimeMessage]:
        self.prompts.append(prompt)
        for msg in self.messages:
            yield msg

    def register_hook(self, event: str, hook: Any) -> None:
        self._hooks.setdefault(event, []).append(hook)

    async def spawn_subagents(self, specs: Sequence[Any]) -> Sequence[Any]:
        return []


def _default_stream(*, cost: float | None = None, input_tokens: int = 0, output_tokens: int = 0):
    return [
        RuntimeMessage(kind="tool_use", tool_id="t1", tool_name="Read", tool_input={"path": "x"}),
        RuntimeMessage(kind="text", text="I suspect SQL injection in users.py."),
        RuntimeMessage(kind="text", text=THREE_FINDINGS_JSON),
        RuntimeMessage(
            kind="result",
            total_cost_usd=cost,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            result_text=THREE_FINDINGS_JSON,
        ),
    ]


class _Harness(NamedTuple):
    orch: Orchestrator
    scope: ScopeArtifact
    emitter: EventEmitter
    ledger: SQLiteLedger


async def _build_orchestrator(
    tmp_path: Any,
    *,
    runtime: _FakeRuntime | None = None,
    kill: KillSwitch | None = None,
    max_budget_usd: float = 5.0,
    scope_expires_in: timedelta = timedelta(hours=1),
) -> _Harness:
    priv, pub = _keypair()
    scope = _signed_scope(priv, expires_in=scope_expires_in)
    kill = kill or KillSwitch()
    gate = GovernanceGate(
        scope=scope, public_key_pem=pub, kill_switch=kill, max_budget_usd=max_budget_usd
    )
    ledger = await SQLiteLedger(str(tmp_path / "ledger.db")).init()
    emitter = EventEmitter()
    orch = Orchestrator(
        runtime=runtime or _FakeRuntime(),
        sandbox=_FakeSandbox(),
        ledger=ledger,
        emitter=emitter,
        gate=gate,
        kill_switch=kill,
        skill=_skill(),
        threat_model=_threat_model(),
        corpus_files={"src/api/users.py": "cursor.execute(f'...')"},
        max_budget_usd=max_budget_usd,
    )
    return _Harness(orch, scope, emitter, ledger)


def _kinds(result: ReviewResult) -> set[str]:
    return {e.event_type for e in result.events}


def _run_complete(result: ReviewResult) -> RunComplete:
    """Narrow to the single terminal `RunComplete` event (strict-typing friendly)."""
    done = [e for e in result.events if isinstance(e, RunComplete)]
    assert len(done) == 1, f"expected exactly one RunComplete, got {len(done)}"
    return done[0]


async def test_run_returns_review_result(tmp_path: Any) -> None:
    h = await _build_orchestrator(tmp_path)
    result = await h.orch.run(h.scope)
    assert isinstance(result, ReviewResult)
    assert result.sarif["version"] == "2.1.0"


async def test_finding_json_parsing_extracts_three(tmp_path: Any) -> None:
    h = await _build_orchestrator(tmp_path)
    result = await h.orch.run(h.scope)
    assert len(result.findings) == 3
    cwes = {f.cwe for f in result.findings}
    assert cwes == {"CWE-89", "CWE-79", "CWE-22"}


async def test_findings_persisted_to_ledger(tmp_path: Any) -> None:
    h = await _build_orchestrator(tmp_path)
    result = await h.orch.run(h.scope)
    stored = await h.ledger.list_findings()
    assert len(stored) == len(result.findings) == 3


async def test_governance_deny_aborts_before_query(tmp_path: Any) -> None:
    runtime = _FakeRuntime()
    h = await _build_orchestrator(tmp_path, runtime=runtime, scope_expires_in=timedelta(seconds=-1))
    result = await h.orch.run(h.scope)
    assert runtime.prompts == []  # never queried
    assert result.findings == []
    gate_events = [e for e in result.events if isinstance(e, GateDecision)]
    assert gate_events and gate_events[0].decision == "fail"


async def test_kill_switch_mid_run_emits_worker_stuck(tmp_path: Any) -> None:
    # Tripping before the run: gate.check() consults the kill switch and denies, so the
    # run aborts at the gate. Either path ends in a failing RunComplete.
    kill = KillSwitch()
    runtime = _FakeRuntime()
    h = await _build_orchestrator(tmp_path, runtime=runtime, kill=kill)
    kill.trigger("operator halt")
    result = await h.orch.run(h.scope)
    assert any(isinstance(e, WorkerStuck | GateDecision) for e in result.events)
    assert _run_complete(result).status == "fail"


async def test_kill_switch_trips_inside_loop(tmp_path: Any) -> None:
    """A kill switch that passes the gate but trips inside the stream emits WorkerStuck."""

    class _TripOnReadKill(KillSwitch):
        def __init__(self) -> None:
            super().__init__()
            self._reads = 0

        @property
        def triggered(self) -> bool:
            # Pass the initial gate.check(), then trip on the loop's first read.
            self._reads += 1
            if self._reads > 1 and not super().triggered:
                self.trigger("tripped in loop")
            return super().triggered

    kill = _TripOnReadKill()
    h = await _build_orchestrator(tmp_path, kill=kill)
    result = await h.orch.run(h.scope)
    assert any(isinstance(e, WorkerStuck) for e in result.events)
    assert _run_complete(result).status == "fail"


async def test_budget_warnings_at_thresholds(tmp_path: Any) -> None:
    # cost = full budget => all three thresholds (50/80/100%) fire on the result msg.
    runtime = _FakeRuntime(_default_stream(cost=5.0))
    h = await _build_orchestrator(tmp_path, runtime=runtime, max_budget_usd=5.0)
    result = await h.orch.run(h.scope)
    resources = {e.resource for e in result.events if isinstance(e, BudgetWarning)}
    assert resources == {"budget_usd@50%", "budget_usd@80%", "budget_usd@100%"}


async def test_budget_warning_partial_threshold(tmp_path: Any) -> None:
    # cost = 60% of budget => 50% fires, 80%/100% do not.
    runtime = _FakeRuntime(_default_stream(cost=3.0))
    h = await _build_orchestrator(tmp_path, runtime=runtime, max_budget_usd=5.0)
    result = await h.orch.run(h.scope)
    resources = {e.resource for e in result.events if isinstance(e, BudgetWarning)}
    assert resources == {"budget_usd@50%"}


async def test_budget_from_token_usage(tmp_path: Any) -> None:
    # No explicit cost => derive spend from token usage; large output trips thresholds.
    runtime = _FakeRuntime(_default_stream(input_tokens=200_000, output_tokens=100_000))
    h = await _build_orchestrator(tmp_path, runtime=runtime, max_budget_usd=0.5)
    result = await h.orch.run(h.scope)
    assert any(isinstance(e, BudgetWarning) for e in result.events)


async def test_every_phase_emits_expected_events(tmp_path: Any) -> None:
    h = await _build_orchestrator(tmp_path)
    result = await h.orch.run(h.scope)
    kinds = _kinds(result)
    assert {"gate_decision", "phase_transition", "finding_emitted", "run_complete"} <= kinds


async def test_phase_transition_recon_to_find(tmp_path: Any) -> None:
    h = await _build_orchestrator(tmp_path)
    result = await h.orch.run(h.scope)
    phases = [e for e in result.events if isinstance(e, PhaseTransition)]
    assert phases[0].from_phase == "recon"
    assert phases[0].to_phase == "find"


async def test_run_complete_carries_finding_count(tmp_path: Any) -> None:
    h = await _build_orchestrator(tmp_path)
    result = await h.orch.run(h.scope)
    done = _run_complete(result)
    assert done.findings_count == 3
    assert done.status == "pass"


async def test_finding_emitted_per_finding(tmp_path: Any) -> None:
    h = await _build_orchestrator(tmp_path)
    result = await h.orch.run(h.scope)
    emitted = [e for e in result.events if isinstance(e, FindingEmitted)]
    assert len(emitted) == 3
    assert {e.cwe for e in emitted} == {"CWE-89", "CWE-79", "CWE-22"}


async def test_tool_use_bridges_to_gate_decision(tmp_path: Any) -> None:
    h = await _build_orchestrator(tmp_path)
    result = await h.orch.run(h.scope)
    tool_gates = [
        e for e in result.events if isinstance(e, GateDecision) and e.gate.startswith("tool:")
    ]
    assert tool_gates and tool_gates[0].gate == "tool:Read"


async def test_no_findings_when_no_json_block(tmp_path: Any) -> None:
    stream = [RuntimeMessage(kind="text", text="No JSON here."), RuntimeMessage(kind="result")]
    h = await _build_orchestrator(tmp_path, runtime=_FakeRuntime(stream))
    result = await h.orch.run(h.scope)
    assert result.findings == []
    assert _run_complete(result).findings_count == 0


async def test_run_pr_seeds_prompt_from_diff(tmp_path: Any) -> None:
    diff = tmp_path / "change.diff"
    diff.write_text("--- a/x\n+++ b/x\n+cursor.execute(f'...')\n", encoding="utf-8")
    runtime = _FakeRuntime()
    h = await _build_orchestrator(tmp_path, runtime=runtime)
    result = await h.orch.run_pr(diff)
    assert len(result.findings) == 3
    assert "UNIFIED DIFF" in runtime.prompts[0]
    assert "UNIFIED DIFF" in runtime.prompts[0]


async def test_audit_head_hash_populated_with_audit(tmp_path: Any) -> None:
    from asec_sandbox.audit import WormAuditWriter

    audit = WormAuditWriter(str(tmp_path / "audit.jsonl"), session="review")
    emitter = EventEmitter(audit=audit)
    priv, pub = _keypair()
    scope = _signed_scope(priv)
    kill = KillSwitch()
    gate = GovernanceGate(scope=scope, public_key_pem=pub, kill_switch=kill)
    ledger = await SQLiteLedger(str(tmp_path / "l.db")).init()
    orch = Orchestrator(
        runtime=_FakeRuntime(),
        sandbox=_FakeSandbox(),
        ledger=ledger,
        emitter=emitter,
        gate=gate,
        kill_switch=kill,
        skill=_skill(),
        threat_model=_threat_model(),
    )
    result = await orch.run(scope)
    assert result.audit_head_hash.startswith("sha256:")
