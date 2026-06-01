"""Day 5 tests for confidence dispatch wired into the orchestrator (PLAN §3).

Tier handling is exercised by injecting a stub strategy that returns a fixed
`ConfidenceScore`, so each tier's dispatch path (specialized / parallel-shell / swarm /
runtime-authorship gate) is asserted deterministically. The axis builders
(`bm25_recall`, `pattern_match_score`) are tested directly for determinism + corpus
recall.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

import pytest
from asec_confidence import BaselineStrategy, ConfidenceInputs, bm25_recall
from asec_confidence.models import ConfidenceScore, Dispatch, Tier
from asec_core import (
    AgentDefinition,
    GovernanceGate,
    KillSwitch,
    Orchestrator,
    ScopeArtifact,
    pattern_match_score,
    sign_scope,
)
from asec_core.runtime import RuntimeMessage
from asec_memory.board import HypothesisBoard
from asec_memory.ledger import SQLiteLedger
from asec_sandbox.events import EventEmitter, GateDecision, HypothesisOpened
from asec_skills.skill import Skill
from asec_threat_model.models import Asset, ThreatModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.asyncio


# ----- direct axis + strategy tests ------------------------------------------------


async def test_tier_boundaries_classify_correctly() -> None:
    strat = BaselineStrategy(weights=(1.0, 0.0, 0.0))
    # pattern_match drives the score directly under these weights.
    cases: list[tuple[float, Tier, Dispatch]] = [
        (0.90, "high", "specialized"),
        (0.75, "medium", "parallel_shell"),
        (0.50, "low", "swarm"),
        (0.10, "very_low", "runtime_authorship"),
    ]
    for pm, tier, dispatch in cases:
        score = await strat.score(
            ConfidenceInputs(pattern_match=pm, memory_recall=0.0, reachability=0.0)
        )
        assert score.tier == tier
        assert score.dispatch == dispatch


async def test_bm25_recall_against_small_corpus() -> None:
    corpus = [
        "py.sql-injection f-string SQL in users query",
        "py.xss unescaped html output",
        "py.path-traversal unsafe join",
    ]
    hit = bm25_recall("sql injection users query", corpus)
    miss = bm25_recall("completely unrelated cryptography nonce", corpus)
    assert hit > 0.0
    assert hit >= miss


async def test_pattern_match_score_deterministic() -> None:
    kw = frozenset({"execute", "cursor", "select"})
    s1 = pattern_match_score("cursor.execute(f'SELECT ...')", kw)
    s2 = pattern_match_score("cursor.execute(f'SELECT ...')", kw)
    assert s1 == s2
    assert s1 == 1.0  # all 3 keywords hit
    assert pattern_match_score("nothing here", kw) == 0.0
    assert pattern_match_score(None, kw) == 0.0


# ----- orchestrator dispatch wiring ------------------------------------------------


class _StubStrategy:
    """Returns a fixed `ConfidenceScore` regardless of inputs (tier under test)."""

    def __init__(self, tier: Tier, dispatch: Dispatch, score: float) -> None:
        self._out = ConfidenceScore(score=score, tier=tier, dispatch=dispatch)

    async def score(self, inputs: ConfidenceInputs) -> ConfidenceScore:
        return self._out


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


def _signed_scope(priv_pem: bytes) -> ScopeArtifact:
    now = datetime.now(UTC)
    unsigned = ScopeArtifact(
        id="scope-1",
        created_at=now,
        expires_at=now + timedelta(hours=1),
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
        version=1, generated_by="test", generated_at=datetime.now(UTC), assets=(asset,)
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


class _SingleFindingRuntime:
    """Lead pass returns nothing; the one worker returns one finding; no chains."""

    def __init__(self) -> None:
        self._call = 0
        self._hooks: dict[str, list[Any]] = {}

    async def query(
        self, prompt: str, *, options: Any | None = None
    ) -> AsyncIterator[RuntimeMessage]:
        idx = self._call
        self._call += 1
        if idx == 1:  # the worker pass
            text = (
                "```json\n"
                '[{"id": "F1", "rule_id": "py.sqli", "message": "f-string SQL", '
                '"cwe": "CWE-89", "uri": "src/api/users.py", "start_line": 12, '
                '"snippet": "cursor.execute(f\\"...\\")"}]\n'
                "```"
            )
        else:
            text = "no chains"
        yield RuntimeMessage(kind="text", text=text)
        yield RuntimeMessage(kind="result", result_text=text)

    def register_hook(self, event: str, hook: Any) -> None:
        self._hooks.setdefault(event, []).append(hook)

    async def spawn_subagents(self, specs: Sequence[Any]) -> Sequence[Any]:
        return []


class _Harness(NamedTuple):
    orch: Orchestrator
    scope: ScopeArtifact


async def _build(tmp_path: Any, *, confidence: Any) -> _Harness:
    tmp_path.mkdir(parents=True, exist_ok=True)
    priv, pub = _keypair()
    scope = _signed_scope(priv)
    kill = KillSwitch()
    gate = GovernanceGate(scope=scope, public_key_pem=pub, kill_switch=kill, max_budget_usd=5.0)
    ledger = await SQLiteLedger(str(tmp_path / "ledger.db")).init()
    board = HypothesisBoard(str(tmp_path / "board.jsonl"))
    worker = AgentDefinition(
        name="sqli-worker",
        description="sqli",
        cwe_id="CWE-89",
        pattern_keywords=frozenset({"cursor", "execute"}),
    )
    orch = Orchestrator(
        runtime=_SingleFindingRuntime(),
        sandbox=_FakeSandbox(),
        ledger=ledger,
        emitter=EventEmitter(),
        gate=gate,
        kill_switch=kill,
        skill=_skill(),
        threat_model=_threat_model(),
        corpus_files={"src/api/users.py": "cursor.execute(f'...')"},
        workers=(worker,),
        board=board,
        confidence=confidence,
        entry_point_files=("src/api/users.py",),
    )
    return _Harness(orch, scope)


async def test_high_tier_uses_finding_directly(tmp_path: Any) -> None:
    h = await _build(tmp_path, confidence=_StubStrategy("high", "specialized", 0.9))
    result = await h.orch.run(h.scope)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.asec.confidence_tier == "high"
    assert f.asec.dispatch == "specialized"
    # No parallel-shell / swarm / gate markers for a high-tier finding.
    assert not [e for e in result.events if isinstance(e, GateDecision) and e.gate == "confidence"]


async def test_medium_tier_marks_parallel_shell(tmp_path: Any) -> None:
    h = await _build(tmp_path, confidence=_StubStrategy("medium", "parallel_shell", 0.75))
    result = await h.orch.run(h.scope)
    markers = [
        e
        for e in result.events
        if isinstance(e, HypothesisOpened) and e.hypothesis_id.startswith("parallel-shell-")
    ]
    assert markers
    assert result.findings[0].asec.dispatch == "parallel_shell"


async def test_low_tier_marks_swarm(tmp_path: Any) -> None:
    h = await _build(tmp_path, confidence=_StubStrategy("low", "swarm", 0.5))
    result = await h.orch.run(h.scope)
    markers = [
        e
        for e in result.events
        if isinstance(e, HypothesisOpened) and e.hypothesis_id.startswith("swarm-")
    ]
    assert markers
    assert result.findings[0].asec.dispatch == "swarm"


async def test_very_low_triggers_runtime_authorship_gate(tmp_path: Any) -> None:
    h = await _build(tmp_path, confidence=_StubStrategy("very_low", "runtime_authorship", 0.1))
    result = await h.orch.run(h.scope)
    gates = [e for e in result.events if isinstance(e, GateDecision) and e.gate == "confidence"]
    assert gates
    assert gates[0].decision == "fail"
    assert gates[0].reason == "runtime_authorship_required"


async def test_confidence_inputs_written_into_asec(tmp_path: Any) -> None:
    h = await _build(tmp_path, confidence=_StubStrategy("high", "specialized", 0.9))
    result = await h.orch.run(h.scope)
    inputs = result.findings[0].asec.confidence_inputs
    assert inputs is not None
    # pattern_match must reflect the keyword hit on the cursor.execute snippet.
    assert inputs.pattern_match == 1.0
    assert 0.0 <= inputs.reachability <= 1.0


async def test_dispatch_deterministic_same_inputs(tmp_path: Any) -> None:
    h1 = await _build(tmp_path / "a", confidence=BaselineStrategy())
    h2 = await _build(tmp_path / "b", confidence=BaselineStrategy())
    r1 = await h1.orch.run(h1.scope)
    r2 = await h2.orch.run(h2.scope)
    assert r1.findings[0].asec.confidence == r2.findings[0].asec.confidence
    assert r1.findings[0].asec.confidence_tier == r2.findings[0].asec.confidence_tier
