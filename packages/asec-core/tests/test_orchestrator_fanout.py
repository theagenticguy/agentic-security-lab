"""Day 5 tests for the per-CWE subagent fan-out (PLAN §2).

A per-call fake runtime returns a distinct canned stream for each `query()` (one per
worker, plus the lead pass and the correlation pass), so the orchestrator's concurrent
dispatch, shared-board dedup, and correlation linkage are exercised without Bedrock.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

import pytest
from asec_core import (
    AgentDefinition,
    GovernanceGate,
    KillSwitch,
    Orchestrator,
    ScopeArtifact,
    sign_scope,
)
from asec_core.runtime import RuntimeMessage
from asec_memory.board import HypothesisBoard
from asec_memory.ledger import SQLiteLedger
from asec_sandbox.events import EventEmitter, FindingEmitted, PhaseTransition
from asec_skills.skill import Skill
from asec_threat_model.models import Asset, ThreatModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.asyncio


def _finding_block(rule_id: str, cwe: str, uri: str, line: int, snippet: str) -> str:
    return (
        "```json\n"
        f'[{{"rule_id": "{rule_id}", "message": "m", "severity": "warning", '
        f'"cwe": "{cwe}", "uri": "{uri}", "start_line": {line}, "snippet": "{snippet}"}}]\n'
        "```"
    )


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


class _PerCallRuntime:
    """Yields one canned text stream per `query()` call, in registration order.

    Records the high-water mark of concurrently-active queries so a test can assert
    the workers actually run concurrently (overlap > 1).
    """

    def __init__(self, streams: list[str]) -> None:
        self._streams = streams
        self._call = 0
        self.prompts: list[str] = []
        self.active = 0
        self.max_active = 0
        self._hooks: dict[str, list[Any]] = {}

    async def query(
        self, prompt: str, *, options: Any | None = None
    ) -> AsyncIterator[RuntimeMessage]:
        idx = self._call
        self._call += 1
        self.prompts.append(prompt)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        # Yield to the loop so siblings can interleave (proves concurrency).
        await asyncio.sleep(0)
        text = self._streams[idx] if idx < len(self._streams) else ""
        self.active -= 1
        yield RuntimeMessage(kind="text", text=text)
        yield RuntimeMessage(kind="result", result_text=text)

    def register_hook(self, event: str, hook: Any) -> None:
        self._hooks.setdefault(event, []).append(hook)

    async def spawn_subagents(self, specs: Sequence[Any]) -> Sequence[Any]:
        return []


class _Harness(NamedTuple):
    orch: Orchestrator
    scope: ScopeArtifact
    ledger: SQLiteLedger
    board: HypothesisBoard
    runtime: _PerCallRuntime


async def _build(
    tmp_path: Any,
    *,
    streams: list[str],
    workers: Sequence[AgentDefinition],
) -> _Harness:
    priv, pub = _keypair()
    scope = _signed_scope(priv)
    kill = KillSwitch()
    gate = GovernanceGate(scope=scope, public_key_pem=pub, kill_switch=kill, max_budget_usd=5.0)
    ledger = await SQLiteLedger(str(tmp_path / "ledger.db")).init()
    board = HypothesisBoard(str(tmp_path / "board.jsonl"))
    runtime = _PerCallRuntime(streams)
    orch = Orchestrator(
        runtime=runtime,
        sandbox=_FakeSandbox(),
        ledger=ledger,
        emitter=EventEmitter(),
        gate=gate,
        kill_switch=kill,
        skill=_skill(),
        threat_model=_threat_model(),
        corpus_files={"src/api/users.py": "cursor.execute(f'...')"},
        workers=workers,
        board=board,
        entry_point_files=("src/api/users.py",),
    )
    return _Harness(orch, scope, ledger, board, runtime)


def _three_workers() -> tuple[AgentDefinition, ...]:
    return (
        AgentDefinition(
            name="sqli-worker",
            description="sqli",
            cwe_id="CWE-89",
            pattern_keywords=frozenset({"execute", "cursor"}),
        ),
        AgentDefinition(
            name="xss-worker",
            description="xss",
            cwe_id="CWE-79",
            pattern_keywords=frozenset({"render", "html"}),
        ),
        AgentDefinition(
            name="path-worker",
            description="path",
            cwe_id="CWE-22",
            pattern_keywords=frozenset({"open", "join"}),
        ),
    )


async def test_three_workers_each_emit_one_finding(tmp_path: Any) -> None:
    workers = _three_workers()
    streams = [
        "lead pass",  # the lead single-query pass
        _finding_block("py.sqli", "CWE-89", "src/api/users.py", 12, "cursor.execute"),
        _finding_block("py.xss", "CWE-79", "src/web/render.py", 8, "render html"),
        _finding_block("py.path", "CWE-22", "src/files/dl.py", 5, "open join"),
        "no chains",  # correlation pass (no json block)
    ]
    h = await _build(tmp_path, streams=streams, workers=workers)
    result = await h.orch.run(h.scope)
    assert len(result.findings) == 3
    assert {f.cwe for f in result.findings} == {"CWE-89", "CWE-79", "CWE-22"}


async def test_workers_dispatch_concurrently(tmp_path: Any) -> None:
    workers = _three_workers()
    streams = [
        "lead pass",
        _finding_block("py.sqli", "CWE-89", "src/api/users.py", 12, "cursor.execute"),
        _finding_block("py.xss", "CWE-79", "src/web/render.py", 8, "render html"),
        _finding_block("py.path", "CWE-22", "src/files/dl.py", 5, "open join"),
        "no chains",
    ]
    h = await _build(tmp_path, streams=streams, workers=workers)
    await h.orch.run(h.scope)
    # The lead pass runs first (serial), then the three workers overlap under gather.
    assert h.runtime.max_active >= 2


async def test_dedup_collisions_resolve_to_one(tmp_path: Any) -> None:
    # 5 workers all emit the SAME dedup_key (same cwe/file/range) -> 1 finding.
    same = _finding_block("py.sqli", "CWE-89", "src/api/users.py", 12, "cursor.execute")
    workers = tuple(
        AgentDefinition(
            name=f"w{i}",
            description="d",
            cwe_id="CWE-89",
            pattern_keywords=frozenset({"execute"}),
        )
        for i in range(5)
    )
    streams = ["lead"] + [same] * 5 + ["no chains"]
    h = await _build(tmp_path, streams=streams, workers=workers)
    result = await h.orch.run(h.scope)
    assert len(result.findings) == 1


async def test_dedup_records_dupes_on_board(tmp_path: Any) -> None:
    same = _finding_block("py.sqli", "CWE-89", "src/api/users.py", 12, "cursor.execute")
    workers = tuple(
        AgentDefinition(name=f"w{i}", description="d", cwe_id="CWE-89") for i in range(3)
    )
    streams = ["lead"] + [same] * 3 + ["no chains"]
    h = await _build(tmp_path, streams=streams, workers=workers)
    await h.orch.run(h.scope)
    rows = h.board.read_all()
    # 1 open hypothesis (the unique winner) + 2 refuted dupes.
    refuted = [r for r in rows if r.status == "refuted"]
    assert len(refuted) == 2


async def test_correlation_attaches_variants_of(tmp_path: Any) -> None:
    workers = (
        AgentDefinition(name="idor", description="d", cwe_id="CWE-639"),
        AgentDefinition(name="path", description="d", cwe_id="CWE-22"),
    )
    f_idor = _finding_block("py.idor", "CWE-639", "src/a.py", 1, "user_id")
    f_path = _finding_block("py.path", "CWE-22", "src/b.py", 2, "open join")
    # Correlation pass links the two findings into one chain.
    chain = '```json\n[{"chain": ["py.idor.id", "py.path.id"]}]\n```'
    streams = ["lead", f_idor, f_path, chain]
    h = await _build(tmp_path, streams=streams, workers=workers)
    # Force deterministic finding ids by post-processing: instead, link via ids the model
    # actually returned. We can't predict uuid ids, so assert linkage exists when the
    # model echoes real ids. Use a runtime that emits the real ids by capturing them.
    result = await h.orch.run(h.scope)
    # The chain referenced ids that won't match generated uuids -> no linkage; but the
    # field must always be present and a tuple.
    for f in result.findings:
        assert isinstance(f.asec.variants_of, tuple)


async def test_correlation_links_real_ids(tmp_path: Any) -> None:
    # Use explicit ids in the worker findings so the correlation chain can reference them.
    f_idor = (
        "```json\n"
        '[{"id": "F-IDOR", "rule_id": "py.idor", "message": "m", "cwe": "CWE-639", '
        '"uri": "src/a.py", "start_line": 1, "snippet": "user_id"}]\n'
        "```"
    )
    f_path = (
        "```json\n"
        '[{"id": "F-PATH", "rule_id": "py.path", "message": "m", "cwe": "CWE-22", '
        '"uri": "src/b.py", "start_line": 2, "snippet": "open join"}]\n'
        "```"
    )
    chain = '```json\n[{"chain": ["F-IDOR", "F-PATH"]}]\n```'
    workers = (
        AgentDefinition(name="idor", description="d", cwe_id="CWE-639"),
        AgentDefinition(name="path", description="d", cwe_id="CWE-22"),
    )
    streams = ["lead", f_idor, f_path, chain]
    h = await _build(tmp_path, streams=streams, workers=workers)
    result = await h.orch.run(h.scope)
    by_id = {f.id: f for f in result.findings}
    assert by_id["F-IDOR"].asec.variants_of == ("F-PATH",)
    assert by_id["F-PATH"].asec.variants_of == ("F-IDOR",)


async def test_phase_transitions_per_boundary(tmp_path: Any) -> None:
    workers = _three_workers()
    streams = [
        "lead",
        _finding_block("py.sqli", "CWE-89", "src/api/users.py", 12, "cursor.execute"),
        _finding_block("py.xss", "CWE-79", "src/web/render.py", 8, "render html"),
        _finding_block("py.path", "CWE-22", "src/files/dl.py", 5, "open join"),
        "no chains",
    ]
    h = await _build(tmp_path, streams=streams, workers=workers)
    result = await h.orch.run(h.scope)
    transitions = [
        (e.from_phase, e.to_phase) for e in result.events if isinstance(e, PhaseTransition)
    ]
    assert ("recon", "find") in transitions
    assert ("find", "fanout") in transitions
    assert ("fanout", "correlate") in transitions


async def test_findings_emitted_for_unique_only(tmp_path: Any) -> None:
    workers = _three_workers()
    streams = [
        "lead",
        _finding_block("py.sqli", "CWE-89", "src/api/users.py", 12, "cursor.execute"),
        _finding_block("py.xss", "CWE-79", "src/web/render.py", 8, "render html"),
        _finding_block("py.path", "CWE-22", "src/files/dl.py", 5, "open join"),
        "no chains",
    ]
    h = await _build(tmp_path, streams=streams, workers=workers)
    result = await h.orch.run(h.scope)
    emitted = [e for e in result.events if isinstance(e, FindingEmitted)]
    assert len(emitted) == 3
