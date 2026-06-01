"""Tests for the deterministic ReportAgentImpl (Executive/Engineering/Auditor)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from asec_memory.ledger import SQLiteLedger
from asec_memory.models import (
    AsecProperties,
    AssetWeight,
    AssetWeightTier,
    Exploitability,
    Finding,
    FindingLocation,
    Reachability,
    ReachabilityVerdict,
)
from asec_memory.report import ReportAgentImpl
from asec_threat_model.models import Asset, Threat, ThreatModel

_MODEL_ID = "global.anthropic.claude-opus-4-8"
_SKILL = "security-code-review"


def _finding(
    fid: str,
    *,
    severity: str = "error",
    priority: float = 0.0,
    reach: float = 1.0,
    exploit: float = 1.0,
    asset_score: float = 1.0,
    asset_id: str | None = None,
    cwe: str | None = "CWE-89",
    snippet: str | None = "cursor.execute(query)",
) -> Finding:
    return Finding(
        id=fid,
        rule_id="py/sql-injection",
        message=f"injection in {fid}",
        severity=severity,  # type: ignore[arg-type]
        cwe=cwe,
        location=FindingLocation(uri=f"src/{fid}.py", start_line=10, snippet=snippet),
        asec=AsecProperties(
            reachability=Reachability(verdict=ReachabilityVerdict.REACHABLE, score=reach),
            exploitability=Exploitability(score=exploit),
            asset=AssetWeight(tier=AssetWeightTier.HIGH, score=asset_score, asset_id=asset_id),
            priority=priority,
        ),
    )


async def _ledger_with_5(tmp_path: Path) -> SQLiteLedger:
    ledger = await SQLiteLedger(str(tmp_path / "ledger.db")).init()
    findings = [
        _finding("f1", severity="error", priority=0.9, asset_id="a1"),
        _finding("f2", severity="error", priority=0.7, asset_id="a1"),
        _finding("f3", severity="warning", priority=0.5, asset_id="a2"),
        _finding("f4", severity="note", priority=0.3),
        _finding("f5", severity="warning", priority=0.1),
    ]
    for f in findings:
        await ledger.add_finding(f)
    return ledger


def _threat_model() -> ThreatModel:
    return ThreatModel(
        version=1,
        generated_by="test",
        generated_at=datetime(2026, 6, 1, tzinfo=UTC),
        assets=(
            Asset.model_validate(
                {"id": "a1", "class": "PII", "weight": "HIGH", "description": "user table"}
            ),
            Asset.model_validate(
                {"id": "a2", "class": "SECRET", "weight": "MED", "description": "api keys"}
            ),
        ),
        threats=(
            Threat(
                id="t1",
                element_id="a1",
                stride="I",
                description="sql injection",
                likelihood="HIGH",
                impact="HIGH",
            ),
        ),
    )


async def test_priority_is_product_of_axes(tmp_path: Path) -> None:
    # When asec.priority is 0, the report computes reach*exploit*asset = 0.1.
    ledger = await SQLiteLedger(str(tmp_path / "p.db")).init()
    await ledger.add_finding(
        _finding("computed", priority=0.0, reach=0.5, exploit=0.4, asset_score=0.5)
    )
    # When persisted, priority wins over the (tiny) product.
    await ledger.add_finding(
        _finding("persisted", priority=0.8, reach=0.1, exploit=0.1, asset_score=0.1)
    )
    out = tmp_path / "reports"
    paths = await ReportAgentImpl(ledger, None, out).generate()
    text = paths["exec"].read_text(encoding="utf-8")
    assert "0.100" in text  # computed product
    assert "0.800" in text  # persisted priority
    # persisted (0.8) outranks computed (0.1)
    assert text.index("persisted") < text.index("computed")


async def test_generate_returns_three_nonempty_files(tmp_path: Path) -> None:
    ledger = await _ledger_with_5(tmp_path)
    out = tmp_path / "reports"
    paths = await ReportAgentImpl(ledger, _threat_model(), out).generate()
    assert set(paths) == {"exec", "engineering", "audit"}
    for p in paths.values():
        assert p.exists()
        assert p.read_text(encoding="utf-8").strip()


async def test_exec_lists_top5_in_priority_order(tmp_path: Path) -> None:
    ledger = await _ledger_with_5(tmp_path)
    out = tmp_path / "reports"
    paths = await ReportAgentImpl(ledger, _threat_model(), out).generate()
    text = paths["exec"].read_text(encoding="utf-8")
    positions = [text.index(fid) for fid in ("f1", "f2", "f3", "f4", "f5")]
    assert positions == sorted(positions)


async def test_eng_has_high_and_deferred_sections(tmp_path: Path) -> None:
    ledger = await _ledger_with_5(tmp_path)
    out = tmp_path / "reports"
    paths = await ReportAgentImpl(ledger, _threat_model(), out).generate()
    text = paths["engineering"].read_text(encoding="utf-8")
    assert "## High severity" in text
    assert "## Deferred" in text
    # error findings appear as cards; a note/warning appears under deferred
    assert "### f1" in text
    high_idx = text.index("## High severity")
    deferred_idx = text.index("## Deferred")
    assert text.index("f4", deferred_idx) > deferred_idx
    assert high_idx < deferred_idx


async def test_audit_mentions_model_and_skill(tmp_path: Path) -> None:
    ledger = await _ledger_with_5(tmp_path)
    out = tmp_path / "reports"
    paths = await ReportAgentImpl(
        ledger,
        _threat_model(),
        out,
        worm_head_range=("aaaa", "ffff"),
    ).generate()
    text = paths["audit"].read_text(encoding="utf-8")
    assert _MODEL_ID in text
    assert _SKILL in text
    assert "aaaa" in text and "ffff" in text
    # coverage table: a1 has a finding -> covered yes; a2 too (f3)
    assert "a1" in text and "a2" in text


async def test_idempotent_byte_identical(tmp_path: Path) -> None:
    ledger = await _ledger_with_5(tmp_path)
    out = tmp_path / "reports"
    agent = ReportAgentImpl(ledger, _threat_model(), out)
    first = {k: v.read_bytes() for k, v in (await agent.generate()).items()}
    second = {k: v.read_bytes() for k, v in (await agent.generate()).items()}
    assert first == second


async def test_empty_ledger_writes_zero_finding_reports(tmp_path: Path) -> None:
    ledger = await SQLiteLedger(str(tmp_path / "empty.db")).init()
    out = tmp_path / "reports"
    paths = await ReportAgentImpl(ledger, None, out).generate()
    assert len(paths) == 3
    exec_text = paths["exec"].read_text(encoding="utf-8")
    eng_text = paths["engineering"].read_text(encoding="utf-8")
    audit_text = paths["audit"].read_text(encoding="utf-8")
    assert "No findings" in exec_text
    assert "_No high-severity findings._" in eng_text
    assert "Findings:** 0" in audit_text
