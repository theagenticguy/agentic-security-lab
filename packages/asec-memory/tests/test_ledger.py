"""Async tests for the SQLite-backed findings ledger."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from asec_memory.ledger import SQLiteLedger
from asec_memory.models import (
    AsecProperties,
    Finding,
    FindingLocation,
    Suppression,
)


def _finding(fid: str, priority: float) -> Finding:
    return Finding(
        id=fid,
        rule_id="py/xss",
        message="reflected XSS",
        location=FindingLocation(uri=f"web/{fid}.py", start_line=1),
        asec=AsecProperties(priority=priority),
    )


async def _ledger(tmp_path: Path) -> SQLiteLedger:
    return await SQLiteLedger(str(tmp_path / "ledger.db")).init()


@pytest.mark.asyncio
async def test_add_and_get_finding(tmp_path: Path) -> None:
    ledger = await _ledger(tmp_path)
    finding = _finding("f-1", 0.9)
    await ledger.add_finding(finding)
    fetched = await ledger.get_finding("f-1")
    assert fetched == finding
    assert await ledger.get_finding("missing") is None


@pytest.mark.asyncio
async def test_list_findings_filters_by_priority(tmp_path: Path) -> None:
    ledger = await _ledger(tmp_path)
    await ledger.add_finding(_finding("low", 0.2))
    await ledger.add_finding(_finding("mid", 0.5))
    await ledger.add_finding(_finding("high", 0.95))
    ranked = await ledger.list_findings(min_priority=0.5)
    ids = [f.id for f in ranked]
    assert ids == ["high", "mid"]  # priority>=0.5, sorted descending


@pytest.mark.asyncio
async def test_suppression_dedup(tmp_path: Path) -> None:
    ledger = await _ledger(tmp_path)
    finding = _finding("f-1", 0.9)
    s1 = Suppression(
        id="s-1", rule_id="py/xss", location_uri="web/f-1.py", reason="test fixture"
    )
    s2 = Suppression(
        id="s-2", rule_id="py/xss", location_uri="web/f-1.py", reason="duplicate"
    )
    await ledger.add_suppression(s1)
    await ledger.add_suppression(s2)  # same (rule, uri) -> dedup_key collision
    similar = await ledger.find_similar(finding)
    assert len(similar) == 1


@pytest.mark.asyncio
async def test_concurrent_writes(tmp_path: Path) -> None:
    ledger = await _ledger(tmp_path)
    findings = [_finding(f"f-{i}", 0.5 + i / 100) for i in range(20)]
    await asyncio.gather(*(ledger.add_finding(f) for f in findings))
    stored = await ledger.list_findings()
    assert len(stored) == 20
    assert {f.id for f in stored} == {f.id for f in findings}
