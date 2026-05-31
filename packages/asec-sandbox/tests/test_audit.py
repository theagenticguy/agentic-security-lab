from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from asec_sandbox.audit import GENESIS, WormAuditWriter, canonical_json, verify_chain


async def test_write_three_and_verify(tmp_path: Path) -> None:
    w = WormAuditWriter(tmp_path / "audit.jsonl", session="s1")
    await w.append(actor="agent", action="a", payload={"i": 1})
    await w.append(actor="agent", action="b", payload={"i": 2})
    await w.append(actor="agent", action="c", payload={"i": 3})
    entries = verify_chain(w.path)
    assert [e["seq"] for e in entries] == [0, 1, 2]
    assert [e["action"] for e in entries] == ["a", "b", "c"]


async def test_first_entry_is_genesis(tmp_path: Path) -> None:
    w = WormAuditWriter(tmp_path / "audit.jsonl")
    await w.append(actor="agent", action="first")
    entries = verify_chain(w.path)
    assert entries[0]["prev_hash"] == GENESIS


async def test_tampering_payload_fails_verify(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    w = WormAuditWriter(path)
    await w.append(actor="agent", action="a", payload={"v": 1})
    await w.append(actor="agent", action="b", payload={"v": 2})
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["payload"] = {"v": 999}  # tamper without recomputing hash
    lines[0] = canonical_json(first)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="tampered"):
        verify_chain(path)


def test_canonical_json_is_deterministic() -> None:
    a = canonical_json({"b": 1, "a": 2, "c": {"z": 1, "y": 2}})
    b = canonical_json({"c": {"y": 2, "z": 1}, "a": 2, "b": 1})
    assert a == b
    assert a == '{"a":2,"b":1,"c":{"y":2,"z":1}}'


async def test_concurrent_appends_serialize(tmp_path: Path) -> None:
    w = WormAuditWriter(tmp_path / "audit.jsonl")
    await asyncio.gather(*(w.append(actor="agent", action=f"a{i}") for i in range(20)))
    entries = verify_chain(w.path)
    assert len(entries) == 20
    assert [e["seq"] for e in entries] == list(range(20))


async def test_path_created_if_missing(tmp_path: Path) -> None:
    nested = tmp_path / "deep" / "nested" / "audit.jsonl"
    assert not nested.parent.exists()
    w = WormAuditWriter(nested)
    assert nested.parent.exists()
    await w.append(actor="agent", action="a")
    assert nested.exists()


def test_verify_empty_missing_file(tmp_path: Path) -> None:
    assert verify_chain(tmp_path / "nope.jsonl") == []
