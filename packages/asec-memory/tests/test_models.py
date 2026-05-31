"""Unit tests for the Pydantic models and their SARIF round-trip."""

from __future__ import annotations

import pytest
from asec_memory.models import (
    ASEC_SCHEMA_VERSION,
    AsecProperties,
    AssetWeight,
    AssetWeightTier,
    Exploitability,
    Finding,
    FindingLocation,
    Reachability,
    ReachabilityVerdict,
)
from asec_memory.sarif import to_sarif_run
from pydantic import ValidationError


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "id": "f-1",
        "rule_id": "py/sql-injection",
        "message": "Tainted input reaches a SQL sink.",
        "severity": "error",
        "cwe": "CWE-89",
        "location": FindingLocation(uri="app/db.py", start_line=42, end_line=44),
        "asec": AsecProperties(
            reachability=Reachability(verdict=ReachabilityVerdict.REACHABLE, score=0.9),
            exploitability=Exploitability(score=0.7),
            asset=AssetWeight(tier=AssetWeightTier.CRITICAL, score=1.0),
            priority=0.84,
            confidence=0.8,
        ),
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


def test_finding_round_trip_via_sarif() -> None:
    finding = _finding()
    run = to_sarif_run([finding])
    result = run["results"][0]
    reparsed = AsecProperties.model_validate(result["properties"]["asec"])
    assert reparsed == finding.asec
    assert result["ruleId"] == "py/sql-injection"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 42


def test_asec_properties_schema_version() -> None:
    props = AsecProperties()
    assert props.schemaVersion == ASEC_SCHEMA_VERSION == "asec.v1"
    with pytest.raises(ValidationError):
        AsecProperties.model_validate({"schemaVersion": "asec.v2"})


def test_sarif_tags_include_expected_duplicates() -> None:
    run = to_sarif_run([_finding()])
    tags = run["results"][0]["properties"]["tags"]
    assert "asec" in tags
    assert "reachability:reachable" in tags
    assert "asset:critical" in tags


def test_scores_clamp_to_unit_interval() -> None:
    with pytest.raises(ValidationError):
        Reachability(score=1.5)
    with pytest.raises(ValidationError):
        Exploitability(score=-0.1)
    with pytest.raises(ValidationError):
        AsecProperties(priority=2.0)


def test_unknown_asec_field_is_refused() -> None:
    with pytest.raises(ValidationError):
        AsecProperties.model_validate({"bogus": 1})


def test_models_are_frozen() -> None:
    finding = _finding()
    with pytest.raises(ValidationError):
        finding.message = "mutated"  # type: ignore[misc]
    assert finding.priority == finding.asec.priority == 0.84
