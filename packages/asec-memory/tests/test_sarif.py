"""Tests for SARIF v2.1 emission and the asec property bag."""

from __future__ import annotations

from asec_memory.models import AsecProperties, Finding, FindingLocation
from asec_memory.sarif import to_sarif_log, to_sarif_run


def _finding() -> Finding:
    return Finding(
        id="f-1",
        rule_id="py/ssrf",
        message="server-side request forgery",
        location=FindingLocation(uri="svc/fetch.py", start_line=10),
        asec=AsecProperties(priority=0.6),
    )


def test_sarif_log_version() -> None:
    log = to_sarif_log([_finding()])
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["results"][0]["ruleId"] == "py/ssrf"


def test_run_schema_version_in_property_bag() -> None:
    run = to_sarif_run([_finding()])
    assert run["properties"]["asec"]["schemaVersion"] == "asec.v1"
    assert run["results"][0]["properties"]["asec"]["schemaVersion"] == "asec.v1"


def test_result_tags_include_asec() -> None:
    run = to_sarif_run([_finding()])
    assert "asec" in run["results"][0]["properties"]["tags"]
