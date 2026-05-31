"""SARIF v2.1.0 emission with the ``asec.v1`` property bag.

We emit plain dicts that conform to the SARIF v2.1 schema directly rather than
depending on a SARIF library — the substrate owns its output contract (ADR-0006).
Every result carries ``properties.asec`` (the validated :class:`AsecProperties`)
and a ``tags`` array that duplicates the reachability verdict, asset weight, and a
bare ``asec`` marker so SARIF-only consumers can filter without parsing the bag.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from asec_memory.models import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "agentic-security-lab"
TOOL_VERSION = "0.1.0"


def _result_tags(finding: Finding) -> list[str]:
    return [
        f"reachability:{finding.asec.reachability.verdict.value}",
        f"asset:{finding.asec.asset.tier.value}",
        "asec",
    ]


def _to_result(finding: Finding) -> dict[str, Any]:
    asec_bag = finding.asec.model_dump(mode="json")
    loc: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.location.uri},
            "region": {"startLine": finding.location.start_line},
        }
    }
    region = loc["physicalLocation"]["region"]
    if finding.location.end_line is not None:
        region["endLine"] = finding.location.end_line
    if finding.location.snippet is not None:
        region["snippet"] = {"text": finding.location.snippet}

    return {
        "ruleId": finding.rule_id,
        "level": finding.severity,
        "message": {"text": finding.message},
        "locations": [loc],
        "properties": {
            "asec": asec_bag,
            "tags": _result_tags(finding),
        },
    }


def to_sarif_run(findings: Sequence[Finding]) -> dict[str, Any]:
    """Build a single SARIF ``run`` dict with the ``asec.v1`` property bag."""
    rule_ids = sorted({f.rule_id for f in findings})
    return {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/agentic-security-lab",
                "rules": [{"id": rid} for rid in rule_ids],
            }
        },
        "results": [_to_result(f) for f in findings],
        "properties": {"asec": {"schemaVersion": "asec.v1"}},
    }


def to_sarif_log(findings: Sequence[Finding]) -> dict[str, Any]:
    """Build the full SARIF v2.1 log envelope wrapping one :func:`to_sarif_run`."""
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [to_sarif_run(findings)],
    }
