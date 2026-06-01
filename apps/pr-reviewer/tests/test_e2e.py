"""CI-safe end-to-end test for the pr-reviewer loop (no network).

Injects a fake ``AgentRuntime`` whose ``query`` yields a canned tool-use stream plus a
final JSON block of three findings (mirroring the real Bedrock SDK message contract), then
drives the full ``load_target -> build_threat_model -> run_review -> score_and_store ->
report`` pipeline and asserts the substrate invariants.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from asec_sandbox.audit import verify_chain
from pr_reviewer.main import (
    build_threat_model,
    load_target,
    report,
    run_review,
    score_and_store,
)

# Repo root: this file is apps/pr-reviewer/tests/test_e2e.py
_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURE = _REPO_ROOT / "apps/pr-reviewer/fixtures/tiny-repo"

# --------------------------------------------------------------------------------------
# Minimal SARIF v2.1 shape validation (embedded; no network, no jsonschema fetch).
# --------------------------------------------------------------------------------------
_REQUIRED_LOG_KEYS = {"$schema", "version", "runs"}
_REQUIRED_RESULT_KEYS = {"ruleId", "level", "message", "locations"}


def _validate_sarif(sarif: dict[str, Any]) -> None:
    """Assert ``sarif`` conforms to the minimal SARIF v2.1 shape we emit."""
    assert set(sarif) >= _REQUIRED_LOG_KEYS, f"missing top-level keys: {sarif.keys()}"
    assert sarif["version"] == "2.1.0"
    runs: list[dict[str, Any]] = sarif["runs"]
    assert isinstance(runs, list) and runs, "runs must be a non-empty list"
    for run in runs:
        assert "tool" in run and "driver" in run["tool"], "run.tool.driver required"
        assert "name" in run["tool"]["driver"], "driver.name required"
        assert "results" in run, "run.results required"
        results: list[dict[str, Any]] = run["results"]
        for result in results:
            assert set(result) >= _REQUIRED_RESULT_KEYS, f"bad result keys: {list(result)}"
            message: dict[str, Any] = result["message"]
            assert isinstance(message.get("text"), str)
            loc: dict[str, Any] = result["locations"][0]["physicalLocation"]
            assert loc["artifactLocation"]["uri"]
            assert loc["region"]["startLine"] >= 1


def _fake_runtime(findings: list[dict[str, Any]]) -> Any:
    """A fake AgentRuntime mirroring the real SDK stream: tool_use msgs + final JSON."""

    class _FakeRuntime:
        def __init__(self) -> None:
            self.hooks: dict[str, list[Any]] = {}

        def register_hook(self, event: str, hook: Any) -> None:
            self.hooks.setdefault(event, []).append(hook)

        async def query(
            self, prompt: str, *, options: Any | None = None
        ) -> AsyncIterator[dict[str, Any]]:
            yield {"type": "tool_use", "name": "Grep", "input": {"pattern": "execute"}}
            yield {"type": "tool_use", "name": "Read", "input": {"file_path": "src/api/users.py"}}
            yield {"type": "result", "text": f"```json\n{json.dumps(findings)}\n```"}

        async def spawn_subagents(self, specs: Any) -> list[Any]:
            return []

    return _FakeRuntime()


_CANNED_FINDINGS = [
    {
        "rule_id": "CWE-89",
        "message": "SQL injection in /users.",
        "severity": "error",
        "cwe": "CWE-89",
        "uri": "src/api/users.py",
        "start_line": 17,
        "end_line": 18,
        "snippet": 'cursor.execute(f"...{name}...")',
    },
    {
        "rule_id": "CWE-79",
        "message": "Reflected XSS in /search.",
        "severity": "error",
        "cwe": "CWE-79",
        "uri": "src/web/render.py",
        "start_line": 13,
        "end_line": 13,
        "snippet": "return f\"<div>{request.args['q']}</div>\"",
    },
    {
        "rule_id": "CWE-22",
        "message": "Path traversal in /download.",
        "severity": "error",
        "cwe": "CWE-22",
        "uri": "src/files/download.py",
        "start_line": 18,
        "end_line": 20,
        "snippet": "path = os.path.join(BASE, requested)",
    },
]


async def _drive(work_dir: Path) -> tuple[Any, list[Any], Any, Path]:
    """Run the full pipeline against the fixture with the fake runtime."""
    corpus = load_target(_FIXTURE)
    tm = build_threat_model(corpus)
    runtime = _fake_runtime(_CANNED_FINDINGS)
    result, ledger = await run_review(corpus, tm, runtime=runtime, work_dir=work_dir)
    scored = await score_and_store(result, tm, ledger)
    await report(scored, tm, ledger, out_dir=work_dir)
    return result, scored, ledger, work_dir / "audit.jsonl"


async def test_threat_model_round_trips() -> None:
    corpus = load_target(_FIXTURE)
    tm = build_threat_model(corpus)
    assert tm.version == 1
    assert len(tm.assets) == 3
    assert len(tm.threats) == 3
    assert {t.element_id for t in tm.threats} == {
        "src/api/users.py",
        "src/web/render.py",
        "src/files/download.py",
    }


async def test_sarif_validates(tmp_path: Path) -> None:
    result, _scored, _ledger, _audit = await _drive(tmp_path)
    _validate_sarif(result.sarif)


async def test_at_least_three_findings(tmp_path: Path) -> None:
    result, scored, _ledger, _audit = await _drive(tmp_path)
    assert len(result.findings) >= 3
    assert len(scored) >= 3
    assert {f.rule_id for f in scored} >= {"CWE-89", "CWE-79", "CWE-22"}


async def test_worm_chain_is_clean(tmp_path: Path) -> None:
    _result, _scored, _ledger, audit_path = await _drive(tmp_path)
    entries = verify_chain(audit_path)  # raises on any tamper/broken link
    assert len(entries) >= 4


async def test_expected_event_types_fired(tmp_path: Path) -> None:
    result, _scored, _ledger, _audit = await _drive(tmp_path)
    fired = {e.event_type for e in result.events}
    assert {"phase_transition", "gate_decision", "finding_emitted", "run_complete"} <= fired


async def test_each_finding_has_full_asec_bag(tmp_path: Path) -> None:
    _result, scored, _ledger, _audit = await _drive(tmp_path)
    for f in scored:
        assert f.asec.reachability is not None
        assert 0.0 <= f.asec.confidence <= 1.0
        assert 0.0 <= f.asec.priority <= 1.0
        # The SARIF result property bag carries the same axes.
    sarif_run = _result_sarif(scored)
    for result in sarif_run["runs"][0]["results"]:
        asec = result["properties"]["asec"]
        assert "reachability" in asec
        assert "confidence" in asec
        assert "priority" in asec


def _result_sarif(scored: list[Any]) -> dict[str, Any]:
    from asec_memory.sarif import to_sarif_log

    return to_sarif_log(scored)


async def test_idempotent_rerun(tmp_path: Path) -> None:
    # First run.
    r1, s1, _l1, _a1 = await _drive(tmp_path)
    # Second run into the same work dir: findings are keyed deterministically, so the
    # ledger holds the same count (INSERT OR REPLACE), not duplicates.
    r2, s2, ledger2, _a2 = await _drive(tmp_path)
    assert len(r1.findings) == len(r2.findings)
    stored = list(await ledger2.list_findings())
    assert len(stored) == len(s2)
    assert {f.id for f in s1} == {f.id for f in s2}


async def test_reports_written(tmp_path: Path) -> None:
    _result, _scored, _ledger, _audit = await _drive(tmp_path)
    for name in ("REPORT_EXEC.md", "REPORT_ENG.md", "REPORT_AUDIT.md", "findings.sarif"):
        assert (tmp_path / name).is_file(), f"{name} not written"
