"""CI-safe dry-run of the variant-hunter loop (no network, no real git history).

Injects a fake ``AgentRuntime`` whose ``query`` echoes the ``variants_of`` seed id from
the prompt (mirroring the real Bedrock SDK message contract), drives the full
``git_log_patches -> seed -> expand -> aggregate -> report`` pipeline over the committed
fixture diff + tiny repo, and asserts variants come back tagged with the seed finding id
and that ``--max-budget-usd`` is respected.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from asec_sandbox.audit import verify_chain
from nightly_variant_hunter.main import (
    git_log_patches,
    parse_patches,
    run_hunt,
    seed_id_from_prompt,
)

# Repo root: this file is apps/nightly-variant-hunter/tests/test_variant.py
_REPO_ROOT = Path(__file__).resolve().parents[3]
_APP = _REPO_ROOT / "apps/nightly-variant-hunter"
_FIXTURE_DIFF = _APP / "fixtures/sample-diff.txt"
_TINY_REPO = _APP / "fixtures/tiny-repo"


def _fake_runtime() -> Any:
    """Fake AgentRuntime: tool_use msgs + a final JSON block echoing the prompt seed id."""

    class _FakeRuntime:
        def __init__(self) -> None:
            self.hooks: dict[str, list[Any]] = {}

        def register_hook(self, event: str, hook: Any) -> None:
            self.hooks.setdefault(event, []).append(hook)

        async def query(
            self, prompt: str, *, options: Any | None = None
        ) -> AsyncIterator[dict[str, Any]]:
            yield {"type": "tool_use", "name": "Grep", "input": {"pattern": "execute"}}
            seed_id = seed_id_from_prompt(prompt)
            findings = [
                {
                    "rule_id": "CWE-89",
                    "message": "SQL injection variant: same execute() shape as the seed.",
                    "severity": "error",
                    "cwe": "CWE-89",
                    "uri": "src/api/orders.py",
                    "start_line": 6,
                    "end_line": 6,
                    "snippet": 'cursor.execute(f"SELECT * FROM orders WHERE id = {oid}")',
                    "variants_of": seed_id,
                }
            ]
            yield {"type": "result", "text": f"```json\n{json.dumps(findings)}\n```"}

        async def spawn_subagents(self, specs: Any) -> list[Any]:
            return []

    return _FakeRuntime()


def test_parse_patches_extracts_shape() -> None:
    raw = _FIXTURE_DIFF.read_text(encoding="utf-8")
    patches = parse_patches(raw)
    assert len(patches) == 1
    patch = patches[0]
    assert patch.uri == "src/api/users.py"
    assert any("SELECT * FROM users" in line for line in patch.removed)
    assert "SELECT * FROM users" in patch.shape


def test_git_log_patches_falls_back_to_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    # Point cwd at the repo root so the relative fixture path resolves, and pass a
    # non-git dir so the subprocess returns None and the fixture fallback kicks in.
    monkeypatch.chdir(_REPO_ROOT)
    patches = git_log_patches(str(_TINY_REPO), "30 days ago")
    assert patches and patches[0].uri == "src/api/users.py"


async def test_variants_tagged_with_seed_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(_REPO_ROOT)
    result = await run_hunt(
        str(_TINY_REPO),
        "30 days ago",
        max_budget_usd=5.0,
        out_dir=tmp_path,
        runtime=_fake_runtime(),
    )
    assert result.seeds, "expected at least one seed shape"
    assert result.variants, "expected at least one variant"
    seed_ids = {s.id for s in result.seeds}
    for variant in result.variants:
        assert variant.asec.variants_of in seed_ids, "variant not linked to a seed"
    # The linkage survives into the SARIF property bag.
    for sarif_result in result.sarif["runs"][0]["results"]:
        assert sarif_result["properties"]["asec"]["variants_of"] in seed_ids


async def test_budget_cap_halts_the_hunt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(_REPO_ROOT)
    # A cap below the per-call estimate denies the very first agent call (E19 hard stop).
    result = await run_hunt(
        str(_TINY_REPO),
        "30 days ago",
        max_budget_usd=0.10,
        out_dir=tmp_path,
        runtime=_fake_runtime(),
    )
    assert result.budget_exhausted is True
    assert result.spent_usd <= 0.10
    assert result.variants == ()


async def test_worm_chain_is_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(_REPO_ROOT)
    await run_hunt(
        str(_TINY_REPO),
        "30 days ago",
        max_budget_usd=5.0,
        out_dir=tmp_path,
        runtime=_fake_runtime(),
    )
    entries = verify_chain(tmp_path / "audit.jsonl")  # raises on tamper/broken link
    assert len(entries) >= 1


async def test_reports_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(_REPO_ROOT)
    await run_hunt(
        str(_TINY_REPO),
        "30 days ago",
        max_budget_usd=5.0,
        out_dir=tmp_path,
        runtime=_fake_runtime(),
    )
    for name in ("REPORT_EXEC.md", "REPORT_ENG.md", "REPORT_AUDIT.md", "variants.sarif"):
        assert (tmp_path / name).is_file(), f"{name} not written"
