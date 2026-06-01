"""Live end-to-end test against real Bedrock Opus 4.8.

Skipped unless ``RUN_LIVE_BEDROCK=1`` and marked ``@pytest.mark.live`` so the default CI
addopts (`-m "not live"`) never select it. Engineers run::

    RUN_LIVE_BEDROCK=1 uv run pytest apps/pr-reviewer -m live

This is the contract check that keeps the CI mock from drifting off the real SDK stream.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from asec_core.runtime import ClaudeAgentRuntime
from asec_core.settings import Settings
from pr_reviewer.main import build_threat_model, load_target, run_review, score_and_store

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURE = _REPO_ROOT / "apps/pr-reviewer/fixtures/tiny-repo"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("RUN_LIVE_BEDROCK") != "1",
        reason="live Bedrock test: set RUN_LIVE_BEDROCK=1 to run",
    ),
]


async def test_live_bedrock_finds_at_least_one(tmp_path: Path) -> None:
    corpus = load_target(_FIXTURE)
    tm = build_threat_model(corpus)
    # Real adapter. TODO(integration): once day3/orchestrator lands, the real
    # ClaudeAgentRuntime.query streams Bedrock messages and run_review drives the real
    # Orchestrator; until then this exercises the same injection seam.
    runtime = ClaudeAgentRuntime(Settings())
    result, ledger = await run_review(corpus, tm, runtime=runtime, work_dir=tmp_path)
    scored = await score_and_store(result, tm, ledger)
    assert len(scored) >= 1, "live Bedrock run should surface at least one finding"
