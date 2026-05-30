"""End-to-end wiring for the pr-reviewer proof app.

Five named functions read top-to-bottom (C's legibility), mirroring the review loop:

    load_target -> build_threat_model -> run_review -> score_and_store -> report

This file is the wiring shell only; each stage raises NotImplementedError until the
Day-3 milestone wires it to the real asec-* packages. The app holds no logic of its own
beyond this orchestration. NOT production-grade.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import cyclopts

app = cyclopts.App(name="pr-reviewer", help="Agentic security review over a tiny corpus.")


def load_target(target: Path) -> Any:
    """Stage 1 — load the review target (the tiny-repo fixture / diff)."""
    # TODO(day-3): read the 3-file corpus + diff from `target`.
    raise NotImplementedError("load_target: wire to the fixture loader (day 3)")


def build_threat_model(target: Any) -> Any:
    """Stage 2 — load the hand-written `threat-model.yaml` fixture (asec-threat-model)."""
    # TODO(day-3): asec_threat_model.load(target / "threat-model.yaml").
    raise NotImplementedError("build_threat_model: wire to asec-threat-model (day 3)")


def run_review(target: Any, threat_model: Any) -> Any:
    """Stage 3 — run the review loop: SKILL.md -> Orchestrator -> Bedrock Opus 4.8."""
    # TODO(day-3): asec_skills load + gate, asec_core.Orchestrator.run(scope).
    raise NotImplementedError("run_review: wire to asec-skills + asec-core (day 3)")


def score_and_store(findings: Any) -> Any:
    """Stage 4 — score findings (asec-confidence) and persist them (asec-memory)."""
    # TODO(day-3): asec_confidence scorer + asec_memory SQLite ledger + WORM append.
    raise NotImplementedError("score_and_store: wire to asec-confidence + asec-memory (day 3)")


def report(scored: Any) -> Any:
    """Stage 5 — emit SARIF + an Engineering Report Agent markdown summary with PASS/FAIL."""
    # TODO(day-3): asec_memory.to_sarif(...) + ReportAgent (Engineering) summary.
    raise NotImplementedError("report: wire to asec-memory.to_sarif + ReportAgent (day 3)")


@app.command
def review(target: str = "fixtures/tiny-repo") -> None:
    """Run the end-to-end review over `target` (defaults to the committed fixture)."""
    path = Path(target)
    loaded = load_target(path)
    threat_model = build_threat_model(loaded)
    findings = run_review(loaded, threat_model)
    scored = score_and_store(findings)
    report(scored)


if __name__ == "__main__":
    app()
