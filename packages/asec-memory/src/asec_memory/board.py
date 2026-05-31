"""Per-session hypothesis board: a minimal append-only JSONL writer (E9).

The board is the agent's scratch space for falsifiable claims during a single
review session. It is deliberately append-only — refutations and confirmations
are written as new lines, never edits — so the session reasoning trail is
reconstructable. Durable findings live in the :mod:`asec_memory.ledger` instead.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import structlog

from asec_memory.models import Hypothesis

log = structlog.get_logger(__name__)


class HypothesisBoard:
    """Append-only JSONL board backed by a single file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def append(self, hypothesis: Hypothesis) -> None:
        """Append one hypothesis as a JSON line."""
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(hypothesis.model_dump_json() + "\n")
        log.info("board.append", hypothesis_id=hypothesis.id, status=hypothesis.status)

    def read_all(self) -> list[Hypothesis]:
        """Materialize every hypothesis written so far, in append order."""
        return list(self._iter())

    def _iter(self) -> Iterator[Hypothesis]:
        if not self._path.exists():
            return
        with self._path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield Hypothesis.model_validate_json(line)
