"""Findings ledger: ``LedgerPort`` protocol + an ``aiosqlite`` implementation.

The default :class:`SQLiteLedger` keeps the durable findings, the per-session
hypotheses, and the false-positive suppression memory in one versioned SQLite
file. Typed payloads are stored as JSON blobs and rehydrated through Pydantic so
the on-disk schema stays narrow while the in-memory contract stays rich (E10/E11).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

import aiosqlite
import structlog
from opentelemetry import trace

from asec_memory.models import Finding, Hypothesis, Suppression

log = structlog.get_logger(__name__)
tracer = trace.get_tracer(__name__)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    priority    REAL NOT NULL,
    created_at  TEXT NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(priority);

CREATE TABLE IF NOT EXISTS hypotheses (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_finding ON hypotheses(finding_id);

CREATE TABLE IF NOT EXISTS suppressions (
    dedup_key   TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    location_uri TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_suppressions_rule ON suppressions(rule_id);
"""


@runtime_checkable
class LedgerPort(Protocol):
    """Durable findings ledger + FP-suppression memory (E10, E11)."""

    async def add_finding(self, finding: Finding) -> None:
        """E10 — persist a finding (idempotent on ``finding.id``)."""
        ...

    async def get_finding(self, finding_id: str) -> Finding | None:
        """E10 — read back a single finding by id, or ``None``."""
        ...

    async def list_findings(self, *, min_priority: float = 0.0) -> Sequence[Finding]:
        """E10 — read findings with ``asec.priority >= min_priority``, highest first."""
        ...

    async def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        """E9 — persist a hypothesis."""
        ...

    async def add_suppression(self, suppression: Suppression) -> None:
        """E11 — record a false-positive suppression (deduplicated)."""
        ...

    async def find_similar(self, finding: Finding) -> Sequence[Suppression]:
        """E11 — return suppressions matching this finding's (rule, location)."""
        ...


class SQLiteLedger(LedgerPort):
    """``aiosqlite``-backed :class:`LedgerPort`. Call :meth:`init` before use."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    async def init(self) -> SQLiteLedger:
        """Create the schema and stamp the version. Safe to call repeatedly."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(_SCHEMA)
            async with db.execute("SELECT version FROM schema_meta LIMIT 1") as cur:
                row = await cur.fetchone()
            if row is None:
                await db.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
            await db.commit()
        log.info("ledger.init", db_path=self._db_path, schema_version=SCHEMA_VERSION)
        return self

    async def add_finding(self, finding: Finding) -> None:
        with tracer.start_as_current_span("ledger.add_finding"):
            async with aiosqlite.connect(self._db_path) as db:
                await db.execute(
                    "INSERT OR REPLACE INTO findings"
                    "(id, rule_id, priority, created_at, payload) VALUES (?, ?, ?, ?, ?)",
                    (
                        finding.id,
                        finding.rule_id,
                        finding.asec.priority,
                        finding.created_at.isoformat(),
                        finding.model_dump_json(),
                    ),
                )
                await db.commit()

    async def get_finding(self, finding_id: str) -> Finding | None:
        async with (
            aiosqlite.connect(self._db_path) as db,
            db.execute("SELECT payload FROM findings WHERE id = ?", (finding_id,)) as cur,
        ):
            row = await cur.fetchone()
        if row is None:
            return None
        return Finding.model_validate_json(row[0])

    async def list_findings(self, *, min_priority: float = 0.0) -> Sequence[Finding]:
        with tracer.start_as_current_span("ledger.list_findings"):
            async with aiosqlite.connect(self._db_path) as db:
                async with db.execute(
                    "SELECT payload FROM findings WHERE priority >= ? "
                    "ORDER BY priority DESC, created_at ASC",
                    (min_priority,),
                ) as cur:
                    rows = await cur.fetchall()
        return [Finding.model_validate_json(r[0]) for r in rows]

    async def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO hypotheses"
                "(id, finding_id, status, created_at, payload) VALUES (?, ?, ?, ?, ?)",
                (
                    hypothesis.id,
                    hypothesis.finding_id,
                    hypothesis.status,
                    hypothesis.created_at.isoformat(),
                    hypothesis.model_dump_json(),
                ),
            )
            await db.commit()

    async def add_suppression(self, suppression: Suppression) -> None:
        with tracer.start_as_current_span("ledger.add_suppression"):
            async with aiosqlite.connect(self._db_path) as db:
                await db.execute(
                    "INSERT OR REPLACE INTO suppressions"
                    "(dedup_key, rule_id, location_uri, created_at, payload) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        suppression.dedup_key,
                        suppression.rule_id,
                        suppression.location_uri,
                        suppression.created_at.isoformat(),
                        suppression.model_dump_json(),
                    ),
                )
                await db.commit()

    async def find_similar(self, finding: Finding) -> Sequence[Suppression]:
        async with (
            aiosqlite.connect(self._db_path) as db,
            db.execute(
                "SELECT payload FROM suppressions WHERE rule_id = ? AND location_uri = ?",
                (finding.rule_id, finding.location.uri),
            ) as cur,
        ):
            rows = await cur.fetchall()
        return [Suppression.model_validate_json(r[0]) for r in rows]
