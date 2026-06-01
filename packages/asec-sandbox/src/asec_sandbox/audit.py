"""WormAuditWriter — append-only, hash-chained JSON Lines audit log (E12, E13).

Each line is a JSON object with fields::

    {ts, seq, session, actor, action, payload, prev_hash, hash}

The chain is tamper-evident: ``hash = sha256(canonical_json(line_without_hash))`` and
each line carries the previous line's ``hash`` as its ``prev_hash``. The first line
uses the sentinel ``prev_hash="GENESIS"``. The canonicalization conforms to a subset
of RFC 8785 (JSON Canonicalization Scheme); see ``canonical_json`` and ADR-005 for the
two known deviations. The file is opened in append mode only; writes serialize through
an ``asyncio.Lock`` so concurrent ``append`` calls cannot interleave the chain.

``verify_chain(path)`` re-walks the file, recomputes each line's hash, and checks that
the ``prev_hash`` linkage is intact, returning the parsed entries on success.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

GENESIS = "GENESIS"


def canonical_json(obj: dict[str, Any]) -> str:
    """Serialize ``obj`` to a canonical JSON form for hashing (sorted keys, no whitespace).

    Conforms to a subset of RFC 8785 (the JSON Canonicalization Scheme). Two
    documented deviations: number formatting falls back to Python's default
    (RFC 8785 §3.2 mandates the I-JSON / ES6 algorithm — fine for integers,
    not bit-for-bit guaranteed for edge-case floats; the audit log carries
    no float fields today), and ``ensure_ascii=False`` emits literal UTF-8
    above U+007F rather than ``\\u`` escapes (legal JSON, byte-different from
    a strict JCS encoder). See ADR-005 §Decision for the full rationale.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_line(line: dict[str, Any]) -> str:
    """Compute ``sha256`` over the canonical JSON of ``line`` excluding its ``hash`` field."""
    unhashed = {k: v for k, v in line.items() if k != "hash"}
    digest = hashlib.sha256(canonical_json(unhashed).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class WormAuditWriter:
    """Append-only hash-chained audit writer backed by a JSONL file."""

    def __init__(self, path: str | Path, *, session: str = "default") -> None:
        self._path = Path(path)
        self._session = session
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def _last_hash(self) -> str:
        """Read the chain head hash from disk (sentinel ``GENESIS`` if empty/missing)."""
        if not self._path.exists():
            return GENESIS
        last = GENESIS
        with self._path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if raw:
                    last = json.loads(raw)["hash"]
        return last

    async def append(
        self,
        *,
        actor: str,
        action: str,
        payload: dict[str, Any] | None = None,
        session: str | None = None,
    ) -> str:
        """Append one tamper-evident entry; return its ``hash`` (the new chain head)."""
        async with self._lock:
            prev_hash = self._last_hash()
            seq = self._next_seq()
            line: dict[str, Any] = {
                "ts": datetime.now(UTC).isoformat(),
                "seq": seq,
                "session": session or self._session,
                "actor": actor,
                "action": action,
                "payload": payload or {},
                "prev_hash": prev_hash,
            }
            line["hash"] = _hash_line(line)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(canonical_json(line) + "\n")
            logger.debug("worm.append", seq=seq, action=action, hash=line["hash"])
            return line["hash"]

    def _next_seq(self) -> int:
        if not self._path.exists():
            return 0
        count = 0
        with self._path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                if raw.strip():
                    count += 1
        return count


def verify_chain(path: str | Path) -> list[dict[str, Any]]:
    """Re-walk ``path``; raise ``ValueError`` on any broken link or tampered hash.

    Returns the parsed entries in order on success.
    """
    p = Path(path)
    entries: list[dict[str, Any]] = []
    expected_prev = GENESIS
    expected_seq = 0
    if not p.exists():
        return entries
    with p.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh):
            raw = raw.strip()
            if not raw:
                continue
            line: dict[str, Any] = json.loads(raw)
            if line.get("prev_hash") != expected_prev:
                msg = f"broken chain at line {lineno}: prev_hash mismatch"
                raise ValueError(msg)
            recomputed = _hash_line(line)
            if recomputed != line.get("hash"):
                msg = f"tampered entry at line {lineno}: hash mismatch (seq={line.get('seq')})"
                raise ValueError(msg)
            if line.get("seq") != expected_seq:
                msg = f"out-of-order entry at line {lineno}: expected seq {expected_seq}"
                raise ValueError(msg)
            entries.append(line)
            expected_prev = line["hash"]
            expected_seq += 1
    return entries
