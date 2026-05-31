"""Kill switch for halting an in-flight review (E19).

A `KillSwitch` is a thread-safe, async-awaitable abort flag. The orchestrator checks
`triggered` before each tool call and may `await wait()` to block until a stop is
requested. `FileKillSwitch` additionally trips when a sentinel file appears on disk, so
an operator can halt a long-running review out-of-band.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path


class KillSwitch:
    """Thread-safe in-memory abort flag with an async `wait()` (E19)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._triggered = False
        self._reason: str | None = None
        self._event = asyncio.Event()

    @property
    def triggered(self) -> bool:
        """E19 — true once the switch has been tripped."""
        with self._lock:
            return self._triggered

    @property
    def reason(self) -> str | None:
        """Operator-supplied reason for the abort, if any."""
        with self._lock:
            return self._reason

    def trigger(self, reason: str | None = None) -> None:
        """E19 — trip the switch; idempotent. Wakes any awaiter of `wait()`."""
        with self._lock:
            self._triggered = True
            self._reason = reason
        self._event.set()

    async def wait(self) -> None:
        """E19 — block until the switch is tripped."""
        if self.triggered:
            return
        await self._event.wait()


class FileKillSwitch(KillSwitch):
    """`KillSwitch` that also trips when a sentinel file exists at `path` (E19)."""

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self._path = Path(path)
        if self._path.exists():
            reason = self._read_reason()
            self.trigger(reason)

    def _read_reason(self) -> str | None:
        try:
            text = self._path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return text or None

    @property
    def triggered(self) -> bool:
        """E19 — true if tripped in-memory or the sentinel file now exists."""
        if not super().triggered and self._path.exists():
            self.trigger(self._read_reason())
        return super().triggered
