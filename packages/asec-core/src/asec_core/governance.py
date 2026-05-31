"""Pre-tool-call governance gate (E16, E19).

`GovernanceGate` is the deterministic policy choke point the orchestrator consults
before every tool call. It enforces three invariants in order: the scope artifact must
be valid (signed and unexpired), the kill switch must not be tripped, and cumulative
spend must stay under the budget cap. The decision shape mirrors the SDK's PreToolUse
hook output so the gate can be wired directly as a hook.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal, TypedDict

import structlog

from .killswitch import KillSwitch
from .scope import ScopeArtifact, verify_scope

_log = structlog.get_logger(__name__)


class Decision(TypedDict):
    """PreToolUse-shaped allow/deny decision (E16)."""

    decision: Literal["allow", "deny"]
    reason: str


class GovernanceGate:
    """Wires scope validity, kill switch, and budget cap into one decision (E19)."""

    def __init__(
        self,
        *,
        scope: ScopeArtifact,
        public_key_pem: bytes,
        kill_switch: KillSwitch | None = None,
        max_budget_usd: float = 5.0,
    ) -> None:
        self._scope = scope
        self._public_key_pem = public_key_pem
        self._kill = kill_switch or KillSwitch()
        self._max_budget_usd = max_budget_usd

    def check(self, *, spent_usd: float = 0.0, now: datetime | None = None, **_: Any) -> Decision:
        """E19 — evaluate scope, kill switch, and budget; return an allow/deny decision."""
        ref = now or datetime.now(UTC)

        if not self._scope.signature or not verify_scope(self._scope, self._public_key_pem):
            return self._deny("scope artifact is unsigned or signature is invalid")
        if self._scope.is_expired(now=ref):
            return self._deny(f"scope artifact expired at {self._scope.expires_at.isoformat()}")
        if self._kill.triggered:
            return self._deny(f"kill switch tripped: {self._kill.reason or 'no reason given'}")
        if spent_usd >= self._max_budget_usd:
            return self._deny(
                f"budget cap reached: ${spent_usd:.2f} >= ${self._max_budget_usd:.2f}"
            )
        return {"decision": "allow", "reason": "within scope, budget, and not halted"}

    def _deny(self, reason: str) -> Decision:
        _log.warning("governance.deny", reason=reason)
        return {"decision": "deny", "reason": reason}
