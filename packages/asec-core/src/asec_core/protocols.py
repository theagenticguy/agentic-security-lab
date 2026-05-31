"""Cross-package ports (typing.Protocol) owned by asec-core.

No package imports another's concrete class — only these Protocols are re-exported and
depended upon, enforcing the `apps -> packages -> asec-core` direction with no inheritance
coupling. Method docstrings reference the EARS invariant each port represents.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AgentRuntime(Protocol):
    """Provider-abstract agent runtime seam (E14, E15).

    The orchestrator depends only on this Protocol; `ClaudeAgentRuntime` is the sole v1
    adapter. A future an alternate-runtime adapter (e.g. `OpenAIAgentsRuntime`, `DeepAgentsRuntime`, `OpenCodeRuntime`) satisfies the same shape without inheritance.
    """

    async def query(self, prompt: str, **options: Any) -> str:
        """E14 — issue a single completion against the configured model and return text."""
        raise NotImplementedError

    def stream(self, prompt: str, **options: Any) -> AsyncIterator[str]:
        """E14 — stream a completion as normalized text chunks."""
        raise NotImplementedError

    async def spawn_subagents(self, prompts: Sequence[str], **options: Any) -> Sequence[str]:
        """E15 — fan out per-concern subagents and gather their results."""
        raise NotImplementedError

    def register_hook(self, event: str, handler: Any) -> None:
        """E16 — register a lifecycle hook (e.g. PreToolUse) on the runtime."""
        raise NotImplementedError


@runtime_checkable
class SandboxPort(Protocol):
    """Isolated execution surface for target-code experiments (E3, E4).

    Implementations must default to `--network=none`; isolation is a property of the
    concrete adapter (DockerSandbox), proven against this Protocol.
    """

    async def start(self) -> None:
        """E3 — launch a throwaway sandbox with networking disabled by default."""
        raise NotImplementedError

    async def exec(self, command: Sequence[str]) -> tuple[int, str, str]:
        """E4 — run a command inside the sandbox; return (exit_code, stdout, stderr)."""
        raise NotImplementedError

    async def collect_artifacts(self) -> dict[str, bytes]:
        """E5 — collect declared output artifacts from the sandbox before teardown."""
        raise NotImplementedError

    async def teardown(self) -> None:
        """E6 — destroy the sandbox and reclaim all of its resources."""
        raise NotImplementedError


@runtime_checkable
class LedgerPort(Protocol):
    """Append-only findings ledger + hash-chained WORM audit surface (E10, E12)."""

    async def append(self, entry: Any) -> str:
        """E12 — append an entry to the hash-chained WORM log; return the new prev_hash."""
        raise NotImplementedError

    async def record_finding(self, finding: Any) -> None:
        """E10 — persist a finding in the durable ledger."""
        raise NotImplementedError

    async def list_findings(self) -> Sequence[Any]:
        """E10 — read back all persisted findings."""
        raise NotImplementedError


@runtime_checkable
class SkillLoaderPort(Protocol):
    """SKILL.md discovery + deny-by-default permission gate (E7, E8)."""

    def discover(self, root: Any) -> Sequence[Any]:
        """E7 — discover and parse SKILL.md skills under the given root."""
        raise NotImplementedError

    def permission_gate(self, tool: str, **context: Any) -> bool:
        """E8 — deny-by-default PreToolUse decision for a requested tool call."""
        raise NotImplementedError
