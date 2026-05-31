"""Provider-abstract agent runtime seam + the v1 Claude adapter (E14, E15, E16).

Per PLAN.md §11 decision 2 (tech-stack ADR-0002), the orchestrator depends only on the
`AgentRuntime` Protocol so a future `StrandsRuntime` can satisfy the same shape without
inheritance coupling and without leaking SDK types upward. `ClaudeAgentRuntime` is the
sole v1 adapter; it lazy-imports `claude-agent-sdk` inside its methods so the Protocol
(and the package) stays importable even when the SDK is not yet installed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import structlog

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .settings import Settings

_log = structlog.get_logger(__name__)

_SDK_MISSING = (
    "claude-agent-sdk is not installed. Install it (and the Claude Code CLI on PATH) "
    "to use ClaudeAgentRuntime: `uv add claude-agent-sdk`."
)


@runtime_checkable
class AgentRuntime(Protocol):
    """Provider-abstract agent runtime seam (E14, E15, E16).

    The orchestrator depends only on this Protocol. `query` yields normalized provider
    messages; `register_hook` wires a lifecycle hook (e.g. PreToolUse) for deterministic
    policy enforcement; `spawn_subagents` fans out per-concern subagents.
    """

    def query(self, prompt: str, *, options: Any | None = ...) -> AsyncIterator[Any]:
        """E14 — issue a query against the configured model; yield provider messages."""
        ...

    def register_hook(self, event: str, hook: Any) -> None:
        """E16 — register a lifecycle hook (e.g. PreToolUse) on the runtime."""
        ...

    async def spawn_subagents(self, specs: Sequence[Any]) -> Sequence[Any]:
        """E15 — fan out per-concern subagents and gather their results."""
        ...


class ClaudeAgentRuntime:
    """v1 `AgentRuntime` adapter over `claude-agent-sdk` (E14, E15, E16).

    Defensive by design: the SDK is imported lazily inside each method, so importing this
    class never fails when the SDK is absent. Methods raise a friendly `RuntimeError`
    instead.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings
        self._hooks: dict[str, list[Any]] = {}

    @staticmethod
    def _require_sdk() -> Any:
        try:
            import claude_agent_sdk as sdk
        except ImportError as exc:  # pragma: no cover - exercised only without SDK
            raise RuntimeError(_SDK_MISSING) from exc
        return sdk

    def register_hook(self, event: str, hook: Any) -> None:
        """E16 — buffer a hook to be passed to ClaudeAgentOptions on the next query."""
        self._hooks.setdefault(event, []).append(hook)

    async def query(  # type: ignore[empty-body]
        self, prompt: str, *, options: Any | None = None
    ) -> AsyncIterator[Any]:
        """E14 — stream normalized SDK messages for `prompt`.

        TODO(day-3): build ClaudeAgentOptions from Settings + buffered hooks and delegate
        to `claude_agent_sdk.query(prompt=..., options=...)`, normalizing each yielded
        message. Wired once claude-agent-sdk is installed in the workspace env.
        """
        self._require_sdk()
        _log.info("runtime.query", prompt_len=len(prompt))
        raise NotImplementedError("ClaudeAgentRuntime.query wired on day 3")
        yield  # pragma: no cover - marks this as an async generator

    async def spawn_subagents(self, specs: Sequence[Any]) -> Sequence[Any]:
        """E15 — fan out AgentDefinition-backed subagents.

        TODO(day-3): translate specs into `claude_agent_sdk.AgentDefinition`s and dispatch
        them via a single `query` with `options.agents`, gathering per-subagent results.
        """
        self._require_sdk()
        raise NotImplementedError("ClaudeAgentRuntime.spawn_subagents wired on day 3")
