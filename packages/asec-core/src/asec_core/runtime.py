"""Provider-abstract agent runtime seam + the v1 Claude adapter (E14, E15, E16).

Per PLAN.md §11 decision 2 (tech-stack ADR-0002), the orchestrator depends only on the
`AgentRuntime` Protocol so a future alternate-runtime adapter (e.g. `OpenAIAgentsRuntime`,
`DeepAgentsRuntime`, `OpenCodeRuntime`) can satisfy the same shape without inheritance
coupling and without leaking SDK types upward. `ClaudeAgentRuntime` is the sole v1 adapter;
it lazy-imports `claude-agent-sdk` inside its methods so the Protocol (and the package)
stays importable even when the SDK is not yet installed.

`query` never yields raw SDK objects: each SDK message is normalized into a small frozen
`RuntimeMessage` (text / tool_use / tool_result / result) so the rest of the substrate is
provider-pure. The runtime maps `Settings` + the loaded `Skill.allowed_tools` + buffered
`register_hook` callables into a `ClaudeAgentOptions`; the Bedrock backend is selected by
env (`CLAUDE_CODE_USE_BEDROCK=1`, set in `mise.toml`) so no explicit option is needed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .settings import Settings

_log = structlog.get_logger(__name__)

_SDK_MISSING = (
    "claude-agent-sdk is not installed. Install it (and the Claude Code CLI on PATH) "
    "to use ClaudeAgentRuntime: `uv add claude-agent-sdk`."
)


class RuntimeMessage(BaseModel):
    """A provider-neutral, frozen normalization of one SDK stream message.

    ``kind`` discriminates the payload: ``text`` carries assistant prose; ``tool_use``
    carries a requested tool call; ``tool_result`` carries a tool's output; ``result``
    carries the terminal usage/cost summary. Unset fields stay ``None`` so the orchestrator
    can branch on ``kind`` and read only the fields that apply.
    """

    model_config = ConfigDict(frozen=True)

    kind: Literal["text", "tool_use", "tool_result", "result"]
    # text
    text: str | None = None
    # tool_use
    tool_id: str | None = None
    tool_name: str | None = None
    tool_input: dict[str, Any] | None = None
    # tool_result
    tool_use_id: str | None = None
    tool_output: str | None = None
    is_error: bool | None = None
    # result
    total_cost_usd: float | None = None
    usage: dict[str, Any] | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    result_text: str | None = None


@runtime_checkable
class AgentRuntime(Protocol):
    """Provider-abstract agent runtime seam (E14, E15, E16).

    The orchestrator depends only on this Protocol. `query` yields normalized provider
    messages; `register_hook` wires a lifecycle hook (e.g. PreToolUse) for deterministic
    policy enforcement; `spawn_subagents` fans out per-concern subagents.
    """

    def query(self, prompt: str, *, options: Any | None = ...) -> AsyncIterator[RuntimeMessage]:
        """E14 — issue a query against the configured model; yield normalized messages."""
        ...

    def register_hook(self, event: str, hook: Any) -> None:
        """E16 — register a lifecycle hook (e.g. PreToolUse) on the runtime."""
        ...

    async def spawn_subagents(self, specs: Sequence[Any]) -> Sequence[Any]:
        """E15 — fan out per-concern subagents and gather their results."""
        ...


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class ClaudeAgentRuntime:
    """v1 `AgentRuntime` adapter over `claude-agent-sdk` (E14, E15, E16).

    Defensive by design: the SDK is imported lazily inside each method, so importing this
    class never fails when the SDK is absent. Methods raise a friendly `RuntimeError`
    instead.
    """

    def __init__(
        self, settings: Settings | None = None, *, allowed_tools: Sequence[str] | None = None
    ) -> None:
        self._settings = settings
        self._allowed_tools: list[str] = list(allowed_tools or ())
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

    def _build_options(self, sdk: Any, options: Any | None) -> Any:
        """Map asec settings + buffered hooks into a `ClaudeAgentOptions` (or pass-through)."""
        if options is not None:
            return options
        kwargs: dict[str, Any] = {
            # Bedrock backend is selected by env (CLAUDE_CODE_USE_BEDROCK=1); no option needed.
            # Pass setting_sources=[] so the SDK doesn't auto-load host user/project config.
            "setting_sources": [],
            "allowed_tools": list(self._allowed_tools),
        }
        if self._settings is not None:
            kwargs["model"] = self._settings.model_id
            kwargs["permission_mode"] = self._settings.permission_mode
        pre = self._hooks.get("PreToolUse")
        if pre:
            kwargs["hooks"] = {"PreToolUse": [sdk.HookMatcher(hooks=[h]) for h in pre]}
        return sdk.ClaudeAgentOptions(**kwargs)

    @staticmethod
    def _normalize(sdk: Any, message: Any) -> list[RuntimeMessage]:
        """Translate one SDK message into zero or more provider-neutral `RuntimeMessage`s."""
        out: list[RuntimeMessage] = []
        if isinstance(message, sdk.ResultMessage):
            usage: dict[str, Any] = message.usage or {}
            out.append(
                RuntimeMessage(
                    kind="result",
                    total_cost_usd=message.total_cost_usd,
                    usage=usage,
                    input_tokens=_coerce_int(usage.get("input_tokens")),
                    output_tokens=_coerce_int(usage.get("output_tokens")),
                    result_text=message.result,
                )
            )
            return out
        content = getattr(message, "content", None)
        if content is None:
            return out
        if isinstance(content, str):
            out.append(RuntimeMessage(kind="text", text=content))
            return out
        for block in content:
            if isinstance(block, sdk.TextBlock):
                out.append(RuntimeMessage(kind="text", text=block.text))
            elif isinstance(block, sdk.ToolUseBlock):
                out.append(
                    RuntimeMessage(
                        kind="tool_use",
                        tool_id=block.id,
                        tool_name=block.name,
                        tool_input=dict(block.input),
                    )
                )
            elif isinstance(block, sdk.ToolResultBlock):
                raw = block.content
                text = raw if isinstance(raw, str) else None if raw is None else str(raw)
                out.append(
                    RuntimeMessage(
                        kind="tool_result",
                        tool_use_id=block.tool_use_id,
                        tool_output=text,
                        is_error=block.is_error,
                    )
                )
        return out

    async def query(
        self, prompt: str, *, options: Any | None = None
    ) -> AsyncIterator[RuntimeMessage]:
        """E14 — stream normalized SDK messages for `prompt`.

        Builds `ClaudeAgentOptions` from `Settings` + the loaded skill's allowed tools +
        buffered `register_hook` callables, then delegates to `claude_agent_sdk.query`,
        yielding each SDK message normalized to a frozen `RuntimeMessage`.
        """
        sdk = self._require_sdk()
        opts = self._build_options(sdk, options)
        _log.info("runtime.query", prompt_len=len(prompt), allowed_tools=self._allowed_tools)
        async for message in sdk.query(prompt=prompt, options=opts):
            for normalized in self._normalize(sdk, message):
                yield normalized

    async def spawn_subagents(self, specs: Sequence[Any]) -> Sequence[Any]:
        """E15 — fan out AgentDefinition-backed subagents.

        TODO(day-5): translate specs into `claude_agent_sdk.AgentDefinition`s and dispatch
        them via a single `query` with `options.agents`, gathering per-subagent results
        (PLAN §6 fan-out). Day 3 is single-`query`; this remains a raise-free shim.
        """
        self._require_sdk()
        _log.info("runtime.spawn_subagents.noop", count=len(list(specs)))
        return []
