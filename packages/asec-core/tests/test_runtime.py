"""Day 3 tests for `ClaudeAgentRuntime` — Settings→options mapping + message normalization.

`claude_agent_sdk` is mocked via `unittest.mock.patch` so these run hermetically (no CLI,
no Bedrock). The contract under test is the thin adapter seam, not the SDK itself.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import pytest
from asec_core import ClaudeAgentRuntime, RuntimeMessage, Settings

pytestmark = pytest.mark.asyncio


async def test_runtime_imports_without_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """The module + class import (and the adapter constructs) even with no SDK installed."""
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)  # simulate absent SDK
    rt = importlib.import_module("asec_core.runtime")
    assert rt.ClaudeAgentRuntime() is not None  # construction never imports the SDK


# ----- a minimal fake `claude_agent_sdk` module ---------------------------------------


@dataclass
class _TextBlock:
    text: str


@dataclass
class _ToolUseBlock:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class _ToolResultBlock:
    tool_use_id: str
    content: Any
    is_error: bool | None = None


@dataclass
class _AssistantMessage:
    content: list[Any]


@dataclass
class _ResultMessage:
    total_cost_usd: float | None
    usage: dict[str, Any] | None
    result: str | None


@dataclass
class _HookMatcher:
    hooks: list[Any]
    matcher: str | None = None


@dataclass
class _ClaudeAgentOptions:
    setting_sources: Any = None
    allowed_tools: Any = None
    model: str | None = None
    permission_mode: str | None = None
    hooks: Any = None


class _FakeSDK:
    TextBlock = _TextBlock
    ToolUseBlock = _ToolUseBlock
    ToolResultBlock = _ToolResultBlock
    AssistantMessage = _AssistantMessage
    ResultMessage = _ResultMessage
    HookMatcher = _HookMatcher
    ClaudeAgentOptions = _ClaudeAgentOptions

    def __init__(self, messages: list[Any]) -> None:
        self._messages = messages
        self.captured_options: Any = None

    def query(self, *, prompt: str, options: Any = None) -> AsyncIterator[Any]:
        self.captured_options = options

        async def _gen() -> AsyncIterator[Any]:
            for m in self._messages:
                yield m

        return _gen()


def _install_fake(messages: list[Any]) -> _FakeSDK:
    fake = _FakeSDK(messages)
    sys.modules["claude_agent_sdk"] = fake  # type: ignore[assignment]
    return fake


@pytest.fixture(autouse=True)
def _restore_sdk():  # pyright: ignore[reportUnusedFunction]  # consumed by pytest
    saved = sys.modules.get("claude_agent_sdk")
    yield
    if saved is not None:
        sys.modules["claude_agent_sdk"] = saved
    else:
        sys.modules.pop("claude_agent_sdk", None)


async def test_settings_map_to_options(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install_fake([_ResultMessage(total_cost_usd=0.1, usage={}, result="done")])
    settings = Settings(
        _env_file=None  # type: ignore[call-arg]
    )
    rt = ClaudeAgentRuntime(settings, allowed_tools=["Read", "Grep"])
    async for _ in rt.query("hello"):
        pass
    opts = fake.captured_options
    assert opts.model == settings.model_id
    assert opts.permission_mode == settings.permission_mode
    assert opts.allowed_tools == ["Read", "Grep"]
    assert opts.setting_sources == []  # SDK does not auto-load host config


async def test_hooks_wired_into_options() -> None:
    fake = _install_fake([_ResultMessage(total_cost_usd=None, usage=None, result=None)])
    rt = ClaudeAgentRuntime(allowed_tools=["Read"])

    async def _hook(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {}

    rt.register_hook("PreToolUse", _hook)
    async for _ in rt.query("x"):
        pass
    opts = fake.captured_options
    assert "PreToolUse" in opts.hooks
    assert len(opts.hooks["PreToolUse"]) == 1
    assert opts.hooks["PreToolUse"][0].hooks == [_hook]


async def test_explicit_options_passthrough() -> None:
    fake = _install_fake([_ResultMessage(total_cost_usd=None, usage=None, result=None)])
    rt = ClaudeAgentRuntime()
    sentinel = object()
    async for _ in rt.query("x", options=sentinel):
        pass
    assert fake.captured_options is sentinel


async def test_normalization_text() -> None:
    _install_fake([_AssistantMessage(content=[_TextBlock(text="hi")])])
    rt = ClaudeAgentRuntime()
    out = [m async for m in rt.query("x")]
    assert out == [RuntimeMessage(kind="text", text="hi")]


async def test_normalization_tool_use() -> None:
    _install_fake(
        [_AssistantMessage(content=[_ToolUseBlock(id="t1", name="Read", input={"p": "a"})])]
    )
    rt = ClaudeAgentRuntime()
    out = [m async for m in rt.query("x")]
    assert out[0].kind == "tool_use"
    assert out[0].tool_name == "Read"
    assert out[0].tool_input == {"p": "a"}


async def test_normalization_tool_result() -> None:
    _install_fake(
        [
            _AssistantMessage(
                content=[_ToolResultBlock(tool_use_id="t1", content="ok", is_error=False)]
            )
        ]
    )
    rt = ClaudeAgentRuntime()
    out = [m async for m in rt.query("x")]
    assert out[0].kind == "tool_result"
    assert out[0].tool_use_id == "t1"
    assert out[0].tool_output == "ok"
    assert out[0].is_error is False


async def test_normalization_result_tokens() -> None:
    _install_fake(
        [
            _ResultMessage(
                total_cost_usd=0.42,
                usage={"input_tokens": 100, "output_tokens": 50},
                result="final",
            )
        ]
    )
    rt = ClaudeAgentRuntime()
    out = [m async for m in rt.query("x")]
    assert out[0].kind == "result"
    assert out[0].total_cost_usd == 0.42
    assert out[0].input_tokens == 100
    assert out[0].output_tokens == 50
    assert out[0].result_text == "final"


async def test_spawn_subagents_is_noop_shim() -> None:
    _install_fake([])
    rt = ClaudeAgentRuntime()
    assert await rt.spawn_subagents([{"role": "x"}]) == []
