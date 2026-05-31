"""Deny-by-default PreToolUse permission gate.

The gate is shaped to drop into a ``claude_agent_sdk`` ``PreToolUse`` hook
(``async (input_data, tool_use_id, context) -> dict | None``) but takes only
plain dicts so the package carries no dependency on the SDK.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from fnmatch import fnmatch
from pathlib import PurePosixPath
from typing import Any, cast

import structlog
from opentelemetry import trace

_log = structlog.get_logger(__name__)
_tracer = trace.get_tracer(__name__)

# Tools whose target file path must be checked against the denied globs.
_PATH_WRITE_TOOLS = frozenset({"Edit", "Write"})

# Keys a PreToolUse payload may use to carry the target path.
_PATH_KEYS = ("file_path", "path", "notebook_path")


def _deny(reason: str) -> dict[str, Any]:
    """Build the SDK-compatible deny payload."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _extract_path(tool_input: Mapping[str, Any]) -> str | None:
    for key in _PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _path_is_denied(path: str, denied_paths: Iterable[str]) -> bool:
    name = PurePosixPath(path).name
    return any(fnmatch(path, pattern) or fnmatch(name, pattern) for pattern in denied_paths)


async def permission_gate(
    input_data: Mapping[str, Any],
    tool_use_id: str | None,
    context: Any,
    *,
    allowed_tools: Iterable[str],
    denied_paths: Iterable[str],
) -> dict[str, Any] | None:
    """Return a deny payload, or ``None`` to allow the tool call.

    Denies when the tool is not in ``allowed_tools``, or when the tool is a
    file-writing tool (``Edit``/``Write``) whose target path matches one of the
    ``denied_paths`` globs. Matching the glob against both the full path and the
    bare filename lets ``*.env`` block ``/work/secrets/.env`` style targets.
    """
    with _tracer.start_as_current_span("permission_gate"):
        tool_name = str(input_data.get("tool_name", ""))
        allowed = set(allowed_tools)
        if tool_name not in allowed:
            reason = f"tool {tool_name!r} is not in the allowed-tools list"
            _log.warning("gate.deny", tool=tool_name, tool_use_id=tool_use_id, reason=reason)
            return _deny(reason)

        if tool_name in _PATH_WRITE_TOOLS:
            raw_input: object = input_data.get("tool_input") or {}
            if isinstance(raw_input, Mapping):
                mapping = cast("Mapping[Any, Any]", raw_input)
                tool_input: Mapping[str, Any] = {str(k): v for k, v in mapping.items()}
                path = _extract_path(tool_input)
                if path is not None and _path_is_denied(path, denied_paths):
                    reason = f"{tool_name} to {path!r} is blocked by a denied-path policy"
                    _log.warning(
                        "gate.deny", tool=tool_name, tool_use_id=tool_use_id, reason=reason
                    )
                    return _deny(reason)

        return None
