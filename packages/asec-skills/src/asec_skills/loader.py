"""Discover and parse ``SKILL.md`` files into :class:`Skill` instances."""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

import structlog
import yaml
from opentelemetry import trace
from pydantic import ValidationError

from .skill import Skill

_log = structlog.get_logger(__name__)
_tracer = trace.get_tracer(__name__)

_FRONTMATTER_RE = re.compile(
    r"\A---[ \t]*\r?\n(?P<frontmatter>.*?)\r?\n---[ \t]*\r?\n?(?P<body>.*)\Z",
    re.DOTALL,
)

# Splits a tool spec string on whitespace while keeping ``Bash(foo *)`` groups
# (and any other parenthesised argument hint) intact.
_TOOL_SPEC_RE = re.compile(r"\S+?\([^)]*\)|\S+")

# Frontmatter keys that arrive kebab-cased in the standard but map to snake_case
# attributes on :class:`Skill`.
_KEY_ALIASES = {
    "argument-hint": "argument_hint",
    "allowed-tools": "allowed_tools",
    "disallowed-tools": "disallowed_tools",
    "disable-model-invocation": "disable_model_invocation",
}

_TOOL_FIELDS = ("allowed_tools", "disallowed_tools")


def _coerce_tools(value: Any) -> tuple[str, ...]:
    """Normalise an ``allowed-tools`` value into a tuple of tool specs."""
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(m.group(0) for m in _TOOL_SPEC_RE.finditer(value))
    if isinstance(value, (list, tuple)):
        items = cast("list[Any] | tuple[Any, ...]", value)
        return tuple(str(item) for item in items)
    return (str(value),)


def _normalise_frontmatter(raw: dict[str, Any]) -> dict[str, Any]:
    """Apply key aliases and coerce tool fields to tuples."""
    data: dict[str, Any] = {}
    for key, value in raw.items():
        field = _KEY_ALIASES.get(key, key)
        data[field] = value
    for field in _TOOL_FIELDS:
        if field in data:
            data[field] = _coerce_tools(data[field])
    # `argument-hint: [arch-file]` is valid YAML for a list, but the standard
    # treats the hint as a free-form string; reconstruct the bracketed form.
    hint = data.get("argument_hint")
    if isinstance(hint, list):
        parts = cast("list[Any]", hint)
        data["argument_hint"] = "[" + " ".join(str(h) for h in parts) + "]"
    return data


def parse_skill(text: str) -> Skill:
    """Parse the text of a ``SKILL.md`` file into a :class:`Skill`.

    Raises :class:`ValueError` if the frontmatter block is missing or not a
    mapping, and :class:`pydantic.ValidationError` if required fields are
    absent or mistyped.
    """
    match = _FRONTMATTER_RE.match(text)
    if match is None:
        raise ValueError("SKILL.md is missing a '---' frontmatter block")
    loaded = yaml.safe_load(match.group("frontmatter"))
    if not isinstance(loaded, dict):
        raise ValueError("SKILL.md frontmatter is not a YAML mapping")
    mapping = cast(dict[Any, Any], loaded)
    raw: dict[str, Any] = {str(k): v for k, v in mapping.items()}
    data = _normalise_frontmatter(raw)
    data["body"] = match.group("body")
    return Skill.model_validate(data)


class SkillLoader:
    """Walks skill roots and loads every well-formed ``SKILL.md``."""

    @staticmethod
    def discover(roots: Iterable[Path]) -> list[Skill]:
        """Discover ``*/SKILL.md`` files beneath each root.

        Files whose frontmatter is missing, malformed, or fails validation are
        skipped with a logged warning rather than aborting the whole scan.
        """
        with _tracer.start_as_current_span("SkillLoader.discover"):
            skills: list[Skill] = []
            for root in roots:
                root_path = Path(root)
                for skill_file in sorted(root_path.glob("*/SKILL.md")):
                    try:
                        text = skill_file.read_text(encoding="utf-8")
                        skills.append(parse_skill(text))
                    except (ValueError, ValidationError, yaml.YAMLError) as exc:
                        _log.warning(
                            "skipping invalid SKILL.md",
                            path=str(skill_file),
                            error=str(exc),
                        )
            return skills
