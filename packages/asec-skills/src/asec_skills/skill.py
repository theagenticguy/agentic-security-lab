"""The :class:`Skill` value object — a parsed ``SKILL.md`` document."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Skill(BaseModel):
    """A frozen representation of a ``SKILL.md`` skill definition.

    The frontmatter fields mirror the Agent Skills open standard; the Markdown
    body (everything after the closing ``---``) is preserved verbatim in
    :attr:`body`.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    argument_hint: str | None = None
    allowed_tools: tuple[str, ...] = ()
    disallowed_tools: tuple[str, ...] = ()
    disable_model_invocation: bool = False
    context: Literal["main", "fork"] = "main"
    agent: str | None = None
    effort: Literal["low", "medium", "high"] | None = None
    model: str | None = None
    body: str = Field(default="")
