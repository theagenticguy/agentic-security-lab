from pathlib import Path

import pytest
from asec_skills import Skill, SkillLoader, permission_gate
from asec_skills.loader import parse_skill
from pydantic import ValidationError

FIXTURES = Path(__file__).parent / "fixtures"


def test_imports() -> None:
    from asec_skills import __version__

    assert __version__ == "0.1.0"


def test_parse_full_frontmatter() -> None:
    skills = SkillLoader.discover([FIXTURES.parent])
    assert len(skills) == 1
    skill = skills[0]
    assert skill.name == "threat-model-bootstrap"
    # >- block scalar folds onto one line.
    assert skill.description.startswith("Given an architecture")
    assert "\n" not in skill.description.strip()
    assert skill.context == "fork"
    assert skill.agent == "general-purpose"
    assert skill.effort == "high"
    # allowed-tools string is split while keeping Bash(...) groups intact.
    assert skill.allowed_tools == ("Read", "Write", "Glob", "Bash(git diff *)")
    assert "## Task" in skill.body


def test_argument_hint_kebab_alias() -> None:
    skill = (FIXTURES / "SKILL.md").read_text()
    parsed = parse_skill(skill)
    assert parsed.argument_hint == "[arch-file]"


def test_reject_missing_name() -> None:
    text = "---\ndescription: no name here\n---\nbody\n"
    with pytest.raises(ValidationError):
        parse_skill(text)


def test_missing_frontmatter_raises() -> None:
    with pytest.raises(ValueError):
        parse_skill("no frontmatter at all\n")


def test_allowed_tools_tuple_is_frozen() -> None:
    skill = Skill(name="s", description="d", allowed_tools=("Read",))
    assert isinstance(skill.allowed_tools, tuple)
    with pytest.raises(ValidationError):
        skill.name = "other"  # type: ignore[misc]


def test_loader_skips_invalid(tmp_path: Path) -> None:
    good = tmp_path / "good"
    good.mkdir()
    (good / "SKILL.md").write_text("---\nname: ok\ndescription: fine\n---\nbody\n")
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "SKILL.md").write_text("no frontmatter\n")
    skills = SkillLoader.discover([tmp_path])
    assert [s.name for s in skills] == ["ok"]


@pytest.mark.asyncio
async def test_gate_denies_unknown_tool() -> None:
    result = await permission_gate(
        {"tool_name": "WebFetch", "tool_input": {}},
        "tu_1",
        None,
        allowed_tools=["Read", "Write"],
        denied_paths=[],
    )
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.asyncio
async def test_gate_allows_known_tool() -> None:
    result = await permission_gate(
        {"tool_name": "Read", "tool_input": {"file_path": "/work/a.py"}},
        "tu_2",
        None,
        allowed_tools=["Read"],
        denied_paths=["*.env"],
    )
    assert result is None


@pytest.mark.asyncio
async def test_gate_denies_write_to_denied_glob() -> None:
    result = await permission_gate(
        {"tool_name": "Write", "tool_input": {"file_path": "/work/secrets/.env"}},
        "tu_3",
        None,
        allowed_tools=["Write"],
        denied_paths=["*.env"],
    )
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
