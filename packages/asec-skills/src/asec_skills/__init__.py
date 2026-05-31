"""asec-skills: SKILL.md loader and the deny-by-default permission gate."""

from .gate import permission_gate
from .loader import SkillLoader
from .skill import Skill

__all__ = ["Skill", "SkillLoader", "permission_gate"]

__version__ = "0.1.0"
