"""asec-threat-model: Phase-Zero pydantic threat artifacts (E1/E2)."""

from .diff import ThreatModelDiff, diff
from .io import dump, load
from .models import Asset, AttackTreeNode, Threat, ThreatModel

__all__ = [
    "Asset",
    "AttackTreeNode",
    "Threat",
    "ThreatModel",
    "ThreatModelDiff",
    "diff",
    "dump",
    "load",
]

__version__ = "0.1.0"
