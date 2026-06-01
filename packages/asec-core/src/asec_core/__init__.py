"""asec-core: orchestrator, AgentRuntime seam, and governance for the substrate."""

from __future__ import annotations

from .agents import (
    CWE_WORKERS,
    AgentDefinition,
    default_cwe_workers,
    pattern_match_score,
)
from .governance import GovernanceGate
from .killswitch import FileKillSwitch, KillSwitch
from .orchestrator import Orchestrator, ReviewResult
from .runtime import AgentRuntime, ClaudeAgentRuntime, RuntimeMessage
from .scope import ScopeArtifact, sign_scope, verify_scope
from .settings import Settings

__version__ = "0.1.0"

__all__ = [
    "CWE_WORKERS",
    "AgentDefinition",
    "AgentRuntime",
    "ClaudeAgentRuntime",
    "FileKillSwitch",
    "GovernanceGate",
    "KillSwitch",
    "Orchestrator",
    "ReviewResult",
    "RuntimeMessage",
    "ScopeArtifact",
    "Settings",
    "__version__",
    "default_cwe_workers",
    "pattern_match_score",
    "sign_scope",
    "verify_scope",
]
