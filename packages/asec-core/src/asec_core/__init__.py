"""asec-core: orchestrator, AgentRuntime seam, and governance for the substrate."""

from __future__ import annotations

from .governance import GovernanceGate
from .killswitch import FileKillSwitch, KillSwitch
from .orchestrator import Orchestrator, ReviewResult
from .runtime import AgentRuntime, ClaudeAgentRuntime, RuntimeMessage
from .scope import ScopeArtifact, sign_scope, verify_scope
from .settings import Settings

__version__ = "0.1.0"

__all__ = [
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
    "sign_scope",
    "verify_scope",
]
