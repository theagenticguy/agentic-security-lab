"""Per-CWE subagent definitions for the Day-5 fan-out (PLAN §2).

Each :class:`AgentDefinition` is a tighter SKILL slice scoped to one CWE class
(`sqli-worker`, `xss-worker`, ...). The orchestrator builds the SDK ``agents`` map
from these and dispatches one worker per definition concurrently, every worker
writing to a single shared :class:`asec_memory.board.HypothesisBoard`.

The ``pattern_keywords`` set per CWE is the v0 rule-based ``pattern_match`` axis:
the fraction of a CWE's keyword set that hits a finding snippet stands in for the
embedding-similarity pass deferred to a later day (PLAN §3, risk 2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ModelEffort = Literal["low", "medium", "high"]


@dataclass(frozen=True, slots=True)
class AgentDefinition:
    """A single per-CWE worker spec passed to ``spawn_subagents``."""

    name: str
    description: str
    cwe_id: str
    system_prompt_extra: str = ""
    allowed_tools: tuple[str, ...] = ()
    model_effort: ModelEffort = "high"
    pattern_keywords: frozenset[str] = field(default_factory=lambda: frozenset[str]())
    confidence_tier_hint: str = "high"


# Keyword sets are intentionally small and lowercased; the heuristic lowercases the
# snippet before matching, so casing never affects the score.
_DEFAULT_TOOLS: tuple[str, ...] = ("Read", "Grep", "Glob")


CWE_WORKERS: tuple[AgentDefinition, ...] = (
    AgentDefinition(
        name="sqli-worker",
        description="SQL injection (CWE-89) specialist worker.",
        cwe_id="CWE-89",
        system_prompt_extra="Hunt only for SQL injection: tainted input reaching a query string.",
        allowed_tools=_DEFAULT_TOOLS,
        pattern_keywords=frozenset(
            {"execute", "cursor", "select", "f'", 'f"', "query", "sql", "%s", "format"}
        ),
    ),
    AgentDefinition(
        name="xss-worker",
        description="Cross-site scripting (CWE-79) specialist worker.",
        cwe_id="CWE-79",
        system_prompt_extra="Hunt only for XSS: unescaped user input rendered into markup.",
        allowed_tools=_DEFAULT_TOOLS,
        pattern_keywords=frozenset(
            {"render", "html", "<div>", "innerhtml", "escape", "template", "markup", "{q}"}
        ),
    ),
    AgentDefinition(
        name="path-traversal-worker",
        description="Path traversal (CWE-22) specialist worker.",
        cwe_id="CWE-22",
        system_prompt_extra="Hunt only for path traversal: unsanitized path joins / file reads.",
        allowed_tools=_DEFAULT_TOOLS,
        pattern_keywords=frozenset(
            {"open(", "join(", "..", "path", "os.path", "send_file", "download", "read"}
        ),
    ),
    AgentDefinition(
        name="deserialization-worker",
        description="Unsafe deserialization (CWE-502) specialist worker.",
        cwe_id="CWE-502",
        system_prompt_extra="Hunt only for unsafe deserialization of untrusted data.",
        allowed_tools=_DEFAULT_TOOLS,
        pattern_keywords=frozenset(
            {"pickle", "loads", "yaml.load", "marshal", "deserialize", "eval", "__reduce__"}
        ),
    ),
    AgentDefinition(
        name="idor-worker",
        description="Insecure direct object reference (CWE-639) specialist worker.",
        cwe_id="CWE-639",
        system_prompt_extra="Hunt only for IDOR: object access without an ownership check.",
        allowed_tools=_DEFAULT_TOOLS,
        pattern_keywords=frozenset(
            {"id", "request.args", "get_object", "owner", "user_id", "authorize", "filter_by"}
        ),
    ),
)


def default_cwe_workers() -> tuple[AgentDefinition, ...]:
    """Return the canonical per-CWE worker set used by the orchestrator fan-out."""
    return CWE_WORKERS


def pattern_match_score(snippet: str | None, keywords: frozenset[str]) -> float:
    """v0 rule-based ``pattern_match`` axis: fraction of ``keywords`` hit in ``snippet``.

    Deterministic and embedding-free so CI stays hermetic (PLAN §3). Returns 0.0 for
    an empty snippet or an empty keyword set.
    """
    if not snippet or not keywords:
        return 0.0
    haystack = snippet.lower()
    hits = sum(1 for kw in keywords if kw in haystack)
    return hits / len(keywords)
