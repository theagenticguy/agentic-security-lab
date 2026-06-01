"""The review orchestrator — composes the substrate into one E2E review loop (Day 3).

`Orchestrator` is the single place where the provider-pure `AgentRuntime` stream is bridged
to typed `ProgressEvent`s, governance is enforced, findings are parsed from the model's final
JSON block, and a SARIF log is assembled. Everything it touches is injected (`__init__` DI),
so swapping `LocalSandbox`→`DockerSandbox` (Day 4) or the fake runtime→`ClaudeAgentRuntime`
(live) is a one-line change at the call site.

The model's output contract (declared in `SKILL.md`) is a single fenced ```json block of
``[{rule_id, message, severity, cwe, uri, start_line, snippet}, ...]`` in the *last* text
message; `_parse_findings` extracts it with a regex so the parse is deterministic across the
mocked and live runtimes. Budget is tracked from the terminal `result` message's token usage
against `settings.max_budget_usd`, emitting `BudgetWarning` at the 50/80/100% thresholds. The
`KillSwitch` is checked at the top of every stream iteration; once tripped the loop emits a
`WorkerStuck` abort marker and stops.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import anyio.to_thread
import structlog
from asec_memory.models import Finding, FindingLocation
from asec_memory.sarif import to_sarif_log
from asec_sandbox.events import (
    BudgetWarning,
    EventEmitter,
    FindingEmitted,
    GateDecision,
    HypothesisOpened,
    PhaseTransition,
    ProgressEvent,
    RunComplete,
    WorkerStuck,
)
from pydantic import BaseModel, ConfigDict

from .governance import GovernanceGate
from .killswitch import KillSwitch
from .runtime import AgentRuntime, RuntimeMessage

if TYPE_CHECKING:  # pragma: no cover - typing only
    from asec_memory.ledger import LedgerPort
    from asec_skills.skill import Skill
    from asec_threat_model.models import ThreatModel

    from .protocols import SandboxPort
    from .scope import ScopeArtifact

_log = structlog.get_logger(__name__)

# Fenced ```json ... ``` block extractor — non-greedy, tolerant of a bare ``` open fence.
_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```", re.DOTALL)

# Per-run synthetic cost model: rough USD-per-token so token usage maps onto the budget cap
# without a live pricing call. Opus-class output is ~5x input; numbers are illustrative and
# only need to be monotone for the threshold logic (Day 5 swaps in real cost from the SDK).
_USD_PER_INPUT_TOKEN = 15.0 / 1_000_000
_USD_PER_OUTPUT_TOKEN = 75.0 / 1_000_000

_BUDGET_THRESHOLDS = (0.5, 0.8, 1.0)


class ReviewResult(BaseModel):
    """The frozen outcome of one `Orchestrator.run` / `run_pr` invocation."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    findings: list[Finding]
    sarif: dict[str, Any]
    audit_head_hash: str
    events: list[ProgressEvent]


class Orchestrator:
    """Composes the substrate into the Day-3 E2E review loop (single-`query`)."""

    def __init__(
        self,
        *,
        runtime: AgentRuntime,
        sandbox: SandboxPort,
        ledger: LedgerPort,
        emitter: EventEmitter,
        gate: GovernanceGate,
        kill_switch: KillSwitch,
        skill: Skill,
        threat_model: ThreatModel,
        corpus_files: dict[str, str] | None = None,
        session: str = "review",
        max_budget_usd: float = 5.0,
    ) -> None:
        self._runtime = runtime
        self._sandbox = sandbox
        self._ledger = ledger
        self._emitter = emitter
        self._gate = gate
        self._kill = kill_switch
        self._skill = skill
        self._threat_model = threat_model
        self._corpus_files = dict(corpus_files or {})
        self._session = session
        self._max_budget_usd = max_budget_usd

    # ----- public entry points -------------------------------------------------------

    async def run(self, scope: ScopeArtifact) -> ReviewResult:
        """Run a full-corpus review: prompt = SKILL body + threat-model summary + files."""
        corpus = "\n\n".join(
            f"### FILE: {path}\n```\n{content}\n```"
            for path, content in sorted(self._corpus_files.items())
        )
        return await self._run(scope, corpus_section=corpus)

    async def run_pr(self, diff_path: Path) -> ReviewResult:
        """Run a PR review: prompt seeded from a unified diff instead of full file bodies."""
        diff = await anyio.to_thread.run_sync(lambda: Path(diff_path).read_text(encoding="utf-8"))
        corpus = f"### UNIFIED DIFF UNDER REVIEW\n```diff\n{diff}\n```"
        return await self._run(scope=None, corpus_section=corpus)

    # ----- core loop -----------------------------------------------------------------

    async def _run(self, scope: ScopeArtifact | None, *, corpus_section: str) -> ReviewResult:
        events: list[ProgressEvent] = []
        findings: list[Finding] = []

        # 1. Governance gate — deny aborts before any model work.
        decision = self._gate.check()
        gate_event = GateDecision(
            session=self._session,
            gate="governance",
            decision="pass" if decision["decision"] == "allow" else "fail",
            reason=decision["reason"],
        )
        await self._emit(events, gate_event)
        if decision["decision"] != "allow":
            return await self._finalize(events, findings, status="fail")

        # 2. Phase transition recon→find + prompt assembly.
        await self._emit(
            events, PhaseTransition(session=self._session, from_phase="recon", to_phase="find")
        )
        prompt = self._build_prompt(corpus_section)

        # 3. Stream the runtime, bridging messages to events.
        last_text: str | None = None
        warned: set[float] = set()
        async for msg in self._runtime.query(prompt, options=None):
            if self._kill.triggered:
                await self._emit(
                    events,
                    WorkerStuck(
                        session=self._session,
                        worker_id="orchestrator",
                        detail=f"aborted: kill switch tripped ({self._kill.reason or 'no reason'})",
                    ),
                )
                return await self._finalize(events, findings, status="fail")

            if msg.kind == "tool_use":
                await self._bridge_tool_use(events, msg)
            elif msg.kind == "text" and msg.text:
                last_text = msg.text
                await self._bridge_hypothesis(events, msg.text)
            elif msg.kind == "result":
                if msg.result_text:
                    last_text = msg.result_text
                await self._bridge_budget(events, msg, warned)

        # 4. Parse findings from the final text, persist + emit.
        findings = self._parse_findings(last_text)
        for finding in findings:
            await self._ledger.add_finding(finding)
            await self._emit(
                events,
                FindingEmitted(
                    session=self._session,
                    finding_id=finding.id,
                    severity=finding.severity,
                    cwe=finding.cwe,
                ),
            )

        return await self._finalize(events, findings, status="pass")

    # ----- bridges -------------------------------------------------------------------

    async def _bridge_tool_use(self, events: list[ProgressEvent], msg: RuntimeMessage) -> None:
        """Map a model tool-use request through the governance gate to a `GateDecision`."""
        decision = self._gate.check()
        await self._emit(
            events,
            GateDecision(
                session=self._session,
                gate=f"tool:{msg.tool_name or 'unknown'}",
                decision="pass" if decision["decision"] == "allow" else "fail",
                reason=decision["reason"],
            ),
        )

    async def _bridge_hypothesis(self, events: list[ProgressEvent], text: str) -> None:
        """Surface a model claim as a `HypothesisOpened` event (lightweight heuristic)."""
        stripped = text.strip()
        if not stripped or stripped.startswith("```"):
            return
        await self._emit(
            events,
            HypothesisOpened(
                session=self._session,
                hypothesis_id=f"hyp-{uuid.uuid4().hex[:8]}",
                statement=stripped[:280],
            ),
        )

    async def _bridge_budget(
        self, events: list[ProgressEvent], msg: RuntimeMessage, warned: set[float]
    ) -> None:
        """Convert terminal token usage to spend and emit `BudgetWarning` at thresholds."""
        spent = (
            msg.total_cost_usd
            if msg.total_cost_usd is not None
            else msg.input_tokens * _USD_PER_INPUT_TOKEN + msg.output_tokens * _USD_PER_OUTPUT_TOKEN
        )
        if self._max_budget_usd <= 0:
            return
        frac = spent / self._max_budget_usd
        for threshold in _BUDGET_THRESHOLDS:
            if frac >= threshold and threshold not in warned:
                warned.add(threshold)
                await self._emit(
                    events,
                    BudgetWarning(
                        session=self._session,
                        resource=f"budget_usd@{int(threshold * 100)}%",
                        used=spent,
                        limit=self._max_budget_usd,
                    ),
                )

    # ----- helpers -------------------------------------------------------------------

    def _build_prompt(self, corpus_section: str) -> str:
        return "\n\n".join(
            [
                self._skill.body.strip(),
                "## Threat model",
                self._threat_model_summary(),
                "## Corpus under review",
                corpus_section,
            ]
        )

    def _threat_model_summary(self) -> str:
        tm = self._threat_model
        assets = ", ".join(f"{a.id}({a.asset_class}/{a.weight})" for a in tm.assets)
        threats = "\n".join(
            f"- {t.id} [{t.stride}] on {t.element_id}: {t.description}" for t in tm.threats
        )
        return f"Assets: {assets or 'none'}\nThreats:\n{threats or '- none'}"

    def _parse_findings(self, text: str | None) -> list[Finding]:
        """Extract the last fenced JSON block and coerce it into `Finding` value objects."""
        if not text:
            return []
        matches = _JSON_BLOCK.findall(text)
        if not matches:
            return []
        try:
            parsed: Any = json.loads(matches[-1])
        except json.JSONDecodeError:
            return []
        records: list[Any] = cast("list[Any]", parsed if isinstance(parsed, list) else [parsed])
        findings: list[Finding] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            finding = self._record_to_finding(cast("dict[Any, Any]", rec))
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _record_to_finding(rec: dict[Any, Any]) -> Finding | None:
        rule_id = rec.get("rule_id") or rec.get("ruleId")
        uri = rec.get("uri") or rec.get("file")
        if not rule_id or not uri:
            return None
        severity = rec.get("severity", "warning")
        if severity not in {"error", "warning", "note", "none"}:
            severity = "warning"
        try:
            start_line = int(rec.get("start_line", 1) or 1)
        except (TypeError, ValueError):
            start_line = 1
        return Finding(
            id=rec.get("id") or f"finding-{uuid.uuid4().hex[:12]}",
            rule_id=str(rule_id),
            message=str(rec.get("message", "")),
            severity=severity,
            cwe=rec.get("cwe"),
            location=FindingLocation(
                uri=str(uri),
                start_line=max(1, start_line),
                snippet=rec.get("snippet"),
            ),
        )

    async def _emit(self, events: list[ProgressEvent], event: ProgressEvent) -> None:
        events.append(event)
        await self._emitter.emit(event)

    async def _finalize(
        self, events: list[ProgressEvent], findings: list[Finding], *, status: str
    ) -> ReviewResult:
        sarif = to_sarif_log(findings)
        await self._emit(
            events,
            RunComplete(
                session=self._session,
                findings_count=len(findings),
                status="pass" if status == "pass" else "fail",
            ),
        )
        return ReviewResult(
            findings=findings,
            sarif=sarif,
            audit_head_hash=self._audit_head_hash(),
            events=events,
        )

    def _audit_head_hash(self) -> str:
        audit = getattr(self._emitter, "_audit", None)
        if audit is None:
            return ""
        try:
            return audit._last_hash()
        except Exception:  # pragma: no cover - defensive
            return ""
