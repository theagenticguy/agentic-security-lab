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

import asyncio
import json
import os
import re
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import anyio.to_thread
import structlog
from asec_confidence import BaselineStrategy, bm25_recall
from asec_confidence import ConfidenceInputs as ScoringInputs
from asec_memory.board import HypothesisBoard
from asec_memory.models import (
    ConfidenceInputs,
    Finding,
    FindingLocation,
    Hypothesis,
)
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

from .agents import AgentDefinition, default_cwe_workers, pattern_match_score
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
        workers: Sequence[AgentDefinition] | None = None,
        board: HypothesisBoard | None = None,
        confidence: BaselineStrategy | None = None,
        entry_point_files: Sequence[str] | None = None,
    ) -> None:
        # The SDK Task tool must be available before any subagent fan-out (PLAN §2).
        os.environ.setdefault("CLAUDE_CODE_ENABLE_TASKS", "1")
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
        self._workers: tuple[AgentDefinition, ...] = tuple(
            workers if workers is not None else default_cwe_workers()
        )
        self._board = board
        self._confidence = confidence or BaselineStrategy()
        # Entry points anchor the deterministic reachability proxy: the closer a
        # finding's file is (by name) to an entry point, the shorter its taint path.
        self._entry_point_files: tuple[str, ...] = tuple(
            entry_point_files
            if entry_point_files is not None
            else tuple(sorted(self._corpus_files))[:1]
        )

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

        # 4. Parse findings from the final text. When a shared board is configured the
        #    Day-5 per-CWE fan-out + confidence dispatch supersedes the single-query parse;
        #    otherwise the Day-3 single-query path stands.
        if self._board is not None:
            findings = await self.spawn_subagents(self._workers, corpus_section, events=events)
        else:
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

    # ----- fan-out (Day 5) -----------------------------------------------------------

    async def spawn_subagents(
        self,
        specs: Sequence[AgentDefinition],
        corpus_section: str,
        *,
        events: list[ProgressEvent],
    ) -> list[Finding]:
        """Concurrently dispatch one worker per spec, dedup, correlate, and dispatch.

        Each worker runs its own `runtime.query()` on a CWE-scoped prompt slice. All
        workers write to a single shared `HypothesisBoard` keyed by
        ``dedup_key = "{cwe}:{file}:{range}"`` (first writer wins; dupes recorded, not
        re-emitted). A single correlation `query()` then proposes chain hypotheses,
        attaching `variants_of` linkage. Finally every unique finding is routed through
        `BaselineStrategy` to a tier-appropriate dispatch.
        """
        await self._emit(
            events, PhaseTransition(session=self._session, from_phase="find", to_phase="fanout")
        )

        results = await asyncio.gather(*(self._run_worker(spec, corpus_section) for spec in specs))

        board = self._board
        unique: dict[str, Finding] = {}
        spec_by_finding: dict[str, AgentDefinition] = {}
        for spec, parsed in zip(specs, results, strict=True):
            for finding in parsed:
                key = self._dedup_key(spec, finding)
                if key in unique:
                    # Dupe: record on the board but do not re-emit.
                    if board is not None:
                        board.append(
                            Hypothesis(
                                id=f"dup-{uuid.uuid4().hex[:8]}",
                                finding_id=unique[key].id,
                                statement=f"duplicate of {key} from {spec.name}",
                                status="refuted",
                            )
                        )
                    continue
                unique[key] = finding
                spec_by_finding[finding.id] = spec
                if board is not None:
                    board.append(
                        Hypothesis(
                            id=f"hyp-{uuid.uuid4().hex[:8]}",
                            finding_id=finding.id,
                            statement=f"{spec.cwe_id} candidate at {key}",
                            status="open",
                        )
                    )

        unique_findings = list(unique.values())

        # Correlation pass: a single LLM call proposes chain hypotheses across findings.
        linkage = await self._correlate(unique_findings)

        scored: list[Finding] = []
        for finding in unique_findings:
            spec = spec_by_finding[finding.id]
            variants = tuple(linkage.get(finding.id, ()))
            scored_finding = await self._dispatch_confidence(finding, spec, variants, events)
            scored.append(scored_finding)

        await self._emit(
            events,
            PhaseTransition(session=self._session, from_phase="fanout", to_phase="correlate"),
        )
        return scored

    async def _run_worker(self, spec: AgentDefinition, corpus_section: str) -> list[Finding]:
        """Run one CWE worker's own `query()` on a scoped prompt slice."""
        prompt = "\n\n".join(
            [
                self._skill.body.strip(),
                f"## Specialized worker: {spec.name} ({spec.cwe_id})",
                spec.system_prompt_extra,
                "## Corpus under review",
                corpus_section,
            ]
        )
        last_text: str | None = None
        async for msg in self._runtime.query(prompt, options=None):
            if msg.kind == "text" and msg.text:
                last_text = msg.text
            elif msg.kind == "result" and msg.result_text:
                last_text = msg.result_text
        return self._parse_findings(last_text)

    @staticmethod
    def _dedup_key(spec: AgentDefinition, finding: Finding) -> str:
        loc = finding.location
        rng = f"{loc.start_line}-{loc.end_line or loc.start_line}"
        cwe = finding.cwe or spec.cwe_id
        return f"{cwe}:{loc.uri}:{rng}"

    async def _correlate(self, findings: list[Finding]) -> dict[str, list[str]]:
        """One LLM call proposes chain hypotheses linking findings; returns id->variants.

        Findings that share an inferred chain are mutually linked via `variants_of`. The
        model returns a JSON array of ``{"chain": [finding_id, ...]}`` objects; each id in
        a chain links to the other ids. Falls back to an empty linkage if no chain parses.
        """
        if len(findings) < 2:
            return {}
        catalog = json.dumps([{"id": f.id, "cwe": f.cwe, "uri": f.location.uri} for f in findings])
        prompt = (
            "Given these security findings, propose attack-chain hypotheses linking "
            "findings that compose into a single exploit (e.g. IDOR->path-traversal->RCE). "
            'Reply with a single fenced ```json block of [{"chain": [finding_id, ...]}].\n'
            f"FINDINGS: {catalog}"
        )
        last_text: str | None = None
        async for msg in self._runtime.query(prompt, options=None):
            if msg.kind == "text" and msg.text:
                last_text = msg.text
            elif msg.kind == "result" and msg.result_text:
                last_text = msg.result_text

        linkage: dict[str, list[str]] = {}
        chains = self._parse_chains(last_text)
        valid_ids = {f.id for f in findings}
        for chain in chains:
            members = [fid for fid in chain if fid in valid_ids]
            for fid in members:
                others = [o for o in members if o != fid]
                linkage.setdefault(fid, [])
                for o in others:
                    if o not in linkage[fid]:
                        linkage[fid].append(o)
        return linkage

    def _parse_chains(self, text: str | None) -> list[list[str]]:
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
        chains: list[list[str]] = []
        for rec in records:
            if isinstance(rec, dict):
                chain = cast("dict[str, Any]", rec).get("chain")
                if isinstance(chain, list):
                    chains.append([str(c) for c in cast("list[Any]", chain)])
        return chains

    async def _dispatch_confidence(
        self,
        finding: Finding,
        spec: AgentDefinition,
        variants: tuple[str, ...],
        events: list[ProgressEvent],
    ) -> Finding:
        """Build `ConfidenceInputs`, score, and route to a tier-appropriate dispatch."""
        snippet = finding.location.snippet or finding.message
        pattern = pattern_match_score(snippet, spec.pattern_keywords)
        recall = bm25_recall(finding.message, await self._past_claims())
        reach = self._reachability(finding)

        score = await self._confidence.score(
            ScoringInputs(pattern_match=pattern, memory_recall=recall, reachability=reach)
        )

        conf_inputs = ConfidenceInputs(
            pattern_match=pattern, memory_recall=recall, reachability=reach
        )
        asec = finding.asec.model_copy(
            update={
                "confidence": score.score,
                "confidence_inputs": conf_inputs,
                "confidence_tier": score.tier,
                "dispatch": score.dispatch,
                "variants_of": variants,
            }
        )
        updated = finding.model_copy(update={"asec": asec})

        if score.tier == "high":
            # Use the specialized worker's finding directly.
            pass
        elif score.tier == "medium":
            await self._emit(
                events,
                HypothesisOpened(
                    session=self._session,
                    hypothesis_id=f"parallel-shell-{finding.id}",
                    statement=f"medium confidence: marked for parallel-shell ({finding.rule_id})",
                ),
            )
        elif score.tier == "low":
            await self._emit(
                events,
                HypothesisOpened(
                    session=self._session,
                    hypothesis_id=f"swarm-{finding.id}",
                    statement=f"low confidence: marked for swarm ({finding.rule_id})",
                ),
            )
        else:  # very_low -> runtime authorship gate (raised/refused)
            await self._emit(
                events,
                GateDecision(
                    session=self._session,
                    gate="confidence",
                    decision="fail",
                    reason="runtime_authorship_required",
                ),
            )
        return updated

    async def _past_claims(self) -> list[str]:
        """Past findings in this repo (from the ledger) as the BM25 recall corpus."""
        try:
            prior = await self._ledger.list_findings()
        except Exception:  # pragma: no cover - defensive
            return []
        return [f"{f.rule_id} {f.message}" for f in prior]

    def _reachability(self, finding: Finding) -> float:
        """Deterministic taint-hop proxy: import depth from the nearest entry point.

        Counts path-segment distance between the finding's file and the closest
        entry-point file; closer files are more reachable. Normalized to [0, 1].
        """
        if not self._entry_point_files:
            return 0.5
        target = finding.location.uri.split("/")
        best = min(self._path_distance(target, ep.split("/")) for ep in self._entry_point_files)
        # 0 hops -> 1.0; each hop decays reachability; floor at 0.1.
        return max(0.1, 1.0 / (1.0 + best))

    @staticmethod
    def _path_distance(a: list[str], b: list[str]) -> int:
        """Symmetric difference in path segments as a cheap call-graph-depth proxy."""
        sa, sb = set(a), set(b)
        return len(sa.symmetric_difference(sb))

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
