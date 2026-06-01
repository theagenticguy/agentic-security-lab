"""End-to-end wiring for the pr-reviewer proof app.

Five named functions read top-to-bottom (C's legibility), mirroring the review loop::

    load_target -> build_threat_model -> run_review -> score_and_store -> report

Day-3 isolation note: this branch (`day3/pr-reviewer`) merges LAST, after
`day3/orchestrator` and `day3/report-agent`. To keep this branch self-contained and its
tests hermetic, two collaborators are provided as *local placeholders*:

  * ``_DayThreeOrchestrator`` — stands in for ``asec_core.orchestrator.Orchestrator``.
    It runs the same compose-and-stream loop the real orchestrator will, but over an
    injected fake ``AgentRuntime`` whose ``query`` yields a canned tool-use stream plus a
    final JSON block of findings (mirrors the real Bedrock contract).
  * ``_DayThreeReportAgent`` — stands in for
    ``asec_memory.report.ReportAgentImpl``. Reads the ledger and writes three markdown
    reports deterministically.

Each is marked with a ``TODO(integration)`` showing the one-line import swap. NOT
production-grade.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import cyclopts
from asec_confidence.models import ConfidenceInputs
from asec_confidence.strategies import BaselineStrategy
from asec_core.governance import GovernanceGate
from asec_core.scope import ScopeArtifact, sign_scope
from asec_core.settings import Settings
from asec_memory.ledger import SQLiteLedger
from asec_memory.models import (
    AsecProperties,
    AssetWeight,
    AssetWeightTier,
    Exploitability,
    Finding,
    FindingLocation,
    Reachability,
    ReachabilityVerdict,
)
from asec_memory.sarif import to_sarif_log
from asec_sandbox.audit import GENESIS, WormAuditWriter, verify_chain
from asec_sandbox.events import (
    EventEmitter,
    FindingEmitted,
    GateDecision,
    PhaseTransition,
    ProgressEvent,
    RunComplete,
)
from asec_sandbox.sandbox import LocalSandbox
from asec_skills.gate import permission_gate
from asec_skills.loader import SkillLoader
from asec_skills.skill import Skill
from asec_threat_model import io as tm_io
from asec_threat_model.models import ThreatModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict

app = cyclopts.App(name="pr-reviewer", help="Agentic security review over a tiny corpus.")

# Where the security-code-review SKILL.md lives, relative to the repo root.
_SKILL_ROOTS = (Path("apps/pr-reviewer/.claude/skills"),)
_SKILL_NAME = "security-code-review"
_DENIED_PATHS = (".env", "*.pem")
_SESSION_PREFIX = "pr-reviewer"


# --------------------------------------------------------------------------------------
# Value objects
# --------------------------------------------------------------------------------------
class TargetCorpus(BaseModel):
    """The loaded review target: every source file plus the discovered skill."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    root: Path
    files: dict[str, str]
    skill: Skill


class ReviewResult(BaseModel):
    """Result of one orchestrated review run.

    TODO(integration): replace with ``asec_core.ReviewResult`` once
    ``day3/orchestrator`` has landed on ``main``; the shape is intentionally identical.
    """

    model_config = ConfigDict(frozen=True)

    findings: tuple[Finding, ...]
    sarif: dict[str, Any]
    audit_head_hash: str
    events: tuple[ProgressEvent, ...]


# --------------------------------------------------------------------------------------
# Day-3 placeholder collaborators (swapped for real imports on integration)
# --------------------------------------------------------------------------------------
def _canned_runtime_stream(findings_json: str) -> Any:
    """Build a fake ``AgentRuntime`` whose ``query`` mirrors the real SDK message shape.

    The stream yields a couple of read-only tool-use messages (Grep, Read) and then a
    final assistant message carrying the findings as a single JSON code block, exactly
    as the security-code-review SKILL output contract specifies.

    TODO(integration): delete; the real ``ClaudeAgentRuntime`` + Bedrock provides this.
    """

    class _FakeRuntime:
        def __init__(self) -> None:
            self._hooks: dict[str, list[Any]] = {}

        def register_hook(self, event: str, hook: Any) -> None:
            self._hooks.setdefault(event, []).append(hook)

        async def query(
            self, prompt: str, *, options: Any | None = None
        ) -> AsyncIterator[dict[str, Any]]:
            yield {"type": "tool_use", "name": "Grep", "input": {"pattern": "execute"}}
            yield {"type": "tool_use", "name": "Read", "input": {"file_path": "src/api/users.py"}}
            yield {"type": "result", "text": f"```json\n{findings_json}\n```"}

        async def spawn_subagents(self, specs: Sequence[Any]) -> Sequence[Any]:
            return []

    return _FakeRuntime()


_FINDINGS_JSON_RE = re.compile(r"```json\s*(?P<body>\[.*?\])\s*```", re.DOTALL)


class _DayThreeOrchestrator:
    """Local placeholder for ``asec_core.orchestrator.Orchestrator`` (Day-3 isolation).

    Composes runtime + sandbox + ledger + emitter + gate, runs the gate, streams the
    runtime query, maps messages to typed ``ProgressEvent``s, parses the final JSON block
    into ``Finding``s, and builds the SARIF log.

    TODO(integration): replace with::

        from asec_core.orchestrator import Orchestrator, ReviewResult

    and delete this class + the local ``ReviewResult``.
    """

    def __init__(
        self,
        *,
        runtime: Any,
        sandbox: LocalSandbox,
        emitter: EventEmitter,
        gate: GovernanceGate,
        skill: Skill,
        threat_model: ThreatModel,
        session: str,
        audit_path: Path,
    ) -> None:
        self._runtime = runtime
        self._sandbox = sandbox
        self._emitter = emitter
        self._gate = gate
        self._skill = skill
        self._tm = threat_model
        self._session = session
        self._audit_path = audit_path

    def _build_prompt(self, corpus: TargetCorpus) -> str:
        tm_summary = "\n".join(
            f"- {t.id} ({t.stride}) on {t.element_id}: {t.description}" for t in self._tm.threats
        )
        files = "\n\n".join(
            f"### {uri}\n```python\n{body}\n```" for uri, body in sorted(corpus.files.items())
        )
        return f"{self._skill.body}\n\n## Threat model\n{tm_summary}\n\n## Corpus\n{files}"

    async def run(self, scope: ScopeArtifact, corpus: TargetCorpus) -> ReviewResult:
        events: list[ProgressEvent] = []

        async def emit(event: ProgressEvent) -> None:
            events.append(event)
            await self._emitter.emit(event)

        decision = self._gate.check()
        passed = decision["decision"] == "allow"
        await emit(
            GateDecision(
                session=self._session,
                gate="governance",
                decision="pass" if passed else "fail",
                reason=decision["reason"],
            )
        )
        if not passed:
            return ReviewResult(
                findings=(),
                sarif=to_sarif_log([]),
                audit_head_hash=_audit_head(self._audit_path),
                events=tuple(events),
            )

        await emit(PhaseTransition(session=self._session, from_phase="recon", to_phase="find"))

        await self._sandbox.start()
        prompt = self._build_prompt(corpus)
        final_text = ""
        async for msg in self._runtime.query(prompt, options=None):
            kind = msg.get("type")
            if kind == "tool_use":
                # Bridge each requested tool through the gate (model claim -> decision).
                gate_dec = self._gate.check()
                await emit(
                    GateDecision(
                        session=self._session,
                        gate=f"tool:{msg.get('name', '?')}",
                        decision="pass" if gate_dec["decision"] == "allow" else "fail",
                        reason=gate_dec["reason"],
                    )
                )
            elif kind == "result":
                final_text = str(msg.get("text", ""))
        await self._sandbox.teardown()

        findings = self._parse_findings(final_text)
        for f in findings:
            await emit(
                FindingEmitted(
                    session=self._session,
                    finding_id=f.id,
                    severity=f.severity,
                    cwe=f.cwe,
                )
            )

        sarif = to_sarif_log(findings)
        await emit(
            RunComplete(
                session=self._session,
                findings_count=len(findings),
                status="pass" if findings else "fail",
            )
        )

        return ReviewResult(
            findings=tuple(findings),
            sarif=sarif,
            audit_head_hash=_audit_head(self._audit_path),
            events=tuple(events),
        )

    def _parse_findings(self, text: str) -> list[Finding]:
        match = _FINDINGS_JSON_RE.search(text)
        if match is None:
            return []
        raw: list[dict[str, Any]] = json.loads(match.group("body"))
        out: list[Finding] = []
        for item in raw:
            out.append(
                Finding(
                    id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{item['rule_id']}:{item['uri']}")),
                    rule_id=str(item["rule_id"]),
                    message=str(item["message"]),
                    severity=item.get("severity", "warning"),
                    cwe=item.get("cwe"),
                    location=FindingLocation(
                        uri=str(item["uri"]),
                        start_line=int(item["start_line"]),
                        end_line=item.get("end_line"),
                        snippet=item.get("snippet"),
                    ),
                )
            )
        return out


class _DayThreeReportAgent:
    """Local placeholder for ``asec_memory.report.ReportAgentImpl`` (Day-3 isolation).

    Reads the ledger only (idempotent) and writes three deterministic markdown reports.

    TODO(integration): replace with::

        from asec_memory.report import ReportAgentImpl

    and delete this class.
    """

    def __init__(self, ledger: SQLiteLedger, threat_model: ThreatModel, out_dir: Path) -> None:
        self._ledger = ledger
        self._tm = threat_model
        self._out_dir = out_dir

    async def generate(self) -> dict[str, Path]:
        findings = list(await self._ledger.list_findings())
        self._out_dir.mkdir(parents=True, exist_ok=True)
        exec_path = self._out_dir / "REPORT_EXEC.md"
        eng_path = self._out_dir / "REPORT_ENG.md"
        audit_path = self._out_dir / "REPORT_AUDIT.md"

        top = sorted(findings, key=lambda f: f.priority, reverse=True)[:5]
        exec_lines = ["# Executive Report", "", f"{len(findings)} finding(s) recorded.", ""]
        for f in top:
            exec_lines.append(f"- **{f.rule_id}** ({f.severity}) — {f.message}")
        exec_path.write_text("\n".join(exec_lines) + "\n", encoding="utf-8")

        eng_lines = ["# Engineering Report", ""]
        for f in findings:
            eng_lines += [
                f"## {f.rule_id} — {f.location.uri}:{f.location.start_line}",
                "",
                f"- severity: {f.severity}",
                f"- priority: {f.priority:.3f}",
                f"- snippet: `{f.location.snippet or ''}`",
                "- suggested patch: TODO",
                f"- regression test: tests/regression/test_{f.rule_id.lower().replace('-', '_')}.py",
                "",
            ]
        eng_path.write_text("\n".join(eng_lines) + "\n", encoding="utf-8")

        audit_lines = [
            "# Audit Report",
            "",
            f"- threat-model version: {self._tm.version}",
            f"- generated_by: {self._tm.generated_by}",
            "",
            "## Threat-model coverage",
            "",
            "| threat | element | covered |",
            "| --- | --- | --- |",
        ]
        covered_uris = {f.location.uri for f in findings}
        for t in self._tm.threats:
            mark = "yes" if t.element_id in covered_uris else "no"
            audit_lines.append(f"| {t.id} | {t.element_id} | {mark} |")
        audit_path.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

        return {"exec": exec_path, "eng": eng_path, "audit": audit_path}


# --------------------------------------------------------------------------------------
# The five review stages (§5)
# --------------------------------------------------------------------------------------
def load_target(target: Path) -> TargetCorpus:
    """Stage 1 — read every file under ``target/src`` and discover the review skill."""
    src_root = target / "src"
    files: dict[str, str] = {}
    for path in sorted(src_root.rglob("*.py")):
        if path.is_file():
            files[str(path.relative_to(target))] = path.read_text(encoding="utf-8")

    skills = SkillLoader.discover(_SKILL_ROOTS)
    skill = next((s for s in skills if s.name == _SKILL_NAME), None)
    if skill is None:
        raise ValueError(f"skill {_SKILL_NAME!r} not found under {[str(r) for r in _SKILL_ROOTS]}")
    return TargetCorpus(root=target, files=files, skill=skill)


def build_threat_model(corpus: TargetCorpus) -> ThreatModel:
    """Stage 2 — load the hand-written ``threat-model.yaml`` fixture (asec-threat-model)."""
    return tm_io.load(corpus.root / "threat-model.yaml")


async def run_review(
    corpus: TargetCorpus,
    threat_model: ThreatModel,
    *,
    runtime: Any | None = None,
    work_dir: Path | None = None,
) -> tuple[ReviewResult, SQLiteLedger]:
    """Stage 3 — compose the substrate and run the orchestrated review loop.

    ``runtime`` is injectable so tests pass a fake; production passes ``None`` and gets the
    canned Day-3 stream. ``work_dir`` is where the ledger + WORM audit live.

    TODO(integration): replace ``_DayThreeOrchestrator`` with
    ``asec_core.orchestrator.Orchestrator`` and pass it the same DI'd collaborators.
    """
    work = work_dir or (corpus.root.parent / ".asec-run")
    work.mkdir(parents=True, exist_ok=True)
    session = f"{_SESSION_PREFIX}-{uuid.uuid4().hex[:8]}"

    settings = Settings()
    sandbox = LocalSandbox()
    ledger = await SQLiteLedger(str(work / "findings.db")).init()
    audit = WormAuditWriter(work / "audit.jsonl", session=session)
    emitter = EventEmitter(audit=audit)

    # Self-signed dev scope: an ephemeral Ed25519 key authorizes this single run.
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = datetime.now(UTC)
    unsigned = ScopeArtifact(
        id=session,
        created_at=now,
        expires_at=now + timedelta(hours=1),
        targets=(str(corpus.root),),
        egress_allowlist=(),
        signer="",
        signature="",
    )
    scope = sign_scope(unsigned, private_pem, signer="pr-reviewer-dev")
    gate = GovernanceGate(
        scope=scope,
        public_key_pem=public_pem,
        max_budget_usd=settings.max_budget_usd,
    )

    active_runtime: Any = (
        runtime if runtime is not None else _canned_runtime_stream(_default_findings_json(corpus))
    )

    # PreToolUse permission gate, bound to the skill's allowed tools + denied paths.
    async def _pre_tool_use(
        input_data: dict[str, Any], tool_use_id: str | None, context: Any
    ) -> dict[str, Any] | None:
        return await permission_gate(
            input_data,
            tool_use_id,
            context,
            allowed_tools=corpus.skill.allowed_tools,
            denied_paths=_DENIED_PATHS,
        )

    active_runtime.register_hook("PreToolUse", _pre_tool_use)

    orchestrator = _DayThreeOrchestrator(
        runtime=active_runtime,
        sandbox=sandbox,
        emitter=emitter,
        gate=gate,
        skill=corpus.skill,
        threat_model=threat_model,
        session=session,
        audit_path=audit.path,
    )
    result = await orchestrator.run(scope, corpus)
    return result, ledger


async def score_and_store(
    result: ReviewResult, threat_model: ThreatModel, ledger: SQLiteLedger
) -> list[Finding]:
    """Stage 4 — score each finding (asec-confidence) and persist it (asec-memory)."""
    strategy = BaselineStrategy()
    asset_by_element = {t.element_id: t for t in threat_model.threats}
    weight_by_id = {a.id: a.weight for a in threat_model.assets}
    scored: list[Finding] = []
    for finding in result.findings:
        threat = asset_by_element.get(finding.location.uri)
        reachability = 0.9 if threat else 0.5
        inputs = ConfidenceInputs(
            pattern_match=0.9,
            memory_recall=0.5,
            reachability=reachability,
        )
        confidence = await strategy.score(inputs)
        tier = _asset_tier(threat, weight_by_id)
        asec = AsecProperties(
            reachability=Reachability(
                verdict=ReachabilityVerdict.REACHABLE if threat else ReachabilityVerdict.UNKNOWN,
                score=reachability,
                rationale="threat-model element match" if threat else None,
            ),
            exploitability=Exploitability(score=0.7),
            asset=AssetWeight(tier=tier, score=_tier_score(tier)),
            confidence=confidence.score,
            priority=round(reachability * 0.7 * _tier_score(tier), 4),
        )
        updated = finding.model_copy(update={"asec": asec})
        await ledger.add_finding(updated)
        scored.append(updated)
    return scored


async def report(
    scored: Sequence[Finding],
    threat_model: ThreatModel,
    ledger: SQLiteLedger,
    *,
    out_dir: Path,
) -> dict[str, Path]:
    """Stage 5 — write ``findings.sarif`` + 3 reports, print the Engineering PASS/FAIL gate.

    TODO(integration): replace ``_DayThreeReportAgent`` with
    ``asec_memory.report.ReportAgentImpl(ledger, threat_model, out_dir)``.
    """
    sarif_path = _write_sarif(scored, out_dir)

    agent = _DayThreeReportAgent(ledger, threat_model, out_dir)
    paths = await agent.generate()
    paths["sarif"] = sarif_path

    has_high = any(f.severity == "error" for f in scored)
    gate = "FAIL" if has_high else "PASS"
    print(f"Engineering gate: {gate} ({len(scored)} findings, SARIF -> {sarif_path})")
    return paths


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
_TIER_SCORES: dict[AssetWeightTier, float] = {
    AssetWeightTier.CRITICAL: 1.0,
    AssetWeightTier.HIGH: 0.85,
    AssetWeightTier.MEDIUM: 0.5,
    AssetWeightTier.LOW: 0.25,
}


def _audit_head(audit_path: Path) -> str:
    """Return the WORM chain head hash (sentinel ``GENESIS`` if the log is empty)."""
    entries = verify_chain(audit_path)
    return str(entries[-1]["hash"]) if entries else GENESIS


def _write_sarif(scored: Sequence[Finding], out_dir: Path) -> Path:
    """Serialize findings to ``findings.sarif`` (sync; kept out of the async path)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = out_dir / "findings.sarif"
    sarif_path.write_text(json.dumps(to_sarif_log(list(scored)), indent=2), encoding="utf-8")
    return sarif_path


def _tier_score(tier: AssetWeightTier) -> float:
    return _TIER_SCORES[tier]


def _asset_tier(threat: Any, weight_by_id: dict[str, str]) -> AssetWeightTier:
    # The fixture's threat descriptions reference asset weights; map HIGH/MED/LOW onto the
    # memory tiers. Without a threat match, default MEDIUM.
    if threat is None:
        return AssetWeightTier.MEDIUM
    mapping = {
        "HIGH": AssetWeightTier.HIGH,
        "MED": AssetWeightTier.MEDIUM,
        "LOW": AssetWeightTier.LOW,
    }
    return mapping.get(threat.impact, AssetWeightTier.MEDIUM)


def _default_findings_json(corpus: TargetCorpus) -> str:
    """The canned final-message findings the Day-3 stream emits (3 CWEs over the corpus)."""
    findings = [
        {
            "rule_id": "CWE-89",
            "message": "SQL injection: request parameter interpolated into a SELECT statement.",
            "severity": "error",
            "cwe": "CWE-89",
            "uri": "src/api/users.py",
            "start_line": 17,
            "end_line": 18,
            "snippet": "cursor.execute(f\"SELECT * FROM users WHERE name='{name}'\")",
        },
        {
            "rule_id": "CWE-79",
            "message": "Reflected XSS: query parameter rendered into HTML without escaping.",
            "severity": "error",
            "cwe": "CWE-79",
            "uri": "src/web/render.py",
            "start_line": 13,
            "end_line": 13,
            "snippet": "return f\"<div>{request.args['q']}</div>\"",
        },
        {
            "rule_id": "CWE-22",
            "message": "Path traversal: untrusted path joined to BASE with no containment check.",
            "severity": "error",
            "cwe": "CWE-22",
            "uri": "src/files/download.py",
            "start_line": 18,
            "end_line": 20,
            "snippet": "path = os.path.join(BASE, requested)",
        },
    ]
    _ = corpus  # corpus is available for a future grounded variant
    return json.dumps(findings)


# --------------------------------------------------------------------------------------
# CLI entrypoint
# --------------------------------------------------------------------------------------
async def _review_async(target: str) -> None:
    path = Path(target)
    corpus = load_target(path)
    threat_model = build_threat_model(corpus)
    result, ledger = await run_review(corpus, threat_model)
    scored = await score_and_store(result, threat_model, ledger)
    await report(scored, threat_model, ledger, out_dir=path.parent / ".asec-run")


@app.command
def review(target: str = "fixtures/tiny-repo") -> None:
    """Run the end-to-end review over ``target`` (defaults to the committed fixture)."""
    anyio.run(_review_async, target)


if __name__ == "__main__":
    app()
