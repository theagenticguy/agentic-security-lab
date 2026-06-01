"""End-to-end wiring for the nightly variant-hunter app (Big Sleep "find more like this").

Five named stages read top-to-bottom, mirroring the variant loop::

    git_log_patches -> seed_findings_from_patches -> expand_to_repo -> aggregate -> report

The loop ingests the last N days of ``git log -p``, distils each recently-fixed bug into a
seed shape, asks the agent to find code with the same shape across the rest of the repo,
and files each variant linked to its seed via ``asec.variants_of``. Budget is enforced
through the orchestrator's :class:`GovernanceGate` (E19): each agent call is charged a
flat estimate and the gate denies further work once ``--max-budget-usd`` is reached.

Day-5 isolation note: this branch (`day5/nightly-variant`) merges after
`day5/fanout-confidence` finalizes the real ``Orchestrator``. To keep this branch
self-contained and its tests hermetic, the orchestrator is provided as a *local
placeholder* (``_VariantOrchestrator``) that runs the same compose-and-stream loop over an
injected fake ``AgentRuntime``. It is marked with a ``TODO(integration)`` showing the
one-line import swap. NOT production-grade.
"""

from __future__ import annotations

import json
import re
import subprocess
import uuid
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import cyclopts
from asec_confidence.models import ConfidenceInputs
from asec_confidence.strategies import BaselineStrategy
from asec_core.governance import GovernanceGate
from asec_core.scope import ScopeArtifact, sign_scope
from asec_memory.ledger import SQLiteLedger
from asec_memory.models import (
    AsecProperties,
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

app = cyclopts.App(
    name="nightly-variant-hunter",
    help="Big Sleep nightly variant analysis over recent git history.",
)

# Where the variant-analysis SKILL.md lives, relative to the repo root.
_SKILL_ROOTS = (Path("apps/nightly-variant-hunter/.claude/skills"),)
_SKILL_NAME = "variant-analysis"
_DENIED_PATHS = (".env", "*.pem")
_SESSION_PREFIX = "variant-hunter"

# Flat per-agent-call cost estimate (USD). Hermetic: no real Bedrock call in CI, so we
# attribute a nominal cost per query to exercise the budget gate deterministically.
_COST_PER_CALL_USD = 0.25

# Cap the number of recently-fixed bug shapes we chase per run, so a large history window
# cannot blow the budget on the seed stage before any variant expansion happens (risk 5).
_MAX_SEED_PATCHES = 10

# The committed dry-run corpus: a sample fix diff used when ``repo`` is not the root of its
# own git work tree (the hermetic CI path), so the loop is exercisable without a real repo.
_SAMPLE_DIFF = Path("apps/nightly-variant-hunter/fixtures/sample-diff.txt")


# --------------------------------------------------------------------------------------
# Value objects
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Patch:
    """One recently-fixed bug: the changed file plus the diff hunk that fixed it."""

    commit: str
    uri: str
    added: tuple[str, ...]
    removed: tuple[str, ...]

    @property
    def shape(self) -> str:
        """The bug shape: the vulnerable (removed) lines the fix replaced."""
        return "\n".join(self.removed)


@dataclass
class HuntResult:
    """Result of one variant-hunt run."""

    seeds: tuple[Finding, ...] = ()
    variants: tuple[Finding, ...] = ()
    sarif: dict[str, Any] = field(default_factory=lambda: dict[str, Any]())
    audit_head_hash: str = GENESIS
    events: tuple[ProgressEvent, ...] = ()
    spent_usd: float = 0.0
    budget_exhausted: bool = False


# --------------------------------------------------------------------------------------
# Day-5 placeholder collaborators (swapped for real imports on integration)
# --------------------------------------------------------------------------------------
_FINDINGS_JSON_RE = re.compile(r"```json\s*(?P<body>\[.*?\])\s*```", re.DOTALL)


def _canned_runtime() -> Any:
    """Build a fake ``AgentRuntime`` whose ``query`` mirrors the real SDK message shape.

    The stream yields a couple of read-only tool-use messages and then a final assistant
    message carrying findings as a single JSON code block. The findings echo any
    ``variants_of`` id embedded in the prompt, so the canned path produces a correctly
    linked variant just like a real worker would.

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
            seed_id = seed_id_from_prompt(prompt)
            findings = [
                {
                    "rule_id": "CWE-89",
                    "message": "SQL injection variant: same execute() shape as the seed fix.",
                    "severity": "error",
                    "cwe": "CWE-89",
                    "uri": "src/api/orders.py",
                    "start_line": 6,
                    "end_line": 6,
                    "snippet": 'cursor.execute(f"SELECT * FROM orders WHERE id = {oid}")',
                    "variants_of": seed_id,
                }
            ]
            yield {"type": "result", "text": f"```json\n{json.dumps(findings)}\n```"}

        async def spawn_subagents(self, specs: Sequence[Any]) -> Sequence[Any]:
            return []

    return _FakeRuntime()


_SEED_ID_RE = re.compile(r"variants_of:\s*(?P<id>[0-9a-fA-F-]+)")


def seed_id_from_prompt(prompt: str) -> str:
    match = _SEED_ID_RE.search(prompt)
    return match.group("id") if match else ""


class _VariantOrchestrator:
    """Local placeholder for ``asec_core.orchestrator.Orchestrator`` (Day-5 isolation).

    Composes runtime + sandbox + emitter + gate, charges each agent call against the
    budget, streams the runtime query, maps messages to typed ``ProgressEvent``s, and
    parses the final JSON block into ``Finding``s. The budget gate (E19) denies further
    work once ``max_budget_usd`` is reached.

    TODO(integration): replace with::

        from asec_core.orchestrator import Orchestrator

    and delete this class.
    """

    def __init__(
        self,
        *,
        runtime: Any,
        sandbox: LocalSandbox,
        emitter: EventEmitter,
        gate: GovernanceGate,
        skill: Skill,
        session: str,
        audit_path: Path,
    ) -> None:
        self._runtime = runtime
        self._sandbox = sandbox
        self._emitter = emitter
        self._gate = gate
        self._skill = skill
        self._session = session
        self._audit_path = audit_path
        self._events: list[ProgressEvent] = []
        self.spent_usd = 0.0
        self.budget_exhausted = False

    async def emit(self, event: ProgressEvent) -> None:
        self._events.append(event)
        await self._emitter.emit(event)

    @property
    def skill(self) -> Skill:
        return self._skill

    @property
    def events(self) -> tuple[ProgressEvent, ...]:
        return tuple(self._events)

    def audit_head(self) -> str:
        return _audit_head(self._audit_path)

    async def query_findings(self, prompt: str, *, phase: str) -> list[Finding]:
        """Charge one agent call against the budget, stream it, and parse findings.

        Returns an empty list (and sets ``budget_exhausted``) if the gate denies the call
        because the budget cap has been reached — the E19 hard stop.
        """
        decision = self._gate.check(spent_usd=self.spent_usd + _COST_PER_CALL_USD)
        allowed = decision["decision"] == "allow"
        await self.emit(
            GateDecision(
                session=self._session,
                gate=f"budget:{phase}",
                decision="pass" if allowed else "fail",
                reason=decision["reason"],
            )
        )
        if not allowed:
            self.budget_exhausted = True
            return []

        self.spent_usd += _COST_PER_CALL_USD
        await self.emit(PhaseTransition(session=self._session, from_phase="hunt", to_phase=phase))

        await self._sandbox.start()
        final_text = ""
        async for msg in self._runtime.query(prompt, options=None):
            kind = msg.get("type")
            if kind == "tool_use":
                tool_dec = self._gate.check(spent_usd=self.spent_usd)
                await self.emit(
                    GateDecision(
                        session=self._session,
                        gate=f"tool:{msg.get('name', '?')}",
                        decision="pass" if tool_dec["decision"] == "allow" else "fail",
                        reason=tool_dec["reason"],
                    )
                )
            elif kind == "result":
                final_text = str(msg.get("text", ""))
        await self._sandbox.teardown()
        return _parse_findings(final_text)


def _parse_findings(text: str) -> list[Finding]:
    match = _FINDINGS_JSON_RE.search(text)
    if match is None:
        return []
    raw: list[dict[str, Any]] = json.loads(match.group("body"))
    out: list[Finding] = []
    for item in raw:
        # The prompt contract emits a single string seed id (or null); the
        # AsecProperties model carries a tuple to support multi-seed correlation
        # in the orchestrator's correlation pass. Normalize.
        raw_variant = item.get("variants_of")
        variants_of: tuple[str, ...] = (str(raw_variant),) if raw_variant else ()
        out.append(
            Finding(
                id=str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"{item['rule_id']}:{item['uri']}:{raw_variant or 'seed'}",
                    )
                ),
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
                asec=AsecProperties(variants_of=variants_of),
            )
        )
    return out


# --------------------------------------------------------------------------------------
# Stage 1 — ingest recent git history
# --------------------------------------------------------------------------------------
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(?P<uri>.+)$")
_COMMIT_RE = re.compile(r"^commit (?P<sha>[0-9a-f]+)", re.MULTILINE)


def git_log_patches(repo: str, since: str) -> list[Patch]:
    """Stage 1 — read patches via ``git log --since=... -p --no-merges`` (subprocess).

    Extracts the changed file and the added/removed diff lines per file hunk. Uses real
    git only when ``repo`` is the *root* of its own git work tree; otherwise falls back to
    the committed ``fixtures/sample-diff.txt`` (the hermetic CI path), so the loop is
    exercisable without a real repo and never walks up into a parent work tree.
    """
    raw = _run_git_log(repo, since) if _is_git_root(repo) else None
    if raw is None:
        raw = _SAMPLE_DIFF.read_text(encoding="utf-8")
    return parse_patches(raw)[:_MAX_SEED_PATCHES]


def _is_git_root(repo: str) -> bool:
    """True iff ``repo`` is the top level of its own git work tree (not a nested subdir)."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode != 0:
        return False
    return Path(proc.stdout.strip()).resolve() == Path(repo).resolve()


def _run_git_log(repo: str, since: str) -> str | None:
    """Run read-only ``git log -p`` over ``repo``; return None if it yields nothing."""
    cmd = [
        "git",
        "-C",
        repo,
        "log",
        f"--since={since}",
        "-p",
        "--no-merges",
        "--no-color",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return proc.stdout


def parse_patches(raw: str) -> list[Patch]:
    """Parse unified-diff text into per-file :class:`Patch` records (added/removed lines)."""
    patches: list[Patch] = []
    commit = ""
    uri = ""
    added: list[str] = []
    removed: list[str] = []

    def flush() -> None:
        nonlocal added, removed
        if uri and (added or removed):
            patches.append(
                Patch(commit=commit, uri=uri, added=tuple(added), removed=tuple(removed))
            )
        added, removed = [], []

    for line in raw.splitlines():
        commit_match = _COMMIT_RE.match(line)
        if commit_match:
            flush()
            commit = commit_match.group("sha")
            uri = ""
            continue
        file_match = _DIFF_FILE_RE.match(line)
        if file_match:
            flush()
            uri = file_match.group("uri")
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    flush()
    return patches


# --------------------------------------------------------------------------------------
# Stage 2 — seed findings from the patched bug shapes
# --------------------------------------------------------------------------------------
async def seed_findings_from_patches(
    orch: _VariantOrchestrator, patches: Sequence[Patch]
) -> list[Finding]:
    """Stage 2 — for each patch, build a seed finding from the patched bug shape.

    The seed records the location of the bug that was just fixed; later stages ask the
    agent to find more code with the same shape.
    """
    seeds: list[Finding] = []
    for patch in patches:
        if orch.budget_exhausted:
            break
        prompt = _seed_prompt(orch.skill.body, patch)
        # The seed call confirms the just-fixed shape; charge it against the budget too.
        found = await orch.query_findings(prompt, phase="seed")
        if found:
            seeds.extend(found)
        else:
            # No agent finding (e.g. budget exhausted): synthesize the seed from the patch
            # so the variant expansion still has a shape to chase.
            if not orch.budget_exhausted:
                seeds.append(_seed_from_patch(patch))
    return seeds


def _seed_prompt(skill_body: str, patch: Patch) -> str:
    return (
        f"{skill_body}\n\n## Seed patch ({patch.commit[:8]} on {patch.uri})\n"
        f"The following vulnerable lines were just removed by a fix:\n"
        f"```\n{patch.shape}\n```\n"
        f"Confirm the bug shape and report it as a finding."
    )


def _seed_from_patch(patch: Patch) -> Finding:
    return Finding(
        id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"seed:{patch.commit}:{patch.uri}")),
        rule_id="CWE-89",
        message=f"Seed bug shape recently fixed in {patch.uri}.",
        severity="note",
        cwe="CWE-89",
        location=FindingLocation(uri=patch.uri, start_line=1, snippet=patch.shape[:200] or None),
    )


# --------------------------------------------------------------------------------------
# Stage 3 — expand each seed to repo-wide variants
# --------------------------------------------------------------------------------------
async def expand_to_repo(
    orch: _VariantOrchestrator, repo: str, seeds: Sequence[Finding]
) -> list[Finding]:
    """Stage 3 — for each seed, hunt the repo for code with the same shape.

    Each returned variant is tagged with ``asec.variants_of = <seed.id>`` so the linkage
    survives into the SARIF property bag and the ledger.
    """
    variants: list[Finding] = []
    for seed in seeds:
        if orch.budget_exhausted:
            break
        prompt = _expand_prompt(orch.skill.body, repo, seed)
        found = await orch.query_findings(prompt, phase="expand")
        for variant in found:
            # Defence in depth: enforce the linkage even if the agent omitted it.
            tagged = variant.model_copy(
                update={"asec": variant.asec.model_copy(update={"variants_of": seed.id})}
            )
            variants.append(tagged)
    return variants


def _expand_prompt(skill_body: str, repo: str, seed: Finding) -> str:
    return (
        f"{skill_body}\n\n## Variant hunt over {repo}\n"
        f"Seed finding ({seed.rule_id}) at {seed.location.uri}:{seed.location.start_line}\n"
        f"Shape: {seed.location.snippet or seed.message}\n"
        f"Find code in this repo with the same shape and report variants.\n"
        f"Tag every variant with variants_of: {seed.id}"
    )


# --------------------------------------------------------------------------------------
# Stage 4 — aggregate (score + persist variants)
# --------------------------------------------------------------------------------------
async def aggregate(variants: Sequence[Finding], ledger: SQLiteLedger) -> list[Finding]:
    """Stage 4 — score each variant (asec-confidence) and persist it (asec-memory)."""
    strategy = BaselineStrategy()
    scored: list[Finding] = []
    for variant in variants:
        inputs = ConfidenceInputs(pattern_match=0.9, memory_recall=0.6, reachability=0.7)
        confidence = await strategy.score(inputs)
        asec = variant.asec.model_copy(
            update={
                "reachability": Reachability(
                    verdict=ReachabilityVerdict.REACHABLE,
                    score=0.7,
                    rationale="same shape as a confirmed-and-fixed seed bug",
                ),
                "exploitability": Exploitability(score=0.7),
                "confidence": confidence.score,
                "priority": round(0.7 * 0.7 * confidence.score, 4),
            }
        )
        updated = variant.model_copy(update={"asec": asec})
        await ledger.add_finding(updated)
        scored.append(updated)
    return scored


# --------------------------------------------------------------------------------------
# Stage 5 — report (SARIF + ledger + 3 markdown reports)
# --------------------------------------------------------------------------------------
def report(seeds: Sequence[Finding], variants: Sequence[Finding], out_dir: Path) -> dict[str, Path]:
    """Stage 5 — write ``variants.sarif`` + Executive/Engineering/Auditor reports."""
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = out_dir / "variants.sarif"
    sarif_path.write_text(json.dumps(to_sarif_log(list(variants)), indent=2), encoding="utf-8")

    exec_path = out_dir / "REPORT_EXEC.md"
    eng_path = out_dir / "REPORT_ENG.md"
    audit_path = out_dir / "REPORT_AUDIT.md"

    exec_lines = [
        "# Executive Report — Nightly Variant Hunt",
        "",
        f"{len(seeds)} seed bug shape(s) ingested, {len(variants)} variant(s) found.",
        "",
    ]
    for v in sorted(variants, key=lambda f: f.priority, reverse=True)[:5]:
        exec_lines.append(f"- **{v.rule_id}** ({v.severity}) — {v.message}")
    exec_path.write_text("\n".join(exec_lines) + "\n", encoding="utf-8")

    eng_lines = ["# Engineering Report — Variants", ""]
    for v in variants:
        eng_lines += [
            f"## {v.rule_id} — {v.location.uri}:{v.location.start_line}",
            "",
            f"- variant_of seed: `{v.asec.variants_of}`",
            f"- severity: {v.severity}",
            f"- priority: {v.priority:.3f}",
            f"- snippet: `{v.location.snippet or ''}`",
            "",
        ]
    eng_path.write_text("\n".join(eng_lines) + "\n", encoding="utf-8")

    audit_lines = [
        "# Audit Report — Variant Linkage",
        "",
        "| variant | uri:line | variants_of |",
        "| --- | --- | --- |",
    ]
    for v in variants:
        loc = f"{v.location.uri}:{v.location.start_line}"
        audit_lines.append(f"| {v.rule_id} | {loc} | {v.asec.variants_of} |")
    audit_path.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

    return {"sarif": sarif_path, "exec": exec_path, "eng": eng_path, "audit": audit_path}


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def _audit_head(audit_path: Path) -> str:
    """Return the WORM chain head hash (sentinel ``GENESIS`` if the log is empty)."""
    entries = verify_chain(audit_path)
    return str(entries[-1]["hash"]) if entries else GENESIS


def load_skill() -> Skill:
    """Discover and return the ``variant-analysis`` skill."""
    skills = SkillLoader.discover(_SKILL_ROOTS)
    skill = next((s for s in skills if s.name == _SKILL_NAME), None)
    if skill is None:
        raise ValueError(f"skill {_SKILL_NAME!r} not found under {[str(r) for r in _SKILL_ROOTS]}")
    return skill


def _build_orchestrator(
    *,
    skill: Skill,
    runtime: Any,
    work_dir: Path,
    session: str,
    max_budget_usd: float,
) -> _VariantOrchestrator:
    """Compose the substrate (sandbox, ledger-adjacent audit, gate) for one hunt run."""
    work_dir.mkdir(parents=True, exist_ok=True)
    sandbox = LocalSandbox()
    audit = WormAuditWriter(work_dir / "audit.jsonl", session=session)
    emitter = EventEmitter(audit=audit)

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
        targets=(),
        egress_allowlist=(),
        signer="",
        signature="",
    )
    scope = sign_scope(unsigned, private_pem, signer="variant-hunter-dev")
    gate = GovernanceGate(scope=scope, public_key_pem=public_pem, max_budget_usd=max_budget_usd)

    async def _pre_tool_use(
        input_data: dict[str, Any], tool_use_id: str | None, context: Any
    ) -> dict[str, Any] | None:
        return await permission_gate(
            input_data,
            tool_use_id,
            context,
            allowed_tools=skill.allowed_tools,
            denied_paths=_DENIED_PATHS,
        )

    runtime.register_hook("PreToolUse", _pre_tool_use)
    return _VariantOrchestrator(
        runtime=runtime,
        sandbox=sandbox,
        emitter=emitter,
        gate=gate,
        skill=skill,
        session=session,
        audit_path=audit.path,
    )


async def run_hunt(
    repo: str,
    since: str,
    *,
    max_budget_usd: float,
    out_dir: Path,
    runtime: Any | None = None,
) -> HuntResult:
    """Drive the full variant-hunt pipeline; ``runtime`` is injectable for tests."""
    session = f"{_SESSION_PREFIX}-{uuid.uuid4().hex[:8]}"
    skill = load_skill()
    active_runtime: Any = runtime if runtime is not None else _canned_runtime()

    orch = _build_orchestrator(
        skill=skill,
        runtime=active_runtime,
        work_dir=out_dir,
        session=session,
        max_budget_usd=max_budget_usd,
    )
    ledger = await SQLiteLedger(str(out_dir / "findings.db")).init()

    patches = git_log_patches(repo, since)
    seeds = await seed_findings_from_patches(orch, patches)
    variants = await expand_to_repo(orch, repo, seeds)
    scored = await aggregate(variants, ledger)
    report(seeds, scored, out_dir)

    for f in scored:
        await orch.emit(
            FindingEmitted(session=session, finding_id=f.id, severity=f.severity, cwe=f.cwe)
        )
    await orch.emit(
        RunComplete(
            session=session,
            findings_count=len(scored),
            status="pass" if scored else "fail",
        )
    )

    return HuntResult(
        seeds=tuple(seeds),
        variants=tuple(scored),
        sarif=to_sarif_log(list(scored)),
        audit_head_hash=orch.audit_head(),
        events=orch.events,
        spent_usd=orch.spent_usd,
        budget_exhausted=orch.budget_exhausted,
    )


# --------------------------------------------------------------------------------------
# CLI entrypoint
# --------------------------------------------------------------------------------------
async def _hunt_async(repo: str, since: str, max_budget_usd: float, out_dir: str) -> None:
    result = await run_hunt(repo, since, max_budget_usd=max_budget_usd, out_dir=Path(out_dir))
    status = "budget-exhausted" if result.budget_exhausted else "complete"
    print(
        f"Variant hunt {status}: {len(result.seeds)} seed(s), "
        f"{len(result.variants)} variant(s), ${result.spent_usd:.2f} spent "
        f"(cap ${max_budget_usd:.2f}). SARIF -> {Path(out_dir) / 'variants.sarif'}"
    )


@app.command
def hunt(
    repo: str = ".",
    since: str = "30 days ago",
    max_budget_usd: float = 5.0,
    out_dir: str = ".asec-variant-run",
) -> None:
    """Hunt for variants of recently-fixed bugs across ``repo`` (Big Sleep loop)."""
    anyio.run(_hunt_async, repo, since, max_budget_usd, out_dir)


if __name__ == "__main__":
    app()
