"""ReportAgent: deterministic Executive / Engineering / Auditor markdown reports.

The Day-3 :class:`ReportAgentImpl` is a pure Python string-builder over the
findings ledger — no second LLM pass — so CI stays hermetic and reruns are
byte-identical (E12 reporting, PLAN §6). It reads :meth:`LedgerPort.list_findings`
once and emits three audience-specific markdown files into ``out_dir``:

* ``REPORT_EXEC.md`` — top-5 findings by derived priority, executive prose.
* ``REPORT_ENG.md`` — one card per HIGH/error finding; MED/LOW deferred.
* ``REPORT_AUDIT.md`` — threat-model coverage, model/skill provenance, WORM range.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

import structlog

from asec_memory.models import Finding

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from asec_threat_model.models import ThreatModel

    from asec_memory.ledger import LedgerPort

log = structlog.get_logger(__name__)

_EXEC_FILE = "REPORT_EXEC.md"
_ENG_FILE = "REPORT_ENG.md"
_AUDIT_FILE = "REPORT_AUDIT.md"

# Severities treated as "must-fix now" for the Engineering report.
_HIGH_SEVERITIES = frozenset({"error"})


def _priority(finding: Finding) -> float:
    """Ranking score = Reachability x Exploitability x Asset weight (whitepaper section 06).

    Pure product of the three unit-interval axes from the ``asec.v1`` bag. When the
    persisted ``asec.priority`` is already populated it is used as the source of
    truth; otherwise the product is computed on the fly. Both are in ``[0, 1]``.
    """
    persisted = finding.asec.priority
    if persisted > 0.0:
        return persisted
    return (
        finding.asec.reachability.score
        * finding.asec.exploitability.score
        * finding.asec.asset.score
    )


def _sort_key(finding: Finding) -> tuple[float, str]:
    """Sort by priority descending, breaking ties on ``id`` for idempotency."""
    return (-_priority(finding), finding.id)


def _is_high(finding: Finding) -> bool:
    return finding.severity in _HIGH_SEVERITIES


def _snippet(finding: Finding) -> str:
    snippet = finding.location.snippet
    if snippet:
        return snippet.strip()
    return "<no snippet captured>"


def _loc(finding: Finding) -> str:
    return f"{finding.location.uri}:{finding.location.start_line}"


@runtime_checkable
class ReportAgent(Protocol):
    """Renders the findings ledger into audience-specific markdown reports (E12)."""

    async def generate(self) -> dict[str, Path]:
        """Write the report set and return a ``{audience: path}`` map."""
        ...


class ReportAgentImpl(ReportAgent):
    """Deterministic markdown reporter over a :class:`LedgerPort` (PLAN §6)."""

    def __init__(
        self,
        ledger: LedgerPort,
        threat_model: ThreatModel | None,
        out_dir: Path,
        *,
        model_id: str = "global.anthropic.claude-opus-4-8",
        skill_name: str = "security-code-review",
        worm_head_range: tuple[str, str] | None = None,
    ) -> None:
        self._ledger = ledger
        self._threat_model = threat_model
        self._out_dir = out_dir
        self._model_id = model_id
        self._skill_name = skill_name
        self._worm_head_range = worm_head_range

    async def generate(self) -> dict[str, Path]:
        """Read the ledger once and write all three reports. Idempotent."""
        findings = sorted(await self._ledger.list_findings(), key=_sort_key)
        self._out_dir.mkdir(parents=True, exist_ok=True)

        exec_path = self._out_dir / _EXEC_FILE
        eng_path = self._out_dir / _ENG_FILE
        audit_path = self._out_dir / _AUDIT_FILE

        exec_path.write_text(self._render_exec(findings), encoding="utf-8")
        eng_path.write_text(self._render_eng(findings), encoding="utf-8")
        audit_path.write_text(self._render_audit(findings), encoding="utf-8")

        log.info(
            "report.generate",
            findings=len(findings),
            out_dir=str(self._out_dir),
        )
        return {"exec": exec_path, "engineering": eng_path, "audit": audit_path}

    # -- Executive ---------------------------------------------------------

    def _render_exec(self, findings: Sequence[Finding]) -> str:
        top = list(findings[:5])
        deferred = list(findings[5:])
        lines: list[str] = ["# Executive Security Report", ""]

        if not findings:
            lines += [
                "No findings were recorded for this review. The reviewed scope "
                "produced zero security findings above the reporting threshold.",
                "",
                "## Top findings",
                "",
                "_None._",
                "",
            ]
            return "\n".join(lines)

        high = sum(1 for f in findings if _is_high(f))
        lines += [
            (
                f"This review surfaced {len(findings)} finding(s), of which {high} "
                "are high-severity and warrant immediate engineering attention. The "
                "five highest-priority items below are ranked by reachability, "
                "exploitability, and the weight of the asset they touch."
            ),
            "",
            "## Top findings",
            "",
            "| Rank | ID | Rule | Severity | Priority | Location |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for rank, f in enumerate(top, start=1):
            lines.append(
                f"| {rank} | {f.id} | {f.rule_id} | {f.severity} | {_priority(f):.3f} | {_loc(f)} |"
            )
        lines += ["", "## Affected components", ""]
        lines += self._component_table(top)
        lines += ["", "## Deferred", ""]
        if deferred:
            for f in deferred:
                lines.append(f"- {f.id} ({f.rule_id}, {f.severity}) at {_loc(f)}")
        else:
            lines.append("_No deferred findings._")
        lines.append("")
        return "\n".join(lines)

    def _component_table(self, findings: Sequence[Finding]) -> list[str]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.location.uri] = counts.get(f.location.uri, 0) + 1
        rows = ["| Component | Findings |", "| --- | --- |"]
        for uri in sorted(counts):
            rows.append(f"| {uri} | {counts[uri]} |")
        return rows

    # -- Engineering -------------------------------------------------------

    def _render_eng(self, findings: Sequence[Finding]) -> str:
        high = [f for f in findings if _is_high(f)]
        deferred = [f for f in findings if not _is_high(f)]
        lines: list[str] = ["# Engineering Remediation Report", "", "## High severity", ""]

        if high:
            for f in high:
                lines += self._eng_card(f)
        else:
            lines += ["_No high-severity findings._", ""]

        lines += ["## Deferred", ""]
        if deferred:
            for f in deferred:
                lines.append(f"- `{f.id}` {f.rule_id} ({f.severity}) at {_loc(f)} — {f.message}")
        else:
            lines.append("_No deferred findings._")
        lines.append("")
        return "\n".join(lines)

    def _eng_card(self, f: Finding) -> list[str]:
        cwe = f.cwe or "CWE-unspecified"
        test_path = f"tests/regression/test_{f.rule_id.replace('/', '_')}.py"
        return [
            f"### {f.id} — {f.rule_id} ({cwe})",
            "",
            f"- **Location:** `{_loc(f)}`",
            f"- **Severity:** {f.severity}",
            f"- **Priority:** {_priority(f):.3f}",
            f"- **Message:** {f.message}",
            "",
            "**Evidence**",
            "",
            "```",
            _snippet(f),
            "```",
            "",
            "**Suggested patch**",
            "",
            "_TODO: propose a fix (placeholder — populated by remediation pass)._",
            "",
            "**Regression test**",
            "",
            f"_Add coverage at_ `{test_path}`",
            "",
        ]

    # -- Auditor -----------------------------------------------------------

    def _render_audit(self, findings: Sequence[Finding]) -> str:
        lines: list[str] = [
            "# Auditor Report",
            "",
            "## Provenance",
            "",
            f"- **Model:** `{self._model_id}`",
            f"- **Skill:** `{self._skill_name}`",
            f"- **Findings:** {len(findings)}",
        ]
        if self._worm_head_range is not None:
            start, end = self._worm_head_range
            lines.append(f"- **WORM head range:** `{start}` .. `{end}`")
        else:
            lines.append("- **WORM head range:** _not provided_")

        lines += ["", "## Threat-model coverage", ""]
        lines += self._coverage_table(findings)
        lines.append("")
        return "\n".join(lines)

    def _coverage_table(self, findings: Sequence[Finding]) -> list[str]:
        if self._threat_model is None or not self._threat_model.assets:
            return ["_No threat model supplied; coverage not assessed._"]

        # Map asset_id -> covered? via findings whose asec.asset.asset_id matches.
        covered: dict[str, int] = {}
        for f in findings:
            asset_id = f.asec.asset.asset_id
            if asset_id is not None:
                covered[asset_id] = covered.get(asset_id, 0) + 1

        # Threats grouped by the element/asset they reference.
        threats_for: dict[str, list[str]] = {}
        for threat in self._threat_model.threats:
            threats_for.setdefault(threat.element_id, []).append(threat.id)

        rows = [
            "| Asset | Class | Weight | Threats | Findings | Covered |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for asset in self._threat_model.assets:
            threat_ids = ", ".join(sorted(threats_for.get(asset.id, []))) or "—"
            n = covered.get(asset.id, 0)
            mark = "yes" if n > 0 else "no"
            rows.append(
                f"| {asset.id} | {asset.asset_class} | {asset.weight} | "
                f"{threat_ids} | {n} | {mark} |"
            )
        return rows
