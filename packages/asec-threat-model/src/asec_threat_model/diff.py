"""Structural diff between two :class:`ThreatModel` artifacts."""

from __future__ import annotations

from opentelemetry import trace
from pydantic import BaseModel, ConfigDict

from .models import Asset, Threat, ThreatModel

_tracer = trace.get_tracer(__name__)


class ThreatModelDiff(BaseModel):
    """The set of changes moving from threat model ``a`` to ``b``."""

    model_config = ConfigDict(frozen=True)

    added_threats: tuple[Threat, ...] = ()
    removed_threats: tuple[Threat, ...] = ()
    modified_threats: tuple[tuple[Threat, Threat], ...] = ()
    added_assets: tuple[Asset, ...] = ()
    removed_assets: tuple[Asset, ...] = ()


def diff(a: ThreatModel, b: ThreatModel) -> ThreatModelDiff:
    """Diff two threat models, keyed on ``threat.id`` and ``asset.id``.

    A threat present under the same id in both models but with any differing
    field is reported as a ``(old, new)`` pair in ``modified_threats``.
    """
    with _tracer.start_as_current_span("threat_model.diff"):
        a_threats = {t.id: t for t in a.threats}
        b_threats = {t.id: t for t in b.threats}
        added_threats = tuple(b_threats[i] for i in b_threats if i not in a_threats)
        removed_threats = tuple(a_threats[i] for i in a_threats if i not in b_threats)
        modified_threats = tuple(
            (a_threats[i], b_threats[i])
            for i in a_threats
            if i in b_threats and a_threats[i] != b_threats[i]
        )

        a_assets = {x.id: x for x in a.assets}
        b_assets = {x.id: x for x in b.assets}
        added_assets = tuple(b_assets[i] for i in b_assets if i not in a_assets)
        removed_assets = tuple(a_assets[i] for i in a_assets if i not in b_assets)

        return ThreatModelDiff(
            added_threats=added_threats,
            removed_threats=removed_threats,
            modified_threats=modified_threats,
            added_assets=added_assets,
            removed_assets=removed_assets,
        )
