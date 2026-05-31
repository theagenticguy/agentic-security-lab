"""YAML load/dump for :class:`ThreatModel`, with stable key ordering."""

from __future__ import annotations

from pathlib import Path

import structlog
import yaml
from opentelemetry import trace

from .models import ThreatModel

_log = structlog.get_logger(__name__)
_tracer = trace.get_tracer(__name__)


def load(path: str | Path) -> ThreatModel:
    """Load and validate a :class:`ThreatModel` from a YAML file.

    Raises :class:`FileNotFoundError` with a clear message if the path is
    missing, and :class:`pydantic.ValidationError` if the contents are invalid.
    """
    with _tracer.start_as_current_span("threat_model.load"):
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"threat-model file not found: {p}")
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        return ThreatModel.model_validate(data)


def dump(tm: ThreatModel, path: str | Path) -> None:
    """Serialise a :class:`ThreatModel` to YAML with a stable key order.

    ``sort_keys=False`` preserves field declaration order; ``by_alias=True``
    re-emits ``class`` for the asset class so the file round-trips through
    :func:`load`.
    """
    with _tracer.start_as_current_span("threat_model.dump"):
        payload = tm.model_dump(mode="json", by_alias=True)
        text = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)
        Path(path).write_text(text, encoding="utf-8")
        _log.info("threat_model.dump", path=str(path), threats=len(tm.threats))
