from datetime import UTC, datetime
from pathlib import Path

import pytest
from asec_threat_model import (
    Asset,
    AttackTreeNode,
    Threat,
    ThreatModel,
    diff,
    dump,
    load,
)
from pydantic import ValidationError


def _asset(id: str, cls: str, weight: str, description: str) -> Asset:
    return Asset.model_validate(
        {"id": id, "class": cls, "weight": weight, "description": description}
    )


def _tm(**overrides: object) -> ThreatModel:
    base: dict[str, object] = dict(
        version=1,
        generated_by="opus-4-8",
        generated_at=datetime(2026, 5, 31, 12, 0, tzinfo=UTC),
        assets=(_asset("a1", "PII", "HIGH", "user table"),),
        threats=(
            Threat(
                id="t1",
                element_id="e1",
                stride="S",
                description="spoof login",
                likelihood="HIGH",
                impact="HIGH",
                mitigation="MFA",
                owner="appsec",
            ),
        ),
        attack_trees=(
            AttackTreeNode(
                goal="compromise account",
                kind="OR",
                children=(AttackTreeNode(goal="phish creds", kind="LEAF"),),
            ),
        ),
    )
    base.update(overrides)
    return ThreatModel(**base)  # type: ignore[arg-type]


def test_imports() -> None:
    from asec_threat_model import __version__

    assert __version__ == "0.1.0"


def test_yaml_round_trip(tmp_path: Path) -> None:
    tm = _tm()
    path = tmp_path / "tm.yaml"
    dump(tm, path)
    loaded = load(path)
    assert loaded == tm
    assert loaded.assets[0].asset_class == "PII"


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="threat-model file not found"):
        load(tmp_path / "nope.yaml")


def test_invalid_stride_rejected() -> None:
    with pytest.raises(ValidationError):
        Threat(
            id="t",
            element_id="e",
            stride="X",  # type: ignore[arg-type]
            description="bad",
            likelihood="LOW",
            impact="LOW",
        )


def test_diff_added_removed_modified() -> None:
    a = _tm()
    new_threat = Threat(
        id="t2",
        element_id="e2",
        stride="T",
        description="tamper",
        likelihood="MED",
        impact="MED",
    )
    modified = a.threats[0].model_copy(update={"mitigation": "MFA + WebAuthn"})
    b = _tm(threats=(modified, new_threat))
    d = diff(a, b)
    assert [t.id for t in d.added_threats] == ["t2"]
    assert d.removed_threats == ()
    assert len(d.modified_threats) == 1
    old, fresh = d.modified_threats[0]
    assert old.mitigation == "MFA"
    assert fresh.mitigation == "MFA + WebAuthn"


def test_diff_is_directional() -> None:
    a = _tm()
    b = _tm(threats=())
    forward = diff(a, b)
    backward = diff(b, a)
    assert [t.id for t in forward.removed_threats] == ["t1"]
    assert [t.id for t in backward.added_threats] == ["t1"]


def test_assets_only_diff() -> None:
    a = _tm()
    extra = _asset("a2", "SECRET", "MED", "api key")
    b = _tm(assets=(a.assets[0], extra))
    d = diff(a, b)
    assert [x.id for x in d.added_assets] == ["a2"]
    assert d.added_threats == ()
    assert d.removed_assets == ()
