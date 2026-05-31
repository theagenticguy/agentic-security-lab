from __future__ import annotations

import pytest
from asec_sandbox.spec import SandboxSpec


def test_gvisor_on_non_linux_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("asec_sandbox.spec.platform.system", lambda: "Darwin")
    with pytest.raises(ValueError, match="Linux"):
        SandboxSpec(kind="gvisor")


def test_gvisor_on_linux_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("asec_sandbox.spec.platform.system", lambda: "Linux")
    spec = SandboxSpec(kind="gvisor")
    assert spec.kind == "gvisor"


def test_network_none_with_allowlist_rejected() -> None:
    with pytest.raises(ValueError, match="deny-all"):
        SandboxSpec(network="none", egress_allowlist=("github.com:443",))


def test_allowlist_requires_nonempty() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        SandboxSpec(network="allowlist")


def test_defaults_are_deny_all_egress() -> None:
    spec = SandboxSpec()
    assert spec.kind == "local"
    assert spec.network == "none"
    assert spec.egress_allowlist == ()
    assert spec.read_only_root is True


def test_frozen() -> None:
    spec = SandboxSpec()
    with pytest.raises(Exception):  # noqa: B017 — pydantic frozen raises ValidationError
        spec.kind = "docker"  # type: ignore[misc]
