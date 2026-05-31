"""Day 2 tests: Settings, ScopeArtifact, KillSwitch, GovernanceGate, runtime seam."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from asec_core import (
    AgentRuntime,
    ClaudeAgentRuntime,
    FileKillSwitch,
    GovernanceGate,
    KillSwitch,
    ScopeArtifact,
    Settings,
    sign_scope,
    verify_scope,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError


def _keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _scope(*, expires_in: timedelta = timedelta(hours=1)) -> ScopeArtifact:
    now = datetime.now(UTC)
    return ScopeArtifact(
        id="scope-1",
        created_at=now,
        expires_at=now + expires_in,
        targets=("repo/src",),
        egress_allowlist=("api.example.com",),
        signer="",
        signature="",
    )


def test_settings_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("ANTHROPIC_MODEL", "global.anthropic.claude-opus-4-8")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    s = Settings()
    assert s.bedrock_use is True
    assert s.model_id == "global.anthropic.claude-opus-4-8"
    assert s.aws_region == "us-west-2"
    assert s.permission_mode == "plan"
    assert s.max_budget_usd == 5.0


def test_settings_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_DEFAULT_OPUS_MODEL", raising=False)
    s = Settings()
    assert s.model_id == "global.anthropic.claude-opus-4-8"
    with pytest.raises(ValidationError):
        s.max_budget_usd = 9.0  # type: ignore[misc]


def test_scope_rejects_expired() -> None:
    expired = _scope(expires_in=timedelta(seconds=-1))
    assert expired.is_expired() is True
    assert _scope().is_expired() is False


def test_sign_verify_roundtrip() -> None:
    priv_pem, pub_pem = _keypair()
    signed = sign_scope(_scope(), priv_pem, signer="ciso@example.com")
    assert signed.signer == "ciso@example.com"
    assert signed.signature
    assert verify_scope(signed, pub_pem) is True


def test_verify_wrong_key_false() -> None:
    priv_pem, _ = _keypair()
    _, other_pub = _keypair()
    signed = sign_scope(_scope(), priv_pem, signer="ciso@example.com")
    assert verify_scope(signed, other_pub) is False


def test_verify_unsigned_false() -> None:
    _, pub_pem = _keypair()
    assert verify_scope(_scope(), pub_pem) is False


def test_killswitch_trigger_flips() -> None:
    ks = KillSwitch()
    assert ks.triggered is False
    ks.trigger("operator halt")
    assert ks.triggered is True
    assert ks.reason == "operator halt"


async def test_killswitch_wait_returns_after_trigger() -> None:
    ks = KillSwitch()
    ks.trigger()
    await ks.wait()  # must not block
    assert ks.triggered is True


def test_file_killswitch_reads_existing_file(tmp_path: Path) -> None:
    sentinel = tmp_path / "STOP"
    sentinel.write_text("halt now", encoding="utf-8")
    fks = FileKillSwitch(sentinel)
    assert fks.triggered is True
    assert fks.reason == "halt now"


def test_file_killswitch_absent_not_triggered(tmp_path: Path) -> None:
    fks = FileKillSwitch(tmp_path / "STOP")
    assert fks.triggered is False


def test_gate_allows_valid_scope() -> None:
    priv_pem, pub_pem = _keypair()
    signed = sign_scope(_scope(), priv_pem, signer="ciso")
    gate = GovernanceGate(scope=signed, public_key_pem=pub_pem, max_budget_usd=5.0)
    assert gate.check(spent_usd=0.0)["decision"] == "allow"


def test_gate_denies_expired_scope() -> None:
    priv_pem, pub_pem = _keypair()
    signed = sign_scope(_scope(expires_in=timedelta(seconds=-1)), priv_pem, signer="x")
    gate = GovernanceGate(scope=signed, public_key_pem=pub_pem)
    decision = gate.check(spent_usd=0.0)
    assert decision["decision"] == "deny"
    assert "expired" in decision["reason"]


def test_gate_denies_unsigned_scope() -> None:
    _, pub_pem = _keypair()
    gate = GovernanceGate(scope=_scope(), public_key_pem=pub_pem)
    assert gate.check()["decision"] == "deny"


def test_gate_denies_over_budget() -> None:
    priv_pem, pub_pem = _keypair()
    signed = sign_scope(_scope(), priv_pem, signer="x")
    gate = GovernanceGate(scope=signed, public_key_pem=pub_pem, max_budget_usd=5.0)
    decision = gate.check(spent_usd=6.0)
    assert decision["decision"] == "deny"
    assert "budget" in decision["reason"]


def test_gate_denies_when_killswitch_tripped() -> None:
    priv_pem, pub_pem = _keypair()
    signed = sign_scope(_scope(), priv_pem, signer="x")
    ks = KillSwitch()
    ks.trigger("abort")
    gate = GovernanceGate(scope=signed, public_key_pem=pub_pem, kill_switch=ks)
    assert gate.check()["decision"] == "deny"


def test_claude_runtime_imports_without_sdk() -> None:
    rt = ClaudeAgentRuntime()
    assert isinstance(rt, AgentRuntime)

    def _noop_hook(*_a: Any, **_k: Any) -> None:
        return None

    rt.register_hook("PreToolUse", _noop_hook)
