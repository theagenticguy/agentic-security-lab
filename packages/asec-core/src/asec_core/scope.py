"""Signed scope-of-engagement artifact (E19).

A `ScopeArtifact` is the cryptographic authorization boundary for a review run: which
targets may be touched, which egress destinations are permitted, and an Ed25519
signature over the canonical-JSON of every field except the signature itself. The
orchestrator refuses to act on an artifact that is expired, unsigned, or whose
signature does not verify against a trusted public key.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from pydantic import BaseModel, ConfigDict


class ScopeArtifact(BaseModel):
    """Frozen scope-of-engagement value object (E19)."""

    model_config = ConfigDict(frozen=True)

    id: str
    created_at: datetime
    expires_at: datetime
    targets: tuple[str, ...]
    egress_allowlist: tuple[str, ...]
    signer: str
    signature: str

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """E19 — true once the artifact's `expires_at` has passed."""
        ref = now or datetime.now(UTC)
        return ref >= self.expires_at


def _signing_bytes(scope: ScopeArtifact) -> bytes:
    """Canonical-JSON of every field except `signature`, used as the signed payload."""
    payload = scope.model_dump(mode="json", exclude={"signature"})
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_scope(scope: ScopeArtifact, private_key_pem: bytes, *, signer: str) -> ScopeArtifact:
    """E19 — return a copy of `scope` carrying an Ed25519 signature over its fields."""
    key = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("sign_scope requires an Ed25519 private key")
    unsigned = scope.model_copy(update={"signer": signer, "signature": ""})
    sig = key.sign(_signing_bytes(unsigned))
    return unsigned.model_copy(update={"signature": sig.hex()})


def verify_scope(scope: ScopeArtifact, public_key_pem: bytes) -> bool:
    """E19 — verify the Ed25519 signature; return False on any mismatch or bad input."""
    if not scope.signature:
        return False
    key = load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        return False
    unsigned = scope.model_copy(update={"signature": ""})
    try:
        key.verify(bytes.fromhex(scope.signature), _signing_bytes(unsigned))
    except (InvalidSignature, ValueError):
        return False
    return True
