"""SandboxSpec — the frozen, declarative description of an isolation environment (E3).

A `SandboxSpec` is a value object: it says *what* isolation is wanted (kind, network
posture, resource limits, mounts) without any reference to *how* a concrete `Sandbox`
realizes it. Defaults are deny-all: `network="none"`, empty egress allowlist, read-only
root. Validators encode the cross-cutting invariants from PLAN.md §5 / track-c configs:
gVisor requires a Linux host, and an `allowlist` network posture is meaningless without
at least one allowed endpoint.
"""

from __future__ import annotations

import platform
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SandboxKind = Literal["local", "docker", "gvisor", "firecracker", "agentcore"]
NetworkMode = Literal["none", "allowlist"]


class Mount(BaseModel):
    """A single host->sandbox bind mount."""

    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    read_only: bool = True


class SandboxSpec(BaseModel):
    """Declarative, frozen description of a sandbox to be realized by a `Sandbox` impl."""

    model_config = ConfigDict(frozen=True)

    kind: SandboxKind = "local"
    network: NetworkMode = "none"
    egress_allowlist: tuple[str, ...] = ()
    cpu_limit: float | None = None
    mem_limit_mib: int | None = None
    pids_limit: int | None = None
    read_only_root: bool = True
    tmpfs_paths: tuple[str, ...] = ()
    mounts: tuple[Mount, ...] = ()
    env: dict[str, str] = Field(default_factory=dict)
    image: str = "asec-sandbox:dev"
    allow_fallback: bool = False
    """When ``kind='gvisor'`` and the ``runsc`` runtime is not registered with Docker, fall
    back to the default runtime (runc) with a ``structlog`` warning + a WORM ``gate_decision``
    instead of raising. Defaults to ``False``: an unavailable gVisor runtime is a hard error."""

    @model_validator(mode="after")
    def _check_invariants(self) -> SandboxSpec:
        if self.kind == "gvisor" and platform.system() != "Linux":
            msg = "gvisor sandboxes require a Linux host (runsc is Linux-only)"
            raise ValueError(msg)
        if self.network == "allowlist" and not self.egress_allowlist:
            msg = "network='allowlist' requires a non-empty egress_allowlist"
            raise ValueError(msg)
        if self.network == "none" and self.egress_allowlist:
            msg = "network='none' must have an empty egress_allowlist (deny-all)"
            raise ValueError(msg)
        return self
