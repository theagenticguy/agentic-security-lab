"""Sandbox Protocol + a test-only LocalSandbox (E3, E4, E5, E6).

`Sandbox` is the async port satisfied by every concrete isolation backend; it mirrors
`asec_core.protocols.SandboxPort`. `LocalSandbox` is a passthrough that runs commands in a
private tempdir via ``subprocess.run`` with **no isolation whatsoever** — it exists only so
the orchestrator and tests have a working `Sandbox` before the real `DockerSandbox` /
`GVisorSandbox` land on day 4. Do not use `LocalSandbox` against untrusted target code.
"""

from __future__ import annotations

import functools
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

import anyio.to_thread
import structlog

from .spec import SandboxSpec

logger = structlog.get_logger(__name__)


@runtime_checkable
class Sandbox(Protocol):
    """Async isolated-execution port (see `asec_core.protocols.SandboxPort`)."""

    async def start(self) -> None:
        """E3 — launch a throwaway sandbox with networking disabled by default."""
        ...

    async def exec(self, command: Sequence[str]) -> tuple[int, str, str]:
        """E4 — run a command inside the sandbox; return (exit_code, stdout, stderr)."""
        ...

    async def collect_artifacts(self) -> dict[str, bytes]:
        """E5 — collect declared output artifacts before teardown."""
        ...

    async def teardown(self) -> None:
        """E6 — destroy the sandbox and reclaim all of its resources."""
        ...


class LocalSandbox:
    """No-isolation passthrough sandbox. **Tests only** — runs on the host directly."""

    def __init__(self, spec: SandboxSpec | None = None) -> None:
        self._spec = spec or SandboxSpec(kind="local")
        self._workdir: Path | None = None

    @property
    def workdir(self) -> Path | None:
        return self._workdir

    async def start(self) -> None:
        self._workdir = Path(tempfile.mkdtemp(prefix="asec-local-"))
        logger.debug("local_sandbox.start", workdir=str(self._workdir))

    async def exec(self, command: Sequence[str]) -> tuple[int, str, str]:
        if self._workdir is None:
            await self.start()
        assert self._workdir is not None
        import subprocess

        def _run() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                list(command),
                cwd=self._workdir,
                capture_output=True,
                text=True,
                env=dict(self._spec.env) or None,
                check=False,
            )

        result: subprocess.CompletedProcess[str] = await anyio.to_thread.run_sync(
            functools.partial(_run)
        )
        logger.debug("local_sandbox.exec", command=list(command), exit_code=result.returncode)
        return result.returncode, result.stdout, result.stderr

    async def collect_artifacts(self) -> dict[str, bytes]:
        if self._workdir is None:
            return {}
        artifacts: dict[str, bytes] = {}
        for f in sorted(self._workdir.rglob("*")):
            if f.is_file():
                artifacts[str(f.relative_to(self._workdir))] = f.read_bytes()
        return artifacts

    async def teardown(self) -> None:
        if self._workdir is not None and self._workdir.exists():
            shutil.rmtree(self._workdir, ignore_errors=True)
            logger.debug("local_sandbox.teardown", workdir=str(self._workdir))
        self._workdir = None


class DockerSandbox:
    """Rootless hardened Docker sandbox. STUB — implemented day 4 (B)."""

    def __init__(self, spec: SandboxSpec) -> None:
        self._spec = spec

    async def start(self) -> None:
        # TODO(day4): rootless docker run --cap-drop=ALL --read-only --network=none,
        # seccomp=default.json, tmpfs scratch, UID 10001 (see track-c-sandbox-configs §1,§3).
        raise NotImplementedError("DockerSandbox is implemented on day 4")

    async def exec(self, command: Sequence[str]) -> tuple[int, str, str]:
        raise NotImplementedError("DockerSandbox is implemented on day 4")

    async def collect_artifacts(self) -> dict[str, bytes]:
        raise NotImplementedError("DockerSandbox is implemented on day 4")

    async def teardown(self) -> None:
        raise NotImplementedError("DockerSandbox is implemented on day 4")


class GVisorSandbox:
    """gVisor (runsc) sandbox. STUB — implemented day 4 (B)."""

    def __init__(self, spec: SandboxSpec) -> None:
        self._spec = spec

    async def start(self) -> None:
        # TODO(day4): docker run --runtime=runsc with the hardened SandboxSpec flags.
        raise NotImplementedError("GVisorSandbox is implemented on day 4")

    async def exec(self, command: Sequence[str]) -> tuple[int, str, str]:
        raise NotImplementedError("GVisorSandbox is implemented on day 4")

    async def collect_artifacts(self) -> dict[str, bytes]:
        raise NotImplementedError("GVisorSandbox is implemented on day 4")

    async def teardown(self) -> None:
        raise NotImplementedError("GVisorSandbox is implemented on day 4")
