"""Sandbox Protocol + LocalSandbox + the hardened DockerSandbox (E3, E4, E5, E6).

`Sandbox` is the async port satisfied by every concrete isolation backend; it mirrors
`asec_core.protocols.SandboxPort`. `LocalSandbox` is a passthrough that runs commands in a
private tempdir via ``subprocess.run`` with **no isolation whatsoever** — it exists only for
tests and bootstrapping; do not use it against untrusted target code.

`DockerSandbox` is the real isolation backend. It launches a long-lived container
(``sleep infinity``) with a deny-by-default hardening profile derived from `SandboxSpec`:
``--cap-drop=ALL``, ``--security-opt no-new-privileges``, ``--read-only`` root, tmpfs scratch,
``--pids-limit``/``--memory``/``--cpus`` caps, and ``--network=none`` by default. Target code
is bind-mounted **read-only** at ``/work``; ``exec`` runs inside the container; artifacts are
``docker cp``'d *out* (never bind-mounted out — whitepaper §07). When ``spec.kind=="gvisor"``
it probes Docker for the ``runsc`` runtime and either uses it, soft-falls to runc
(``allow_fallback=True``, with a WORM ``gate_decision``), or raises. `GVisorSandbox` is a thin
subclass that defaults ``kind="gvisor"``. All Docker calls are off-thread via
``anyio.to_thread.run_sync`` so the async ports never block the event loop.
"""

from __future__ import annotations

import contextlib
import functools
import shutil
import tempfile
from collections.abc import Generator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import anyio
import anyio.from_thread
import anyio.to_thread
import structlog

from .spec import SandboxSpec

if TYPE_CHECKING:
    from python_on_whales import DockerClient

    from .events import EventEmitter

logger = structlog.get_logger(__name__)

#: Mount point for the (read-only) target repo inside the sandbox.
WORK_DIR = "/work"
#: The single writable scratch path; everything else is read-only.
SCRATCH_DIR = "/work/.scratch"
#: Default memory/cpu/pids caps applied when the spec leaves them unset.
DEFAULT_MEMORY = "4g"
DEFAULT_CPUS = 2.0
DEFAULT_PIDS_LIMIT = 512


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
    """Hardened Docker sandbox: deny-by-default caps/network, read-only root, tmpfs scratch.

    The container is long-lived (``sleep infinity``) so multiple `exec` calls share one
    isolation boundary; `teardown` force-removes it. The ``target`` directory (if given) is
    bind-mounted **read-only** at ``/work``; the only writable paths are the tmpfs scratch
    mounts. ``emitter`` (optional) receives a `ProgressEvent` per ``exec`` and records the
    gVisor fallback decision to the WORM audit.
    """

    def __init__(
        self,
        spec: SandboxSpec,
        *,
        target: str | Path | None = None,
        workdir: str | Path | None = None,
        docker: DockerClient | None = None,
        emitter: EventEmitter | None = None,
        session: str = "default",
    ) -> None:
        self._spec = spec
        self._target = Path(target).resolve() if target is not None else None
        self._host_workdir = Path(workdir).resolve() if workdir is not None else None
        self._emitter = emitter
        self._session = session
        if docker is None:
            from python_on_whales import DockerClient as _DockerClient

            docker = _DockerClient()
        # Typed as Any: this object is interchangeably a real python-on-whales DockerClient or
        # a unittest.mock.MagicMock in contract tests, and several flags we pass (e.g. the
        # internal-network create) are not in the typed surface. Strict typing here would be
        # noise, not safety — the run/exec argument vectors are asserted in tests instead.
        self._docker: Any = docker
        self._container: Any = None
        self._runtime: str | None = None

    @property
    def spec(self) -> SandboxSpec:
        return self._spec

    @property
    def container(self) -> Any:
        return self._container

    @property
    def runtime(self) -> str | None:
        """The runtime actually selected at ``start`` (``"runsc"``/``"runc"``/``None``)."""
        return self._runtime

    def _runsc_registered(self) -> bool:
        """True if Docker reports a ``runsc`` runtime in ``docker info``."""
        info = self._docker.system.info()
        runtimes: dict[str, Any] = getattr(info, "runtimes", None) or {}
        return "runsc" in runtimes

    def _resolve_runtime(self) -> str | None:
        """Pick the runtime for ``kind=='gvisor'``; honor ``allow_fallback``; emit decisions."""
        if self._spec.kind != "gvisor":
            return None
        if self._runsc_registered():
            return "runsc"
        if self._spec.allow_fallback:
            logger.warning(
                "docker_sandbox.gvisor_unavailable_fallback",
                detail="runsc runtime not registered; falling back to runc",
            )
            if self._emitter is not None:
                from .events import GateDecision

                anyio.from_thread.run(
                    self._emitter.emit,
                    GateDecision(
                        session=self._session,
                        gate="gvisor_unavailable_fallback",
                        decision="pass",
                        reason="runsc runtime not registered; allow_fallback=True -> runc",
                    ),
                )
            return "runc"
        msg = (
            "gvisor sandbox requested but the runsc runtime is not registered with Docker "
            "and allow_fallback=False"
        )
        raise RuntimeError(msg)

    def _tmpfs_args(self) -> list[str]:
        """tmpfs mounts: hardened ``/tmp`` + the ``/work/.scratch`` scratch, plus spec extras."""
        mem = self._spec.mem_limit_mib
        scratch_size = f"{mem}m" if mem else "512m"
        # B108: `/tmp` here is a tmpfs mount *inside the sandboxed agent
        # container* with `noexec,nosuid` and a bounded size — not a host path.
        # The container runs read-only with cap-drop=ALL on a no-internet
        # network; tmpfs at /tmp is the standard hardened pattern.
        mounts = [
            f"/tmp:noexec,nosuid,size={scratch_size}",  # nosec B108
            f"{SCRATCH_DIR}:nosuid,nodev,size={scratch_size}",
        ]
        mounts.extend(f"{p}:nosuid,nodev" for p in self._spec.tmpfs_paths)
        return mounts

    def _run_kwargs(self) -> dict[str, Any]:
        """Build the hardened ``docker run`` keyword arguments from the spec."""
        volumes: list[tuple[str, str, str]] = []
        if self._target is not None:
            volumes.append((str(self._target), WORK_DIR, "ro"))
        for m in self._spec.mounts:
            mode = "ro" if m.read_only else "rw"
            volumes.append((m.source, m.target, mode))

        kwargs: dict[str, Any] = {
            "command": ["sleep", "infinity"],
            "detach": True,
            "remove": False,
            "cap_drop": ["ALL"],
            "security_options": ["no-new-privileges"],
            "read_only": self._spec.read_only_root,
            "tmpfs": self._tmpfs_args(),
            "pids_limit": self._spec.pids_limit or DEFAULT_PIDS_LIMIT,
            "memory": (
                f"{self._spec.mem_limit_mib}m" if self._spec.mem_limit_mib else DEFAULT_MEMORY
            ),
            "cpus": self._spec.cpu_limit or DEFAULT_CPUS,
            "networks": ["none"],
            "envs": dict(self._spec.env),
            "workdir": WORK_DIR,
        }
        if volumes:
            kwargs["volumes"] = volumes
        if self._runtime is not None:
            kwargs["runtime"] = self._runtime
        return kwargs

    def _start_sync(self) -> Any:
        self._runtime = self._resolve_runtime()
        if self._host_workdir is None:
            self._host_workdir = Path(tempfile.mkdtemp(prefix="asec-docker-"))
        kwargs = self._run_kwargs()
        self._container = self._docker.run(self._spec.image, **kwargs)
        logger.info(
            "docker_sandbox.start",
            image=self._spec.image,
            runtime=self._runtime or "default",
            network="none",
            read_only=self._spec.read_only_root,
        )
        return self._container

    async def start(self) -> None:
        """E3 — launch the hardened container (resolving the gVisor runtime first)."""
        await anyio.to_thread.run_sync(self._start_sync)

    def _exec_sync(self, command: Sequence[str]) -> tuple[int, str, str]:
        from python_on_whales.exceptions import DockerException

        try:
            out = self._docker.container.execute(self._container, list(command), workdir=WORK_DIR)
            stdout = out if isinstance(out, str) else ""
            return 0, stdout, ""
        except DockerException as exc:
            # ``return_code`` is non-optional on DockerException; default to 1 only if the
            # CLI somehow failed before producing one (``or 1`` also coerces a 0 nonsense).
            return exc.return_code or 1, exc.stdout or "", exc.stderr or ""

    async def exec(
        self,
        command: Sequence[str],
        *,
        timeout: float | None = None,  # noqa: ASYNC109 — part of the SandboxPort contract; honored via anyio.fail_after.
    ) -> tuple[int, str, str]:
        """E4 — run ``command`` inside the container; emit a `ProgressEvent`; return result."""
        if self._container is None:
            await self.start()

        try:
            with anyio.fail_after(timeout) if timeout else _null_cm():
                code, stdout, stderr = await anyio.to_thread.run_sync(self._exec_sync, command)
        except TimeoutError:
            code, stdout, stderr = 124, "", f"command timed out after {timeout}s"
        if self._emitter is not None:
            from .events import WorkerStuck

            await self._emitter.emit(
                WorkerStuck(
                    session=self._session,
                    worker_id="docker_sandbox",
                    detail=f"exec exit={code} cmd={' '.join(command)}",
                )
            )
        logger.debug("docker_sandbox.exec", command=list(command), exit_code=code)
        return code, stdout, stderr

    def _collect_sync(self, paths: Sequence[str]) -> dict[str, bytes]:
        assert self._host_workdir is not None
        artifacts: dict[str, bytes] = {}
        for p in paths:
            dest = self._host_workdir / Path(p).name
            self._docker.container.copy((self._container, p), dest)
            if dest.is_file():
                artifacts[p] = dest.read_bytes()
        return artifacts

    async def collect_artifacts(self, paths: Sequence[str] | None = None) -> dict[str, bytes]:
        """E5 — ``docker cp`` declared paths out of the container to the host workdir."""
        if self._container is None or not paths:
            return {}
        return await anyio.to_thread.run_sync(self._collect_sync, list(paths))

    def _teardown_sync(self) -> None:
        if self._container is not None:
            try:
                self._docker.container.remove(self._container, force=True)
            except Exception:
                logger.warning("docker_sandbox.remove_failed", exc_info=True)
            self._container = None
        if self._host_workdir is not None and self._host_workdir.exists():
            shutil.rmtree(self._host_workdir, ignore_errors=True)
            self._host_workdir = None

    async def teardown(self) -> None:
        """E6 — force-remove the container and clean the host workdir; idempotent."""
        await anyio.to_thread.run_sync(self._teardown_sync)


class GVisorSandbox(DockerSandbox):
    """`DockerSandbox` that defaults ``kind='gvisor'`` (runsc is a runtime flag, not a class)."""

    def __init__(self, spec: SandboxSpec | None = None, **kwargs: Any) -> None:
        if spec is None:
            spec = SandboxSpec(kind="gvisor")
        super().__init__(spec, **kwargs)


@contextlib.contextmanager
def _null_cm() -> Generator[None]:
    """A no-op context manager used when no ``exec`` timeout is requested."""
    yield
