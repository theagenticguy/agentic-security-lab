"""Tests for the hardened DockerSandbox.

`python_on_whales` is required (``importorskip``); a `_docker_available()` probe further
gates the one test that needs a live daemon. The rest are CI-portable *contract* tests: they
drive a `unittest.mock.MagicMock` standing in for the `DockerClient` and assert the run/exec
argument vectors carry every hardening flag — this is the portable guarantee that the sandbox
stays deny-by-default even where Docker is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from unittest.mock import MagicMock

import anyio
import pytest

pytest.importorskip("python_on_whales")

from asec_sandbox.sandbox import (
    DEFAULT_CPUS,
    DEFAULT_MEMORY,
    DEFAULT_PIDS_LIMIT,
    DockerSandbox,
)
from asec_sandbox.spec import Mount, SandboxSpec


def _docker_available() -> bool:
    """True only if the docker CLI exists and a daemon answers ``docker version``."""
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "version"],
                capture_output=True,
                timeout=10,
                check=False,
            ).returncode
            == 0
        )
    except Exception:
        return False


DOCKER_AVAILABLE = _docker_available()


def _mock_docker(*, runsc: bool = False) -> MagicMock:
    docker = MagicMock()
    info = MagicMock()
    info.runtimes = {"runc": {}, **({"runsc": {}} if runsc else {})}
    docker.system.info.return_value = info
    docker.run.return_value = MagicMock(name="container")
    return docker


def test_defaults_applied_to_run_args() -> None:
    docker = _mock_docker()
    sb = DockerSandbox(SandboxSpec(kind="docker"), docker=docker)
    anyio.run(sb.start)

    docker.run.assert_called_once()
    image, run_kwargs = docker.run.call_args.args[0], docker.run.call_args.kwargs
    assert image == "asec-sandbox:dev"
    assert run_kwargs["cap_drop"] == ["ALL"]
    assert run_kwargs["security_options"] == ["no-new-privileges"]
    assert run_kwargs["read_only"] is True
    assert run_kwargs["networks"] == ["none"]
    assert run_kwargs["pids_limit"] == DEFAULT_PIDS_LIMIT
    assert run_kwargs["memory"] == DEFAULT_MEMORY
    assert run_kwargs["cpus"] == DEFAULT_CPUS
    assert run_kwargs["command"] == ["sleep", "infinity"]
    # tmpfs covers /tmp (noexec) + the scratch dir.
    tmpfs = run_kwargs["tmpfs"]
    assert any(t.startswith("/tmp:") and "noexec" in t for t in tmpfs)
    assert any(t.startswith("/work/.scratch:") for t in tmpfs)
    # No runtime flag for a plain docker sandbox.
    assert "runtime" not in run_kwargs
    assert sb.runtime is None


def test_mount_is_read_only() -> None:
    docker = _mock_docker()
    spec = SandboxSpec(kind="docker", mounts=(Mount(source="/host/repo", target="/work"),))
    sb = DockerSandbox(spec, target="/host/target", docker=docker)
    anyio.run(sb.start)

    volumes = docker.run.call_args.kwargs["volumes"]
    # Bind-mounted target at /work is read-only ("ro"); declared spec mount likewise.
    assert ("/host/target", "/work", "ro") in volumes
    assert all(mode == "ro" for *_rest, mode in volumes)


def test_gvisor_unavailable_falls_back_when_allowed() -> None:
    docker = _mock_docker(runsc=False)
    spec = SandboxSpec(kind="gvisor", allow_fallback=True)
    sb = DockerSandbox(spec, docker=docker)
    anyio.run(sb.start)

    assert sb.runtime == "runc"
    # runc fallback is passed through as the docker runtime flag.
    assert docker.run.call_args.kwargs["runtime"] == "runc"


def test_gvisor_unavailable_raises_when_not_allowed() -> None:
    docker = _mock_docker(runsc=False)
    spec = SandboxSpec(kind="gvisor", allow_fallback=False)
    sb = DockerSandbox(spec, docker=docker)
    with pytest.raises(RuntimeError, match="runsc runtime is not registered"):
        anyio.run(sb.start)
    docker.run.assert_not_called()


def test_gvisor_uses_runsc_when_registered() -> None:
    docker = _mock_docker(runsc=True)
    sb = DockerSandbox(SandboxSpec(kind="gvisor"), docker=docker)
    anyio.run(sb.start)
    assert sb.runtime == "runsc"
    assert docker.run.call_args.kwargs["runtime"] == "runsc"


def test_exec_captures_stdout() -> None:
    docker = _mock_docker()
    docker.container.execute.return_value = "hello\n"
    sb = DockerSandbox(SandboxSpec(kind="docker"), docker=docker)
    anyio.run(sb.start)

    code, out, err = anyio.run(lambda: sb.exec(["echo", "hello"]))
    assert code == 0
    assert out == "hello\n"
    assert err == ""


def test_exec_nonzero_exit_captured() -> None:
    from python_on_whales.exceptions import DockerException

    docker = _mock_docker()
    docker.container.execute.side_effect = DockerException(
        command_launched=["docker", "exec"],
        return_code=2,
        stdout=b"partial",
        stderr=b"boom",
    )
    sb = DockerSandbox(SandboxSpec(kind="docker"), docker=docker)
    anyio.run(sb.start)
    code, _out, err = anyio.run(lambda: sb.exec(["false"]))
    assert code == 2
    assert err == "boom"


def test_teardown_is_idempotent() -> None:
    docker = _mock_docker()
    sb = DockerSandbox(SandboxSpec(kind="docker"), docker=docker)
    anyio.run(sb.start)
    anyio.run(sb.teardown)
    anyio.run(sb.teardown)  # second teardown is a no-op, must not raise.
    docker.container.remove.assert_called_once()


@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="requires a live Docker daemon")
def test_live_network_none_blocks_egress() -> None:
    spec = SandboxSpec(kind="docker", image="python:3.13-slim")
    sb = DockerSandbox(spec)
    anyio.run(sb.start)
    try:
        code, _out, _err = anyio.run(
            lambda: sb.exec(
                ["python", "-c", "import socket; socket.create_connection(('1.1.1.1',53),2)"]
            )
        )
        assert code != 0  # network=none -> egress must fail.
    finally:
        anyio.run(sb.teardown)
