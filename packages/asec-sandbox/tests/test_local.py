from __future__ import annotations

from asec_sandbox.sandbox import LocalSandbox
from asec_sandbox.spec import SandboxSpec


async def test_exec_echo_returns_stdout() -> None:
    sb = LocalSandbox()
    await sb.start()
    try:
        code, out, err = await sb.exec(["echo", "hello"])
        assert code == 0
        assert out.strip() == "hello"
        assert err == ""
    finally:
        await sb.teardown()


async def test_teardown_deletes_tempdir() -> None:
    sb = LocalSandbox()
    await sb.start()
    workdir = sb.workdir
    assert workdir is not None and workdir.exists()
    await sb.teardown()
    assert not workdir.exists()
    assert sb.workdir is None


async def test_collect_artifacts_empty() -> None:
    sb = LocalSandbox()
    await sb.start()
    try:
        assert await sb.collect_artifacts() == {}
    finally:
        await sb.teardown()


async def test_collect_artifacts_picks_up_written_file() -> None:
    sb = LocalSandbox()
    await sb.start()
    try:
        code, _, _ = await sb.exec(["sh", "-c", "echo data > out.txt"])
        assert code == 0
        artifacts = await sb.collect_artifacts()
        assert artifacts == {"out.txt": b"data\n"}
    finally:
        await sb.teardown()


async def test_env_is_passed(monkeypatch: object) -> None:
    sb = LocalSandbox(SandboxSpec(env={"ASEC_X": "42"}))
    await sb.start()
    try:
        code, out, _ = await sb.exec(["sh", "-c", "echo $ASEC_X"])
        assert code == 0
        assert out.strip() == "42"
    finally:
        await sb.teardown()
