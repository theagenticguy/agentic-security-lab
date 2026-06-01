"""Unit tests for the EgressProxy tinyproxy allowlist sidecar.

These tests never touch a real Docker daemon: spec validation and `_render_tinyproxy_conf`
are pure, and the start/stop lifecycle drives a `unittest.mock.MagicMock` standing in for the
`DockerClient`. The golden-string assertion pins the rendered config (deny-default + anchored
host regexes) so a behavioral regression in the egress filter is caught in CI.
"""
# The rendered-config helpers are module-private by intent but are part of the tested
# contract (golden-string render); exercising them here is deliberate.
# pyright: reportPrivateUsage=false

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from asec_sandbox.egress import (
    EgressProxy,
    EgressProxySpec,
    _render_filter,
    _render_tinyproxy_conf,
)


def test_empty_allowlist_rejected() -> None:
    with pytest.raises(ValueError, match="allowlist must be non-empty"):
        EgressProxySpec(allowlist=())


def test_bad_port_rejected() -> None:
    with pytest.raises(ValueError, match=r"must be in 1\.\.65535"):
        EgressProxySpec(allowlist=(("example.com", 70000),))


def test_bad_bind_port_rejected() -> None:
    with pytest.raises(ValueError, match=r"bind_port must be in 1\.\.65535"):
        EgressProxySpec(allowlist=(("example.com", 443),), bind_port=0)


def test_render_tinyproxy_conf_golden() -> None:
    spec = EgressProxySpec(
        allowlist=(("bedrock-runtime.us-east-1.amazonaws.com", 443),),
        bind_port=8888,
    )
    expected = (
        "User nobody\n"
        "Group nogroup\n"
        "Port 8888\n"
        "Timeout 600\n"
        "Allow 0.0.0.0/0\n"
        "FilterDefaultDeny Yes\n"
        "FilterExtended On\n"
        "Filter /etc/tinyproxy/filter\n"
        "FilterURLs Off\n"
        "LogLevel Info\n"
    )
    assert _render_tinyproxy_conf(spec) == expected


def test_render_filter_is_regex_anchored() -> None:
    spec = EgressProxySpec(
        allowlist=(
            ("bedrock-runtime.us-east-1.amazonaws.com", 443),
            ("git.example.com", 443),
        )
    )
    # Hosts are escaped and anchored so api.example.com cannot match api.example.com.evil.net.
    assert _render_filter(spec) == (
        "^bedrock\\-runtime\\.us\\-east\\-1\\.amazonaws\\.com$\n^git\\.example\\.com$\n"
    )


def test_allowlist_deduplicated_in_filter() -> None:
    # Same host on two ports yields a single filter line (filter matches host, not port).
    spec = EgressProxySpec(allowlist=(("api.example.com", 443), ("api.example.com", 8443)))
    assert spec.hosts == ("api.example.com",)
    assert _render_filter(spec) == "^api\\.example\\.com$\n"


def test_start_stop_lifecycle_and_internal_network() -> None:
    docker = MagicMock()
    # exists() is False before create (so we create it) and True at stop (so we can remove it).
    docker.network.exists.side_effect = [False, True]
    container = MagicMock()
    docker.run.return_value = container
    # Inspected network reports no other consumers -> safe to remove on stop.
    inspected = MagicMock()
    inspected.containers = {}
    docker.network.inspect.return_value = inspected

    spec = EgressProxySpec(allowlist=(("bedrock-runtime.us-east-1.amazonaws.com", 443),))
    proxy = EgressProxy(spec, docker=docker)

    import anyio

    handle = anyio.run(proxy.start)
    assert handle is container

    # The asec-internal network was created with internal=True (no internet route).
    docker.network.create.assert_called_once()
    _, kwargs = docker.network.create.call_args
    assert kwargs.get("internal") is True
    assert docker.network.create.call_args.args[0] == "asec-internal"

    # The proxy container joined that network with a hardened profile.
    _, run_kwargs = docker.run.call_args
    assert run_kwargs["networks"] == ["asec-internal"]
    assert run_kwargs["cap_drop"] == ["ALL"]
    assert run_kwargs["read_only"] is True

    anyio.run(proxy.stop)
    docker.container.remove.assert_called_once()
    docker.network.remove.assert_called_once_with("asec-internal")


def test_stop_retains_network_with_other_consumers() -> None:
    docker = MagicMock()
    docker.network.exists.side_effect = [False, True]
    docker.run.return_value = MagicMock()
    inspected = MagicMock()
    inspected.containers = {"someone-else": object()}
    docker.network.inspect.return_value = inspected

    spec = EgressProxySpec(allowlist=(("example.com", 443),))
    proxy = EgressProxy(spec, docker=docker)

    import anyio

    anyio.run(proxy.start)
    anyio.run(proxy.stop)
    # Network has other consumers -> we must not remove it.
    docker.network.remove.assert_not_called()
