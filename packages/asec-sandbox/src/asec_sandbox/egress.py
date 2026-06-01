"""EgressProxy — a deny-default tinyproxy allowlist sidecar on an internal Docker network.

The agent sandbox runs with ``--network=none`` by default. When a `SandboxSpec` requests an
``allowlist`` network posture, the only sanctioned egress path is *through* this proxy: we
create an `asec-internal` Docker network with ``internal=true`` (no gateway, no internet
route), launch tinyproxy on it with a rendered deny-default config, and join the agent
container to the proxy's network namespace via ``--network=container:<proxy_id>`` (whitepaper
§07). tinyproxy's filter is built from the allowlist as **anchored** regexes so
``api.example.com`` cannot match ``api.example.com.evil.net``.

`_render_tinyproxy_conf` is a pure, deterministic function so the rendered config can be
asserted against a golden string in tests without touching Docker.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import anyio.to_thread
import structlog
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

if TYPE_CHECKING:
    from python_on_whales import DockerClient

logger = structlog.get_logger(__name__)

#: Default internal network: ``internal=true`` means Docker provisions no gateway, so the
#: only way out is the proxy itself.
DEFAULT_NETWORK_NAME = "asec-internal"


class EgressProxySpec(BaseModel):
    """Frozen description of the tinyproxy egress allowlist sidecar."""

    model_config = ConfigDict(frozen=True)

    image: str = "tinyproxy:latest"
    allowlist: tuple[tuple[str, int], ...]
    bind_port: int = 8888
    network_name: str = DEFAULT_NETWORK_NAME

    @field_validator("bind_port")
    @classmethod
    def _check_bind_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            msg = f"bind_port must be in 1..65535, got {v}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def _check_allowlist(self) -> EgressProxySpec:
        # An empty allowlist is rejected: a deny-default proxy with zero rules permits
        # nothing, which is exactly network='none' — so it should be expressed that way,
        # not as a degenerate proxy.
        if not self.allowlist:
            msg = "allowlist must be non-empty (use network='none' for no egress at all)"
            raise ValueError(msg)
        for host, port in self.allowlist:
            if not host:
                msg = "allowlist entries must have a non-empty host"
                raise ValueError(msg)
            if not (1 <= port <= 65535):
                msg = f"allowlist port for {host!r} must be in 1..65535, got {port}"
                raise ValueError(msg)
        return self

    @property
    def hosts(self) -> tuple[str, ...]:
        """Deduplicated allowlist host names, in first-seen order."""
        seen: dict[str, None] = {}
        for host, _port in self.allowlist:
            seen.setdefault(host, None)
        return tuple(seen)


def _render_tinyproxy_conf(spec: EgressProxySpec) -> str:
    """Render a deterministic deny-default tinyproxy config body.

    The ``Filter`` directive points at ``/etc/tinyproxy/filter``; ``FilterDefaultDeny Yes``
    flips tinyproxy from allow-default to deny-default so only hosts matching a filter line
    are permitted. The companion filter file (see `_render_filter`) holds one anchored regex
    per allowlisted host.
    """
    lines = [
        "User nobody",
        "Group nogroup",
        f"Port {spec.bind_port}",
        "Timeout 600",
        "Allow 0.0.0.0/0",
        "FilterDefaultDeny Yes",
        "FilterExtended On",
        "Filter /etc/tinyproxy/filter",
        "FilterURLs Off",
        "LogLevel Info",
    ]
    return "\n".join(lines) + "\n"


def _render_filter(spec: EgressProxySpec) -> str:
    """Render the tinyproxy filter file: one anchored regex per allowlisted host."""
    return "".join(f"^{re.escape(host)}$\n" for host in spec.hosts)


class EgressProxy:
    """Lifecycle manager for the tinyproxy allowlist sidecar on an internal Docker network."""

    def __init__(self, spec: EgressProxySpec, *, docker: DockerClient | None = None) -> None:
        self._spec = spec
        if docker is None:
            from python_on_whales import DockerClient as _DockerClient

            docker = _DockerClient()
        # Any: interchangeably a real DockerClient or a MagicMock in tests, and we call the
        # internal-network create that is outside python-on-whales' typed surface.
        self._docker: Any = docker
        self._container: Any = None
        self._created_network = False

    @property
    def spec(self) -> EgressProxySpec:
        return self._spec

    @property
    def container(self) -> Any:
        return self._container

    @property
    def network_name(self) -> str:
        return self._spec.network_name

    def _ensure_network(self) -> None:
        """Idempotently create the internal (no-gateway) Docker network.

        ``internal=True`` provisions the network with no gateway, so the proxy is the only
        route off it. python-on-whales' typed ``network.create`` does not surface the
        ``--internal`` flag, so for a real client we fall back to the docker CLI built from
        ``docker.docker_cmd``; the call is expressed as ``network.create(name, internal=True)``
        first so tests with a mocked client can assert the ``internal`` flag directly.
        """
        name = self._spec.network_name
        if self._docker.network.exists(name):
            logger.debug("egress.network.exists", network=name)
            return
        try:
            self._docker.network.create(name, internal=True)
        except TypeError:
            # Real python-on-whales client: no ``internal`` kwarg — shell out to the CLI.
            import subprocess

            base = [str(p) for p in self._docker.docker_cmd]
            subprocess.run(
                [*base, "network", "create", "--internal", name],
                check=True,
                capture_output=True,
                text=True,
            )
        self._created_network = True
        logger.info("egress.network.created", network=name, internal=True)

    def _start_sync(self) -> Any:
        self._ensure_network()
        conf = _render_tinyproxy_conf(self._spec)
        filt = _render_filter(self._spec)
        # Write the rendered config into the container's writable tmpfs via an entrypoint
        # heredoc, then exec tinyproxy in the foreground (-d). Mounting tmpfs at the conf
        # dir keeps the root filesystem read-only while letting us drop the rendered files.
        bootstrap = (
            "set -e; "
            "mkdir -p /etc/tinyproxy; "
            "printf '%s' \"$ASEC_TINYPROXY_CONF\" > /etc/tinyproxy/tinyproxy.conf; "
            "printf '%s' \"$ASEC_TINYPROXY_FILTER\" > /etc/tinyproxy/filter; "
            "exec tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf"
        )
        self._container = self._docker.run(
            self._spec.image,
            ["sh", "-c", bootstrap],
            networks=[self._spec.network_name],
            envs={
                "ASEC_TINYPROXY_CONF": conf,
                "ASEC_TINYPROXY_FILTER": filt,
            },
            cap_drop=["ALL"],
            security_options=["no-new-privileges"],
            read_only=True,
            tmpfs=["/etc/tinyproxy", "/var/log/tinyproxy", "/tmp"],
            detach=True,
            remove=False,
        )
        logger.info(
            "egress.proxy.started",
            network=self._spec.network_name,
            bind_port=self._spec.bind_port,
            allowed_hosts=list(self._spec.hosts),
        )
        return self._container

    async def start(self) -> Any:
        """Ensure the internal network, launch tinyproxy, and return the container handle."""
        return await anyio.to_thread.run_sync(self._start_sync)

    def _stop_sync(self) -> None:
        if self._container is not None:
            try:
                self._docker.container.remove(self._container, force=True)
            except Exception:
                logger.warning("egress.proxy.remove_failed", exc_info=True)
            self._container = None
        # Only tear the network down if we created it and nothing else is attached to it.
        name = self._spec.network_name
        if self._created_network and self._docker.network.exists(name):
            net = self._docker.network.inspect(name)
            containers = getattr(net, "containers", {}) or {}
            if not containers:
                try:
                    self._docker.network.remove(name)
                    logger.info("egress.network.removed", network=name)
                except Exception:
                    logger.warning("egress.network.remove_failed", network=name, exc_info=True)
            else:
                logger.debug("egress.network.retained", network=name, consumers=len(containers))
            self._created_network = False

    async def stop(self) -> None:
        """Stop + remove the proxy; remove the network only if we own it and it is empty."""
        await anyio.to_thread.run_sync(self._stop_sync)
