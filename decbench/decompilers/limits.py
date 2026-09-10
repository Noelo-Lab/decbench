"""Shared runtime limits for decompiler backends and benchmark workers."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
import uuid
from functools import cache
from pathlib import Path
from typing import TextIO

BINARY_TIMEOUT_SECONDS = 3600
FUNCTION_TIMEOUT_SECONDS = 600
BINARY_MEMORY_LIMIT_BYTES = 16 * 1024**3

_SCOPE_RE = re.compile(r"^decbench-[A-Za-z0-9_.-]+\.scope$")
_DOCKER_CONTAINER_ID_RE = re.compile(r"^[a-f0-9]{12,64}$")
_DOCKER_LABEL_RE = re.compile(r"^decbench\.(?:invocation|resource-scope)=[A-Za-z0-9_.-]+$")
_RESOURCE_SCOPE_ENV = "DECBENCH_RESOURCE_SCOPE_UNIT"
_l = logging.getLogger(__name__)


def timeout_env_var(decompiler_name: str) -> str:
    """Return the per-backend timeout variable for a decompiler spec."""
    base_name = decompiler_name.split("@", 1)[0]
    suffix = re.sub(r"[^A-Za-z0-9]", "_", base_name).upper()
    return f"DECBENCH_{suffix}_TIMEOUT"


def binary_timeout_seconds(decompiler_name: str) -> int:
    """Resolve a backend override, the global override, or the shared default."""
    raw = os.environ.get(timeout_env_var(decompiler_name))
    if raw in (None, ""):
        raw = os.environ.get("DECBENCH_DECOMPILE_TIMEOUT")
    timeout = int(raw) if raw not in (None, "") else BINARY_TIMEOUT_SECONDS
    if timeout <= 0:
        raise ValueError("decompiler binary timeout must be positive")
    return timeout


def docker_memory_args(memory_limit_bytes: int = BINARY_MEMORY_LIMIT_BYTES) -> list[str]:
    """Docker arguments for a hard RAM limit with no additional swap."""
    if not 0 < memory_limit_bytes <= BINARY_MEMORY_LIMIT_BYTES:
        raise ValueError("decompiler memory limit must be between 1 byte and 16 GiB")
    limit = str(memory_limit_bytes)
    return ["--memory", limit, "--memory-swap", limit]


def docker_tracking_args() -> list[str]:
    """Label one container invocation and its enclosing resource scope."""
    labels = [f"decbench.invocation={uuid.uuid4().hex}"]
    scope = os.environ.get(_RESOURCE_SCOPE_ENV)
    if scope and _SCOPE_RE.fullmatch(scope):
        labels.append(f"decbench.resource-scope={scope}")
    return [item for label in labels for item in ("--label", label)]


def cleanup_docker_containers(label: str, wait_seconds: float = 5.0) -> int:
    """Poll for and force-remove containers carrying one exact DecBench label."""
    if not _DOCKER_LABEL_RE.fullmatch(label):
        raise ValueError(f"refusing to remove containers for unexpected label: {label!r}")
    docker = shutil.which("docker")
    if docker is None:
        return 0
    removed_ids: set[str] = set()
    deadline = time.monotonic() + max(0.0, wait_seconds)
    while True:
        try:
            found = subprocess.run(
                [
                    docker,
                    "ps",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    f"label={label}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if found.returncode != 0:
                _l.warning("could not list Docker containers for %s", label)
                return len(removed_ids)
            container_ids = [
                line.strip()
                for line in found.stdout.splitlines()
                if _DOCKER_CONTAINER_ID_RE.fullmatch(line.strip())
            ]
            if container_ids:
                removed = subprocess.run(
                    [docker, "rm", "--force", *container_ids],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
                if removed.returncode != 0:
                    _l.warning("could not remove every Docker container for %s", label)
                removed_ids.update(container_ids)
        except (OSError, subprocess.TimeoutExpired):
            _l.warning("Docker container cleanup failed for %s", label, exc_info=True)
            return len(removed_ids)
        if time.monotonic() >= deadline:
            return len(removed_ids)
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def cleanup_docker_invocation(command: list[str], wait_seconds: float = 5.0) -> int:
    """Clean up the uniquely labelled container launched by ``command``."""
    for index, arg in enumerate(command[:-1]):
        label = command[index + 1]
        if arg == "--label" and label.startswith("decbench.invocation="):
            return cleanup_docker_containers(label, wait_seconds)
    return 0


def cleanup_docker_scope(unit_name: str, wait_seconds: float = 5.0) -> int:
    """Clean up containers launched from a timed-out DecBench resource scope."""
    if not _SCOPE_RE.fullmatch(unit_name):
        raise ValueError(f"refusing to clean containers for unexpected unit: {unit_name!r}")
    return cleanup_docker_containers(f"decbench.resource-scope={unit_name}", wait_seconds)


def resource_scope_command(
    command: list[str],
    timeout_seconds: int,
    *,
    memory_limit_bytes: int = BINARY_MEMORY_LIMIT_BYTES,
    unit_name: str | None = None,
) -> tuple[list[str], str]:
    """Wrap a command in a user cgroup enforcing time and aggregate memory limits."""
    systemd_run = shutil.which("systemd-run")
    if systemd_run is None:
        raise RuntimeError("systemd-run is required for decompiler resource limits")
    if timeout_seconds <= 0:
        raise ValueError("decompiler binary timeout must be positive")
    if not 0 < memory_limit_bytes <= BINARY_MEMORY_LIMIT_BYTES:
        raise ValueError("decompiler memory limit must be between 1 byte and 16 GiB")
    unit = unit_name or f"decbench-decompile-{os.getpid()}-{uuid.uuid4().hex}.scope"
    if not _SCOPE_RE.fullmatch(unit):
        raise ValueError(f"invalid DecBench resource-scope name: {unit!r}")
    wrapped = [
        systemd_run,
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        f"--unit={unit}",
        f"--setenv={_RESOURCE_SCOPE_ENV}={unit}",
        "--property=MemoryAccounting=yes",
        f"--property=MemoryMax={memory_limit_bytes}",
        "--property=MemorySwapMax=0",
        f"--property=RuntimeMaxSec={timeout_seconds}",
        "--property=KillSignal=SIGKILL",
        "--property=KillMode=control-group",
        "--",
        *command,
    ]
    return wrapped, unit


@cache
def resource_scopes_available() -> bool:
    """Return whether the user systemd manager accepts the required cgroup policy."""
    true_bin = shutil.which("true")
    if true_bin is None:
        return False
    try:
        command, _unit = resource_scope_command(
            [true_bin],
            10,
            unit_name=f"decbench-preflight-{os.getpid()}-{uuid.uuid4().hex}.scope",
        )
        probe = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


def require_resource_scopes() -> None:
    """Fail closed when the canonical runner cannot enforce per-binary cgroups."""
    if resource_scopes_available():
        return
    raise RuntimeError(
        "per-binary decompiler limits require cgroup v2 and a working user "
        "systemd manager (`systemd-run --user`)"
    )


def kill_resource_scope(unit_name: str) -> bool:
    """Kill every process in a DecBench scope, including children that called setsid."""
    if not _SCOPE_RE.fullmatch(unit_name):
        raise ValueError(f"refusing to kill unexpected systemd unit: {unit_name!r}")
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        _l.error("systemctl is unavailable; could not kill %s", unit_name)
        return False
    try:
        killed = subprocess.run(
            [
                systemctl,
                "--user",
                "kill",
                "--kill-who=all",
                "--signal=SIGKILL",
                unit_name,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        _l.error("could not kill resource scope %s", unit_name, exc_info=True)
        return False
    if killed.returncode != 0:
        _l.error("systemctl could not kill resource scope %s", unit_name)
        return False
    return True


def resource_scope_memory_events(
    process_id: int, unit_name: str, wait_seconds: float = 5.0
) -> TextIO | None:
    """Open a scope's cgroup-v2 events before systemd can collect its path."""
    deadline = time.monotonic() + wait_seconds
    cgroup_file = Path(f"/proc/{process_id}/cgroup")
    while time.monotonic() < deadline:
        try:
            for line in cgroup_file.read_text().splitlines():
                hierarchy, _controllers, relative = line.split(":", 2)
                if hierarchy == "0" and relative.endswith(f"/{unit_name}"):
                    events = Path("/sys/fs/cgroup") / relative.lstrip("/") / "memory.events"
                    if events.is_file():
                        return events.open()
        except (FileNotFoundError, OSError, ValueError):
            return None
        time.sleep(0.05)
    return None


def resource_scope_oom_killed(memory_events: TextIO | None) -> bool:
    """Return whether the cgroup has killed a process for exceeding MemoryMax."""
    if memory_events is None:
        return False
    try:
        memory_events.seek(0)
        events = dict(line.split() for line in memory_events.read().splitlines())
        return int(events.get("oom_kill", "0")) > 0
    except (OSError, ValueError):
        return False
