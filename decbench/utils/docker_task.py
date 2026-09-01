"""Exact-scope Docker labels and cleanup for benchmark decompile tasks."""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess

DOCKER_TASK_TOKEN_ENV = "DECBENCH_DOCKER_TASK_TOKEN"
DOCKER_TASK_LABEL = "com.decbench.decompile-task"

_TOKEN_RE = re.compile(r"[0-9a-f]{32}")
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}")


def validate_docker_task_token(token: str) -> str:
    """Return a valid task token or fail closed before a Docker operation."""
    if not _TOKEN_RE.fullmatch(token):
        raise ValueError("Docker decompile task token must be 32 lowercase hex characters")
    return token


def new_docker_task_token() -> str:
    """Generate a unique 128-bit token for one timed decompile child."""
    return secrets.token_hex(16)


def docker_task_label_args() -> list[str]:
    """Return Docker CLI label arguments for the current timed task, if any."""
    token = os.environ.get(DOCKER_TASK_TOKEN_ENV)
    if token is None:
        return []
    return ["--label", f"{DOCKER_TASK_LABEL}={validate_docker_task_token(token)}"]


def remove_docker_task_containers(
    token: str,
    docker_path: str | None = None,
) -> tuple[str, ...]:
    """Force-remove only containers whose exact task label matches ``token``."""
    token = validate_docker_task_token(token)
    docker = docker_path or shutil.which("docker")
    if docker is None:
        return ()
    try:
        query = subprocess.run(
            [
                docker,
                "container",
                "ls",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label={DOCKER_TASK_LABEL}={token}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception:  # noqa: BLE001
        return ()
    if query.returncode != 0:
        return ()

    candidates = [
        container_id
        for line in query.stdout.splitlines()
        if _CONTAINER_ID_RE.fullmatch(container_id := line.strip())
    ]
    verified: list[str] = []
    for container_id in candidates:
        try:
            inspect = subprocess.run(
                [
                    docker,
                    "inspect",
                    "--type",
                    "container",
                    "--format",
                    f'{{{{ index .Config.Labels "{DOCKER_TASK_LABEL}" }}}}',
                    container_id,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except Exception:  # noqa: BLE001
            continue
        if inspect.returncode == 0 and inspect.stdout.strip() == token:
            verified.append(container_id)
    if not verified:
        return ()

    try:
        removed = subprocess.run(
            [docker, "container", "rm", "--force", *verified],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:  # noqa: BLE001
        return ()
    return tuple(verified) if removed.returncode == 0 else ()
