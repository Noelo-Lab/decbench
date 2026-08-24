from __future__ import annotations

import pickle
import subprocess
from pathlib import Path

import pytest

from decbench.decompilers.dockerized import RetDecDecompiler
from decbench.decompilers.raw import glaurung_raw, manifold_raw
from decbench.decompilers.raw.glaurung_raw import RawGlaurungDecompiler
from decbench.decompilers.raw.manifold_raw import ManifoldDecompiler
from decbench.utils import docker_task
from decbench.utils.docker_task import (
    DOCKER_TASK_LABEL,
    DOCKER_TASK_TOKEN_ENV,
    docker_task_label_args,
    remove_docker_task_containers,
)
from scripts import run_benchmark


def _assert_task_label(command: list[str], token: str) -> None:
    label_index = command.index("--label")
    assert command[label_index + 1] == f"{DOCKER_TASK_LABEL}={token}"


def test_task_label_args_are_absent_outside_timed_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(DOCKER_TASK_TOKEN_ENV, raising=False)
    assert docker_task_label_args() == []


def test_task_label_rejects_untrusted_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DOCKER_TASK_TOKEN_ENV, "not-a-task-token")
    with pytest.raises(ValueError, match="32 lowercase hex"):
        docker_task_label_args()


def test_cleanup_revalidates_full_ids_and_exact_labels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "1" * 32
    exact_id = "a" * 64
    wrong_label_id = "b" * 64
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[1:3] == ["container", "ls"]:
            return subprocess.CompletedProcess(
                command,
                0,
                f"{exact_id}\n{wrong_label_id}\nshort-id\n",
                "",
            )
        if command[1] == "inspect":
            label = token if command[-1] == exact_id else "2" * 32
            return subprocess.CompletedProcess(command, 0, f"{label}\n", "")
        if command[1:3] == ["container", "rm"]:
            return subprocess.CompletedProcess(command, 0, f"{exact_id}\n", "")
        raise AssertionError(command)

    monkeypatch.setattr(docker_task.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(docker_task.subprocess, "run", fake_run)

    assert remove_docker_task_containers(token) == (exact_id,)
    query = calls[0]
    assert query[-2:] == ["--filter", f"label={DOCKER_TASK_LABEL}={token}"]
    remove = calls[-1]
    assert remove == ["/usr/bin/docker", "container", "rm", "--force", exact_id]
    assert wrong_label_id not in remove
    assert "short-id" not in remove


def test_cleanup_never_removes_without_exact_inspect_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "3" * 32
    candidate = "c" * 64
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[1:3] == ["container", "ls"]:
            return subprocess.CompletedProcess(command, 0, f"{candidate}\n", "")
        if command[1] == "inspect":
            return subprocess.CompletedProcess(command, 0, "different\n", "")
        raise AssertionError("cleanup issued a broad removal")

    monkeypatch.setattr(docker_task.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(docker_task.subprocess, "run", fake_run)

    assert remove_docker_task_containers(token) == ()
    assert all(command[1:3] != ["container", "rm"] for command in calls)


def test_timed_tasks_pass_unique_tokens_and_cleanup_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tokens = iter(("4" * 32, "5" * 32))
    child_envs: list[dict[str, str]] = []
    cleaned: list[str] = []

    class TimedOutProcess:
        pid = 12345

        def __init__(self) -> None:
            self.finished = False

        def wait(self, timeout: float) -> int:
            raise subprocess.TimeoutExpired("decompile", timeout)

        def poll(self) -> int | None:
            return 0 if self.finished else None

    def fake_popen(_command: list[str], **kwargs: object) -> TimedOutProcess:
        child_envs.append(dict(kwargs["env"]))  # type: ignore[arg-type]
        return TimedOutProcess()

    def fake_kill(process: TimedOutProcess) -> None:
        process.finished = True

    def fake_cleanup(token: str) -> tuple[str, ...]:
        cleaned.append(token)
        return ()

    monkeypatch.setattr(run_benchmark, "new_docker_task_token", lambda: next(tokens))
    monkeypatch.setattr(run_benchmark.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(run_benchmark, "_kill_process_group", fake_kill)
    monkeypatch.setattr(run_benchmark, "remove_docker_task_containers", fake_cleanup)

    binary = tmp_path / "binary"
    for _ in range(2):
        result = run_benchmark._timed_decompile(binary, "test", tmp_path, "NONE")
        assert result.decompiler.extra["timed_out"] is True

    assert [env[DOCKER_TASK_TOKEN_ENV] for env in child_envs] == ["4" * 32, "5" * 32]
    assert cleaned == ["4" * 32, "5" * 32]


def test_timed_task_cleans_container_after_backend_reports_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    token = "8" * 32
    cleaned: list[str] = []

    class ErrorResultProcess:
        pid = 23456

        def __init__(self, pickle_path: Path) -> None:
            self.pickle_path = pickle_path

        def wait(self, timeout: float) -> int:
            assert timeout > 0
            from decbench.models.decompilation import DecompilationResult, DecompilerMetadata

            result = DecompilationResult(
                binary_path=tmp_path / "binary",
                binary_name="binary",
                decompiler=DecompilerMetadata(
                    decompiler_name="test",
                    failed_functions=["all"],
                    extra={"error": "container timeout"},
                ),
            )
            self.pickle_path.write_bytes(pickle.dumps(result))
            return 0

        def poll(self) -> int:
            return 0

    def fake_popen(command: list[str], **_kwargs: object) -> ErrorResultProcess:
        return ErrorResultProcess(Path(command[5]))

    monkeypatch.setattr(run_benchmark, "new_docker_task_token", lambda: token)
    monkeypatch.setattr(run_benchmark.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        run_benchmark,
        "remove_docker_task_containers",
        lambda value: cleaned.append(value) or (),
    )

    result = run_benchmark._timed_decompile(tmp_path / "binary", "test", tmp_path, "NONE")

    assert result.decompiler.extra["error"] == "container timeout"
    assert cleaned == [token]


def test_every_decompile_docker_path_carries_current_task_label(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    token = "6" * 32
    monkeypatch.setenv(DOCKER_TASK_TOKEN_ENV, token)
    captured: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append(command)
        return subprocess.CompletedProcess(command, 0, "revision\n", "")

    monkeypatch.setattr("decbench.decompilers.dockerized.subprocess.run", fake_run)
    monkeypatch.setattr(RetDecDecompiler, "_docker_bin", staticmethod(lambda: "docker"))
    RetDecDecompiler()._run_docker([], tmp_path / "binary", tmp_path)

    glaurung = RawGlaurungDecompiler()
    monkeypatch.setattr(glaurung, "_select_path", lambda: ("docker", None))
    monkeypatch.setattr(glaurung_raw, "_docker_bin", lambda: "docker")
    captured.append(glaurung._build_command(tmp_path / "binary", {0x1000}))

    monkeypatch.setattr(manifold_raw, "_docker_bin", lambda: "docker")
    manifold = ManifoldDecompiler()
    manifold._run_docker(tmp_path / "binary", tmp_path, "out.c", 10)

    for command in captured:
        _assert_task_label(command, token)


def test_docker_version_probes_carry_current_task_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "7" * 32
    monkeypatch.setenv(DOCKER_TASK_TOKEN_ENV, token)
    captured: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append(command)
        return subprocess.CompletedProcess(command, 0, "abcdef0\n", "")

    monkeypatch.setattr(glaurung_raw, "_docker_bin", lambda: "docker")
    monkeypatch.setattr(manifold_raw, "_docker_bin", lambda: "docker")
    monkeypatch.setattr(glaurung_raw.subprocess, "run", fake_run)

    assert RawGlaurungDecompiler()._docker_version() == "git-abcdef0"
    assert ManifoldDecompiler()._docker_version() == "git-abcdef0"
    assert len(captured) == 2
    for command in captured:
        _assert_task_label(command, token)
