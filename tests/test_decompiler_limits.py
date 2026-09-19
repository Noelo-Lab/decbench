"""Shared decompiler timeout and memory-limit policy tests."""

from __future__ import annotations

import pickle
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from decbench.decompilers.base import DecompilerConfig
from decbench.decompilers.dockerized import DockerizedDecompiler
from decbench.decompilers.limits import (
    BINARY_MEMORY_LIMIT_BYTES,
    BINARY_TIMEOUT_SECONDS,
    FUNCTION_TIMEOUT_SECONDS,
    binary_timeout_seconds,
    cleanup_docker_containers,
    cleanup_docker_invocation,
    docker_memory_args,
    docker_tracking_args,
    kill_resource_scope,
    resource_scope_command,
    resource_scope_memory_events,
    resource_scope_oom_killed,
    resource_scopes_available,
    timeout_env_var,
)
from decbench.decompilers.raw.glaurung_raw import RawGlaurungDecompiler
from decbench.decompilers.raw.kuna_raw import RawKunaDecompiler
from decbench.decompilers.registry import DecompilerRegistry
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)


def test_shared_config_defaults() -> None:
    config = DecompilerConfig()
    assert config.binary_timeout_seconds == BINARY_TIMEOUT_SECONDS == 3600
    assert config.function_timeout_seconds == FUNCTION_TIMEOUT_SECONDS == 600
    assert BINARY_MEMORY_LIMIT_BYTES == 16 * 1024**3


def test_every_registered_backend_inherits_shared_limits() -> None:
    for name in DecompilerRegistry.list_registered():
        config = DecompilerRegistry.get(name).config
        assert config.binary_timeout_seconds == BINARY_TIMEOUT_SECONDS
        assert config.function_timeout_seconds == FUNCTION_TIMEOUT_SECONDS


def test_binary_timeout_resolver_handles_versions_and_hyphens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DECBENCH_DECOMPILE_TIMEOUT", raising=False)
    monkeypatch.delenv("DECBENCH_CLAUDE_CODE_TIMEOUT", raising=False)
    assert timeout_env_var("claude-code@model") == "DECBENCH_CLAUDE_CODE_TIMEOUT"
    assert binary_timeout_seconds("claude-code@model") == 3600

    monkeypatch.setenv("DECBENCH_DECOMPILE_TIMEOUT", "2400")
    assert binary_timeout_seconds("future-backend") == 2400

    monkeypatch.setenv("DECBENCH_CLAUDE_CODE_TIMEOUT", "1800")
    assert binary_timeout_seconds("claude-code@model") == 1800


def test_docker_memory_limit_disables_additional_swap() -> None:
    limit = str(16 * 1024**3)
    assert docker_memory_args() == ["--memory", limit, "--memory-swap", limit]
    with pytest.raises(ValueError):
        docker_memory_args(BINARY_MEMORY_LIMIT_BYTES + 1)


def test_docker_tracking_and_cleanup_are_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DECBENCH_RESOURCE_SCOPE_UNIT", "decbench-test.scope")
    args = docker_tracking_args()
    invocation = next(
        args[index + 1]
        for index, arg in enumerate(args[:-1])
        if arg == "--label" and args[index + 1].startswith("decbench.invocation=")
    )
    assert "decbench.resource-scope=decbench-test.scope" in args

    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        stdout = "a" * 64 + "\nnot-a-container\n" if "ps" in command else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr("decbench.decompilers.limits.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("decbench.decompilers.limits.subprocess.run", fake_run)
    cleanup_docker_invocation(["docker", "run", "--label", invocation, "image"], wait_seconds=0)
    assert calls[0][-1] == f"label={invocation}"
    assert calls[1] == ["/usr/bin/docker", "rm", "--force", "a" * 64]

    with pytest.raises(ValueError):
        cleanup_docker_containers("unowned=true")


def test_docker_cleanup_waits_for_a_late_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    list_attempts = 0

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal list_attempts
        calls.append(command)
        if "ps" in command:
            list_attempts += 1
            stdout = "" if list_attempts == 1 else "b" * 64
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr("decbench.decompilers.limits.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("decbench.decompilers.limits.subprocess.run", fake_run)

    removed = cleanup_docker_containers("decbench.invocation=late", wait_seconds=0.11)

    assert removed == 1
    assert calls[-1] == ["/usr/bin/docker", "rm", "--force", "b" * 64]


def test_resource_scope_enforces_time_and_aggregate_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("decbench.decompilers.limits.shutil.which", lambda name: f"/usr/bin/{name}")
    command, unit = resource_scope_command(
        ["/usr/bin/python3", "worker.py"],
        3600,
        unit_name="decbench-test.scope",
    )
    assert unit == "decbench-test.scope"
    assert "--property=MemoryMax=17179869184" in command
    assert "--property=MemorySwapMax=0" in command
    assert "--property=RuntimeMaxSec=3600" in command
    assert "--property=KillSignal=SIGKILL" in command
    assert "--property=KillMode=control-group" in command
    assert "--setenv=DECBENCH_RESOURCE_SCOPE_UNIT=decbench-test.scope" in command
    assert command[-3:] == ["--", "/usr/bin/python3", "worker.py"]


def test_backend_function_watchdogs_share_600_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DECBENCH_KUNA_MAX_FN_SECONDS", raising=False)
    kuna = RawKunaDecompiler()
    monkeypatch.setattr(kuna, "_kuna_bin", lambda: "/usr/bin/kuna")
    assert kuna._build_command(Path("sample"))[-2:] == ["--max-fn-seconds", "600"]

    monkeypatch.delenv("DECBENCH_GLAURUNG_TIMEOUT_MS", raising=False)
    glaurung = RawGlaurungDecompiler()
    monkeypatch.setattr(glaurung, "_select_path", lambda: ("native", Path("/usr/bin/glaurung")))
    command = glaurung._build_command(Path("sample"), {0x1000})
    assert command[-2:] == ["--timeout-ms", "600000"]

    assert DecompilerRegistry.get("codex")._timeout() == 600


def test_dockerized_default_binary_timeout_is_shared() -> None:
    assert DockerizedDecompiler().container_timeout == 3600


def test_dockerized_run_uses_memory_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    decompiler = DockerizedDecompiler()
    monkeypatch.setattr(decompiler, "_docker_bin", lambda: "/usr/bin/docker")
    seen: list[str] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.extend(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("decbench.decompilers.dockerized.subprocess.run", fake_run)
    binary = tmp_path / "sample"
    binary.touch()
    decompiler._run_docker([], binary, tmp_path)

    limit = str(16 * 1024**3)
    assert seen[seen.index("--memory") + 1] == limit
    assert seen[seen.index("--memory-swap") + 1] == limit
    assert seen[seen.index("--network") + 1] == "none"


def test_llm_docker_memory_is_split_across_function_workers(tmp_path: Path) -> None:
    config = DecompilerConfig(
        extra_options={"docker_image": "agents", "fn_workers": 4, "max_funcs": 8}
    )
    decompiler = DecompilerRegistry.get("claude-code", config)
    command, _kwargs = decompiler._invocation(tmp_path, "prompt", tmp_path / "target.bin")
    limit = str(4 * 1024**3)
    assert command[command.index("--memory") + 1] == limit
    assert command[command.index("--memory-swap") + 1] == limit


def test_decompile_result_pickle_uses_unique_system_temp_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from scripts import run_benchmark

    system_temp = tmp_path / "system-temp"
    system_temp.mkdir()
    out_dir = tmp_path / "durable"
    out_dir.mkdir()
    stale_path = out_dir / "angr_target.result.pkl"
    stale_path.write_bytes(b"stale")
    result_paths: list[Path] = []
    result = DecompilationResult(
        binary_path=tmp_path / "target",
        binary_name="target",
        decompiler=DecompilerMetadata(decompiler_name="angr"),
    )

    def decompile(
        _binary: Path, _name: str, output: Path, _names: str, result_path: Path
    ) -> DecompilationResult:
        assert output == out_dir
        result_paths.append(result_path)
        result_path.write_bytes(b"result")
        result_path.with_suffix(".pkl.tmp").write_bytes(b"partial")
        return result

    monkeypatch.setattr(
        run_benchmark,
        "_timed_decompile_with_result_path",
        decompile,
    )
    monkeypatch.setenv("TMPDIR", str(system_temp))
    monkeypatch.setattr(tempfile, "tempdir", None)

    results = [
        run_benchmark._timed_decompile(tmp_path / parent / "target", "angr", out_dir, "NONE")
        for parent in ("first", "second")
    ]

    assert results == [result, result]
    assert len(set(result_paths)) == 2
    assert all(path.is_relative_to(system_temp) for path in result_paths)
    assert all(not path.parent.exists() for path in result_paths)
    assert stale_path.read_bytes() == b"stale"


def test_oom_result_recovers_partial_checkpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from scripts import run_benchmark

    binary = tmp_path / "target"
    partial = DecompilationResult(
        binary_path=binary,
        binary_name=binary.stem,
        decompiler=DecompilerMetadata(decompiler_name="angr"),
        functions={
            "finished": FunctionDecompilation(
                name="finished", address=0x1000, decompiled_code="int finished(void) {}"
            )
        },
    )

    class FakeProcess:
        pid = 1234
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    process = FakeProcess()

    def kill(_process: FakeProcess, _unit: str | None = None) -> None:
        process.returncode = 128 + 9

    seen_command: list[str] = []
    result_paths: list[Path] = []

    def scope_command(
        command: list[str], _timeout: int, **_kwargs: object
    ) -> tuple[list[str], str]:
        seen_command.extend(command)
        return command, "decbench-test.scope"

    def popen(command: list[str], **_kwargs: object) -> FakeProcess:
        result_path = Path(command[-3])
        result_paths.append(result_path)
        result_path.write_bytes(pickle.dumps(partial))
        return process

    monkeypatch.setenv("DECBENCH_ANGR_TIMEOUT", "7200")
    monkeypatch.setattr(
        run_benchmark,
        "resource_scope_command",
        scope_command,
    )
    monkeypatch.setattr(run_benchmark.subprocess, "Popen", popen)
    monkeypatch.setattr(run_benchmark, "resource_scope_memory_events", lambda *_args: None)
    monkeypatch.setattr(run_benchmark, "resource_scope_oom_killed", lambda _events: True)
    monkeypatch.setattr(run_benchmark, "_kill_process_group", kill)
    monkeypatch.setattr(run_benchmark, "cleanup_docker_scope", lambda _unit: None)

    recovered = run_benchmark._timed_decompile(binary, "angr", tmp_path, "NONE")

    assert set(recovered.functions) == {"finished"}
    assert recovered.decompiler.timeout_occurred is False
    assert recovered.decompiler.extra["failure"] == "memory>16GiB"
    assert recovered.decompiler.extra["memory_limit_exceeded"] is True
    assert recovered.decompiler.extra["recovered_partial"] is True
    assert seen_command[-1] == "7200"
    assert not result_paths[0].parent.exists()


def test_timeout_result_preserves_empty_progress_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from scripts import run_benchmark

    binary = tmp_path / "target"
    binary.touch()

    class FakeProcess:
        pid = 1234
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    process = FakeProcess()

    def popen(command: list[str], **_kwargs: object) -> FakeProcess:
        progress_path = Path(command[-3])
        progress_path.write_bytes(
            pickle.dumps(
                DecompilationResult(
                    binary_path=binary,
                    binary_name=binary.stem,
                    decompiler=DecompilerMetadata(
                        decompiler_name="dewolf@2026.7.11",
                        decompiler_version="v2026.7.11",
                        extra={"backend": "dewolf", "via": "raw", "partial": True},
                    ),
                )
            )
        )
        return process

    def kill(_process: FakeProcess, _unit: str | None = None) -> None:
        process.returncode = 128 + 9

    times = iter((0.0, 3601.0))
    monkeypatch.delenv("DECBENCH_DEWOLF_TIMEOUT", raising=False)
    monkeypatch.delenv("DECBENCH_DECOMPILE_TIMEOUT", raising=False)
    monkeypatch.setattr(run_benchmark.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(
        run_benchmark,
        "resource_scope_command",
        lambda command, _timeout, **_kwargs: (command, "decbench-test.scope"),
    )
    monkeypatch.setattr(run_benchmark.subprocess, "Popen", popen)
    monkeypatch.setattr(run_benchmark, "resource_scope_memory_events", lambda *_args: None)
    monkeypatch.setattr(run_benchmark, "resource_scope_oom_killed", lambda _events: False)
    monkeypatch.setattr(run_benchmark, "_kill_process_group", kill)

    result = run_benchmark._timed_decompile(binary, "dewolf@2026.7.11", tmp_path, "NONE")

    assert result.functions == {}
    assert result.decompiler.decompiler_name == "dewolf@2026.7.11"
    assert result.decompiler.decompiler_version == "v2026.7.11"
    assert result.decompiler.failed_functions == ["all"]
    assert result.decompiler.timeout_occurred is True
    assert result.decompiler.extra == {
        "backend": "dewolf",
        "via": "raw",
        "partial": True,
        "failure": "timeout>3600s",
        "memory_limit_exceeded": False,
        "timed_out": True,
    }


def test_decompile_worker_receives_resolved_binary_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from scripts import decompile_one

    binary = tmp_path / "binary"
    output = tmp_path / "result.pkl"
    seen: list[DecompilerConfig] = []

    def decompile(
        _binary: Path,
        decompiler: str,
        _output_dir: Path,
        **kwargs: object,
    ) -> DecompilationResult:
        config = kwargs["config"]
        assert isinstance(config, DecompilerConfig)
        seen.append(config)
        return DecompilationResult(
            binary_path=binary,
            binary_name=binary.stem,
            decompiler=DecompilerMetadata(decompiler_name=decompiler),
        )

    monkeypatch.setattr(decompile_one, "decompile_binary", decompile)
    monkeypatch.setattr(
        sys,
        "argv",
        ["decompile_one.py", str(binary), "angr", str(tmp_path), str(output), "NONE", "7200"],
    )

    assert decompile_one.main() == 0
    assert seen[0].binary_timeout_seconds == 7200
    assert pickle.loads(output.read_bytes()).decompiler.decompiler_name == "angr"
    assert not output.with_suffix(".pkl.tmp").exists()


@pytest.mark.parametrize(
    ("name", "selected_via", "expected_via"),
    [
        ("angr", "raw", "raw"),
        ("binja", "raw", "raw"),
        ("dewolf", "raw", "raw"),
        ("ghidra", "raw", "raw"),
        ("ida", "raw", "raw"),
        ("kuna", "raw", "raw"),
        ("r2dec", "docker", "docker"),
        ("r2dec", "native", "native"),
        ("glaurung", "raw", None),
    ],
)
def test_native_producers_seed_progress_metadata_before_decompilation(
    tmp_path: Path,
    name: str,
    selected_via: str,
    expected_via: str | None,
) -> None:
    from decbench.pipeline import decompile as pipeline_decompile

    binary = tmp_path / "target"
    binary.touch()
    progress_path = tmp_path / "result.pkl"
    decompiler = SimpleNamespace(
        name=name,
        id=f"{name}@requested",
        image="decbench/r2dec:test",
        get_version=lambda: "realized-version",
        _select_path=lambda: selected_via,
    )

    pipeline_decompile._seed_progress(
        cast(Any, decompiler),
        binary,
        tmp_path,
        progress_path,
    )

    if expected_via is None:
        assert not progress_path.exists()
        return

    seed = pickle.loads(progress_path.read_bytes())
    assert seed.functions == {}
    assert seed.binary_path == binary
    assert seed.output_dir == tmp_path
    assert seed.decompiler.decompiler_name == f"{name}@requested"
    assert seed.decompiler.decompiler_version == "realized-version"
    assert seed.decompiler.failed_functions == []
    assert seed.decompiler.extra == {
        "backend": name,
        "via": expected_via,
        "partial": True,
        **({"image": "decbench/r2dec:test"} if expected_via == "docker" else {}),
    }


@pytest.mark.parametrize(
    ("elapsed", "expected_timeout", "expected_failure"),
    [(3601.0, True, "timeout>3600s"), (1.0, False, "exit 137")],
)
def test_sigkill_is_only_a_timeout_at_the_scope_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    elapsed: float,
    expected_timeout: bool,
    expected_failure: str,
) -> None:
    from scripts import run_benchmark

    class KilledProcess:
        pid = 1234

        @staticmethod
        def poll() -> int:
            return 137

    times = iter((0.0, elapsed))
    result_paths: list[Path] = []

    def popen(command: list[str], **_kwargs: object) -> KilledProcess:
        result_path = Path(command[-3])
        result_paths.append(result_path)
        result_path.write_bytes(b"incomplete")
        result_path.with_suffix(".pkl.tmp").write_bytes(b"incomplete")
        return KilledProcess()

    monkeypatch.delenv("DECBENCH_ANGR_TIMEOUT", raising=False)
    monkeypatch.delenv("DECBENCH_DECOMPILE_TIMEOUT", raising=False)
    monkeypatch.setattr(run_benchmark.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(
        run_benchmark,
        "resource_scope_command",
        lambda command, _timeout, **_kwargs: (command, "decbench-test.scope"),
    )
    monkeypatch.setattr(run_benchmark.subprocess, "Popen", popen)
    monkeypatch.setattr(run_benchmark, "resource_scope_memory_events", lambda *_args: None)
    monkeypatch.setattr(run_benchmark, "resource_scope_oom_killed", lambda _events: False)
    monkeypatch.setattr(run_benchmark, "_cleanup_scope_containers", lambda _unit: None)

    result = run_benchmark._timed_decompile(tmp_path / "target", "angr", tmp_path, "NONE")

    assert result.decompiler.timeout_occurred is expected_timeout
    assert result.decompiler.extra["memory_limit_exceeded"] is False
    assert result.decompiler.extra["failure"] == expected_failure
    assert not result_paths[0].parent.exists()


def test_llm_function_timeout_kills_descendants(tmp_path: Path) -> None:
    child_pid = tmp_path / "child.pid"
    script = (
        "import pathlib, subprocess, time\n"
        "child = subprocess.Popen(['sleep', '60'])\n"
        f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid))\n"
        "time.sleep(60)\n"
    )
    config = DecompilerConfig(extra_options={"timeout": 1, "save_traces": False})
    decompiler = DecompilerRegistry.get("codex", config)
    decompiler._invocation = lambda *_args: ([sys.executable, "-c", script], {})
    binary = tmp_path / "binary"
    binary.touch()

    code, _elapsed, _tokens, _mappings = decompiler._decompile_one(binary, "target", 0x1000)

    assert code is None
    assert child_pid.is_file()
    pid = int(child_pid.read_text())
    deadline = time.monotonic() + 5
    status_path = Path(f"/proc/{pid}/status")

    def running() -> bool:
        try:
            state = next(
                line for line in status_path.read_text().splitlines() if line.startswith("State:")
            )
        except (FileNotFoundError, StopIteration):
            return False
        return "Z (zombie)" not in state

    while running() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not running()


def test_cgroup_limit_kills_the_whole_descendant_tree(tmp_path: Path) -> None:
    if not resource_scopes_available():
        pytest.skip("user systemd resource scopes are unavailable")

    child_pid = tmp_path / "child.pid"
    script = (
        "import pathlib, subprocess, time\n"
        f"child = subprocess.Popen(['sleep', '60'])\n"
        f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid))\n"
        "time.sleep(0.2)\n"
        "allocation = bytearray(256 * 1024 * 1024)\n"
        "time.sleep(60)\n"
    )
    command, unit = resource_scope_command(
        [sys.executable, "-c", script],
        30,
        memory_limit_bytes=64 * 1024**2,
    )
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        events = resource_scope_memory_events(process.pid, unit)
        deadline = time.monotonic() + 10
        while not resource_scope_oom_killed(events) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert resource_scope_oom_killed(events)
    finally:
        if events is not None:
            events.close()
        kill_resource_scope(unit)
        process.wait(timeout=10)

    assert child_pid.is_file()
    pid = int(child_pid.read_text())
    deadline = time.monotonic() + 5
    status_path = Path(f"/proc/{pid}/status")

    def running() -> bool:
        try:
            state = next(
                line for line in status_path.read_text().splitlines() if line.startswith("State:")
            )
        except (FileNotFoundError, StopIteration):
            return False
        return "Z (zombie)" not in state

    while running() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not running()
