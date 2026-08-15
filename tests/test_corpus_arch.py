"""Tests for architecture handling across the compile -> score path."""

from __future__ import annotations

import logging
import struct
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from decbench.compilers.gcc import GCCCompiler
from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
from decbench.scoring.datasets import _is_arm
from decbench.scoring.function_data_builder import _binary_arch
from decbench.scoring.subset import SubsetManifest, filter_function_data
from decbench.utils import binfmt

_MACHINES = {"x86-64": 0x3E, "aarch64": 0xB7}


def _fake_elf(path: Path, arch: str) -> Path:
    path.write_bytes(b"\x7fELF" + b"\x00" * 14 + struct.pack("<H", _MACHINES[arch]))
    return path


def _group(arch: str | None, labels: list[str]) -> BinaryGroup:
    return BinaryGroup(project="p", opt_level="O0", binary="b", labels=labels, arch=arch)


def test_measured_arch_beats_the_label_heuristic() -> None:
    """A natively built aarch64 sailr project carries no ARM label."""
    natively_built = _group("aarch64", ["sailr", "cli-tool", "compression"])
    assert _is_arm(natively_built) is True


def test_measured_x86_overrides_a_stale_arm_label() -> None:
    assert _is_arm(_group("x86-64", ["cps", "bare-metal"])) is False


def test_a_non_arm_target_is_not_filed_as_arm() -> None:
    assert _is_arm(_group("riscv", [])) is False


def test_labels_still_decide_when_arch_was_not_recorded() -> None:
    """Datasets built before `arch` existed keep their previous membership."""
    assert _is_arm(_group(None, ["cps"])) is True
    assert _is_arm(_group(None, ["cortex-m4"])) is True
    assert _is_arm(_group(None, ["sailr", "cli-tool"])) is False


def test_binary_arch_read_from_the_decompiled_binary(tmp_path: Path) -> None:
    class _Result:
        def __init__(self, path: Path):
            self.binary_path = path

    binary = _fake_elf(tmp_path / "bzip2", "aarch64")
    assert _binary_arch({"angr": _Result(binary)}) == "aarch64"
    assert _binary_arch({}) is None
    assert _binary_arch({"angr": _Result(tmp_path / "absent")}) is None


def test_an_unrecognised_machine_is_not_recorded(tmp_path: Path) -> None:
    """binfmt reports an unknown e_machine as "other", which is not an answer."""

    class _Result:
        def __init__(self, path: Path):
            self.binary_path = path

    sparc = tmp_path / "sparc"
    sparc.write_bytes(b"\x7fELF" + b"\x00" * 14 + struct.pack("<H", 0x02))
    assert _binary_arch({"angr": _Result(sparc)}) is None


def test_the_collect_filter_and_the_recorder_agree_on_machine_names() -> None:
    """The compiler's table matches `DECBENCH_TARGET_ARCH`; binfmt's records `arch`.

    If they drift, an arch the docs invite you to collect is one the dataset cannot record.
    """
    assert GCCCompiler._ELF_MACHINES == binfmt._ELF_MACHINES
    assert GCCCompiler._PE_MACHINES == binfmt._PE_MACHINES


def test_a_truncated_binary_does_not_abort_the_build(tmp_path: Path) -> None:
    """`_binary_arch` runs inside the canonical rebuild; it must not raise."""

    class _Result:
        def __init__(self, path: Path):
            self.binary_path = path

    truncated = tmp_path / "trunc"
    truncated.write_bytes(b"\x7fELF" + b"\x00" * 8)
    assert _binary_arch({"angr": _Result(truncated)}) is None


def test_arch_survives_a_subset_rebuild() -> None:
    """A subsetted dataset must not fall back to the label heuristic."""
    group = _group("aarch64", [])
    group.functions = [FunctionRecord(function="f", size=1, values={"angr": {"ged": 1.0}})]
    data = FunctionData(decompilers=["angr"], metrics=["ged"], groups=[group])
    manifest = SubsetManifest(
        method="std",
        k=1.0,
        threshold=0.0,
        functions=[{"project": "p", "opt": "O0", "binary": "b", "function": "f"}],
    )
    assert filter_function_data(data, manifest).groups[0].arch == "aarch64"


def test_arch_survives_the_json_round_trip() -> None:
    group = _group("aarch64", [])
    assert BinaryGroup.model_validate_json(group.model_dump_json()).arch == "aarch64"


def test_failed_pre_make_command_is_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="decbench.compilers.gcc"):
        GCCCompiler(gcc_path="gcc").compile_project(
            project_dir=tmp_path,
            output_dir=tmp_path / "out",
            optimization="O0",
            pre_commands=["exit 3"],
            project_root=tmp_path,
        )
    assert any("pre-make command failed" in r.message for r in caplog.records)


def test_timed_out_pre_make_command_is_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A configure whose run-tests hang under emulation is the slow failure mode."""
    hang = subprocess.TimeoutExpired("./configure", 600)
    with (
        caplog.at_level(logging.WARNING, logger="decbench.compilers.gcc"),
        mock.patch("subprocess.run", side_effect=hang),
    ):
        GCCCompiler(gcc_path="gcc").compile_project(
            project_dir=tmp_path,
            output_dir=tmp_path / "out",
            optimization="O0",
            pre_commands=["./configure"],
            project_root=tmp_path,
        )
    assert any("pre-make command failed" in r.message for r in caplog.records)


def test_timed_out_make_is_a_failed_result_not_an_exception(tmp_path: Path) -> None:
    hang = subprocess.TimeoutExpired("make", 3600)
    with mock.patch("subprocess.run", side_effect=hang):
        results = GCCCompiler(gcc_path="gcc").compile_project(
            project_dir=tmp_path,
            output_dir=tmp_path / "out",
            optimization="O0",
            make_command="make",
            project_root=tmp_path,
        )
    assert [r.success for r in results] == [False]
    assert "timed out" in (results[0].error_message or "")
