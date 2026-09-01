from __future__ import annotations

import pickle
from pathlib import Path

import pytest

from decbench.decompilers.raw import common
from decbench.models.decompilation import DecompilationResult, DecompilerMetadata


def _result(generation: str) -> DecompilationResult:
    return DecompilationResult(
        binary_path=Path("binary"),
        binary_name=generation,
        decompiler=DecompilerMetadata(decompiler_name="test"),
    )


def test_dump_progress_throttles_growing_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "progress.pkl"
    clock = iter((10.0, 12.0, 15.0))
    monkeypatch.setattr(common.time, "monotonic", lambda: next(clock))

    common.dump_progress(output, _result("first"))
    common.dump_progress(output, _result("skipped"))
    assert pickle.loads(output.read_bytes()).binary_name == "first"

    common.dump_progress(output, _result("next"))
    assert pickle.loads(output.read_bytes()).binary_name == "next"


def test_dump_progress_force_bypasses_throttle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "progress.pkl"
    monkeypatch.setattr(common.time, "monotonic", lambda: 20.0)

    common.dump_progress(output, _result("first"))
    common.dump_progress(output, _result("forced"), force=True)

    assert pickle.loads(output.read_bytes()).binary_name == "forced"
