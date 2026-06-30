"""Tests for report extras: side-by-side samples, hardest source, compile rates."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from decbench.models.function_data import (
    BinaryGroup,
    FunctionData,
    FunctionRecord,
)
from decbench.scoring.report_extras import (
    build_hardest,
    build_samples,
    compute_compile_rates,
)

SOURCE = """\
int target(int a, int b) {
    int s = a + b;
    return s * 2;
}
"""


def _make_decompile_results(binary_path: Path):
    """proj -> opt -> binary -> dec -> DecompilationResult-ish mock."""
    func = SimpleNamespace(decompiled_code="int target(int a,int b){return a+b+b;}", line_count=1)
    dec_result = SimpleNamespace(binary_path=binary_path, functions={"target": func})
    return {"proj": {"O0": {"bin1": {"angr": dec_result}}}}


def _function_data():
    fr = FunctionRecord(
        function="target",
        values={"angr": {"ged": 0.0, "type_match": 1.0, "byte_match": 0.5}},
        perfects={"angr": {"ged": True, "type_match": True, "byte_match": False}},
        labels=["O0"],
        datasets=["full", "tiny"],
        size=4,
    )
    return FunctionData(
        decompilers=["angr"],
        metrics=["ged", "type_match", "byte_match"],
        perfect_values={"ged": 0.0, "type_match": 1.0, "byte_match": 1.0},
        groups=[BinaryGroup(project="proj", opt_level="O0", binary="bin1", functions=[fr])],
    )


def test_build_samples_includes_source_and_decompiled(tmp_path: Path) -> None:
    # A fake binary with a sibling .c source (source_extract finds it w/o DWARF).
    binary = tmp_path / "bin1"
    binary.write_bytes(b"\x7fELF not-really")
    (tmp_path / "bin1.c").write_text(SOURCE)

    fd = _function_data()
    samples = build_samples(fd, _make_decompile_results(binary))
    assert len(samples) == 1
    s = samples[0]
    assert s.function == "target"
    assert "angr" in s.decompiled
    assert "return a+b+b" in s.decompiled["angr"]
    assert s.source_code is not None
    assert "return s * 2;" in s.source_code
    # Carries the per-metric scores for display.
    assert s.values["angr"]["byte_match"] == 0.5


def test_build_hardest_fills_source(tmp_path: Path) -> None:
    binary = tmp_path / "bin1"
    binary.write_bytes(b"\x7fELF")
    (tmp_path / "bin1.c").write_text(SOURCE)

    bm = SimpleNamespace(function_results={"target": SimpleNamespace(value=0.5)})
    evaluation = {"proj": {"O0": {"bin1": {"angr": {"byte_match": bm}}}}}
    entries = build_hardest(evaluation, _make_decompile_results(binary))
    assert entries
    e = entries[0]
    assert e.function == "target"
    assert e.decompiled_code is not None
    assert e.source_code is not None and "return s * 2;" in e.source_code


def test_compute_compile_rates() -> None:
    def mv(compilable: bool):
        return SimpleNamespace(metadata={"compilable": compilable})

    bm = SimpleNamespace(function_results={"a": mv(True), "b": mv(False), "c": mv(True)})
    evaluation = {"proj": {"O0": {"bin1": {"angr": {"byte_match": bm}}}}}
    rates = compute_compile_rates(evaluation)
    assert abs(rates["angr"] - (2 / 3)) < 1e-9
