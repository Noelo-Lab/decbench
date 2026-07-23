"""Tests for decbench.results_store: slice-scoped overlay merges, the coverage
guard, and the canonical finalize. The slice-scoping tests are named regression
tests for the 2026-07-22 kuna@betaflight O2-noinline wipe."""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
from decbench.models.metrics import MetricResult, MetricValue
from decbench.models.project import OptimizationLevel
from decbench.results_store import (
    CoverageRegressionError,
    coverage_counts,
    coverage_regressions,
    finalize_tree,
    merge_typematch_overlay,
    read_ged_overlay,
    update_byte_match,
    update_ged,
    write_function_data_guarded,
)


def _record(name: str, decs: dict[str, dict[str, float]]) -> FunctionRecord:
    return FunctionRecord(
        function=name,
        values={d: dict(mv) for d, mv in decs.items()},
        perfects={d: {m: v == 0.0 for m, v in mv.items()} for d, mv in decs.items()},
        distances={d: dict(mv) for d, mv in decs.items()},
        decompiled={d: True for d in decs},
    )


def _fd_two_slices() -> FunctionData:
    """kuna has inline GED in projA at O0 AND O2-noinline (two slices)."""
    groups = [
        BinaryGroup(
            project="projA",
            opt_level="O0",
            binary="binA",
            functions=[_record("f1", {"kuna": {"ged": 3.0}, "angr": {"ged": 1.0}})],
        ),
        BinaryGroup(
            project="projA",
            opt_level="O2-noinline",
            binary="binA",
            functions=[_record("f1", {"kuna": {"ged": 5.0}, "angr": {"ged": 2.0}})],
        ),
    ]
    return FunctionData(decompilers=["angr", "kuna"], metrics=["ged"], groups=groups)


def test_update_ged_slice_scoped_clear_regression_kuna() -> None:
    """An overlay covering only one of a decompiler's slices must not wipe the
    others — the kuna@betaflight O2-noinline incident (1716 perfects silently
    lost because the whole kuna column was cleared, then only O0/O2 rewritten)."""
    fd = _fd_two_slices()
    overlay = {"O0::projA::binA::kuna::f1": {"value": 0.0, "perfect": True}}
    n = update_ged(fd, overlay)
    assert n == 1
    o0, noinline = fd.groups
    # Covered slice: cleared + rewritten from the overlay.
    assert o0.functions[0].values["kuna"]["ged"] == 0.0
    assert o0.functions[0].perfects["kuna"]["ged"] is True
    # Uncovered slice of the SAME decompiler: inline value KEPT.
    assert noinline.functions[0].values["kuna"]["ged"] == 5.0
    # Uncovered decompiler untouched everywhere.
    assert o0.functions[0].values["angr"]["ged"] == 1.0
    assert noinline.functions[0].values["angr"]["ged"] == 2.0


def test_update_ged_sidecar_covers_empty_slice() -> None:
    """A slice the reeval evaluated but found empty (sidecar-covered, no entries)
    must CLEAR its stale inline values instead of keeping them."""
    fd = _fd_two_slices()
    overlay = {"O0::projA::binA::kuna::f1": {"value": 0.0, "perfect": True}}
    covered = {
        ("O0", "projA", "binA", "kuna"),
        ("O2-noinline", "projA", "binA", "kuna"),  # evaluated: artifact empty
    }
    update_ged(fd, overlay, covered=covered)
    o0, noinline = fd.groups
    assert o0.functions[0].values["kuna"]["ged"] == 0.0
    assert "ged" not in noinline.functions[0].values["kuna"]
    assert noinline.functions[0].values["angr"]["ged"] == 2.0


def test_update_byte_match_slice_scoped() -> None:
    fd = _fd_two_slices()
    for g in fd.groups:
        for f in g.functions:
            for dec in list(f.values):
                f.values[dec]["byte_match"] = 0.4
                f.compiles[dec] = True
    overlay = {"O0::projA::binA::kuna::f1": {"value": 1.0, "compilable": True, "dist": 0}}
    tally = update_byte_match(fd, overlay)
    o0, noinline = fd.groups
    assert o0.functions[0].values["kuna"]["byte_match"] == 1.0
    # Same decompiler, uncovered slice: stale value KEPT (per-slice scoping).
    assert noinline.functions[0].values["kuna"]["byte_match"] == 0.4
    # Uncovered decompiler untouched.
    assert o0.functions[0].values["angr"]["byte_match"] == 0.4
    assert tally["kuna"] == {"comp": 1, "tot": 1}
    # add_only never drops anything even inside a covered slice.
    fd2 = _fd_two_slices()
    fd2.groups[0].functions[0].values["kuna"]["byte_match"] = 0.4
    update_byte_match(fd2, {"O0::projA::binA::kuna::zzz": {"value": 1.0}}, add_only=True)
    assert fd2.groups[0].functions[0].values["kuna"]["byte_match"] == 0.4


def test_read_ged_overlay_covers_evaluated_empty_slices(tmp_path: Path) -> None:
    """The evaluated-slice set unions the payload keys, the sidecar, AND the
    reeval_ged/ checkpoint filenames — so an evaluated-but-empty slice (present in
    the cache with no entries) still clears stale inline GED, even without a
    sidecar (older trees). Regression guard for the 219-slice re-inflation."""
    root = tmp_path
    (root / "ged_new.json").write_text(
        json.dumps({"O0::projA::binA::angr::f1": {"value": 0.0, "perfect": True}})
    )
    # reeval cache has an EMPTY checkpoint for a kuna slice that scored nothing.
    (root / "reeval_ged").mkdir()
    (root / "reeval_ged" / "O2-noinline__projA__binA__kuna.json").write_text("{}")
    (root / "reeval_ged" / "O0__projA__binA__angr.json").write_text(
        json.dumps({"f1": {"value": 0.0, "perfect": True}})
    )
    payload, covered = read_ged_overlay(root)
    assert payload is not None
    assert ("O0", "projA", "binA", "angr") in covered  # from entries + cache
    assert ("O2-noinline", "projA", "binA", "kuna") in covered  # empty cache slice

    # That empty-but-evaluated kuna slice must clear its stale inline GED.
    fd = _fd_two_slices()
    update_ged(fd, payload, covered=covered)
    noinline = fd.groups[1]
    assert "ged" not in noinline.functions[0].values["kuna"]


def test_merge_typematch_overlay() -> None:
    existing = {"kuna": {"a::O0::b::f": {"value": 0.5}}, "angr": {"a::O0::b::f": {"value": 0.2}}}
    fresh = {"kuna": {"a::O0::b::f": {"value": 0.9}, "a::O0::b::g": {"value": 0.1}}}
    merged = merge_typematch_overlay(existing, fresh)
    assert merged["kuna"]["a::O0::b::f"] == {"value": 0.9}  # fresh wins
    assert merged["kuna"]["a::O0::b::g"] == {"value": 0.1}  # fresh added
    assert merged["angr"]["a::O0::b::f"] == {"value": 0.2}  # untouched dec kept
    assert existing["kuna"]["a::O0::b::f"] == {"value": 0.5}  # inputs not mutated


def test_coverage_guard_catches_column_drop() -> None:
    old = coverage_counts(_fd_two_slices())
    shrunk = _fd_two_slices()
    shrunk.groups[1].functions[0].values.pop("kuna")  # the kuna wipe, in miniature
    regs = coverage_regressions(old, coverage_counts(shrunk))
    assert any(g == "projA::O2-noinline::binA" and c == "kuna::ged" for g, c, _o, _n in regs)


def test_guard_allows_excluded_project_and_decompiler() -> None:
    old = coverage_counts(_fd_two_slices())
    empty = FunctionData(decompilers=["angr", "kuna"], metrics=["ged"], groups=[])
    assert coverage_regressions(old, coverage_counts(empty), allowed_projects=["projA"]) == []
    no_kuna = _fd_two_slices()
    for g in no_kuna.groups:
        for f in g.functions:
            f.values.pop("kuna")
            f.decompiled.pop("kuna")
    regs = coverage_regressions(old, coverage_counts(no_kuna), allowed_decompilers=["kuna"])
    assert regs == []


def test_guarded_write_blocks_and_preserves_old_file(tmp_path: Path) -> None:
    root = tmp_path
    write_function_data_guarded(_fd_two_slices(), root)  # first write: no old file
    original = (root / "function_results.json").read_bytes()

    shrunk = _fd_two_slices()
    shrunk.groups[1].functions[0].values.pop("kuna")
    with pytest.raises(CoverageRegressionError):
        write_function_data_guarded(shrunk, root)
    # Failed guard leaves the previous file byte-identical and no temp litter.
    assert (root / "function_results.json").read_bytes() == original
    assert not (root / "function_results.json.tmp").exists()

    # allow_drops writes and rotates the previous file to .prev.
    write_function_data_guarded(shrunk, root, allow_drops=True)
    assert (root / "function_results.prev.json").read_bytes() == original
    reloaded = FunctionData.from_json(root / "function_results.json")
    assert "kuna" not in reloaded.groups[1].functions[0].values


# --------------------------------------------------------------------------- #
# finalize_tree over a miniature results tree.
# --------------------------------------------------------------------------- #
def _mini_checkpoint(project: str, dec: str = "angr") -> dict:
    fn = FunctionDecompilation(name="main", address=0x1000, decompiled_code="int main(){}\n")
    dr = DecompilationResult(
        binary_path=Path(f"/nonexistent/{project}/bin"),
        binary_name=f"{project}bin",
        decompiler=DecompilerMetadata(decompiler_name=dec, decompiler_version="1.0"),
        functions={"main": fn},
    )
    mr = MetricResult(
        metric_name="ged",
        decompiler_name=dec,
        binary_name=f"{project}bin",
        function_results={"main": MetricValue(value=0.0)},
    )
    return {
        "decompile": {OptimizationLevel.O0: {f"{project}bin": {dec: dr}}},
        "evaluate": {OptimizationLevel.O0: {f"{project}bin": {dec: {"ged": mr}}}},
    }


def _mini_tree(tmp_path: Path, projects: tuple[str, ...] = ("alpha", "beta")) -> Path:
    root = tmp_path / "tree"
    (root / "checkpoints").mkdir(parents=True)
    for p in projects:
        (root / "checkpoints" / f"{p}.pkl").write_bytes(pickle.dumps(_mini_checkpoint(p)))
    return root


def test_finalize_tree_reads_all_checkpoints(tmp_path: Path) -> None:
    root = _mini_tree(tmp_path)
    fd, sb = finalize_tree(root, log=lambda _msg: None)
    assert sorted(g.project for g in fd.groups) == ["alpha", "beta"]
    assert (root / "function_results.json").exists()
    assert (root / "scoreboard.toml").exists()
    assert sb.decompilers == ["angr"]

    # A vanished checkpoint is a coverage regression, not a silent drop...
    (root / "checkpoints" / "beta.pkl").unlink()
    with pytest.raises(CoverageRegressionError):
        finalize_tree(root, log=lambda _msg: None)
    # ...unless the project is explicitly excluded.
    fd2, _sb2 = finalize_tree(root, exclude_projects=["beta"], log=lambda _msg: None)
    assert sorted(g.project for g in fd2.groups) == ["alpha"]


def test_finalize_preserves_dataset_info_and_history(tmp_path: Path) -> None:
    root = _mini_tree(tmp_path, projects=("alpha",))
    fd, _ = finalize_tree(root, log=lambda _msg: None)
    # Simulate compute_dataset_info + ingest_history having written their fields.
    fd.dataset_info = {"total_loc": 123}
    fd.history = []
    raw = json.loads((root / "function_results.json").read_text())
    raw["dataset_info"] = {"total_loc": 123}
    raw["history"] = [
        {"decompiler": "ghidra", "version": "11.0", "scores": {"ged": 1.0}, "overall": 1.0}
    ]
    (root / "function_results.json").write_text(json.dumps(raw))

    fd2, _ = finalize_tree(root, log=lambda _msg: None)
    assert fd2.dataset_info == {"total_loc": 123}
    assert [h.decompiler for h in fd2.history] == ["ghidra"]
    reloaded = FunctionData.from_json(root / "function_results.json")
    assert reloaded.dataset_info == {"total_loc": 123}
    assert [h.decompiler for h in reloaded.history] == ["ghidra"]


def test_finalize_tree_strips_excluded_decompilers(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "checkpoints").mkdir(parents=True)
    ckpt = _mini_checkpoint("alpha")
    extra = _mini_checkpoint("alpha", dec="kuna")
    ckpt["decompile"][OptimizationLevel.O0]["alphabin"].update(
        extra["decompile"][OptimizationLevel.O0]["alphabin"]
    )
    ckpt["evaluate"][OptimizationLevel.O0]["alphabin"].update(
        extra["evaluate"][OptimizationLevel.O0]["alphabin"]
    )
    (root / "checkpoints" / "alpha.pkl").write_bytes(pickle.dumps(ckpt))

    fd, sb = finalize_tree(root, exclude_decompilers=["kuna"], log=lambda _msg: None)
    assert fd.decompilers == ["angr"]
    assert sb.decompilers == ["angr"]
    for g in fd.groups:
        for f in g.functions:
            assert "kuna" not in f.values
