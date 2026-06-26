"""Tests for the curated dataset presets (full/hard/hard-inlined/tiny)."""

from __future__ import annotations

from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
from decbench.scoring.datasets import assign_datasets, large_threshold


def _make_data() -> FunctionData:
    groups = []
    for proj in ("alpha", "beta", "gamma"):
        for opt in ("O0", "O2", "O2-noinline"):
            funcs = [
                FunctionRecord(function=f"{proj}_{opt}_f{i}", size=sz)
                for i, sz in enumerate([5, 8, 12, 40, 150, 220])
            ]
            groups.append(
                BinaryGroup(
                    project=proj, opt_level=opt, binary=f"{proj}bin", functions=funcs
                )
            )
    return FunctionData(decompilers=["angr"], metrics=["ged"], groups=groups)


def test_presets_are_attached() -> None:
    fd = _make_data()
    assign_datasets(fd)
    assert [p.name for p in fd.dataset_presets] == [
        "full",
        "hard",
        "hard-inlined",
        "tiny",
    ]


def test_full_contains_everything() -> None:
    fd = _make_data()
    assign_datasets(fd)
    for g in fd.groups:
        for f in g.functions:
            assert "full" in f.datasets


def test_hard_rules() -> None:
    fd = _make_data()
    assign_datasets(fd)
    thr = large_threshold(fd)
    for g in fd.groups:
        for f in g.functions:
            if "hard" in f.datasets:
                assert g.opt_level == "O2-noinline" and f.size >= thr
            if "hard-inlined" in f.datasets:
                assert g.opt_level == "O2" and f.size >= thr
    # there IS at least one large function per opt level here (size 220)
    assert any("hard" in f.datasets for g in fd.groups for f in g.functions)
    assert any("hard-inlined" in f.datasets for g in fd.groups for f in g.functions)


def test_tiny_is_bounded_and_spread() -> None:
    fd = _make_data()
    assign_datasets(fd, tiny_total=20)
    tiny = [
        (g.opt_level, g.project)
        for g in fd.groups
        for f in g.functions
        if "tiny" in f.datasets
    ]
    assert 0 < len(tiny) <= 24  # ~tiny_total, bounded
    # spread across all opt levels and all projects
    assert {opt for opt, _ in tiny} == {"O0", "O2", "O2-noinline"}
    assert {proj for _, proj in tiny} == {"alpha", "beta", "gamma"}


def test_idempotent() -> None:
    fd = _make_data()
    assign_datasets(fd)
    first = [sorted(f.datasets) for g in fd.groups for f in g.functions]
    assign_datasets(fd)
    second = [sorted(f.datasets) for g in fd.groups for f in g.functions]
    assert first == second


def _tiny_keys(fd: FunctionData) -> set[str]:
    return {
        f"{g.project}/{g.opt_level}/{f.function}"
        for g in fd.groups
        for f in g.functions
        if "tiny" in f.datasets
    }


def test_tiny_is_seeded_and_reproducible() -> None:
    # Same seed -> identical tiny selection, every time.
    fd1 = _make_data()
    assign_datasets(fd1, tiny_total=20, seed=42)
    fd2 = _make_data()
    assign_datasets(fd2, tiny_total=20, seed=42)
    assert _tiny_keys(fd1) == _tiny_keys(fd2)
    assert len(_tiny_keys(fd1)) > 0


def test_tiny_changes_with_seed() -> None:
    # A different seed should (with this much data) pick a different sample.
    fd_a = _make_data()
    assign_datasets(fd_a, tiny_total=20, seed=1)
    fd_b = _make_data()
    assign_datasets(fd_b, tiny_total=20, seed=2)
    assert _tiny_keys(fd_a) != _tiny_keys(fd_b)


def _make_many_binaries(n_bins: int = 40) -> FunctionData:
    groups = []
    for proj in ("p1", "p2", "p3"):
        for b in range(n_bins):
            funcs = [
                FunctionRecord(function=f"{proj}_b{b}_f{i}", size=sz)
                for i, sz in enumerate([10, 30, 200])
            ]
            groups.append(
                BinaryGroup(
                    project=proj,
                    opt_level="O0",
                    binary=f"{proj}_bin{b}",
                    functions=funcs,
                )
            )
    return FunctionData(decompilers=["angr"], metrics=["ged"], groups=groups)


def _tiny_binkeys(fd: FunctionData) -> list[tuple[str, str, str]]:
    return [
        (g.project, g.opt_level, g.binary)
        for g in fd.groups
        for f in g.functions
        if "tiny" in f.datasets
    ]


def test_tiny_one_function_per_binary_when_enough() -> None:
    # With many distinct binaries, no binary contributes more than one function.
    fd = _make_many_binaries(n_bins=40)
    assign_datasets(fd, tiny_total=100)
    keys = _tiny_binkeys(fd)
    assert len(keys) == len(set(keys)), "each binary should appear at most once"
    assert len(keys) >= 40  # plenty selected


def test_tiny_relaxes_when_few_binaries() -> None:
    # Only 9 binary-groups but we want ~20 -> must reuse some binaries.
    fd = _make_data()
    assign_datasets(fd, tiny_total=20)
    keys = _tiny_binkeys(fd)
    assert len(keys) > len(set(keys)), "should reuse binaries when too few exist"


def test_env_var_seed(monkeypatch) -> None:
    monkeypatch.setenv("DECBENCH_TINY_SEED", "777")
    fd_env = _make_data()
    assign_datasets(fd_env, tiny_total=20)  # seed from env
    fd_explicit = _make_data()
    assign_datasets(fd_explicit, tiny_total=20, seed=777)  # same, explicit
    assert _tiny_keys(fd_env) == _tiny_keys(fd_explicit)
