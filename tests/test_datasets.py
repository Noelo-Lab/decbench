"""Tests for the curated dataset presets (unoptimized/optimized/inlined/large/sample-set)."""

from __future__ import annotations

from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
from decbench.scoring.datasets import assign_datasets, large_threshold, topup_sample_members


def _make_data() -> FunctionData:
    groups = []
    for proj in ("alpha", "beta", "gamma"):
        for opt in ("O0", "O2", "O2-noinline"):
            funcs = [
                # A recorded metric value makes the record scoreable — the
                # sample-set draw skips value-less phantom rows.
                FunctionRecord(
                    function=f"{proj}_{opt}_f{i}", size=sz, values={"angr": {"ged": 1.0}}
                )
                for i, sz in enumerate([5, 8, 12, 40, 150, 220])
            ]
            labels = ["cps", "cortex-m4"] if proj == "gamma" else []
            groups.append(
                BinaryGroup(
                    project=proj,
                    opt_level=opt,
                    binary=f"{proj}bin",
                    labels=labels,
                    functions=funcs,
                )
            )
    return FunctionData(decompilers=["angr"], metrics=["ged"], groups=groups)


def test_presets_are_attached() -> None:
    fd = _make_data()
    assign_datasets(fd)
    assert [p.name for p in fd.dataset_presets] == [
        "unoptimized",
        "optimized",
        "inlined",
        "large",
        "sample-set",
    ]


def test_every_function_lands_in_an_opt_preset() -> None:
    fd = _make_data()
    assign_datasets(fd)
    by_opt = {"O0": "unoptimized", "O2": "inlined", "O2-noinline": "optimized"}
    for g in fd.groups:
        for f in g.functions:
            assert by_opt[g.opt_level] in f.datasets


def test_unoptimized_is_exactly_O0() -> None:
    fd = _make_data()
    assign_datasets(fd)
    for g in fd.groups:
        for f in g.functions:
            assert ("unoptimized" in f.datasets) == (g.opt_level == "O0")


def test_optimized_and_inlined_split_by_opt_level() -> None:
    fd = _make_data()
    assign_datasets(fd)
    for g in fd.groups:
        for f in g.functions:
            assert ("optimized" in f.datasets) == (g.opt_level == "O2-noinline")
            assert ("inlined" in f.datasets) == (g.opt_level == "O2")


def test_large_rules() -> None:
    """`large` (nee `hard`) keeps its membership: O2-noinline AND large."""
    fd = _make_data()
    assign_datasets(fd)
    thr = large_threshold(fd)
    for g in fd.groups:
        for f in g.functions:
            if "large" in f.datasets:
                assert g.opt_level == "O2-noinline" and f.size >= thr
    # there IS at least one large function per opt level here (size 220)
    assert any("large" in f.datasets for g in fd.groups for f in g.functions)


def test_sample_set_is_bounded_and_spread() -> None:
    fd = _make_data()
    assign_datasets(fd, sample_total=20)
    picked = [
        (g.opt_level, g.project)
        for g in fd.groups
        for f in g.functions
        if "sample-set" in f.datasets
    ]
    assert 0 < len(picked) <= 25  # ~sample_total, bounded (5 buckets x quota)
    # spread across all opt levels and all projects
    assert {opt for opt, _ in picked} == {"O0", "O2", "O2-noinline"}
    assert {proj for _, proj in picked} == {"alpha", "beta", "gamma"}


def test_sample_set_includes_arm_unoptimized() -> None:
    """The fifth bucket draws O0 functions from ARM (cps-labeled) binaries."""
    fd = _make_data()
    assign_datasets(fd, sample_total=20)
    arm_o0 = [
        f
        for g in fd.groups
        for f in g.functions
        if g.project == "gamma" and g.opt_level == "O0" and "sample-set" in f.datasets
    ]
    assert arm_o0, "expected at least one ARM O0 function in the sample-set"


def test_idempotent() -> None:
    fd = _make_data()
    assign_datasets(fd)
    first = [sorted(f.datasets) for g in fd.groups for f in g.functions]
    assign_datasets(fd)
    second = [sorted(f.datasets) for g in fd.groups for f in g.functions]
    assert first == second


def _sample_keys(fd: FunctionData) -> set[str]:
    return {
        f"{g.project}/{g.opt_level}/{f.function}"
        for g in fd.groups
        for f in g.functions
        if "sample-set" in f.datasets
    }


def test_sample_set_is_seeded_and_reproducible() -> None:
    # Same seed -> identical sample-set selection, every time.
    fd1 = _make_data()
    assign_datasets(fd1, sample_total=20, seed=42)
    fd2 = _make_data()
    assign_datasets(fd2, sample_total=20, seed=42)
    assert _sample_keys(fd1) == _sample_keys(fd2)
    assert len(_sample_keys(fd1)) > 0


def test_sample_set_changes_with_seed() -> None:
    # A different seed should (with this much data) pick a different sample.
    fd_a = _make_data()
    assign_datasets(fd_a, sample_total=20, seed=1)
    fd_b = _make_data()
    assign_datasets(fd_b, sample_total=20, seed=2)
    assert _sample_keys(fd_a) != _sample_keys(fd_b)


def _make_many_binaries(n_bins: int = 40) -> FunctionData:
    groups = []
    for proj in ("p1", "p2", "p3"):
        for b in range(n_bins):
            funcs = [
                FunctionRecord(function=f"{proj}_b{b}_f{i}", size=sz, values={"angr": {"ged": 1.0}})
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


def _sample_binkeys(fd: FunctionData) -> list[tuple[str, str, str]]:
    return [
        (g.project, g.opt_level, g.binary)
        for g in fd.groups
        for f in g.functions
        if "sample-set" in f.datasets
    ]


def test_sample_set_one_function_per_binary_when_enough() -> None:
    # With many distinct binaries, no binary contributes more than one function.
    fd = _make_many_binaries(n_bins=40)
    assign_datasets(fd, sample_total=100)
    keys = _sample_binkeys(fd)
    assert len(keys) == len(set(keys)), "each binary should appear at most once"
    assert len(keys) >= 20  # plenty selected (only the O0 bucket has candidates)


def test_sample_set_relaxes_when_few_binaries() -> None:
    # Only 9 binary-groups but we want ~20 -> must reuse some binaries.
    fd = _make_data()
    assign_datasets(fd, sample_total=50)
    keys = _sample_binkeys(fd)
    assert len(keys) > len(set(keys)), "should reuse binaries when too few exist"


def test_sample_set_skips_valueless_phantom_rows() -> None:
    """A record with no metric value from any decompiler never gets a slot.

    The real corpus carries relabel-duplicate phantom rows (the same CRT/TLS
    stub named once per decompiler style) with ``values == {}``; five were
    sampled into the published 2026-07 sample-set and showed up as "missing
    data" for every backend. The draw must skip them — and, because the skip
    happens during the scan rather than by shrinking the shuffled pool, every
    other pick of the same seed stays identical (a phantom is *replaced*, not
    a reshuffle trigger).
    """
    baseline = _make_many_binaries(n_bins=40)
    assign_datasets(baseline, sample_total=100, seed=42)
    picked = _sample_keys(baseline)

    victim = next(iter(sorted(picked)))
    poisoned = _make_many_binaries(n_bins=40)
    for g in poisoned.groups:
        for f in g.functions:
            if f"{g.project}/{g.opt_level}/{f.function}" == victim:
                f.values = {}  # now a phantom: no metric value from anyone
    assign_datasets(poisoned, sample_total=100, seed=42)
    repicked = _sample_keys(poisoned)

    assert victim not in repicked, "phantom must not be sampled"
    assert len(repicked) == len(picked), "quota still met via a replacement"
    assert picked - repicked == {victim}, "every non-phantom pick is unchanged"


def test_env_var_seed(monkeypatch) -> None:
    monkeypatch.setenv("DECBENCH_SAMPLE_SEED", "777")
    fd_env = _make_data()
    assign_datasets(fd_env, sample_total=20)  # seed from env
    fd_explicit = _make_data()
    assign_datasets(fd_explicit, sample_total=20, seed=777)  # same, explicit
    assert _sample_keys(fd_env) == _sample_keys(fd_explicit)


def test_legacy_tiny_seed_env_var_still_honoured(monkeypatch) -> None:
    monkeypatch.setenv("DECBENCH_TINY_SEED", "888")
    fd_env = _make_data()
    assign_datasets(fd_env, sample_total=20)
    fd_explicit = _make_data()
    assign_datasets(fd_explicit, sample_total=20, seed=888)
    assert _sample_keys(fd_env) == _sample_keys(fd_explicit)


def test_assign_datasets_honors_manifest() -> None:
    """A frozen manifest pins sample-set membership exactly — no seeded draw."""
    fd = _make_many_binaries(n_bins=10)
    members = {
        ("p1", "O0", "p1_bin0", "p1_b0_f0"),
        ("p2", "O0", "p2_bin3", "p2_b3_f2"),
    }
    assign_datasets(fd, sample_total=100, seed=1, sample_members=members)
    tagged = {
        (g.project, g.opt_level, g.binary, f.function)
        for g in fd.groups
        for f in g.functions
        if "sample-set" in f.datasets
    }
    assert tagged == members
    # Different seed, same manifest -> identical membership (seed is ignored).
    fd2 = _make_many_binaries(n_bins=10)
    assign_datasets(fd2, sample_total=100, seed=999, sample_members=members)
    tagged2 = {
        (g.project, g.opt_level, g.binary, f.function)
        for g in fd2.groups
        for f in g.functions
        if "sample-set" in f.datasets
    }
    assert tagged2 == members


def _make_multibucket(n_bins: int = 30) -> FunctionData:
    """Fixture spanning every sample-set bucket: O0/O2/O2-noinline, an ARM
    project (populates unoptimized-arm), and large functions (populate large).
    The O0-only fixtures can't exercise the overlapping-bucket top-up path."""
    groups = []
    for proj in ("p1", "p2", "p3"):
        arm = proj == "p3"
        labels = ["cps", "cortex-m4"] if arm else []
        for b in range(n_bins):
            for opt in ("O0", "O2", "O2-noinline"):
                funcs = [
                    FunctionRecord(
                        function=f"{proj}_{opt}_b{b}_f{i}", size=sz, values={"angr": {"ged": 1.0}}
                    )
                    for i, sz in enumerate([10, 30, 400])  # 400 -> large
                ]
                groups.append(
                    BinaryGroup(
                        project=proj,
                        opt_level=opt,
                        binary=f"{proj}_bin{b}",
                        labels=labels,
                        functions=funcs,
                    )
                )
    return FunctionData(decompilers=["angr"], metrics=["ged"], groups=groups)


def _members_of(fd: FunctionData) -> set[tuple[str, str, str, str]]:
    return {
        (g.project, g.opt_level, g.binary, f.function)
        for g in fd.groups
        for f in g.functions
        if "sample-set" in (f.datasets or [])
    }


def test_sample_set_topup_preserves_picks_across_all_buckets() -> None:
    """topup_sample_members KEEPS every non-excluded base pick and refills only the
    freed slots — including when the excluded project touches the overlapping
    `large`/`unoptimized-arm` buckets (the mirai-win removal top-up mechanism).
    A fresh draw with an exclusion could NOT guarantee this (it perturbs the seed)."""
    base_fd = _make_multibucket()
    assign_datasets(base_fd, sample_total=50, seed=1337)
    base_members = _members_of(base_fd)
    # Exclude a NON-ARM project (like the real mirai-win): its picks land in the
    # unoptimized/inlined/optimized/large buckets — all refillable from p2 — while
    # the arm-only bucket (p3) is untouched, so the total is fully replenished.
    excluded_project = "p1"
    base_excluded = {m for m in base_members if m[0] == excluded_project}
    # p1 must have picks in the overlapping large/optimized buckets to make the
    # preservation test meaningful.
    assert any(m[1] == "O2-noinline" for m in base_excluded), "need optimized/large picks"

    fd = _make_multibucket()
    topped = topup_sample_members(
        fd, base_members, frozenset({excluded_project}), sample_total=50, seed=1337
    )

    assert not {m for m in topped if m[0] == excluded_project}, "excluded project never appears"
    # EVERY non-excluded base pick is preserved verbatim — the invariant the
    # review found violated by the old exclude-in-draw approach.
    assert (base_members - base_excluded) <= topped
    assert len(topped) == len(base_members), "total size preserved"
    assert (topped - base_members) and all(
        m[0] != excluded_project for m in (topped - base_members)
    ), "freed slots refilled from other projects"


def test_sample_set_topup_is_deterministic() -> None:
    base_fd = _make_multibucket()
    assign_datasets(base_fd, sample_total=50, seed=1337)
    base_members = _members_of(base_fd)
    a = topup_sample_members(_make_multibucket(), base_members, frozenset({"p3"}), seed=1337)
    b = topup_sample_members(_make_multibucket(), base_members, frozenset({"p3"}), seed=1337)
    assert a == b
