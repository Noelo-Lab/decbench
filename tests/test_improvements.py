"""Tests for the ``decbench improvements`` case finder.

Covers metric-direction-aware "base beats target" selection, the perfect-only
and target-missing options, ordering, validation, and the on-disk resolution of
each case to its compiled-binary path + function address.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
from decbench.scoring.improvements import find_improvement_cases, render_text

PERFECT = {"ged": 0.0, "type_match": 1.0, "byte_match": 1.0}


def _rec(function: str, **dec_values: dict[str, float]) -> FunctionRecord:
    """Build a record; ``dec_values`` maps decompiler -> {metric: value}."""
    values = {d: dict(mv) for d, mv in dec_values.items()}
    perfects = {d: {m: (v == PERFECT[m]) for m, v in mv.items()} for d, mv in values.items()}
    return FunctionRecord(function=function, values=values, perfects=perfects)


def _fd(functions: list[FunctionRecord], *, project="proj", opt="O0", binary="bin") -> FunctionData:
    group = BinaryGroup(project=project, opt_level=opt, binary=binary, functions=functions)
    return FunctionData(
        decompilers=["angr", "kuna"],
        metrics=["ged", "type_match", "byte_match"],
        perfect_values=dict(PERFECT),
        groups=[group],
    )


def _fake_elf(path: Path) -> None:
    """A minimal file binfmt.detect() recognizes as an ELF."""
    path.write_bytes(b"\x7fELF" + b"\x00" * 16)


# --------------------------------------------------------------------------- #
# Core selection (GED — lower is better)
# --------------------------------------------------------------------------- #


def test_ged_selects_only_wins_sorted_by_margin() -> None:
    fd = _fd(
        [
            _rec("win_big", angr={"ged": 0.0}, kuna={"ged": 10.0}),  # win, margin 10
            _rec("win_small", angr={"ged": 3.0}, kuna={"ged": 5.0}),  # win, margin 2
            _rec("tie", angr={"ged": 5.0}, kuna={"ged": 5.0}),  # tie -> excluded
            _rec("base_loses", angr={"ged": 8.0}, kuna={"ged": 2.0}),  # loss -> excluded
        ]
    )
    cases = find_improvement_cases(fd, "angr", "kuna", "ged")
    assert [c.function for c in cases] == ["win_big", "win_small"]
    assert cases[0].base_value == 0.0 and cases[0].target_value == 10.0
    assert cases[0].margin == 10.0 and cases[0].base_perfect is True
    assert cases[1].margin == 2.0 and cases[1].base_perfect is False


def test_perfect_only_filters_to_base_perfect() -> None:
    fd = _fd(
        [
            _rec("perfect", angr={"ged": 0.0}, kuna={"ged": 10.0}),
            _rec("nonperfect", angr={"ged": 3.0}, kuna={"ged": 5.0}),
        ]
    )
    cases = find_improvement_cases(fd, "angr", "kuna", "ged", perfect_only=True)
    assert [c.function for c in cases] == ["perfect"]


def test_target_missing_excluded_by_default_included_on_flag() -> None:
    fd = _fd(
        [
            _rec("both", angr={"ged": 0.0}, kuna={"ged": 4.0}),
            _rec("only_angr", angr={"ged": 1.0}),  # kuna produced nothing
        ]
    )
    assert [c.function for c in find_improvement_cases(fd, "angr", "kuna", "ged")] == ["both"]

    cases = find_improvement_cases(fd, "angr", "kuna", "ged", include_target_missing=True)
    # target-missing sorts first (infinite margin) then real wins.
    assert [c.function for c in cases] == ["only_angr", "both"]
    miss = cases[0]
    assert miss.target_missing is True
    assert miss.target_value is None
    assert math.isinf(miss.margin)


def test_base_without_value_is_never_a_win() -> None:
    # base has no ged value; even though kuna is worse it cannot "win".
    fd = _fd([_rec("no_base", kuna={"ged": 9.0})])
    assert find_improvement_cases(fd, "angr", "kuna", "ged") == []


def test_nonfinite_target_treated_as_missing() -> None:
    # A target GED of inf (metric errored though it decompiled) is NOT a genuine
    # win: it must be gated behind include_target_missing, not ranked #1.
    fd = _fd(
        [
            _rec("real_win", angr={"ged": 0.0}, kuna={"ged": 5.0}),
            _rec("errored", angr={"ged": 0.0}, kuna={"ged": float("inf")}),
        ]
    )
    # Default: the inf-target function is excluded, only the real win shows.
    assert [c.function for c in find_improvement_cases(fd, "angr", "kuna", "ged")] == ["real_win"]

    # With the flag it appears, but normalized to the "no usable score" bucket.
    cases = find_improvement_cases(fd, "angr", "kuna", "ged", include_target_missing=True)
    errored = next(c for c in cases if c.function == "errored")
    assert errored.target_missing is True
    assert errored.target_value is None  # not inf
    # ...and its JSON is valid (no `Infinity` token).
    import json

    dumped = json.dumps(errored.to_dict())
    assert "Infinity" not in dumped
    assert json.loads(dumped)["margin"] is None


def test_nonfinite_target_with_perfect_only() -> None:
    # perfect_only + a non-finite target must still not sneak the inf case in.
    fd = _fd([_rec("errored", angr={"ged": 0.0}, kuna={"ged": float("inf")})])
    assert find_improvement_cases(fd, "angr", "kuna", "ged", perfect_only=True) == []


# --------------------------------------------------------------------------- #
# Direction handling (type_match — higher is better)
# --------------------------------------------------------------------------- #


def test_higher_is_better_metric_direction() -> None:
    fd = _fd(
        [
            _rec("win", angr={"type_match": 1.0}, kuna={"type_match": 0.5}),  # win 0.5
            _rec("loss", angr={"type_match": 0.5}, kuna={"type_match": 0.8}),  # excluded
            _rec("win2", angr={"type_match": 0.8}, kuna={"type_match": 0.5}),  # win 0.3
        ]
    )
    cases = find_improvement_cases(fd, "angr", "kuna", "type_match")
    assert [c.function for c in cases] == ["win", "win2"]
    assert cases[0].margin == pytest.approx(0.5)
    assert cases[0].base_perfect is True

    perfect = find_improvement_cases(fd, "angr", "kuna", "type_match", perfect_only=True)
    assert [c.function for c in perfect] == ["win"]


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "base,target,metric",
    [
        ("nope", "kuna", "ged"),
        ("angr", "nope", "ged"),
        ("angr", "kuna", "nope"),
        ("angr", "angr", "ged"),  # base must differ from target
    ],
)
def test_invalid_inputs_raise(base: str, target: str, metric: str) -> None:
    fd = _fd([_rec("f", angr={"ged": 0.0}, kuna={"ged": 1.0})])
    with pytest.raises(ValueError):
        find_improvement_cases(fd, base, target, metric)


# --------------------------------------------------------------------------- #
# On-disk resolution
# --------------------------------------------------------------------------- #


def test_resolves_binary_path_and_address(tmp_path: Path) -> None:
    root = tmp_path
    comp = root / "O0" / "proj" / "compiled"
    dec = root / "O0" / "proj" / "decompiled"
    comp.mkdir(parents=True)
    dec.mkdir(parents=True)
    _fake_elf(comp / "bin")
    (dec / "angr_bin.c").write_text(
        "// Function: foo @ 0x1234\nint foo(){return 0;}\n"
        "// Function: bar @ 0x5678\nint bar(){return 1;}\n"
    )

    fd = _fd(
        [
            _rec("foo", angr={"ged": 0.0}, kuna={"ged": 7.0}),
            _rec("bar", angr={"ged": 0.0}, kuna={"ged": 3.0}),
        ]
    )
    cases = find_improvement_cases(fd, "angr", "kuna", "ged", results_root=root)
    by_name = {c.function: c for c in cases}
    assert by_name["foo"].binary_path == comp / "bin"
    assert by_name["foo"].address == 0x1234
    assert by_name["bar"].address == 0x5678


def test_versioned_binary_stem_resolution(tmp_path: Path) -> None:
    # group binary stem is "libz.so.1.2" but the real file is "libz.so.1.2.13".
    root = tmp_path
    comp = root / "O0" / "proj" / "compiled"
    dec = root / "O0" / "proj" / "decompiled"
    comp.mkdir(parents=True)
    dec.mkdir(parents=True)
    _fake_elf(comp / "libz.so.1.2.13")
    (dec / "angr_libz.so.1.2.c").write_text("// Function: zfoo @ 0xabc\nvoid zfoo(){}\n")

    fd = _fd([_rec("zfoo", angr={"ged": 0.0}, kuna={"ged": 2.0})], binary="libz.so.1.2")
    (case,) = find_improvement_cases(fd, "angr", "kuna", "ged", results_root=root)
    assert case.binary_path == comp / "libz.so.1.2.13"
    assert case.address == 0xABC


def test_versioned_decompiler_artifact_name(tmp_path: Path) -> None:
    # A versioned id (ghidra@12.0) must resolve addresses from the unversioned
    # artifact filename (ghidra_bin.c), which is how to_c_file names them.
    root = tmp_path
    comp = root / "O0" / "proj" / "compiled"
    dec = root / "O0" / "proj" / "decompiled"
    comp.mkdir(parents=True)
    dec.mkdir(parents=True)
    _fake_elf(comp / "bin")
    (dec / "ghidra_bin.c").write_text("// Function: foo @ 0x111\nvoid foo(){}\n")

    rec = FunctionRecord(
        function="foo",
        values={"ghidra@12.0": {"ged": 0.0}, "angr": {"ged": 5.0}},
        perfects={"ghidra@12.0": {"ged": True}, "angr": {"ged": False}},
    )
    fd = FunctionData(
        decompilers=["angr", "ghidra@12.0"],
        metrics=["ged"],
        perfect_values={"ged": 0.0},
        groups=[BinaryGroup(project="proj", opt_level="O0", binary="bin", functions=[rec])],
    )
    (case,) = find_improvement_cases(fd, "ghidra@12.0", "angr", "ged", results_root=root)
    assert case.binary_path == comp / "bin"
    assert case.address == 0x111


def test_missing_tree_degrades_gracefully(tmp_path: Path) -> None:
    # results_root exists but has no compiled/decompiled artifacts.
    fd = _fd([_rec("foo", angr={"ged": 0.0}, kuna={"ged": 7.0})])
    (case,) = find_improvement_cases(fd, "angr", "kuna", "ged", results_root=tmp_path)
    assert case.binary_path is None
    assert case.address is None


def test_no_results_root_leaves_locations_unset() -> None:
    fd = _fd([_rec("foo", angr={"ged": 0.0}, kuna={"ged": 7.0})])
    (case,) = find_improvement_cases(fd, "angr", "kuna", "ged")
    assert case.binary_path is None and case.address is None


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def test_render_text_and_to_dict() -> None:
    fd = _fd([_rec("foo", angr={"ged": 0.0}, kuna={"ged": 7.0})])
    cases = find_improvement_cases(fd, "angr", "kuna", "ged")
    text = render_text(cases, fd, base="angr", target="kuna", metric="ged", total=len(cases))
    assert "angr beats kuna on 'ged'" in text
    assert "lower is better" in text
    assert "foo" in text and "proj" in text

    d = cases[0].to_dict()
    assert d["function"] == "foo" and d["margin"] == 7.0
    assert d["base_perfect"] is True and d["target_value"] == 7.0
