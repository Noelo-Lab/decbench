from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from decbench.decompilers.raw.ida_raw import RawIDADecompiler
from decbench.experimental.local_variable_distance import (
    VariableEvidence,
    match_variables,
)


def _var(
    identity: str,
    *,
    addresses: set[int] | None = None,
    stack: int | None = None,
    size: int = 4,
    arg: int | None = None,
) -> VariableEvidence:
    return VariableEvidence(
        identity=identity,
        name=identity,
        addresses=frozenset(addresses or set()),
        stack_offsets=() if stack is None else (stack,),
        size=size,
        kind="arg" if arg is not None else "local",
        arg_index=arg,
    )


def _pairs(result):
    return {(match.source_id, match.decompiled_id, match.stage) for match in result.matches}


def test_arguments_match_by_position_not_name() -> None:
    source = [_var("argc", arg=0), _var("argv", arg=1, size=8)]
    decompiled = [_var("v2", arg=1, size=8), _var("v1", arg=0)]
    result = match_variables(source, decompiled)
    assert _pairs(result) == {
        ("argc", "v1", "argument"),
        ("argv", "v2", "argument"),
    }


def test_unique_stack_slots_match_before_overlap() -> None:
    source = [_var("s0", stack=-40), _var("s1", stack=-32)]
    decompiled = [_var("d0", stack=8), _var("d1", stack=16)]
    result = match_variables(source, decompiled)
    assert result.stack_shift == -48
    assert _pairs(result) == {
        ("s0", "d0", "stack"),
        ("s1", "d1", "stack"),
    }


def test_stack_shift_requires_consensus() -> None:
    source = [_var("s0", stack=-40)]
    decompiled = [_var("d0", stack=200)]
    result = match_variables(source, decompiled)
    assert result.stack_shift is None
    assert result.matches == []


def test_tied_stack_shifts_abstain() -> None:
    source = [
        _var("s0", stack=0),
        _var("s1", stack=10),
        _var("s2", stack=100),
        _var("s3", stack=110),
    ]
    decompiled = [_var("d0", stack=0), _var("d1", stack=10)]
    result = match_variables(source, decompiled)
    assert result.stack_shift is None
    assert result.matches == []


def test_stack_aliases_are_resolved_only_by_address_evidence() -> None:
    source = [
        _var("s0", stack=-40, addresses={0x10, 0x11}),
        _var("s1", stack=-40, addresses={0x20, 0x21}),
    ]
    decompiled = [
        _var("d0", stack=8, addresses={0x20, 0x21}),
        _var("d1", stack=8, addresses={0x10, 0x11}),
    ]
    result = match_variables(source, decompiled)
    assert _pairs(result) == {
        ("s0", "d1", "overlap"),
        ("s1", "d0", "overlap"),
    }


def test_overlap_matching_is_name_blind_and_deterministic() -> None:
    source = [
        _var("s0", addresses={1, 2, 3}),
        _var("s1", addresses={8, 9}),
    ]
    decompiled = [
        _var("d0", addresses={8, 9, 10}),
        _var("d1", addresses={1, 2}),
    ]
    baseline = match_variables(source, decompiled)
    renamed = match_variables(
        [replace(var, name=f"renamed_{index}") for index, var in enumerate(reversed(source))],
        [
            replace(var, name=f"synthetic_{index}")
            for index, var in enumerate(reversed(decompiled))
        ],
    )
    assert _pairs(baseline) == _pairs(renamed)
    assert _pairs(baseline) == {
        ("s0", "d1", "overlap"),
        ("s1", "d0", "overlap"),
    }


def test_ambiguous_equal_overlap_is_not_forced() -> None:
    source = [_var("s0", addresses={1, 2})]
    decompiled = [
        _var("d0", addresses={1, 2}),
        _var("d1", addresses={1, 2}),
    ]
    result = match_variables(source, decompiled)
    assert result.matches == []
    assert result.unmatched_source == ["s0"]


def test_edit_distance_counts_insertions_and_unobservable_source() -> None:
    source = [_var("visible", addresses={1}), _var("dead")]
    decompiled = [_var("recovered", addresses={1}), _var("extra")]
    result = match_variables(source, decompiled)
    assert len(result.matches) == 1
    assert result.distance == 1
    assert result.strict_distance == 2
    assert result.unobservable_source == ["dead"]


class _FakeCfunc:
    entry_ea = 0x5010

    def get_pseudocode(self):
        return [object()]

    def get_eamap(self):
        return {0x5020: [object()], 0x5030: [object()]}

    def find_item_coords(self, item):
        return (0, 4 if not hasattr(self, "_seen") else 6)


def test_ida_line_mappings_are_one_based_and_rebased() -> None:
    cfunc = _FakeCfunc()
    mappings = RawIDADecompiler._extract_line_mappings(
        cfunc,
        elf_base=0x1000,
        image_base=0x5000,
    )
    by_line = {mapping.line_number: mapping.addresses for mapping in mappings}
    assert by_line[1] == [0x1010]
    assert by_line[5] == [0x1020, 0x1030]


def test_grep_main_demo(tmp_path: Path) -> None:
    required = [
        Path("testing/grep"),
        Path("testing/grep.c"),
        Path("testing/grep.i"),
        Path("testing/ida_grep.c"),
        Path("/Applications/IDA Professional 9.2.app/Contents/MacOS"),
    ]
    if not all(path.exists() for path in required):
        pytest.skip("grep fixture or IDA 9.2 is unavailable")
    output = tmp_path / "proof"
    subprocess.run(
        [
            sys.executable,
            "scripts/demo_local_variable_distance.py",
            "--check",
            "--output-dir",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    evidence = json.loads((output / "evidence.json").read_text())
    assert evidence["summary"]["mapped_decompiled_lines"] > 500
    assert evidence["summary"]["decompiled_total"] == 140
    assert evidence["artifact_checks"]["provided_declared_names"] == 140
    assert all(row["passed"] for row in evidence["oracle_checks"])
    assert all(row["passed"] for row in evidence["negative_oracle_checks"])
    assert all(row["passed"] for row in evidence["correspondence_checks"])
    source = {var["name"]: var for var in evidence["source"]["variables"]}
    assert all(line >= 2462 for line in source["argc"]["lines"])
    assert all(line >= 2462 for line in source["matcher"]["lines"])
    assert all(
        line >= 2462
        for variable in evidence["source"]["variables"]
        for line in variable["lines"]
    )
    assert all(variable["name"] for variable in evidence["decompiled"]["variables"])
    assert source["num_operands"]["addresses"] == [
        "0x5ddf",
        "0x5df6",
        "0x5e23",
        "0x5e9b",
        "0x5e9d",
    ]
