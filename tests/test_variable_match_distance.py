from __future__ import annotations

import sys
from dataclasses import replace
from types import SimpleNamespace

from decbench.decompilers.raw.ghidra_raw import RawGhidraDecompiler
from decbench.decompilers.raw.ida_raw import RawIDADecompiler
from decbench.metrics.variable_match import (
    VariableEvidence,
    extract_decompiler_evidence,
    match_variables,
)
from decbench.models.decompilation import (
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
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
        [replace(var, name=f"synthetic_{index}") for index, var in enumerate(reversed(decompiled))],
    )
    assert _pairs(baseline) == _pairs(renamed)
    assert _pairs(baseline) == {
        ("s0", "d1", "overlap"),
        ("s1", "d0", "overlap"),
    }


def test_overlap_runner_up_gaps_are_captured_at_the_peeling_iteration() -> None:
    source = [
        _var("s0", addresses={1, 2, 3, 4}),
        _var("s1", addresses={4, 5, 6, 7}),
    ]
    decompiled = [
        _var("d0", addresses={1, 2, 3, 4}),
        _var("d1", addresses={4, 5, 6, 7}),
    ]

    result = match_variables(source, decompiled)
    matches = {(match.source_id, match.decompiled_id): match for match in result.matches}

    first = matches[("s0", "d0")]
    assert first.source_runner_up_gap is not None
    assert first.decompiled_runner_up_gap is not None
    # s0/d0 has been peeled away before s1/d1 is accepted. Its now-inactive
    # cross edges must not be reported as runner-ups for the second pair.
    second = matches[("s1", "d1")]
    assert second.source_runner_up_gap is None
    assert second.decompiled_runner_up_gap is None


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


def test_ida_variable_lines_skip_only_the_bad_tree_item(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "ida_hexrays", SimpleNamespace(cot_var=1))
    good_a = SimpleNamespace(
        op=1,
        cexpr=SimpleNamespace(v=SimpleNamespace(idx=2)),
        line=3,
    )
    bad = SimpleNamespace(
        op=1,
        cexpr=SimpleNamespace(v=SimpleNamespace(idx=9)),
        line=None,
    )
    good_b = SimpleNamespace(
        op=1,
        cexpr=SimpleNamespace(v=SimpleNamespace(idx=2)),
        line=7,
    )

    def find_item_coords(item):
        if item.line is None:
            raise ValueError
        return 0, item.line

    cfunc = SimpleNamespace(
        treeitems=[good_a, bad, good_b],
        find_item_coords=find_item_coords,
    )
    assert RawIDADecompiler._extract_variable_lines(cfunc) == {2: {4, 8}}


class _FakeAddress:
    def __init__(self, offset: int):
        self.offset = offset

    def getOffset(self):
        return self.offset


class _FakeLine:
    def __init__(self, number: int):
        self.number = number

    def getLineNumber(self):
        return self.number


class _FakeSymbol:
    def __init__(self, symbol_id: int):
        self.symbol_id = symbol_id

    def getId(self):
        return self.symbol_id

    def getName(self):
        return "v7"


class _FakeToken:
    def __init__(self, line: int, address: int, symbol_id: int | None = None):
        self.line = _FakeLine(line)
        self.address = _FakeAddress(address)
        self.symbol_id = symbol_id

    def numChildren(self):
        return 0

    def getLineParent(self):
        return self.line

    def getMinAddress(self):
        return self.address

    def isVariableRef(self):
        return self.symbol_id is not None

    def getHighSymbol(self, high):
        return _FakeSymbol(self.symbol_id) if self.symbol_id is not None else None

    def getText(self):
        return "v7" if self.symbol_id is not None else "="


class _FakeGroup:
    def __init__(self, children):
        self.children = children

    def numChildren(self):
        return len(self.children)

    def Child(self, index):
        return self.children[index]


class _FakeGhidraResult:
    def getCCodeMarkup(self):
        return _FakeGroup([_FakeToken(5, 0x5020, 7), _FakeToken(5, 0x5030)])


def test_ghidra_markup_maps_variable_tokens_and_line_addresses() -> None:
    mappings, variable_lines = RawGhidraDecompiler._extract_markup_evidence(
        _FakeGhidraResult(),
        object(),
        {7: 0},
        elf_base=0x1000,
        image_base=0x5000,
    )
    assert mappings == [LineMapping(line_number=5, addresses=[0x1020, 0x1030])]
    assert variable_lines == {0: {5}}


def test_saved_decompiler_evidence_uses_native_variable_addresses() -> None:
    function = FunctionDecompilation(
        name="FUN_1000",
        address=0x1000,
        decompiled_code=(
            "int FUN_1000(int param_1) {\n"
            "    int declaration_only;\n"
            "    return param_1;\n"
            "}"
        ),
        line_count=4,
        line_mappings=[
            LineMapping(line_number=1, addresses=[0x1000]),
            LineMapping(line_number=2, addresses=[0x1002]),
            LineMapping(line_number=3, addresses=[0x1004]),
        ],
        variables=[
            VariableInfo(
                name="param_1",
                type="int",
                kind="arg",
                arg_index=0,
                line_numbers=[1, 3],
                addresses=[0x1004],
            ),
            VariableInfo(name="declaration_only", type="int"),
            VariableInfo(
                name="",
                type="int",
                line_numbers=[2],
                addresses=[0x1002],
            ),
        ],
    )
    evidence = extract_decompiler_evidence(
        function,
        backend="ghidra@12.1",
        function_name="main",
        function_end=0x1010,
    )
    assert evidence.name == "main"
    assert evidence.end == 0x1010
    assert len(evidence.variables) == 2
    assert evidence.variables[0].identity == "ghidra@12.1:0"
    assert evidence.variables[0].addresses == frozenset({0x1004})
    assert evidence.variables[1].addresses == frozenset()

    calibration_evidence = extract_decompiler_evidence(
        function,
        backend="ghidra@12.1",
        function_name="main",
        function_end=0x1010,
        include_unnamed=True,
    )
    assert len(calibration_evidence.variables) == 3
    assert calibration_evidence.variables[2].identity == "ghidra@12.1:2"
    assert calibration_evidence.variables[2].name == ""
    assert calibration_evidence.variables[2].addresses == frozenset({0x1002})
