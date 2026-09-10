from __future__ import annotations

from decbench.metrics.variable_features import variable_occurrence_lines
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
    arg: int | None = None,
) -> VariableEvidence:
    return VariableEvidence(
        identity=identity,
        addresses=frozenset(addresses or set()),
        stack_offsets=() if stack is None else (stack,),
        arg_index=arg,
    )


def _pairs(result):
    return {(match.source_id, match.decompiled_id, match.stage) for match in result.matches}


def test_arguments_match_by_position_not_name() -> None:
    source = [_var("argc", arg=0), _var("argv", arg=1)]
    decompiled = [_var("v2", arg=1), _var("v1", arg=0)]
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


def test_overlap_matching_is_deterministic_across_input_order() -> None:
    source = [
        _var("s0", addresses={1, 2, 3}),
        _var("s1", addresses={8, 9}),
    ]
    decompiled = [
        _var("d0", addresses={8, 9, 10}),
        _var("d1", addresses={1, 2}),
    ]
    baseline = match_variables(source, decompiled)
    renamed = match_variables(list(reversed(source)), list(reversed(decompiled)))
    assert _pairs(baseline) == _pairs(renamed)
    assert _pairs(baseline) == {
        ("s0", "d1", "overlap"),
        ("s1", "d0", "overlap"),
    }


def test_overlap_ranking_is_recomputed_after_each_accepted_pair() -> None:
    source = [
        _var("s0", addresses={1, 2, 3, 4}),
        _var("s1", addresses={4, 5, 6, 7}),
    ]
    decompiled = [
        _var("d0", addresses={1, 2, 3, 4}),
        _var("d1", addresses={4, 5, 6, 7}),
    ]

    result = match_variables(source, decompiled)
    assert _pairs(result) == {
        ("s0", "d0", "overlap"),
        ("s1", "d1", "overlap"),
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


def test_local_binding_excludes_same_spelling_outside_lexical_scope() -> None:
    code = "int item;\nvoid f(void) {\n{ int item; inside(item); }\noutside(item);\n}"

    assert variable_occurrence_lines(code, "f", ["item"]) == {"item": (3,)}


def test_local_binding_excludes_uses_before_the_declaration() -> None:
    code = "int item;\nvoid f(void) {\nbefore(item);\nint item;\nafter(item);\n}"

    assert variable_occurrence_lines(code, "f", ["item"]) == {"item": (4, 5)}


def test_address_mode_golden_pairs() -> None:
    source = [
        VariableEvidence("s_arg", arg_index=0),
        VariableEvidence("s_stack", stack_offsets=(-8,)),
        VariableEvidence("s_address", addresses=frozenset({10, 11})),
        VariableEvidence("s_unobservable"),
    ]
    decompiled = [
        VariableEvidence("d_noise", addresses=frozenset({99})),
        VariableEvidence("d_address", addresses=frozenset({10, 11})),
        VariableEvidence("d_stack", stack_offsets=(-8,)),
        VariableEvidence("d_arg", arg_index=0),
    ]

    address = match_variables(source, decompiled, stack_shift_hint=0)

    assert _pairs(address) == {
        ("s_arg", "d_arg", "argument"),
        ("s_stack", "d_stack", "stack"),
        ("s_address", "d_address", "overlap"),
    }
    assert address.unmatched_decompiled == ["d_noise"]
    assert address.unobservable_source == ["s_unobservable"]


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
    )
    assert len(evidence) == 2
    assert evidence[0].identity == "ghidra@12.1:0"
    assert evidence[0].addresses == frozenset({0x1004})
    assert evidence[1].addresses == frozenset()

    calibration_evidence = extract_decompiler_evidence(
        function,
        backend="ghidra@12.1",
        include_unnamed=True,
    )
    assert len(calibration_evidence) == 3
    assert calibration_evidence[2].identity == "ghidra@12.1:2"
    assert calibration_evidence[2].addresses == frozenset({0x1002})
