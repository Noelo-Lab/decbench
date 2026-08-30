from __future__ import annotations

from decbench.metrics.variable_features import analyze_c_function, variable_occurrence_lines
from decbench.metrics.variable_match import (
    DistanceResult,
    FunctionEvidence,
    VariableEvidence,
    extract_decompiler_evidence,
    match_variables,
)
from decbench.models.decompilation import FunctionDecompilation


def _pairs(result: DistanceResult) -> set[tuple[str, str, str]]:
    return {(match.source_id, match.decompiled_id, match.stage) for match in result.matches}


def test_discovers_parameters_and_locals_but_not_nonvariables() -> None:
    code = """
        int target(int count, char *buffer) {
            typedef int alias_t;
            extern int external;
            int helper(int);
            int value = helper(count);
            struct row record;
            return value + record.member + buffer[0];
        }
    """

    analysis = analyze_c_function(code, "target")

    assert [(var.name, var.kind, var.arg_index) for var in analysis.variables] == [
        ("count", "arg", 0),
        ("buffer", "arg", 1),
        ("value", "local", None),
        ("record", "local", None),
    ]


def test_unnamed_parameters_still_occupy_argument_positions() -> None:
    analysis = analyze_c_function("int f(int, int value) { return value; }", "f")

    assert [(variable.name, variable.arg_index) for variable in analysis.variables] == [
        ("value", 1)
    ]


def test_code_only_decompiler_variables_are_inferred() -> None:
    function = FunctionDecompilation(
        name="FUN_1000",
        address=0x1000,
        decompiled_code=(
            "int FUN_1000(int param_1) { int local_8; "
            "local_8 = transform(param_1); return local_8; }"
        ),
    )

    evidence = extract_decompiler_evidence(function, backend="llm")
    legacy_evidence = extract_decompiler_evidence(
        function,
        backend="llm",
        infer_code_variables=False,
    )

    assert [(var.name, var.kind, var.arg_index) for var in evidence.variables] == [
        ("param_1", "arg", 0),
        ("local_8", "local", None),
    ]
    assert all(not variable.addresses for variable in evidence.variables)
    assert all(variable.inferred_from_code for variable in evidence.variables)
    assert legacy_evidence.variables == []
    address = match_variables(
        [VariableEvidence("source:arg", "", arg_index=0)],
        evidence.variables,
    )
    assert address.decompiled_count == 1
    assert _pairs(address) == {("source:arg", "llm:inferred:0", "argument")}


def test_inferred_candidates_keep_only_explicit_anchors() -> None:
    source = [
        VariableEvidence("s_arg", "", addresses=frozenset({1}), arg_index=0),
        VariableEvidence("s_stack", "", addresses=frozenset({2}), stack_offsets=(-8,)),
        VariableEvidence("s_line", "", addresses=frozenset({3})),
    ]
    decompiled = [
        VariableEvidence(
            "d_arg",
            "",
            addresses=frozenset({99}),
            arg_index=0,
            inferred_from_code=True,
        ),
        VariableEvidence(
            "d_stack",
            "",
            addresses=frozenset({98}),
            stack_offsets=(-8,),
            inferred_from_code=True,
        ),
        VariableEvidence("d_line", "", addresses=frozenset({3}), inferred_from_code=True),
    ]

    address = match_variables(source, decompiled, stack_shift_hint=0)

    assert address.decompiled_count == 2
    assert _pairs(address) == {
        ("s_arg", "d_arg", "argument"),
        ("s_stack", "d_stack", "stack"),
    }
    assert all(match.intersection == () for match in address.matches)


def test_shadowed_code_only_locals_remain_separate_candidates() -> None:
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { int item; { int item; } return 0; }",
    )

    evidence = extract_decompiler_evidence(function, backend="llm")

    assert [variable.name for variable in evidence.variables] == ["item", "item"]
    assert analyze_c_function(function.decompiled_code, "f").ambiguous_names == ("item",)
    assert match_variables([], evidence.variables).decompiled_count == 0


def test_statement_fragment_is_wrapped_for_best_effort_recovery() -> None:
    analysis = analyze_c_function(
        "int temporary = 0; temporary = produce(); return temporary;",
        "missing_header",
    )

    assert not analysis.function_found
    assert [variable.name for variable in analysis.variables] == ["temporary"]


def test_local_binding_excludes_same_spelling_outside_lexical_scope() -> None:
    code = "int item;\nvoid f(void) {\n{ int item; inside(item); }\noutside(item);\n}"

    assert variable_occurrence_lines(code, "f", ["item"]) == {"item": (3,)}


def test_local_binding_excludes_uses_before_the_declaration() -> None:
    code = "int item;\nvoid f(void) {\nbefore(item);\nint item;\nafter(item);\n}"

    assert variable_occurrence_lines(code, "f", ["item"]) == {"item": (4, 5)}


def test_address_mode_golden_pairs() -> None:
    source = [
        VariableEvidence("s_arg", "", arg_index=0),
        VariableEvidence("s_stack", "", stack_offsets=(-8,)),
        VariableEvidence("s_address", "", addresses=frozenset({10, 11})),
        VariableEvidence("s_unobservable", ""),
    ]
    decompiled = [
        VariableEvidence("d_noise", "", addresses=frozenset({99})),
        VariableEvidence("d_address", "", addresses=frozenset({10, 11})),
        VariableEvidence("d_stack", "", stack_offsets=(-8,)),
        VariableEvidence("d_arg", "", arg_index=0),
    ]

    address = match_variables(source, decompiled, stack_shift_hint=0)

    assert _pairs(address) == {
        ("s_arg", "d_arg", "argument"),
        ("s_stack", "d_stack", "stack"),
        ("s_address", "d_address", "overlap"),
    }
    assert address.unmatched_decompiled == ["d_noise"]
    assert address.unobservable_source == ["s_unobservable"]


def test_address_evidence_round_trips_through_blinded_json() -> None:
    variable = VariableEvidence("source:0", "raw", addresses=frozenset({0x1234}), lines=(7,))
    evidence = FunctionEvidence("f", 0x1200, 0x1300, [variable])

    restored = FunctionEvidence.from_dict(evidence.to_dict())

    assert restored == evidence


def test_legacy_usage_features_in_serialized_evidence_are_ignored() -> None:
    payload = {
        "identity": "source:0",
        "name": "raw",
        "addresses": ["0x1234"],
        "usage_features": {"call:named:sink:arg:0": 3},
    }

    restored = VariableEvidence.from_dict(payload)

    assert restored == VariableEvidence("source:0", "raw", addresses=frozenset({0x1234}))
