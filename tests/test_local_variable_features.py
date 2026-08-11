from __future__ import annotations

from dataclasses import replace

from decbench.experimental.local_variable_distance import (
    DistanceResult,
    FunctionEvidence,
    VariableEvidence,
    extract_decompiler_evidence,
    match_variables,
)
from decbench.experimental.local_variable_features import analyze_c_function
from decbench.models.decompilation import FunctionDecompilation


def _features(*names: str) -> tuple[tuple[str, int], ...]:
    return tuple((name, 1) for name in names)


def _variable(
    identity: str,
    feature: str,
    *,
    address: int = 0,
    stack: int | None = None,
    arg_index: int | None = None,
) -> VariableEvidence:
    return VariableEvidence(
        identity=identity,
        name=f"raw_{identity}",
        addresses=frozenset({address}) if address else frozenset(),
        stack_offsets=(stack,) if stack is not None else (),
        arg_index=arg_index,
        usage_features=_features(feature),
    )


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
    assert "helper" not in analysis.features
    assert "member" not in analysis.features
    assert "external" not in analysis.features


def test_unnamed_parameters_still_occupy_argument_positions() -> None:
    analysis = analyze_c_function("int f(int, int value) { return value; }", "f")

    assert [(variable.name, variable.arg_index) for variable in analysis.variables] == [
        ("value", 1)
    ]


def test_usage_vectors_are_alpha_rename_invariant_and_name_free() -> None:
    first = analyze_c_function(
        'int f(int source) { int result = parse(source, "tag"); return result; }',
        "f",
    )
    renamed = analyze_c_function(
        'int f(int alpha) { int omega = parse(alpha, "tag"); return omega; }',
        "f",
    )

    assert first.features["source"] == renamed.features["alpha"]
    assert first.features["result"] == renamed.features["omega"]
    serialized = repr(list(first.features.values()))
    assert "source" not in serialized
    assert "result" not in serialized
    assert "int" not in serialized


def test_calls_capture_callee_and_argument_position() -> None:
    analysis = analyze_c_function(
        "int f(int left, int right) { consume(right, left); return left; }",
        "f",
    )

    left = dict(analysis.features["left"])
    right = dict(analysis.features["right"])
    assert left["call:named:consume:arg:1"] == 1
    assert right["call:named:consume:arg:0"] == 1
    assert left["control:return:value"] == 1


def test_address_bearing_thunk_callees_are_normalized_away() -> None:
    analysis = analyze_c_function(
        "int f(int value) { thunk_FUN_00107e80(value); "
        "j_sub_401000(value); return stable_call(value); }",
        "f",
    )

    features = dict(analysis.features["value"])
    assert "call:named:stable_call:arg:0" in features
    assert not any(
        feature.startswith(("call:named:thunk_", "call:named:j_sub_")) for feature in features
    )


def test_decompiler_width_helpers_are_normalized_without_size_tokens() -> None:
    wide = analyze_c_function(
        "int f(int value) { return __ROR8__(CONCAT71(value, value), 3); }",
        "f",
    )
    narrow = analyze_c_function(
        "int f(int value) { return __ROR4__(CONCAT22(value, value), 3); }",
        "f",
    )

    assert wide.features["value"] == narrow.features["value"]
    serialized = repr(wide.features["value"])
    assert "ROR8" not in serialized
    assert "CONCAT71" not in serialized
    assert "pseudo:rotate-right" in serialized
    assert "pseudo:concatenate" in serialized


def test_call_results_and_commutative_operands_are_normalized() -> None:
    first = analyze_c_function(
        "int f(int input) { int output = convert(input); return output; }",
        "f",
    )
    reordered = analyze_c_function(
        "int f(int alpha) { int beta; beta = 1 + alpha; return beta; }",
        "f",
    )

    output = dict(first.features["output"])
    assert output["call:any:return_target"] == 1
    assert output["call:named:convert:return_target"] == 1
    assert "binary:+:commutative" in dict(reordered.features["alpha"])


def test_only_the_outer_assigned_call_is_a_return_target() -> None:
    analysis = analyze_c_function(
        "int f(int value) { int result = outer(inner(value)); "
        "result = again(deeper(value)); return result; }",
        "f",
    )

    features = dict(analysis.features["result"])
    assert features["call:any:return_target"] == 2
    assert features["call:named:outer:return_target"] == 1
    assert features["call:named:again:return_target"] == 1
    assert "call:named:inner:return_target" not in features
    assert "call:named:deeper:return_target" not in features


def test_unevaluated_and_member_identifiers_do_not_become_uses() -> None:
    analysis = analyze_c_function(
        "int f(int value) { struct row item; return sizeof(value) + item.value; }",
        "f",
    )

    assert analysis.features["value"] == ()
    assert dict(analysis.features["item"]) == {
        "binary:+:commutative": 1,
        "control:return:value": 1,
        "memory:field:base": 1,
        "use:read": 1,
    }


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
    assert all(variable.usage_features for variable in evidence.variables)
    assert all(not variable.addresses for variable in evidence.variables)
    assert all(variable.inferred_from_code for variable in evidence.variables)
    assert legacy_evidence.variables == []
    assert match_variables([], evidence.variables).decompiled_count == 0
    usage = match_variables(
        [
            replace(variable, identity=f"source:{index}", inferred_from_code=False)
            for index, variable in enumerate(evidence.variables)
        ],
        evidence.variables,
        mode="usage",
    )
    assert usage.decompiled_count == 2
    assert len(usage.matches) == 2


def test_shadowed_code_only_locals_remain_featureless_candidates() -> None:
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { int item; { int item; } return 0; }",
    )

    evidence = extract_decompiler_evidence(function, backend="llm")

    assert [variable.name for variable in evidence.variables] == ["item", "item"]
    assert all(not variable.usage_features for variable in evidence.variables)
    assert match_variables([], evidence.variables, mode="usage").decompiled_count == 2


def test_statement_fragment_is_wrapped_for_best_effort_recovery() -> None:
    analysis = analyze_c_function(
        "int temporary = 0; temporary = produce(); return temporary;",
        "missing_header",
    )

    assert not analysis.function_found
    assert [variable.name for variable in analysis.variables] == ["temporary"]
    assert "call:named:produce:return_target" in dict(analysis.features["temporary"])


def test_literals_are_local_to_the_variable_operand() -> None:
    analysis = analyze_c_function(
        "int f(int left, int right) { consume(left, right, 42); return left; }",
        "f",
    )

    assert "literal:number:exact:42" not in dict(analysis.features["left"])
    assert "literal:number:exact:42" not in dict(analysis.features["right"])


def test_c_octal_matches_decimal_and_float_literals_are_omitted() -> None:
    octal = analyze_c_function("int f(int value) { return value & 037; }", "f")
    decimal = analyze_c_function("int f(int value) { return value & 31; }", "f")
    floating = analyze_c_function("double f(double value) { return value + 3.5; }", "f")

    assert octal.features["value"] == decimal.features["value"]
    assert "literal:number:exact:31" in dict(octal.features["value"])
    assert not any(feature.startswith("literal:") for feature, _count in floating.features["value"])


def test_local_binding_excludes_same_spelling_outside_lexical_scope() -> None:
    analysis = analyze_c_function(
        "int item; void f(void) { { int item; inside(item); } outside(item); }",
        "f",
    )

    features = dict(analysis.features["item"])
    assert "call:named:inside:arg:0" in features
    assert "call:named:outside:arg:0" not in features


def test_local_binding_excludes_uses_before_the_declaration() -> None:
    analysis = analyze_c_function(
        "int item; void f(void) { before(item); int item; after(item); }",
        "f",
    )

    features = dict(analysis.features["item"])
    assert "call:named:before:arg:0" not in features
    assert "call:named:after:arg:0" in features


def test_strict_usage_mode_ignores_address_stack_and_argument_evidence() -> None:
    source = [
        _variable("s0", "call:named:first:arg:0", address=1, stack=-8, arg_index=0),
        _variable("s1", "call:named:second:arg:0", address=2, stack=-16, arg_index=1),
    ]
    decompiled = [
        _variable("d0", "call:named:first:arg:0", address=2, stack=8, arg_index=1),
        _variable("d1", "call:named:second:arg:0", address=1, stack=16, arg_index=0),
    ]

    baseline = match_variables(source, decompiled, mode="usage")
    stripped = match_variables(
        [replace(var, addresses=frozenset(), stack_offsets=(), arg_index=None) for var in source],
        [
            replace(var, addresses=frozenset(), stack_offsets=(), arg_index=None)
            for var in decompiled
        ],
        mode="usage",
    )
    perturbed_types = match_variables(
        [replace(var, size=1) for var in source],
        [replace(var, size=16) for var in decompiled],
        mode="usage",
    )

    assert _pairs(baseline) == {
        ("s0", "d0", "usage"),
        ("s1", "d1", "usage"),
    }
    assert all(match.intersection == () for match in baseline.matches)
    assert _pairs(baseline) == _pairs(stripped)
    assert _pairs(baseline) == _pairs(perturbed_types)


def test_usage_mode_abstains_on_equal_vectors() -> None:
    source = [_variable("s0", "binary:+:lhs", address=1)]
    decompiled = [
        _variable("d0", "binary:+:lhs"),
        _variable("d1", "binary:+:lhs"),
    ]

    result = match_variables(
        source,
        decompiled,
        mode="usage",
        usage_ambiguity_margin=0,
    )

    assert result.matches == []


def test_zero_threshold_does_not_admit_disjoint_usage_vectors() -> None:
    source = [_variable("s0", "binary:+:commutative", address=1)]
    decompiled = [_variable("d0", "binary:-:lhs", address=2)]

    usage = match_variables(
        source,
        decompiled,
        mode="usage",
        min_usage_similarity=0,
        usage_ambiguity_margin=0,
    )
    fused = match_variables(
        [replace(source[0], addresses=frozenset())],
        [replace(decompiled[0], addresses=frozenset())],
        mode="address+usage",
        min_combined_similarity=0,
        usage_ambiguity_margin=0,
    )

    assert usage.matches == []
    assert fused.matches == []


def test_fused_mode_can_correct_crossed_address_evidence() -> None:
    source = [
        _variable("s0", "call:named:first:arg:0", address=1),
        _variable("s1", "call:named:second:arg:0", address=2),
    ]
    decompiled = [
        _variable("d0", "call:named:first:arg:0", address=2),
        _variable("d1", "call:named:second:arg:0", address=1),
    ]

    address = match_variables(source, decompiled)
    fused = match_variables(
        source,
        decompiled,
        mode="address+usage",
        address_weight=0.2,
    )

    assert _pairs(address) == {
        ("s0", "d1", "overlap"),
        ("s1", "d0", "overlap"),
    }
    assert _pairs(fused) == {
        ("s0", "d0", "fused"),
        ("s1", "d1", "fused"),
    }


def test_combined_mode_labels_single_channel_matches() -> None:
    address_only = match_variables(
        [VariableEvidence("s", "s", addresses=frozenset({1}))],
        [VariableEvidence("d", "d", addresses=frozenset({1}))],
        mode="address+usage",
    )
    usage_fallback = match_variables(
        [_variable("s", "call:named:use:arg:0")],
        [_variable("d", "call:named:use:arg:0")],
        mode="address+usage",
    )

    assert _pairs(address_only) == {("s", "d", "address-only")}
    assert _pairs(usage_fallback) == {("s", "d", "usage-fallback")}


def test_featureless_decompiler_local_remains_an_unmatched_insertion() -> None:
    source = [_variable("s0", "call:named:use:arg:0")]
    decompiled = [
        _variable("d0", "call:named:use:arg:0"),
        VariableEvidence(
            identity="d_hallucinated",
            name="local_99",
            usage_features=_features("use:read"),
            inferred_from_code=True,
        ),
    ]

    result = match_variables(source, decompiled, mode="usage")

    assert result.decompiled_count == 2
    assert result.unmatched_decompiled == ["d_hallucinated"]
    assert result.distance == 1


def test_generic_only_source_variable_is_not_usage_eligible() -> None:
    source = [
        VariableEvidence(
            identity="s0",
            name="source",
            usage_features=_features("use:read"),
        )
    ]

    result = match_variables(source, [], mode="usage")

    assert result.source_count == 0
    assert result.unobservable_source == ["s0"]


def test_feature_evidence_round_trips_through_blinded_json() -> None:
    variable = _variable("source:0", "control:return:value", address=0x1234)
    evidence = FunctionEvidence("f", 0x1200, 0x1300, [variable])

    restored = FunctionEvidence.from_dict(evidence.to_dict())

    assert restored == evidence
