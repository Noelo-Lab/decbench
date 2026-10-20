"""Focused tests for address-based type correspondence and its generic fallback."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from decbench.metrics.base import MetricConfig
from decbench.metrics.type_match import (
    ADDRESS_CORRESPONDENCE_BACKENDS,
    TypeMatchMetric,
    parse_c_variables,
    uses_legacy_correspondence,
)
from decbench.metrics.variable_match import VariableEvidence
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)


def test_agent_reported_lines_use_address_correspondence() -> None:
    code = 'int target(int arg) {\n int local = arg;\n puts("local"); // arg\n return local;\n}\n'
    assert all(not var.line_numbers for var in parse_c_variables(code, "target"))
    variables = parse_c_variables(code, "target", include_occurrence_lines=True)
    assert [(var.name, var.line_numbers) for var in variables] == [
        ("arg", [1, 2]),
        ("local", [2, 4]),
    ]
    function = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code=code,
        line_mappings=[LineMapping(line_number=2, addresses=[0x1004])],
        metadata={"line_mapping_source": "agent_reported"},
    )
    value = _metric().compute_for_function(
        function,
        ground_truth_vars=[{"name": "arg", "type": "int", "is_arg": True}],
        backend="codex",
    )
    assert value.metadata["correspondence"] == "address"
    assert value.metadata["variable_match_evidence"] == "agent_reported"
    assert value.metadata["decompiler_address_variables"] == 2


@pytest.fixture(autouse=True)
def _disable_metric_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECBENCH_NO_CACHE", "1")


def _metric() -> TypeMatchMetric:
    return TypeMatchMetric(MetricConfig())


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("char *p;", {"p": "char*"}),
        ("char* p;", {"p": "char*"}),
        ("char * p;", {"p": "char*"}),
        ("char*p;", {"p": "char*"}),
        ("char **p;", {"p": "char**"}),
        ("int a, b, c;", {"a": "int", "b": "int", "c": "int"}),
        ("int a = 0, b = 0;", {"a": "int", "b": "int"}),
        ("int *a, b, **c;", {"a": "int*", "b": "int", "c": "int**"}),
        ("int a = call(1, 2), b = 0;", {"a": "int", "b": "int"}),
        ('char *p = "a,b;", *q = 0;', {"p": "char*", "q": "char*"}),
        ("FILE *fp; Widget value;", {"fp": "FILE*", "value": "Widget"}),
        ("struct stat st; struct record_t x;", {"st": "stat", "x": "record_t"}),
        ("union item u, *p;", {"u": "item", "p": "item*"}),
        ("enum state s, *p;", {"s": "state", "p": "state*"}),
        ("int a[2], *b;", {"a": "int", "b": "int*"}),
        ("int grid[2][3];", {"grid": "int"}),
        ("int (__fastcall *v6)(__int64);", {"v6": "int (__fastcall *)(__int64)"}),
        ("int (**cb)(char arg[2]);", {"cb": "int (**)(char arg[2])"}),
        ("const char *const name;", {"name": "char*"}),
        ("char *restrict name;", {"name": "char*"}),
        ("int a; { char *p; }", {"a": "int", "p": "char*"}),
        ("int x [[maybe_unused]]; int y;", {"x": "int", "y": "int"}),
    ],
)
def test_local_declaration_spelling_scores(body: str, expected: dict[str, str]) -> None:
    code = f"void target(void) {{ {body} }}"
    function = FunctionDecompilation(
        name="target", address=0x1000, decompiled_code=code, variables=[]
    )
    gt = [{"name": name, "type": [type_], "rbp_offset": []} for name, type_ in expected.items()]
    result = _metric().compute_for_function(function, ground_truth_vars=gt, backend="decompiler")
    assert result.value == 1.0
    assert result.metadata["tp"] == len(expected)
    assert result.metadata["fp"] == result.metadata["fn"] == 0


@pytest.mark.parametrize(
    ("declaration", "expected"),
    [("char *p;", "int*"), ("char **p;", "char*"), ("struct first p;", "second")],
)
def test_local_declaration_type_mismatches(declaration: str, expected: str) -> None:
    function = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code=f"void target(void) {{ {declaration} }}",
        variables=[],
    )
    result = _metric().compute_for_function(
        function,
        ground_truth_vars=[{"name": "p", "type": [expected], "rbp_offset": []}],
        backend="decompiler",
    )
    assert result.value == 0.0
    assert result.metadata["tp"] == 0


@pytest.mark.parametrize(
    "body",
    [
        '/* int fake; */ puts("char *fake;"); // int fake;\n',
        "return; goto done; done: call(); value = 1;",
        "typedef int Alias; extern int external; int prototype(int arg);",
        "struct layout { int field; char *pointer; };",
        "int broken = ;",
    ],
)
def test_nonlocal_or_invalid_declarations_are_ignored(body: str) -> None:
    code = f"void target(void) {{ int before; {body} int after; }}"
    assert [v.name for v in parse_c_variables(code, "target")] == ["before", "after"]


@pytest.mark.parametrize("body", ["int keep;", ""])
def test_target_scope_excludes_globals_and_sibling_locals(body: str) -> None:
    code = (
        "struct node *g_head;\n"
        "void helper(void) { int helper_local; char keep; }\n"
        f"void target(void) {{ {body} }}\n"
    )
    variables = parse_c_variables(code, "target", include_occurrence_lines=True)
    assert [(v.name, v.line_numbers) for v in variables] == ([("keep", [3])] if body else [])
    function = FunctionDecompilation(name="target", address=0x1000, decompiled_code=code)
    gt = [
        {"name": name, "type": [type_], "rbp_offset": []}
        for name, type_ in [("g_head", "node*"), ("helper_local", "int"), ("keep", "char")]
    ]
    result = _metric().compute_for_function(function, ground_truth_vars=gt, backend="decompiler")
    assert result.value == 0.0
    assert result.metadata["tp"] == 0
    assert result.metadata["fp"] == (1 if body else 0)
    assert result.metadata["fn"] == (2 if body else 3)


def test_unparsed_signature_recovers_only_the_single_outermost_body() -> None:
    code = (
        "struct node *g_head;\n"
        "int __usercall sub_1000@<eax>(int a1@<edi>, char *a2@<rsi>) {\n"
        "    int v3;\n"
        "    { char *nested; }\n"
        "    return v3;\n"
        "}\n"
    )
    variables = parse_c_variables(code, "sub_1000", include_occurrence_lines=True)
    assert [(v.name, v.type, v.kind, v.arg_index) for v in variables] == [
        ("v3", "int", "stack", None),
        ("nested", "char *", "stack", None),
    ]
    assert all(not v.line_numbers for v in variables)
    function = FunctionDecompilation(name="sub_1000", address=0x1000, decompiled_code=code)
    gt = [
        {"name": "v3", "type": ["int"], "rbp_offset": []},
        {"name": "nested", "type": ["char*"], "rbp_offset": []},
        {"name": "g_head", "type": ["node*"], "rbp_offset": []},
    ]
    result = _metric().compute_for_function(function, ground_truth_vars=gt, backend="decompiler")
    assert result.value == pytest.approx(2 / 3)
    assert result.metadata["tp"] == 2
    assert result.metadata["fp"] == 0
    assert result.metadata["fn"] == 1


@pytest.mark.parametrize(
    "code",
    [
        "struct node *g_head; int x;",
        (
            "int __usercall first@<eax>(void) { int x; }\n"
            "int __usercall second@<eax>(void) { int y; }"
        ),
    ],
)
def test_body_recovery_abstains_without_a_unique_body(code: str) -> None:
    assert parse_c_variables(code, "target") == []


def test_attributed_declarators_retain_function_selection_and_occurrences() -> None:
    code = (
        "void helper(void) { int x; }\n"
        "int target(void) [[gnu::noinline]] {\n"
        "    int x [[maybe_unused]];\n"
        "    return x;\n"
        "}\n"
    )
    variables = parse_c_variables(code, "target", include_occurrence_lines=True)
    assert [(v.name, v.type, v.line_numbers) for v in variables] == [("x", "int", [3, 4])]


def test_argument_positions_skip_unnamed_and_variadic_parameters() -> None:
    code = "void target(int (*)(int named), char *p, int (*cb)(int), ...) { int grid[2][3]; }"
    variables = parse_c_variables(code, "target")
    assert [(v.name, v.type, v.arg_index) for v in variables] == [
        ("p", "char *", 1),
        ("cb", "int (*)(int)", 2),
        ("grid", "int", None),
    ]
    function = FunctionDecompilation(name="target", address=0x1000, decompiled_code=code)
    gt = [
        {"name": "renamed_p", "type": ["char*"], "is_arg": True, "arg_index": 1},
        {"name": "renamed_cb", "type": ["int (*)(int)"], "is_arg": True, "arg_index": 2},
        {"name": "grid", "type": ["int"], "rbp_offset": []},
    ]
    result = _metric().compute_for_function(function, ground_truth_vars=gt, backend="decompiler")
    assert result.value == 1.0
    assert result.metadata["tp"] == 3
    assert result.metadata["fp"] == result.metadata["fn"] == 0


def _address_fixture() -> tuple[FunctionDecompilation, list[dict[str, Any]]]:
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(void) { int renamed; sink(renamed); return 0; }",
        variables=[VariableInfo(name="renamed", type="int", size=4, addresses=[0x1004])],
    )
    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "size": 4,
            "rbp_offset": [],
            "addresses": [0x1004],
        }
    ]
    return decompiled, ground_truth


def test_address_correspondence_is_name_type_and_size_blind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import decbench.metrics.type_match as type_match_module

    ground_truth = [
        {
            "identity": "source:0",
            "name": "source_a",
            "type": ["int"],
            "size": 4,
            "rbp_offset": [],
            "addresses": [0x1004],
        },
        {
            "identity": "source:1",
            "name": "source_b",
            "type": ["char"],
            "size": 1,
            "rbp_offset": [],
            "addresses": [0x1008],
        },
    ]
    calls: list[tuple[tuple[str, str], ...]] = []
    real_match = type_match_module.match_variables

    def capture(
        source: list[VariableEvidence],
        decompiled: list[VariableEvidence],
        **kwargs: Any,
    ) -> Any:
        source_rows = list(source)
        decompiled_rows = list(decompiled)
        result = real_match(source_rows, decompiled_rows, **kwargs)
        pairs = tuple(sorted((match.source_id, match.decompiled_id) for match in result.matches))
        calls.append(pairs)
        return result

    monkeypatch.setattr(type_match_module, "match_variables", capture)
    correct, _ = _address_fixture()
    correct.variables.append(VariableInfo(name="other", type="char", addresses=[0x1008]))
    renamed = correct.model_copy(
        update={
            "variables": [
                correct.variables[0].model_copy(
                    update={"name": "source_b", "type": "char", "size": 4096}
                ),
                correct.variables[1].model_copy(
                    update={"name": "source_a", "type": "int", "size": 8192}
                ),
            ]
        }
    )

    assert (
        _metric()
        .compute_for_function(correct, ground_truth_vars=ground_truth, backend="angr")
        .value
        == 1.0
    )
    assert (
        _metric()
        .compute_for_function(renamed, ground_truth_vars=ground_truth, backend="angr")
        .value
        == 0.0
    )
    assert calls[0] == calls[1]


def test_address_path_is_reported_even_when_it_accepts_no_pair() -> None:
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="",
        variables=[VariableInfo(name="same", type="int")],
    )
    ground_truth = [{"identity": "source:0", "name": "same", "type": ["int"], "rbp_offset": []}]

    value = _metric().compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
        backend="ghidra",
    )

    assert value.value == 0.0
    assert value.metadata["correspondence"] == "address"
    assert value.metadata["variable_match_evidence"] == "native"
    assert value.metadata["match_stage_counts"] == {}


def _named_only_decompilation(tmp_path: Path, backend: str) -> DecompilationResult:
    return DecompilationResult(
        binary_path=tmp_path / "program",
        binary_name="program",
        decompiler=DecompilerMetadata(decompiler_name=backend),
        functions={
            "target": FunctionDecompilation(
                name="target",
                address=0x1000,
                decompiled_code=(
                    "int target(void) { int original; int local_10; sink(original); return 0; }"
                ),
                variables=[
                    VariableInfo(name="original", type="int"),
                    VariableInfo(name="local_10", type="char"),
                ],
            )
        },
    )


def _named_only_ground_truth() -> list[dict[str, Any]]:
    return [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "rbp_offset": [],
        },
        {
            "identity": "source:1",
            "name": "unrelated",
            "type": ["char"],
            "rbp_offset": [-0x10],
        },
    ]


def test_unknown_backend_remains_evaluable_through_caveated_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.metrics.type_match as type_match_module

    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {0x1000: {"target": _named_only_ground_truth()}},
    )

    result = _metric().compute_for_binary(
        _named_only_decompilation(tmp_path, "external-text-decompiler")
    )
    value = result.function_results["target"]

    assert value.value == 1.0
    assert value.metadata["correspondence"] == "legacy_name"
    assert value.metadata["variable_match_evidence"] == "fallback_only"
    assert value.metadata["matched_by_name"] == 1
    assert value.metadata["matched_by_offset"] == 1


def test_only_top_seven_backends_use_address_correspondence() -> None:
    assert {
        "angr",
        "binja",
        "dewolf",
        "ghidra",
        "ida",
        "kuna",
        "r2dec",
    } == ADDRESS_CORRESPONDENCE_BACKENDS
    for backend in ADDRESS_CORRESPONDENCE_BACKENDS:
        assert uses_legacy_correspondence(backend) is False
        assert uses_legacy_correspondence(f"{backend}@version") is False

    assert uses_legacy_correspondence("retdec") is True
    assert uses_legacy_correspondence("some-new-submission") is True
    assert uses_legacy_correspondence(None) is True


def test_capable_backend_selection_is_not_inferred_per_function(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.metrics.type_match as type_match_module

    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {0x1000: {"target": _named_only_ground_truth()}},
    )
    result = _metric().compute_for_binary(_named_only_decompilation(tmp_path, "ghidra@12.1"))
    value = result.function_results["target"]

    assert value.value == 0.0
    assert value.metadata["correspondence"] == "address"
    assert value.metadata["variable_match_evidence"] == "native"


def test_direct_call_defaults_to_generic_fallback_but_can_request_address_mode() -> None:
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="",
        variables=[VariableInfo(name="same", type="int")],
    )
    ground_truth = [{"identity": "source:0", "name": "same", "type": ["int"], "rbp_offset": []}]

    fallback = _metric().compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )
    strict = _metric().compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
        address_provenance=True,
    )

    assert strict.value == 0.0
    assert strict.metadata["correspondence"] == "address"
    assert fallback.value == 1.0
    assert fallback.metadata["correspondence"] == "legacy_name"
