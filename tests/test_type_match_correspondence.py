"""Focused tests for production type-blind variable correspondence."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from decbench.metrics.base import MetricConfig
from decbench.metrics.type_evidence import PreprocessedSourceContext, build_source_evidence
from decbench.metrics.type_match import (
    TypeMatchMetric,
    _matching_evidence_payload,
    extract_ground_truth_type_index,
    extract_ground_truth_types,
)
from decbench.metrics.variable_match import (
    VariableEvidence,
    extract_source_evidence,
    match_variables,
)
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)
from decbench.models.metrics import MetricResult


@pytest.fixture(autouse=True)
def _disable_metric_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECBENCH_NO_CACHE", "1")


def _metric(mode: str) -> TypeMatchMetric:
    return TypeMatchMetric(MetricConfig(extra_options={"variable_match_mode": mode}))


def _address_and_usage_fixture() -> tuple[FunctionDecompilation, list[dict[str, Any]]]:
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(void) { int renamed; sink(renamed); return 0; }",
        variables=[
            VariableInfo(
                name="renamed",
                type="int",
                size=4,
                addresses=[0x1004],
            )
        ],
    )
    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "size": 4,
            "rbp_offset": [],
            "addresses": [0x1004],
            "usage_features": {"call:named:sink:arg:0": 1},
        }
    ]
    return decompiled, ground_truth


@pytest.mark.parametrize(
    ("mode", "stage", "evidence"),
    [
        ("address", "overlap", "native"),
        ("usage", "usage", "fallback_only"),
        ("address+usage", "fused", "mixed"),
        ("auto", "fused", "mixed"),
    ],
)
def test_production_modes_report_accepted_evidence(
    mode: str,
    stage: str,
    evidence: str,
) -> None:
    decompiled, ground_truth = _address_and_usage_fixture()

    result = _metric(mode).compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )

    assert result.value == 1.0
    assert result.metadata["match_stage_counts"] == {stage: 1}
    assert result.metadata["variable_match_evidence"] == evidence
    assert result.metadata["variable_match_mode_requested"] == mode
    assert result.metadata["variable_match_mode"] == ("address+usage" if mode == "auto" else mode)


def test_match_selection_cannot_read_names_types_or_sizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import decbench.metrics.type_match as type_match_module

    ground_truth = [
        {
            "identity": "source:0",
            "name": "same_name_0",
            "type": ["int"],
            "size": 4,
            "rbp_offset": [],
            "addresses": [0x1004],
        },
        {
            "identity": "source:1",
            "name": "same_name_1",
            "type": ["char"],
            "size": 1,
            "rbp_offset": [],
            "addresses": [0x1008],
        },
    ]
    calls: list[tuple[tuple[tuple[str, str], ...], tuple[tuple[str, int | None], ...]]] = []
    real_match = type_match_module.match_variables

    def capture(
        source: list[VariableEvidence],
        decompiled: list[VariableEvidence],
        **kwargs: Any,
    ) -> Any:
        source_rows = list(source)
        decompiled_rows = list(decompiled)
        assert all(variable.name == "" and variable.size is None for variable in source_rows)
        assert all(variable.name == "" and variable.size is None for variable in decompiled_rows)
        matched = real_match(source_rows, decompiled_rows, **kwargs)
        pairs = tuple(sorted((match.source_id, match.decompiled_id) for match in matched.matches))
        shape = tuple((variable.name, variable.size) for variable in decompiled_rows)
        calls.append((pairs, shape))
        return matched

    monkeypatch.setattr(type_match_module, "match_variables", capture)

    correct = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="",
        variables=[
            VariableInfo(name="same_name_0", type="int", size=4, addresses=[0x1004]),
            VariableInfo(name="same_name_1", type="char", size=1, addresses=[0x1008]),
        ],
    )
    swapped = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="",
        variables=[
            VariableInfo(name="same_name_1", type="char", size=4096, addresses=[0x1004]),
            VariableInfo(name="same_name_0", type="int", size=8192, addresses=[0x1008]),
        ],
    )

    assert (
        _metric("address").compute_for_function(correct, ground_truth_vars=ground_truth).value
        == 1.0
    )
    assert (
        _metric("address").compute_for_function(swapped, ground_truth_vars=ground_truth).value
        == 0.0
    )
    assert calls[0][0] == calls[1][0]
    assert calls[0][1] == calls[1][1] == (("", None), ("", None))


def test_stacked_mode_routes_thresholds_by_available_channel() -> None:
    source_address = VariableEvidence("source", "", addresses=frozenset({1, 2, 3, 4}))
    decompiled_address = VariableEvidence("decompiled", "", addresses=frozenset({1}))
    address_only = match_variables(
        [source_address],
        [decompiled_address],
        mode="address+usage",
        min_overlap=0.3,
        min_combined_similarity=0.9,
    )
    assert [match.stage for match in address_only.matches] == ["address-only"]

    feature = (("call:named:sink:arg:0", 1),)
    source_usage = VariableEvidence("source", "", usage_features=feature)
    decompiled_usage = VariableEvidence("decompiled", "", usage_features=feature)
    usage_only = match_variables(
        [source_usage],
        [decompiled_usage],
        mode="address+usage",
        min_usage_similarity=0.3,
        min_combined_similarity=1.1,
    )
    assert [match.stage for match in usage_only.matches] == ["usage-fallback"]

    fused = match_variables(
        [
            VariableEvidence(
                "source", "", addresses=source_address.addresses, usage_features=feature
            )
        ],
        [
            VariableEvidence(
                "decompiled",
                "",
                addresses=decompiled_address.addresses,
                usage_features=feature,
            )
        ],
        mode="address+usage",
        min_overlap=0.3,
        min_usage_similarity=0.3,
        min_combined_similarity=0.8,
    )
    assert fused.matches == []


def test_stacked_mode_uses_its_own_ambiguity_margin() -> None:
    feature = (("call:named:sink:arg:0", 1),)
    source = VariableEvidence(
        "source",
        "",
        addresses=frozenset({1, 2}),
        usage_features=feature,
    )
    decompiled = [
        VariableEvidence("best", "", addresses=frozenset({1, 2}), usage_features=feature),
        VariableEvidence("runner_up", "", addresses=frozenset({1}), usage_features=feature),
    ]

    accepted = match_variables(
        [source],
        decompiled,
        mode="address+usage",
        ambiguity_margin=0.9,
        usage_ambiguity_margin=0.9,
        combined_ambiguity_margin=0.0,
    )
    rejected = match_variables(
        [source],
        decompiled,
        mode="address+usage",
        ambiguity_margin=0.0,
        usage_ambiguity_margin=0.0,
        combined_ambiguity_margin=0.3,
    )

    assert [(match.decompiled_id, match.stage) for match in accepted.matches] == [("best", "fused")]
    assert rejected.matches == []


def test_available_but_unused_usage_does_not_mark_an_anchor_mixed() -> None:
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(int renamed) { sink(renamed); return renamed; }",
        variables=[VariableInfo(name="renamed", type="int", kind="arg", arg_index=0)],
    )
    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "is_arg": True,
            "arg_index": 0,
            "rbp_offset": [],
            "usage_features": {"call:named:sink:arg:0": 1},
        }
    ]

    result = _metric("address+usage").compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )

    assert result.metadata["match_stage_counts"] == {"argument": 1}
    assert result.metadata["variable_match_evidence"] == "native"


def test_address_mode_keeps_code_inferred_argument_positions() -> None:
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(int renamed) { return renamed; }",
        variables=[],
    )
    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "is_arg": True,
            "arg_index": 0,
            "rbp_offset": [],
        }
    ]

    result = _metric("address").compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )

    assert result.value == 1.0
    assert result.metadata["match_stage_counts"] == {"argument": 1}
    assert result.metadata["variable_match_evidence"] == "native"


def test_no_accepted_pair_has_no_evidence_category() -> None:
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="",
        variables=[VariableInfo(name="same", type="int")],
    )
    ground_truth = [
        {
            "identity": "source:0",
            "name": "same",
            "type": ["int"],
            "rbp_offset": [],
        }
    ]

    result = _metric("auto").compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )

    assert result.value == 0.0
    assert result.metadata["match_stage_counts"] == {}
    assert "variable_match_evidence" not in result.metadata


def test_unobservable_source_variable_remains_in_denominator() -> None:
    decompiled, ground_truth = _address_and_usage_fixture()
    ground_truth.append(
        {
            "identity": "source:1",
            "name": "optimized_out",
            "type": ["char"],
            "rbp_offset": [],
        }
    )

    result = _metric("address").compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )

    assert result.value == 0.5
    assert result.metadata["tp"] == 1
    assert result.metadata["fn"] == 1
    assert result.metadata["unobservable_source_count"] == 1


def test_all_modes_keep_the_exact_ground_truth_denominator() -> None:
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code=(
            "int target(int renamed_arg) { int renamed_local = 0; "
            "consume(renamed_arg, renamed_local); return renamed_arg; }"
        ),
        variables=[
            VariableInfo(name="renamed_arg", type="int", kind="arg", arg_index=0),
            VariableInfo(name="renamed_local", type="char"),
        ],
    )
    ground_truth = [
        {
            "identity": "source:arg",
            "name": "original_arg",
            "type": ["int"],
            "is_arg": True,
            "arg_index": 0,
            "rbp_offset": [],
            "usage_features": {"call:named:consume:arg:0": 1},
        },
        {
            "identity": "source:local",
            "name": "original_local",
            "type": ["char"],
            "rbp_offset": [],
            "usage_features": {"call:named:consume:arg:1": 1},
        },
        {
            "identity": "source:hidden",
            "name": "hidden",
            "type": ["long long"],
            "rbp_offset": [],
        },
    ]

    results = {
        mode: _metric(mode).compute_for_function(decompiled, ground_truth_vars=ground_truth)
        for mode in ("address", "usage", "address+usage", "auto")
    }

    assert results["address"].value == pytest.approx(1 / 3)
    assert results["usage"].value == pytest.approx(2 / 3)
    assert results["address+usage"].value == pytest.approx(2 / 3)
    assert results["auto"].value == pytest.approx(2 / 3)
    for result in results.values():
        assert result.metadata["gt_vars"] == len(ground_truth)
        assert result.metadata["tp"] + result.metadata["fp"] + result.metadata["fn"] == len(
            ground_truth
        )


def test_source_context_supplies_usage_and_publishes_only_basename(tmp_path: Path) -> None:
    source_path = tmp_path / "program.i"
    source_path.write_text(
        "extern void sink(int);\n"
        "int target(void) { int original = 1; sink(original); return original; }\n"
    )
    context = PreprocessedSourceContext([source_path], "program")
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(void) { int renamed = 1; sink(renamed); return renamed; }",
        variables=[VariableInfo(name="renamed", type="int")],
    )
    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "rbp_offset": [],
        }
    ]

    result = _metric("usage").compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
        source_context=context,
    )

    assert result.value == 1.0
    assert result.metadata["source_file"] == "program.i"
    assert str(tmp_path) not in str(result.metadata)


def test_source_context_requires_exact_names_and_indexes_each_tu_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.metrics.type_evidence as evidence_module

    primary = tmp_path / "primary.i"
    unrelated = tmp_path / "unrelated.i"
    primary.write_text("int alpha(void) { return 1; }\n" "int beta(void) { return 2; }\n")
    unrelated.write_text("int gamma(void) { return 3; }\n")
    real_index = evidence_module.index_c_functions
    index_calls = 0

    def counting_index(code: str) -> dict[str, tuple[str, ...]]:
        nonlocal index_calls
        index_calls += 1
        return real_index(code)

    monkeypatch.setattr(evidence_module, "index_c_functions", counting_index)
    context = PreprocessedSourceContext([primary, unrelated], "program")

    alpha = context.select("alpha")
    beta = context.select("beta")
    missing = context.select("missing")

    assert alpha.path == primary.resolve()
    assert beta.path == primary.resolve()
    assert missing.path is None
    assert index_calls == 2
    assert PreprocessedSourceContext([unrelated], "program").select("alpha").path is None


def _dwarf_function_addresses_by_cu(binary: Path, function_name: str) -> dict[str, int]:
    from elftools.elf.elffile import ELFFile

    from decbench.metrics.variable_match import _die_ranges
    from decbench.utils.binfmt import die_str_attr

    addresses: dict[str, int] = {}
    with binary.open("rb") as stream:
        dwarfinfo = ELFFile(stream).get_dwarf_info()
        for cu in dwarfinfo.iter_CUs():
            cu_name = die_str_attr(cu.get_top_DIE(), "DW_AT_name")
            if not cu_name:
                continue
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                if die_str_attr(die, "DW_AT_name") != function_name:
                    continue
                ranges = _die_ranges(die, dwarfinfo)
                if ranges:
                    addresses[Path(cu_name).name] = ranges[0][0]
    return addresses


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is required")
def test_source_context_pins_duplicate_static_names_by_dwarf_cu(tmp_path: Path) -> None:
    left = tmp_path / "left.c"
    right = tmp_path / "right.c"
    left_i = tmp_path / "left.i"
    right_i = tmp_path / "right.i"
    left_o = tmp_path / "left.o"
    right_o = tmp_path / "right.o"
    binary = tmp_path / "tool"
    left.write_text(
        "static int duplicate(int value) { int left_local = value + 11; return left_local; }\n"
        "int right_call(int value);\n"
        "int main(void) { return duplicate(1) + right_call(2); }\n"
    )
    right.write_text(
        "static long duplicate(long value) { long right_local = value + 29; "
        "return right_local; }\n"
        "int right_call(int value) { return (int)duplicate(value); }\n"
    )
    for source, preprocessed, object_path in (
        (left, left_i, left_o),
        (right, right_i, right_o),
    ):
        subprocess.run(
            ["gcc", "-E", str(source), "-o", str(preprocessed)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["gcc", "-g", "-O0", "-fno-pie", "-c", str(source), "-o", str(object_path)],
            check=True,
            capture_output=True,
        )
    subprocess.run(
        ["gcc", "-no-pie", str(left_o), str(right_o), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    addresses = _dwarf_function_addresses_by_cu(binary, "duplicate")
    context = PreprocessedSourceContext([left_i, right_i], binary.name)

    assert context.select("duplicate").path is None
    selected_left = context.select(
        "duplicate",
        binary_path=binary,
        function_address=addresses["left.c"],
    )
    selected_right = context.select(
        "duplicate",
        binary_path=binary,
        function_address=addresses["right.c"],
    )

    assert selected_left.path == left_i.resolve()
    assert selected_right.path == right_i.resolve()
    assert "+ 11" in (selected_left.function_code or "")
    assert "+ 29" in (selected_right.function_code or "")
    ground_truth = extract_ground_truth_type_index(binary)
    left_argument = next(
        variable
        for variable in ground_truth[addresses["left.c"]]["duplicate"]
        if variable.get("is_arg")
    )
    right_argument = next(
        variable
        for variable in ground_truth[addresses["right.c"]]["duplicate"]
        if variable.get("is_arg")
    )
    assert "int" in left_argument["type"]
    assert "long long" in right_argument["type"]
    assert "duplicate" not in extract_ground_truth_types(binary)


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is required")
def test_source_context_reuses_binary_and_line_indexes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.metrics.type_evidence as evidence_module

    source = tmp_path / "unit.c"
    preprocessed = tmp_path / "unit.i"
    binary = tmp_path / "program"
    source.write_text(
        "int first(int value) { int local = value + 1; return local; }\n"
        "int second(int value) { int local = value + 2; return local; }\n"
        "int main(void) { return first(1) + second(2); }\n"
    )
    subprocess.run(
        ["gcc", "-E", str(source), "-o", str(preprocessed)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["gcc", "-g", "-O0", "-fno-pie", "-no-pie", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    addresses = {
        name: _dwarf_function_addresses_by_cu(binary, name)["unit.c"]
        for name in ("first", "second")
    }
    real_open = evidence_module.open_source_binary_context
    open_calls = 0

    def counting_open(path: Path) -> Any:
        nonlocal open_calls
        open_calls += 1
        return real_open(path)

    monkeypatch.setattr(evidence_module, "open_source_binary_context", counting_open)
    context = PreprocessedSourceContext([preprocessed], binary.name)
    first_selection = context.select(
        "first",
        binary_path=binary,
        function_address=addresses["first"],
    )
    second_selection = context.select(
        "second",
        binary_path=binary,
        function_address=addresses["second"],
    )
    assert first_selection.path == preprocessed.resolve()
    assert second_selection.path == preprocessed.resolve()

    source_lines = context.source_line_index(preprocessed)
    cached = extract_source_evidence(
        binary,
        preprocessed,
        "first",
        preprocessed_path=preprocessed,
        function_address=addresses["first"],
        source_lines=source_lines,
        binary_context=context.binary_context(binary),
    )
    direct = extract_source_evidence(
        binary,
        preprocessed,
        "first",
        preprocessed_path=preprocessed,
        function_address=addresses["first"],
    )

    assert cached.to_dict() == direct.to_dict()
    assert context.source_line_index(preprocessed) is source_lines
    assert open_calls == 1


@pytest.mark.skipif(shutil.which("g++") is None, reason="g++ is required")
def test_cxx_source_retains_native_addresses_but_abstains_from_usage(tmp_path: Path) -> None:
    source = tmp_path / "unit.cc"
    preprocessed = tmp_path / "unit.ii"
    binary = tmp_path / "program"
    source.write_text(
        "int target(int original) {\n"
        "    int local = original + 1;\n"
        "    return local;\n"
        "}\n"
        "int main(void) { return target(1); }\n"
    )
    subprocess.run(
        ["g++", "-E", str(source), "-o", str(preprocessed)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["g++", "-g", "-O0", "-fno-pie", "-no-pie", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    address = _dwarf_function_addresses_by_cu(binary, "target")["unit.cc"]
    ground_truth = extract_ground_truth_types(binary)["target"]

    result = build_source_evidence(
        binary,
        "target",
        address,
        ground_truth,
        PreprocessedSourceContext([preprocessed], binary.name),
    )

    assert result.source_path == preprocessed.resolve()
    assert result.native_address_variables > 0
    assert result.usage_variables == 0
    assert all(not variable.usage_features for variable in result.variables)


@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        ("selection", "source_select:RuntimeError"),
        ("usage", "usage:RuntimeError"),
    ],
)
def test_optional_source_failures_preserve_binary_denominator(
    failure: str,
    expected_error: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.metrics.type_evidence as evidence_module
    import decbench.metrics.type_match as type_match_module

    source = tmp_path / "program.i"
    source.write_text("int target(int original) { return original + 1; }\n")
    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "is_arg": True,
            "arg_index": 0,
            "rbp_offset": [],
        }
    ]
    if failure == "selection":

        def fail_selection(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("selection failed")

        monkeypatch.setattr(PreprocessedSourceContext, "select", fail_selection)
    else:

        def fail_usage(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("usage failed")

        monkeypatch.setattr(evidence_module, "analyze_c_function", fail_usage)
    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {0x1000: {"target": ground_truth}},
    )
    decompilation = DecompilationResult(
        binary_path=tmp_path / "program",
        binary_name="program",
        decompiler=DecompilerMetadata(decompiler_name="ghidra@12.1"),
        functions={
            "target": FunctionDecompilation(
                name="target",
                address=0x1000,
                decompiled_code="int target(int renamed) { return renamed + 1; }",
                variables=[VariableInfo(name="renamed", type="int", kind="arg", arg_index=0)],
            )
        },
    )

    result = _metric("auto").compute_for_binary(
        decompilation,
        preprocessed_sources=[source],
    )

    assert result.errors == []
    assert result.function_results["target"].value == 1.0
    assert result.function_results["target"].metadata["gt_vars"] == 1
    assert expected_error in result.function_results["target"].metadata["source_evidence_error"]


def test_binary_backend_policy_prevents_ghidra_name_derived_addresses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.metrics.type_match as type_match_module

    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "rbp_offset": [],
            "addresses": [0x1004],
        }
    ]
    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {0x1000: {"target": ground_truth}},
    )
    function = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(void) { int renamed = 1; return renamed; }",
        line_mappings=[LineMapping(line_number=1, addresses=[0x1004])],
        variables=[VariableInfo(name="renamed", type="int")],
    )

    def score(backend: str) -> Any:
        decompilation = DecompilationResult(
            binary_path=tmp_path / "program",
            binary_name="program",
            decompiler=DecompilerMetadata(decompiler_name=backend),
            functions={"target": function},
        )
        return _metric("address").compute_for_binary(decompilation).function_results["target"]

    ghidra = score("ghidra@12.1")
    generic = score("other")

    assert ghidra.value == 0.0
    assert ghidra.metadata["match_stage_counts"] == {}
    assert generic.value == 1.0
    assert generic.metadata["match_stage_counts"] == {"overlap": 1}


def test_binary_selects_ground_truth_by_function_address(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.metrics.type_match as type_match_module

    def argument(identity: str, type_name: str) -> dict[str, Any]:
        return {
            "identity": identity,
            "name": "original",
            "type": [type_name],
            "is_arg": True,
            "arg_index": 0,
            "rbp_offset": [],
        }

    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {
            0x1000: {"target": [argument("source:int", "int")]},
            0x2000: {"target": [argument("source:char", "char")]},
        },
    )
    decompilation = DecompilationResult(
        binary_path=tmp_path / "program",
        binary_name="program",
        decompiler=DecompilerMetadata(decompiler_name="ghidra@12.1"),
        functions={
            "target": FunctionDecompilation(
                name="target",
                address=0x1000,
                decompiled_code="int target(int renamed) { return renamed; }",
                variables=[VariableInfo(name="renamed", type="int", kind="arg", arg_index=0)],
            )
        },
    )

    result = _metric("address").compute_for_binary(decompilation)

    assert result.errors == []
    assert result.function_results["target"].value == 1.0
    assert result.function_results["target"].metadata["gt_vars"] == 1


def test_cache_key_covers_source_file_and_linemap_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from decbench import caching

    monkeypatch.delenv("DECBENCH_NO_CACHE", raising=False)
    monkeypatch.setenv("DECBENCH_CACHE_DIR", str(tmp_path / "cache"))
    caching._CACHES.clear()
    first_source = tmp_path / "first.i"
    second_source = tmp_path / "second.i"
    source_code = "int target(void) { int original = 1; return original; }\n"
    first_source.write_text(source_code)
    second_source.write_text(source_code)
    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "rbp_offset": [],
            "addresses": [0x1004],
        }
    ]
    without_linemap = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(void) { int renamed = 1; return renamed; }",
        variables=[VariableInfo(name="renamed", type="int", addresses=[0x1004])],
    )
    with_linemap = without_linemap.model_copy(
        update={"line_mappings": [LineMapping(line_number=99, addresses=[0xDEAD])]},
    )
    metric = _metric("address")
    try:
        first = metric.compute_for_function(
            without_linemap,
            ground_truth_vars=ground_truth,
            source_context=PreprocessedSourceContext([first_source], "program"),
        )
        second = metric.compute_for_function(
            with_linemap,
            ground_truth_vars=ground_truth,
            source_context=PreprocessedSourceContext([second_source], "program"),
        )
    finally:
        caching._CACHES.clear()

    assert first.metadata["source_file"] == "first.i"
    assert first.metadata["linemap_present"] is False
    assert second.metadata["source_file"] == "second.i"
    assert second.metadata["linemap_present"] is True


def test_matching_cache_payload_canonicalizes_evidence_order() -> None:
    unordered = VariableEvidence(
        "variable",
        "",
        addresses=frozenset({3, 1}),
        stack_offsets=(8, -4),
        usage_features=(("z", 1), ("a", 2)),
    )
    ordered = VariableEvidence(
        "variable",
        "",
        addresses=frozenset({1, 3}),
        stack_offsets=(-4, 8),
        usage_features=(("a", 2), ("z", 1)),
    )

    assert _matching_evidence_payload([unordered]) == _matching_evidence_payload([ordered])


def test_old_checkpoint_without_new_mapping_fields_uses_anchors() -> None:
    variable = VariableInfo(name="renamed", type="int", kind="arg", arg_index=0)
    variable.__dict__.pop("addresses")
    variable.__dict__.pop("line_numbers")
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(int renamed) { return renamed; }",
        variables=[variable],
    )
    decompiled.__dict__.pop("line_mappings")
    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "is_arg": True,
            "arg_index": 0,
            "rbp_offset": [],
        }
    ]

    result = _metric("auto").compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )

    assert result.value == 1.0
    assert result.metadata["linemap_present"] is False
    assert result.metadata["match_stage_counts"] == {"argument": 1}


def test_evaluation_pipeline_forwards_preprocessed_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.pipeline.evaluate as evaluate_module

    captured: dict[str, Any] = {}

    class CapturingMetric:
        requires_decompiled_cfg = False
        requires_source_cfg = False

        def compute_for_binary(self, decompilation: Any, **kwargs: Any) -> MetricResult:
            captured.update(kwargs)
            return MetricResult(
                metric_name="capture",
                decompiler_name=decompilation.decompiler.decompiler_name,
                binary_name=decompilation.binary_name,
            )

    metric = CapturingMetric()
    monkeypatch.setattr(
        evaluate_module.MetricRegistry,
        "get",
        classmethod(lambda cls, name, config=None: metric),
    )
    source_path = tmp_path / "program.i"
    decompilation = DecompilationResult(
        binary_path=tmp_path / "program",
        binary_name="program",
        decompiler=DecompilerMetadata(decompiler_name="test"),
    )

    evaluate_module.evaluate_decompilation(
        decompilation,
        metrics=["capture"],
        preprocessed_sources=[source_path],
    )

    assert captured["preprocessed_sources"] == [source_path]


def test_production_rejects_size_compatibility_policy() -> None:
    with pytest.raises(ValueError, match="cannot use variable sizes"):
        TypeMatchMetric(
            MetricConfig(extra_options={"variable_match_policy": {"use_size_compatibility": True}})
        )


@pytest.mark.parametrize("address_weight", [0.0, 1.0])
def test_production_rejects_degenerate_address_weights(address_weight: float) -> None:
    with pytest.raises(ValueError, match="strictly between 0 and 1"):
        TypeMatchMetric(
            MetricConfig(
                extra_options={"variable_match_policy": {"address_weight": address_weight}}
            )
        )
