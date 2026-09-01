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
    extract_decompiler_evidence,
    extract_source_evidence,
)
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
    VariableOccurrencePolicy,
    with_variable_occurrence_policy,
)
from decbench.models.metrics import MetricResult


@pytest.fixture(autouse=True)
def _disable_metric_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECBENCH_NO_CACHE", "1")


def _metric() -> TypeMatchMetric:
    return TypeMatchMetric(MetricConfig())


def _address_fixture() -> tuple[FunctionDecompilation, list[dict[str, Any]]]:
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
        }
    ]
    return decompiled, ground_truth


def test_address_correspondence_reports_accepted_evidence() -> None:
    decompiled, ground_truth = _address_fixture()

    result = _metric().compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )

    assert result.value == 1.0
    assert result.metadata["match_stage_counts"] == {"overlap": 1}
    assert result.metadata["variable_match_evidence"] == "native"


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

    assert _metric().compute_for_function(correct, ground_truth_vars=ground_truth).value == 1.0
    assert _metric().compute_for_function(swapped, ground_truth_vars=ground_truth).value == 0.0
    assert calls[0][0] == calls[1][0]
    assert calls[0][1] == calls[1][1] == (("", None), ("", None))


def test_anchor_only_correspondence_reports_native_evidence() -> None:
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
        }
    ]

    result = _metric().compute_for_function(
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

    result = _metric().compute_for_function(
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

    result = _metric().compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )

    assert result.value == 0.0
    assert result.metadata["match_stage_counts"] == {}
    assert "variable_match_evidence" not in result.metadata


def test_unobservable_source_variable_remains_in_denominator() -> None:
    decompiled, ground_truth = _address_fixture()
    ground_truth.append(
        {
            "identity": "source:1",
            "name": "optimized_out",
            "type": ["char"],
            "rbp_offset": [],
        }
    )

    result = _metric().compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
    )

    assert result.value == 0.5
    assert result.metadata["tp"] == 1
    assert result.metadata["fn"] == 1
    assert result.metadata["unobservable_source_count"] == 1


def test_correspondence_keeps_the_exact_ground_truth_denominator() -> None:
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
        },
        {
            "identity": "source:local",
            "name": "original_local",
            "type": ["char"],
            "rbp_offset": [],
        },
        {
            "identity": "source:hidden",
            "name": "hidden",
            "type": ["long long"],
            "rbp_offset": [],
        },
    ]

    result = _metric().compute_for_function(decompiled, ground_truth_vars=ground_truth)

    assert result.value == pytest.approx(1 / 3)
    assert result.metadata["gt_vars"] == len(ground_truth)
    assert result.metadata["tp"] + result.metadata["fp"] + result.metadata["fn"] == len(
        ground_truth
    )


def test_source_context_publishes_only_the_basename(tmp_path: Path) -> None:
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

    result = _metric().compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
        source_context=context,
    )

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


def test_optional_source_failures_preserve_binary_denominator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
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

    def fail_selection(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("selection failed")

    monkeypatch.setattr(PreprocessedSourceContext, "select", fail_selection)
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
                variables=[
                    VariableInfo(
                        name="renamed",
                        type="int",
                        kind="arg",
                        arg_index=0,
                        addresses=[0x1004],
                    )
                ],
            )
        },
    )

    result = _metric().compute_for_binary(
        decompilation,
        preprocessed_sources=[source],
    )

    assert result.errors == []
    assert result.function_results["target"].value == 1.0
    assert result.function_results["target"].metadata["gt_vars"] == 1
    assert (
        "source_select:RuntimeError"
        in result.function_results["target"].metadata["source_evidence_error"]
    )


def test_structured_occurrence_policy_prevents_name_derived_addresses(
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

    # A sibling function supplies the producer's address provenance, so ``target`` is
    # scored by the address correspondence with a genuinely empty occurrence field.
    addressed = FunctionDecompilation(
        name="other",
        address=0x2000,
        decompiled_code="int other(void) { int kept = 1; return kept; }",
        variables=[VariableInfo(name="kept", type="int", addresses=[0x2004])],
    )

    def score(backend: str) -> Any:
        decompilation = DecompilationResult(
            binary_path=tmp_path / "program",
            binary_name="program",
            decompiler=DecompilerMetadata(decompiler_name=backend),
            functions={"target": function, "other": addressed},
        )
        return _metric().compute_for_binary(decompilation).function_results["target"]

    ghidra = score("ghidra@12.1")
    legacy = score("other")

    assert ghidra.value == 0.0
    assert ghidra.metadata["match_stage_counts"] == {}
    assert ghidra.metadata["producer_variable_occurrence_policy"] == "undeclared"
    assert ghidra.metadata["structured_occurrence_mode"] == "producer"
    assert ghidra.metadata["correspondence"] == "address"
    assert legacy.value == 0.0
    assert legacy.metadata["match_stage_counts"] == {}
    assert legacy.metadata["correspondence"] == "address"


@pytest.mark.parametrize(
    ("backend", "policy"),
    [
        ("angr", "exact"),
        ("binja", "exact"),
        ("ghidra", "exact"),
        ("ida", "exact"),
        ("kuna", "exact"),
        ("retdec", "exact"),
        ("r2dec", "exact"),
        ("dewolf", "direct"),
        ("reko", "direct"),
        ("glaurung", "unavailable"),
        ("manifold", "unavailable"),
        ("angr-declib", "exact"),
        ("ghidra-declib", "exact"),
        ("ida-declib", "exact"),
        ("binja-declib", "unavailable"),
    ],
)
def test_empty_structured_occurrences_fail_closed_for_every_producer(
    backend: str,
    policy: VariableOccurrencePolicy,
) -> None:
    function = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code=(
            "int target(void) {\n"
            "    int shadow = 0;\n"
            "    { int shadow = 1; shadow++; }\n"
            "    return shadow;\n"
            "}\n"
        ),
        line_mappings=[
            LineMapping(line_number=2, addresses=[0x1004]),
            LineMapping(line_number=3, addresses=[0x1008]),
            LineMapping(line_number=4, addresses=[0x100C]),
        ],
        variables=[VariableInfo(name="shadow", type="int")],
        metadata=with_variable_occurrence_policy({}, policy),
    )

    evidence = extract_decompiler_evidence(function, backend=backend)
    experimental = extract_decompiler_evidence(
        function,
        backend=backend,
        structured_occurrence_mode="experimental_legacy_regex",
    )

    assert evidence.variables[0].lines == ()
    assert evidence.variables[0].addresses == frozenset()
    assert experimental.variables[0].lines == (2, 3, 4)
    assert experimental.variables[0].addresses == frozenset({0x1004, 0x1008, 0x100C})


def test_structured_occurrence_mode_rejects_implicit_legacy_aliases() -> None:
    function = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(void) { return 0; }",
    )

    with pytest.raises(ValueError, match="structured_occurrence_mode"):
        extract_decompiler_evidence(
            function,
            backend="legacy",
            structured_occurrence_mode="legacy",  # type: ignore[arg-type]
        )


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

    result = _metric().compute_for_binary(decompilation)

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
    metric = _metric()
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
    )
    ordered = VariableEvidence(
        "variable",
        "",
        addresses=frozenset({1, 3}),
        stack_offsets=(-4, 8),
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

    result = _metric().compute_for_function(
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


def test_unsupported_binary_format_falls_back_to_anchors(tmp_path: Path) -> None:
    """A binary the format detector cannot read must degrade, not abort.

    Native address evidence is optional: ABI argument positions and stack offsets
    remain valid correspondence, so an unreadable binary is recorded as an error
    on the result and the source evidence is still returned.
    """
    from decbench.metrics.variable_match import open_source_binary_context

    source = tmp_path / "unit.i"
    source.write_text("int target(int original) { return original + 1; }\n")
    not_a_binary = tmp_path / "program"
    not_a_binary.write_text("this is not an ELF or PE file\n")

    with pytest.raises(ValueError, match="unsupported binary format"):
        open_source_binary_context(not_a_binary)

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

    result = build_source_evidence(
        not_a_binary,
        "target",
        0x1000,
        ground_truth,
        PreprocessedSourceContext([source], not_a_binary.name),
    )

    assert result.error is not None and "native:" in result.error, result.error
    assert len(result.variables) == 1


def _named_only_decompilation(tmp_path: Path, backend: str) -> DecompilationResult:
    """A producer that ships names and a frame-offset name, but no address provenance."""

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


def test_producer_without_address_provenance_scores_by_legacy_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.metrics.type_match as type_match_module

    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {0x1000: {"target": _named_only_ground_truth()}},
    )

    result = _metric().compute_for_binary(_named_only_decompilation(tmp_path, "glaurung"))
    value = result.function_results["target"]

    assert value.value == 1.0
    assert value.metadata["correspondence"] == "legacy_name"
    assert value.metadata["matched_by_name"] == 1
    assert value.metadata["matched_by_offset"] == 1


def test_legacy_scored_rows_carry_the_asterisk_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import decbench.metrics.type_match as type_match_module
    from decbench.scoring.function_data_builder import _metric_evidence_for
    from decbench.scoring.typematch_ab import ScoreEntry, _evidence_summary

    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {0x1000: {"target": _named_only_ground_truth()}},
    )

    result = _metric().compute_for_binary(_named_only_decompilation(tmp_path, "glaurung"))
    value = result.function_results["target"]

    assert value.metadata["variable_match_evidence"] == "fallback_only"
    assert value.metadata["producer_variable_occurrence_policy"] == "undeclared"
    assert value.metadata["linemap_present"] is False
    assert value.metadata["decompiler_address_variables"] == 0
    assert _metric_evidence_for("type_match", value) == "fallback_only"

    key = ("proj", "O0", "program", "target")
    entry = ScoreEntry(value.value, "fallback_only", "undeclared", "producer")
    summary = _evidence_summary([("glaurung", key, entry)], {})
    assert summary["site_caveated"] == 1
    assert summary["asterisk_recommended"] is True


def test_address_capable_producer_never_matches_by_exact_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The same names, with address provenance present, must not match by name."""

    import decbench.metrics.type_match as type_match_module

    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {0x1000: {"target": _named_only_ground_truth()}},
    )
    decompilation = _named_only_decompilation(tmp_path, "ghidra@12.1")
    decompilation.functions["other"] = FunctionDecompilation(
        name="other",
        address=0x2000,
        decompiled_code="int other(void) { int kept = 1; return kept; }",
        variables=[VariableInfo(name="kept", type="int", addresses=[0x2004])],
    )

    value = _metric().compute_for_binary(decompilation).function_results["target"]

    assert value.metadata["correspondence"] == "address"
    assert value.metadata["matched_by_name"] == 0
    assert value.metadata.get("variable_match_evidence") != "fallback_only"
    assert value.value < 1.0


def test_address_provenance_is_resolved_per_producer_not_per_function(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """One addressless function inside an address-capable producer stays on the address path."""

    import decbench.metrics.type_match as type_match_module

    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {
            0x1000: {"target": _named_only_ground_truth()},
            0x2000: {"other": _named_only_ground_truth()},
        },
    )
    decompilation = _named_only_decompilation(tmp_path, "ida")
    decompilation.functions["other"] = FunctionDecompilation(
        name="other",
        address=0x2000,
        decompiled_code="int other(void) { int original; return 0; }",
        variables=[VariableInfo(name="original", type="int", addresses=[0x2004])],
    )

    results = _metric().compute_for_binary(decompilation).function_results

    assert results["target"].metadata["correspondence"] == "address"
    assert results["other"].metadata["correspondence"] == "address"


def test_undeclared_callers_keep_the_address_correspondence() -> None:
    decompiled = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="",
        variables=[VariableInfo(name="same", type="int")],
    )
    ground_truth = [{"identity": "source:0", "name": "same", "type": ["int"], "rbp_offset": []}]

    undeclared = _metric().compute_for_function(decompiled, ground_truth_vars=ground_truth)
    declared = _metric().compute_for_function(
        decompiled,
        ground_truth_vars=ground_truth,
        address_provenance=False,
    )

    assert undeclared.value == 0.0
    assert undeclared.metadata["correspondence"] == "address"
    assert declared.value == 1.0
    assert declared.metadata["correspondence"] == "legacy_name"


def test_legacy_correspondence_is_declared_per_backend_not_measured() -> None:
    """Only declared address-incapable backends take the legacy name correspondence."""

    from decbench.metrics.type_match import uses_legacy_correspondence

    for name in ("glaurung", "manifold", "claude-code", "codex", "fission", "ventris"):
        assert uses_legacy_correspondence(name) is True, name
    for name in ("ida", "ghidra", "binja", "angr", "kuna", "r2dec", "dewolf", "reko", "retdec"):
        assert uses_legacy_correspondence(name) is False, name

    assert uses_legacy_correspondence("glaurung@0.3") is True
    assert uses_legacy_correspondence("ghidra@12.1") is False
    assert uses_legacy_correspondence(None) is False
    assert uses_legacy_correspondence("some-new-submission") is False


def test_address_backend_without_stored_provenance_keeps_the_address_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A provenance-less checkpoint must NOT move a published column onto name matching.

    Regression test. The canonical results/full_run checkpoints store line mappings
    without per-variable addresses for every backend, IDA and Ghidra included.Selecting
    the correspondence by probing the data would silently flip the entire published
    leaderboard onto exact-name matching and caveat every row.
    """
    import decbench.metrics.type_match as type_match_module

    ground_truth = [
        {
            "identity": "source:0",
            "name": "original",
            "type": ["int"],
            "is_arg": False,
            "rbp_offset": [],
        }
    ]
    monkeypatch.setattr(
        type_match_module,
        "extract_ground_truth_type_index",
        lambda path: {0x1000: {"target": ground_truth}},
    )

    def result_for(decompiler: str) -> Any:
        return DecompilationResult(
            binary_path=tmp_path / "program",
            binary_name="program",
            decompiler=DecompilerMetadata(decompiler_name=decompiler),
            functions={
                "target": FunctionDecompilation(
                    name="target",
                    address=0x1000,
                    decompiled_code="int target(void) { int original = 1; return original; }",
                    variables=[VariableInfo(name="original", type="int", kind="local")],
                )
            },
        )

    addressed = _metric().compute_for_binary(result_for("ghidra@12.1"))
    legacy = _metric().compute_for_binary(result_for("glaurung"))

    assert addressed.function_results["target"].metadata["correspondence"] == "address"
    assert legacy.function_results["target"].metadata["correspondence"] == "legacy_name"
