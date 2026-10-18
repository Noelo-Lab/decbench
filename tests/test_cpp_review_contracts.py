"""Evaluator failures, unambiguous scoped provenance and executable transport."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import decbench.metrics.cpp_type_match as cpp_metric
from decbench.decompilers.raw.fission_raw import RawFissionDecompiler
from decbench.metrics.base import MetricConfig
from decbench.metrics.cpp_type_match import CppTypeMatchMetric
from decbench.metrics.cpp_types import UnsupportedType
from decbench.metrics.variable_match import VariableEvidence, extract_decompiler_evidence
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)


def _evaluation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[CppTypeMatchMetric, DecompilationResult, Any, list[bool]]:
    metric = CppTypeMatchMetric(
        MetricConfig(use_cache=False, extra_options={"view": "source", "data_model": "LP64"})
    )
    result = DecompilationResult(
        binary_path=tmp_path / "input",
        binary_name="input",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    result.add_function(
        FunctionDecompilation(
            name="f",
            address=0x1000,
            decompiled_code="int f(int x){return x;}",
            variables=[VariableInfo(name="x", type="int", kind="arg", arg_index=0)],
        )
    )
    oracle = SimpleNamespace(
        validate=lambda path: None,
        native=None,
        info=SimpleNamespace(arch="x86_64"),
        dwarf=object(),
        pdb=None,
        index={},
    )
    monkeypatch.setattr(cpp_metric, "sanitize_native_provenance", lambda *a, **kw: {})
    monkeypatch.setattr(metric, "_dwarf_rows", lambda *a: [{"identity": "source:0"}])
    monkeypatch.setattr(
        cpp_metric,
        "build_source_evidence",
        lambda *a: SimpleNamespace(variables=[VariableEvidence("source:0", arg_index=0)]),
    )
    closed: list[bool] = []
    original_close = cpp_metric.PreprocessedSourceContext.close

    def close(context: Any) -> None:
        closed.append(True)
        original_close(context)

    monkeypatch.setattr(cpp_metric.PreprocessedSourceContext, "close", close)
    return metric, result, oracle, closed


@pytest.mark.parametrize("stage", ["oracle", "source", "recovery"])
def test_unexpected_evaluator_value_error_is_not_oracle_abstention(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stage: str
) -> None:
    metric, result, oracle, closed = _evaluation(monkeypatch, tmp_path)

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("unexpected evaluator fault")

    if stage == "oracle":
        monkeypatch.setattr(metric, "_dwarf_rows", fail)
    elif stage == "source":
        monkeypatch.setattr(cpp_metric, "build_source_evidence", fail)
    else:
        monkeypatch.setattr(metric, "compute_for_function", fail)
    with pytest.raises(ValueError, match="unexpected evaluator fault"):
        metric.compute_for_binary(result, oracle_context=oracle)
    assert closed == [True]
    assert result.functions["f"].decompiled_code == "int f(int x){return x;}"


def test_unsupported_oracle_abstains_but_unsupported_recovery_does_not_exclude(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    metric, result, oracle, closed = _evaluation(monkeypatch, tmp_path)

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise UnsupportedType("known unsupported representation")

    monkeypatch.setattr(metric, "_dwarf_rows", fail)
    excluded = metric.compute_for_binary(result, oracle_context=oracle)
    assert excluded.function_results == {}
    assert excluded.errors == ["f: known unsupported representation"]
    monkeypatch.setattr(metric, "_dwarf_rows", lambda *a: [{"identity": "source:0"}])
    monkeypatch.setattr(metric, "compute_for_function", fail)
    with pytest.raises(UnsupportedType, match="known unsupported representation"):
        metric.compute_for_binary(result, oracle_context=oracle)
    assert closed == [True, True]


def test_known_pdb_format_limit_is_typed_oracle_abstention(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from decbench.utils.pdb_info import PdbFormatError, _Types

    metric, result, oracle, closed = _evaluation(monkeypatch, tmp_path)
    types = _Types(b"")
    types.records = {0x1000: (0x1203, b"\x04\x14\x00\x00\x00\x10\x00\x00")}
    with pytest.raises(PdbFormatError, match="cyclic"):
        types.field_records(0x1000)

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise PdbFormatError("unsupported CodeView field leaf")

    monkeypatch.setattr(metric, "_dwarf_rows", fail)
    excluded = metric.compute_for_binary(result, oracle_context=oracle)
    assert excluded.function_results == {}
    assert excluded.errors == ["f: unsupported CodeView field leaf"]
    assert closed == [True]


def _scoped_record() -> dict[str, Any]:
    return {
        "code_nir": "int f() {\n int x = 0;\n { int x = 1; }\n return y;\n}",
        "variables": [
            {"name": "x", "type": "int"},
            {"name": "x", "type": "int"},
            {"name": "y", "type": "int"},
        ],
        "line_mappings_nir": [
            {"line_number": 2, "addresses": [0x1000], "defined_variables": ["x", "y"]},
            {"line_number": 3, "addresses": [0x1004], "defined_variables": ["x"]},
        ],
    }


def test_adapter_does_not_bind_duplicate_display_names_to_scoped_lines() -> None:
    record = _scoped_record()
    record["variables"][0]["addresses"] = [0x1008]
    function = RawFissionDecompiler._build_function(record, "f", 0x1000)
    assert function is not None
    assert [v.line_numbers for v in function.variables] == [[], [], [2]]
    rows = extract_decompiler_evidence(function, backend="test")
    assert [r.addresses for r in rows] == [frozenset({0x1008}), frozenset(), frozenset({0x1000})]


def test_shared_matcher_rejects_ambiguous_scope_even_with_claimed_occurrences() -> None:
    function = RawFissionDecompiler._build_function(_scoped_record(), "f", 0x1000)
    assert function is not None
    for variable in function.variables:
        variable.line_numbers = [2, 3]
    rows = extract_decompiler_evidence(function, backend="other-producer")
    assert [r.addresses for r in rows] == [frozenset(), frozenset(), frozenset({0x1000})]
    function.line_mappings = [LineMapping(line_number=2, addresses=[0x100C])]
    assert all(
        r.addresses == frozenset({0x100C})
        for r in extract_decompiler_evidence(function, backend="legacy")
    )


def test_unnamed_variable_cannot_gain_scoped_name_evidence() -> None:
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(){return 0;}",
        variables=[VariableInfo(name="", line_numbers=[1])],
        line_mappings=[LineMapping(line_number=1, addresses=[0x1000], defined_variables=[""])],
    )
    assert not extract_decompiler_evidence(function, backend="test", include_unnamed=True)[
        0
    ].addresses


def test_relative_fission_executable_survives_changed_child_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import decbench.decompilers.raw.fission_raw as fission

    caller, worker = tmp_path / "caller directory", tmp_path / "worker directory"
    caller.mkdir()
    worker.mkdir()
    executable = caller / "fixture CLI"
    payload = [{"address": "0x1000", "code_nir": "int f(){return 0;}", "variables": []}]
    executable.write_text(
        f"#!{sys.executable}\nimport json,sys\n"
        "if '--version' in sys.argv: print('fixture version')\n"
        f"else: print({json.dumps(payload)!r})\n"
    )
    executable.chmod(0o755)
    binary = caller / "input.bin"
    binary.write_bytes(b"not executed")
    monkeypatch.chdir(caller)
    monkeypatch.setenv("FISSION_BIN", executable.name)
    monkeypatch.setenv("FISSION_WORKING_DIR", str(worker))
    monkeypatch.delenv("FISSION_RESOURCE_ROOT", raising=False)
    monkeypatch.setattr(fission, "sanitize_native_provenance", lambda *a, **kw: {})
    adapter = RawFissionDecompiler()
    assert adapter._binary() == str(executable.resolve())
    result = adapter.decompile_binary(binary, functions=[("f", 0x1000)])
    assert result.decompiler.decompiler_version == "fixture version"
    assert result.functions["f"].decompiled_code == payload[0]["code_nir"]


def test_relative_path_lookup_is_also_frozen_before_child_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    executable = tmp_path / "bin" / "fission_cli"
    executable.parent.mkdir()
    executable.touch()
    executable.chmod(0o755)
    monkeypatch.delenv("FISSION_BIN", raising=False)
    monkeypatch.setenv("PATH", "bin")
    assert RawFissionDecompiler._binary() == str(executable.resolve())


@pytest.mark.parametrize("with_plan", [False, True])
def test_cpp_type_population_rejects_duplicate_producer_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, with_plan: bool
) -> None:
    from decbench.models.metrics import MetricValue

    metric, result, oracle, _closed = _evaluation(monkeypatch, tmp_path)
    result.add_function(
        FunctionDecompilation(
            name="alias", address=0x1000, decompiled_code="int alias(){return 1;}"
        )
    )
    monkeypatch.setattr(metric, "compute_for_function", lambda *a, **kw: MetricValue(value=1.0))
    kwargs: dict[str, Any] = {"oracle_context": oracle}
    if with_plan:
        kwargs["requested_functions"] = [("f", 0x1000)]
    with pytest.raises(ValueError, match="ambiguous producer records at one requested address"):
        metric.compute_for_binary(result, **kwargs)
    assert list(result.functions) == ["f", "alias"]


def test_cpp_type_population_filters_extras_and_retains_empty_recovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from decbench.models.metrics import MetricValue

    metric, result, oracle, _closed = _evaluation(monkeypatch, tmp_path)
    for name in ["extra", "extra_alias"]:
        result.add_function(
            FunctionDecompilation(
                name=name, address=0x2000, decompiled_code="int extra(){return 0;}"
            )
        )
    monkeypatch.setattr(
        metric,
        "compute_for_function",
        lambda f, **kw: MetricValue(value=float(bool(f.decompiled_code))),
    )
    scored = metric.compute_for_binary(
        result, oracle_context=oracle, requested_functions=[("f", 0x1000), ("missing", 0x3000)]
    )
    assert set(scored.function_results) == {"f", "missing"}
    assert scored.function_results["missing"].value == 0.0
    assert len(result.functions) == 3


@pytest.mark.parametrize("suffix", ["&", "&&"])
def test_valid_cpp_reference_declarator_selects_error_free_ast(suffix: str) -> None:
    from decbench.metrics.variable_features import (
        _CPP_LANGUAGE,
        _parse_source,
        function_parameters,
        variable_occurrence_lines,
    )

    code = f"int f(int{suffix} x) {{\n return x;\n}}\n"
    tree = _parse_source(code.encode())
    assert not tree.root_node.has_error
    assert tree.language == _CPP_LANGUAGE
    assert function_parameters(code, "f") == f"int{suffix} x"
    assert variable_occurrence_lines(code, "f", ["x"]) == {"x": (1, 2)}


def test_valid_c_ast_keeps_c_grammar() -> None:
    from decbench.metrics.variable_features import _C_LANGUAGE, _parse_source

    tree = _parse_source(b"int f(int *restrict p) { return *p; }")
    assert not tree.root_node.has_error
    assert tree.language == _C_LANGUAGE
