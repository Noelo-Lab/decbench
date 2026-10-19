"""Bounded producer defects, explicit unknowns, and independent oracle populations."""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

import decbench.metrics.cpp_type_match as cpp_module
import decbench.utils.cfg_identity as cfg_module
import decbench.utils.producer_validation as validation_module
from decbench.metrics.base import MetricConfig
from decbench.metrics.cpp_type_graph import primitive_graph
from decbench.metrics.cpp_type_match import CppTypeMatchMetric
from decbench.metrics.cpp_types import UnsupportedType, parse_type
from decbench.metrics.variable_match import VariableEvidence
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    ProducerLanguageContract,
    VariableInfo,
)
from decbench.utils.producer_validation import inspect_producer


@pytest.mark.parametrize(
    "code,kind",
    [
        ("int f(){return ::0x1234::call();}", "numeric_qualified_identifier"),
        ("int f(){return :: 0x1234 :: call();}", "numeric_qualified_identifier"),
        (
            "int f(){int D; return [D] unsupported_Iop_ZeroHI64ofV128();}",
            "unsupported_ir_placeholder",
        ),
        ("int f(){int x; long x; return 0;}", "duplicate_local_binding"),
        ("int f(int x){long x;return 0;}", "duplicate_local_binding"),
        ("int f(int x,int x){return x;}", "duplicate_local_binding"),
        ("int f(){int a,b;char b[8];return 0;}", "duplicate_local_binding"),
        ("int f(){struct S *p;void *p;return 0;}", "duplicate_local_binding"),
    ],
)
def test_unambiguous_defects(code: str, kind: str) -> None:
    inspection = inspect_producer(code)
    assert inspection.invalid
    assert kind in {finding.kind for finding in inspection.findings}
    assert inspection.evidence()["validity"] == "invalid_source_output"


@pytest.mark.parametrize(
    "code",
    [
        "int f(int x){{int x;}return x;}",
        "int f(){ {int x;} {int x;} return 0;}",
        "int f(){int g(int);int g(int);return 0;}",
        "int f(){extern int x;extern int x;return 0;}",
        "int f(){typedef int T;typedef int T;return 0;}",
        "struct S {int x;int f(int x){return x;}};",
        "int f(){int a,b; a*b; a*b; return 0;}",
        "int f(){return 0;} int g(){int x;return 0;}",
        'const char *f(){return "::0x1234::call() [D] unsupported_Iop_bad()";}',
        'const char *f(){return R"tag(::0x1234::call() [D] unsupported_Iop_bad())tag";}',
        "int f(){/* ::0x1234::bad() */ return 0;}",
        "#define EXAMPLE ::0x1234::bad()\nint f(){return 0;}",
        "int f(){Foo *p;Foo *p;return 0;}",
        "int f(){for(int x=0;x<1;++x){int y;}return 0;}",
    ],
)
def test_clean_bounded_inspection_does_not_claim_validity(code: str) -> None:
    inspection = inspect_producer(code)
    assert not inspection.invalid, inspection.findings
    assert inspection.evidence()["validity"] == "not_established"


def test_byte_coordinates_and_immutable_contract() -> None:
    code = "int f(){ /* 한글 */ int x;\nlong x; return 0;}"
    metadata = {
        "output_contract": ProducerLanguageContract(
            surface="c-like-pseudocode", declarations="partial", dialect="fixture"
        ).model_dump()
    }
    before = copy.deepcopy(metadata)
    result = inspect_producer(code, metadata)
    finding = result.findings[0]
    assert (finding.line, finding.column, finding.previous_line) == (2, 6, 1)
    assert metadata == before
    assert result.contract.dialect == "fixture"
    assert inspect_producer("int f(){return 0;}").contract.surface == "unknown"


def test_contract_complete_is_an_assertion_not_a_validity_certificate() -> None:
    result = inspect_producer(
        "int f(){return 0;}", {"output_contract": {"surface": "cpp", "declarations": "complete"}}
    )
    assert result.evidence()["validity"] == "not_established"


@pytest.mark.parametrize(
    "payload", [{"surface": "invented"}, {"version": "wrong"}, {"extra": True}]
)
def test_invalid_contracts_are_not_silently_recovered(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        inspect_producer("int f(){return 0;}", {"output_contract": payload})


def _result(code: str) -> DecompilationResult:
    result = DecompilationResult(
        binary_path=Path("unused"),
        binary_name="input",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    result.add_function(FunctionDecompilation(name="f", address=16, decompiled_code=code))
    return result


def test_invalid_producer_never_reaches_cfg_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _result("int f(){int x;long x;return 0;}")
    before = result.model_dump()

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("invalid producer must not reach CFG construction")

    monkeypatch.setattr(cfg_module, "parse_definitions", forbidden)
    joined = cfg_module.decompiled_cfgs(result)
    assert not joined.cfgs
    assert joined.evidence["f"]["status"] == "invalid_producer_output"
    assert result.model_dump() == before


def test_frontend_rejection_is_not_proof_of_invalid_cpp(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise cfg_module.CfgParseError("unsupported known syntax")

    monkeypatch.setattr(cfg_module, "parse_definitions", fail)
    result = cfg_module.decompiled_cfgs(_result("int f(int x){return x;}"))
    assert result.evidence["f"]["failure_class"] == "frontend_rejected_recognized_syntax"
    assert result.evidence["f"]["validation"]["validity"] == "not_established"


def test_inspection_fault_is_not_a_producer_or_oracle_exclusion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("inspection infrastructure fault")

    monkeypatch.setattr(validation_module, "_parse_source", fail)
    with pytest.raises(ValueError, match="infrastructure"):
        cfg_module.decompiled_cfgs(_result("int f(){return 0;}"))


def test_invalid_recovery_scores_zero_without_shrinking_oracle_population(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    metric = CppTypeMatchMetric(
        MetricConfig(use_cache=False, extra_options={"view": "source", "data_model": "LP64"})
    )
    result = _result("int f(int x){long x;return 0;}")
    result.binary_path = tmp_path / "unused"
    result.functions["f"].variables = [VariableInfo(name="x", type="int", kind="arg", arg_index=0)]
    gt = [{"identity": "source:0", "descriptor": primitive_graph(parse_type("int", "LP64"))}]
    oracle = SimpleNamespace(
        validate=lambda path: None,
        native=None,
        info=SimpleNamespace(arch="x86_64"),
        dwarf=object(),
        pdb=None,
        index={},
    )
    monkeypatch.setattr(cpp_module, "sanitize_native_provenance", lambda *a, **kw: {})
    monkeypatch.setattr(metric, "_dwarf_rows", lambda *a: gt)
    monkeypatch.setattr(
        cpp_module,
        "build_source_evidence",
        lambda *a: SimpleNamespace(variables=[VariableEvidence("source:0", arg_index=0)]),
    )
    scored = metric.compute_for_binary(
        result, oracle_context=oracle, requested_functions=[("f", 16)]
    )
    assert len(scored.function_results) == 1
    assert not scored.errors
    value = scored.function_results["f"]
    assert value.value == 0.0
    assert value.metadata["ground_truth_count"] == 1
    assert value.metadata["producer_failure"] == "invalid_producer_output"

    def unsupported(*args: Any) -> Any:
        raise UnsupportedType("unqualified oracle")

    monkeypatch.setattr(metric, "_dwarf_rows", unsupported)
    excluded = metric.compute_for_binary(result, oracle_context=oracle)
    assert not excluded.function_results
    assert excluded.errors == ["f: unqualified oracle"]
