"""Focused tests for production type-blind variable correspondence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from decbench.metrics.base import MetricConfig
from decbench.metrics.type_evidence import PreprocessedSourceContext
from decbench.metrics.type_match import TypeMatchMetric
from decbench.metrics.variable_match import VariableEvidence, match_variables
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
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
