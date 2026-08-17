from __future__ import annotations

from typing import Any

from decbench.experimental.local_variable_distance import FunctionEvidence, VariableEvidence
from decbench.metrics.variable_match import VariableMatch
from scripts.evaluate_local_variable_matchers import (
    EvidencePair,
    ModeConfig,
    _decisions,
    _edge_metrics,
    _feature_coverage,
    _paired_deltas,
    _production_policy,
    _replace_private_decisions,
    _unlabeled_source_cases,
    _validate_audit_binding,
)


def _joined_row(sample: str, classification: str) -> dict[str, Any]:
    return {
        "audit_sample_id": sample,
        "backend_status": "ok",
        "oracle": {
            "status": "mapped",
            "ambiguous_alias_selection": False,
            "selected_decompiled_audit_ids": ["dv_expected"],
        },
        "matcher": {
            "accepted": [{"classification": classification}],
        },
    }


def test_edge_metrics_use_candidate_confusion_denominators() -> None:
    metrics = _edge_metrics([(3, 1, 2), (1, 0, 1)])

    assert metrics == {
        "precision": 4 / 5,
        "edge_recall": 4 / 7,
        "edge_f1": 8 / 12,
    }


def test_paired_deltas_compare_the_same_source_function_clusters() -> None:
    address = [
        _joined_row("sample_a", "correct"),
        _joined_row("sample_b", "incorrect"),
    ]
    fused = [
        _joined_row("sample_a", "correct"),
        _joined_row("sample_b", "correct"),
    ]

    result = _paired_deltas(
        {"address": address, "address+usage": fused},
        bootstrap_iterations=20,
    )
    comparison = result["by_scope"]["overall"]["comparisons"]["address+usage_minus_address"]

    assert comparison["precision"]["value"] == 0.5
    assert comparison["edge_recall"]["value"] == 0.5
    assert comparison["edge_f1"]["value"] == 0.5
    assert comparison["edge_f1"]["paired_clustered_bootstrap_ci95"] is not None


def test_full_production_universe_competes_before_frozen_label_join() -> None:
    shared = (("call:named:consume:arg:0", 1),)
    source = FunctionEvidence(
        "f",
        0,
        1,
        [
            VariableEvidence("s_audited", "a", usage_features=shared),
            VariableEvidence("s_feature_only", "b", usage_features=shared),
        ],
    )
    decompiled = FunctionEvidence(
        "f",
        0,
        1,
        [VariableEvidence("d0", "v0", usage_features=shared)],
    )
    pairs = [EvidencePair("sample", "held_out", "ida", source, decompiled)]
    audit_source_ids = {("sample", "ida"): frozenset({"s_audited"})}

    decisions, coverage = _decisions(
        pairs,
        ModeConfig(mode="usage"),
        audit_source_ids=audit_source_ids,
    )
    feature_coverage = _feature_coverage(
        [
            {
                "sample_id": "sample",
                "source_status": "ok",
                "source_evidence": source.to_dict(),
            }
        ],
        pairs,
        audit_source_ids,
    )

    assert decisions == {}
    assert coverage["accepted_in_production_universe_total"] == 0
    assert coverage["frozen_source_case_total"] == 1
    assert coverage["production_source_case_total"] == 2
    assert coverage["source_cases_outside_frozen_audit"] == 1
    assert feature_coverage["unique_source_variables"] == {
        "total": 2,
        "address_matchable": 0,
        "features_extracted": 2,
        "usage_matchable": 2,
        "frozen_audit": 1,
        "outside_frozen_audit": 1,
        "usage_only": 2,
        "address_and_usage": 0,
        "neither_channel": 0,
    }


def test_mode_config_is_the_exact_type_match_policy() -> None:
    for mode in ("address", "usage", "address+usage"):
        config = ModeConfig(mode=mode)
        assert config.matcher_kwargs() == {"mode": mode, **_production_policy()}


def test_new_source_and_candidate_decisions_remain_unlabeled() -> None:
    feature = (("call:named:consume:arg:0", 1),)
    source = FunctionEvidence(
        "f",
        0,
        1,
        [
            VariableEvidence("s_audited", "", usage_features=feature),
            VariableEvidence("s_new", "", usage_features=feature),
        ],
    )
    decompiled = FunctionEvidence(
        "f",
        0,
        1,
        [VariableEvidence("d_old", ""), VariableEvidence("d_new", "")],
    )
    pair = EvidencePair("sample", "held_out", "ida", source, decompiled)
    decisions = {
        ("sample", "ida", "s_audited"): VariableMatch("s_audited", "d_new", "usage", 0.8),
        ("sample", "ida", "s_new"): VariableMatch("s_new", "d_old", "usage", 0.7),
    }
    private = {
        "case_id": "case",
        "sample_id": "sample",
        "backend_id": "ida",
        "source_id": "s_audited",
        "decompiled_audit_map": {"candidate_0": ["d_old"]},
    }

    derived, candidate_blockers = _replace_private_decisions([private], decisions)
    source_blockers = _unlabeled_source_cases(
        [pair],
        decisions,
        {("sample", "ida"): frozenset({"s_audited"})},
        ModeConfig(mode="usage"),
    )

    assert derived == []
    assert candidate_blockers[0]["reason"] == "decompiled_candidate_outside_frozen_catalog"
    assert source_blockers[0]["reason"] == "source_outside_frozen_audit"
    assert source_blockers[0]["decision"]["decompiled_id"] == "d_old"


def test_scorer_audit_binding_rejects_address_universe_drift() -> None:
    frozen_config = {
        "project": "coreutils",
        "optimizations": ["O2"],
        "decompiler_bases": ["ida"],
        "sample_size": 1,
        "sample_seed": "seed",
        "tuning_fraction": 0.25,
        "include_inlined": False,
        "min_overlap": 0.1,
        "ambiguity_margin": 0.03,
        "matcher_mode": "address",
    }
    audit_provenance = {
        "checkpoint_sha256": "checkpoint",
        "strict_universe": {"sha256": "universe"},
        "selected_sample_sha256": "sample-set",
        "selected_sample_count": 1,
        "decompilers": ["ida"],
        "score_config": frozen_config,
    }
    scorer_config = {**frozen_config, "production_type_match_policy": True}
    scorer_provenance = {**audit_provenance, "score_config": scorer_config}
    row = {
        "sample_id": "sample",
        "function": {"name": "f"},
        "partition": "held_out",
        "source_evidence": {"variables": [{"identity": "s0", "addresses": ["0x10"]}]},
        "decompilers": {
            "ida": {
                "status": "ok",
                "evidence": {"variables": [{"identity": "d0"}]},
            }
        },
    }
    private = {
        "sample_id": "sample",
        "backend_id": "ida",
        "function": {"name": "f"},
        "partition": "held_out",
        "backend_status": "ok",
        "source_id": "s0",
        "checkpoint_decompiled_ids": ["d0"],
    }

    result = _validate_audit_binding(
        [row],
        {"provenance": scorer_provenance, "frozen_thresholds": _production_policy()},
        {"input_provenance": audit_provenance},
        [private],
    )
    assert result["passed"] is True

    row["source_evidence"]["variables"].append(
        {"identity": "s_new", "addresses": [], "usage_features": {"call:x": 1}}
    )
    row["decompilers"]["ida"]["evidence"]["variables"].append({"identity": "d_new"})
    expanded = _validate_audit_binding(
        [row],
        {"provenance": scorer_provenance, "frozen_thresholds": _production_policy()},
        {"input_provenance": audit_provenance},
        [private],
    )
    assert expanded["production_source_variables_outside_frozen_audit"] == 1
    assert expanded["production_decompiler_candidates_outside_frozen_catalog"] == 1

    row["source_evidence"]["variables"] = [row["source_evidence"]["variables"][1]]
    reduced = _validate_audit_binding(
        [row],
        {"provenance": scorer_provenance, "frozen_thresholds": _production_policy()},
        {"input_provenance": audit_provenance},
        [private],
    )
    assert reduced["frozen_audit_source_cases_outside_production_denominator"] == 1
