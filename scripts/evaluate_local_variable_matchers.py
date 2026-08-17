#!/usr/bin/env python
"""Evaluate address, usage, and fused local-variable matchers on one frozen audit."""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any, cast

from decbench.caching import stable_hash
from decbench.experimental.local_variable_checkpoint import canonical_sha256, file_sha256
from decbench.experimental.local_variable_distance import (
    MATCHER_MODES,
    FunctionEvidence,
    MatcherMode,
    VariableMatch,
    has_usage_context,
    match_variables,
)
from decbench.experimental.local_variable_semantic_audit import (
    join_audit_rows,
    load_completed_audit_package,
    make_audit_report,
    read_jsonl,
    write_json,
)

DEFAULT_THRESHOLDS = (0.05, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5)
DEFAULT_MARGINS = (0.0, 0.03, 0.05, 0.1, 0.15)
DEFAULT_ADDRESS_WEIGHTS = (0.2, 0.35, 0.5, 0.65, 0.8)


@dataclass(frozen=True)
class ModeConfig:
    mode: MatcherMode
    min_overlap: float = 0.1
    ambiguity_margin: float = 0.03
    min_usage_similarity: float = 0.1
    usage_ambiguity_margin: float = 0.03
    min_combined_similarity: float = 0.1
    address_weight: float = 0.5

    def matcher_kwargs(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidencePair:
    sample_id: str
    partition: str
    backend_id: str
    source: FunctionEvidence
    decompiled: FunctionEvidence


DecisionKey = tuple[str, str, str]
DecisionMap = dict[DecisionKey, VariableMatch]
AuditPairKey = tuple[str, str]
AuditSourceMap = Mapping[AuditPairKey, frozenset[str]]


def _float_list(value: str) -> tuple[float, ...]:
    try:
        values = tuple(float(part.strip()) for part in value.split(",") if part.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid comma-separated float list: {value}") from exc
    if not values or any(number < 0 for number in values):
        raise argparse.ArgumentTypeError("float lists must contain non-negative values")
    return values


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scorer", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--audit-package", type=Path, required=True)
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--merge-provenance", type=Path)
    parser.add_argument("--mode", choices=MATCHER_MODES, action="append")
    parser.add_argument(
        "--min-overlap",
        type=float,
        help="must match the frozen address scorer (defaults to its value)",
    )
    parser.add_argument(
        "--ambiguity-margin",
        type=float,
        help="must match the frozen address scorer (defaults to its value)",
    )
    parser.add_argument("--min-usage-similarity", type=float, default=0.1)
    parser.add_argument("--usage-ambiguity-margin", type=float, default=0.03)
    parser.add_argument("--min-combined-similarity", type=float, default=0.1)
    parser.add_argument("--address-weight", type=float, default=0.5)
    parser.add_argument(
        "--tune",
        action="store_true",
        help="select usage/fused parameters by tuning-partition edge F1",
    )
    parser.add_argument(
        "--threshold-grid",
        type=_float_list,
        default=DEFAULT_THRESHOLDS,
        help="comma-separated usage/combined thresholds for --tune",
    )
    parser.add_argument(
        "--margin-grid",
        type=_float_list,
        default=DEFAULT_MARGINS,
        help="comma-separated bidirectional margins for --tune",
    )
    parser.add_argument(
        "--address-weight-grid",
        type=_float_list,
        default=DEFAULT_ADDRESS_WEIGHTS,
        help="comma-separated address weights for fused --tune",
    )
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _load_scorer(
    scorer_path: Path,
    aggregate_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = read_jsonl(scorer_path)
    try:
        aggregate = json.loads(aggregate_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not load aggregate {aggregate_path}: {exc}") from exc
    if not isinstance(aggregate, dict):
        raise ValueError(f"{aggregate_path}: aggregate must be a JSON object")
    provenance = aggregate.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("aggregate lacks scorer provenance")
    scorer_sha256 = file_sha256(scorer_path)
    if provenance.get("scorer_jsonl_sha256") != scorer_sha256:
        raise ValueError("aggregate scorer hash does not match --scorer")
    if provenance.get("selected_sample_count") != len(rows):
        raise ValueError("aggregate selected sample count does not match --scorer")
    sample_ids = [str(row.get("sample_id", "")) for row in rows]
    if not all(sample_ids) or len(sample_ids) != len(set(sample_ids)):
        raise ValueError("scorer sample IDs are empty or duplicated")
    if any(row.get("run_binding_sha256") != provenance.get("run_binding_sha256") for row in rows):
        raise ValueError("scorer rows do not share the aggregate run binding")
    return rows, aggregate


def _evidence_pairs(rows: Sequence[Mapping[str, Any]]) -> list[EvidencePair]:
    pairs: list[EvidencePair] = []
    feature_source_variables = 0
    feature_decompiled_variables = 0
    for row in rows:
        if row.get("source_status") != "ok":
            continue
        source = FunctionEvidence.from_dict(row["source_evidence"])
        feature_source_variables += sum(bool(var.usage_features) for var in source.variables)
        for backend_id, entry in row.get("decompilers", {}).items():
            if entry.get("status") != "ok":
                continue
            decompiled = FunctionEvidence.from_dict(entry["evidence"])
            feature_decompiled_variables += sum(
                bool(var.usage_features) for var in decompiled.variables
            )
            pairs.append(
                EvidencePair(
                    sample_id=str(row["sample_id"]),
                    partition=str(row.get("partition", "")),
                    backend_id=str(backend_id),
                    source=source,
                    decompiled=decompiled,
                )
            )
    if feature_source_variables == 0 or feature_decompiled_variables == 0:
        raise ValueError("scorer has no serialized usage features; regenerate it with this branch")
    return pairs


def _validate_audit_binding(
    rows: Sequence[Mapping[str, Any]],
    aggregate: Mapping[str, Any],
    manifest: Mapping[str, Any],
    private_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    scorer_provenance = aggregate["provenance"]
    audit_provenance = manifest["input_provenance"]
    for field in (
        "checkpoint_sha256",
        "strict_universe",
        "selected_sample_sha256",
        "selected_sample_count",
        "decompilers",
    ):
        if scorer_provenance.get(field) != audit_provenance.get(field):
            raise ValueError(f"scorer/audit provenance mismatch for {field}")

    scorer_config = scorer_provenance.get("score_config")
    audit_config = audit_provenance.get("score_config")
    if not isinstance(scorer_config, dict) or not isinstance(audit_config, dict):
        raise ValueError("scorer or audit score config is missing")
    stable_config_fields = {
        "project",
        "optimizations",
        "decompiler_bases",
        "sample_size",
        "sample_seed",
        "tuning_fraction",
        "include_inlined",
        "min_overlap",
        "ambiguity_margin",
    }
    if any(scorer_config.get(field) != audit_config.get(field) for field in stable_config_fields):
        raise ValueError("scorer/audit frozen sample or address-matcher config differs")
    if scorer_config.get("matcher_mode") != "address":
        raise ValueError("feature evidence scorer must use address mode for legacy parity")

    scorer_by_sample = {str(row["sample_id"]): row for row in rows}
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for private in private_rows:
        key = (str(private["sample_id"]), str(private["backend_id"]))
        groups.setdefault(key, []).append(private)
    for (sample_id, backend_id), private_group in groups.items():
        scorer = scorer_by_sample.get(sample_id)
        if scorer is None:
            raise ValueError(f"audit sample {sample_id} is absent from scorer")
        first = private_group[0]
        if scorer.get("function") != first.get("function"):
            raise ValueError(f"scorer/audit function metadata differs for {sample_id}")
        if scorer.get("partition") != first.get("partition"):
            raise ValueError(f"scorer/audit partition differs for {sample_id}")
        backend = scorer.get("decompilers", {}).get(backend_id)
        if not isinstance(backend, dict) or backend.get("status") != first.get("backend_status"):
            raise ValueError(f"scorer/audit backend status differs for {sample_id}/{backend_id}")
        expected_source_ids = {str(row["source_id"]) for row in private_group}
        source_variables = [
            variable
            for variable in scorer.get("source_evidence", {}).get("variables", [])
            if isinstance(variable, dict)
        ]
        source_ids = {
            str(variable["identity"])
            for variable in source_variables
            if variable.get("addresses")
            or variable.get("stack_offsets")
            or variable.get("arg_index") is not None
        }
        if expected_source_ids != source_ids:
            raise ValueError(
                f"scorer/audit address-observable source universe differs for "
                f"{sample_id}/{backend_id}"
            )
        decompiled_ids = {
            str(variable["identity"])
            for variable in backend.get("evidence", {}).get("variables", [])
        }
        expected_decompiled_ids = {str(value) for value in first["checkpoint_decompiled_ids"]}
        if decompiled_ids != expected_decompiled_ids:
            raise ValueError(
                f"scorer/audit decompiler candidate universe differs for {sample_id}/{backend_id}"
            )
    return {
        "passed": True,
        "frozen_fields": sorted(stable_config_fields),
        "frozen_address_config": {
            "min_overlap": scorer_config["min_overlap"],
            "ambiguity_margin": scorer_config["ambiguity_margin"],
        },
        "audited_function_backend_groups": len(groups),
        "audited_source_cases": len(private_rows),
    }


def _audit_source_map(
    private_rows: Sequence[Mapping[str, Any]],
) -> dict[AuditPairKey, frozenset[str]]:
    mutable: dict[AuditPairKey, set[str]] = {}
    for row in private_rows:
        key = (str(row["sample_id"]), str(row["backend_id"]))
        mutable.setdefault(key, set()).add(str(row["source_id"]))
    return {key: frozenset(values) for key, values in mutable.items()}


def _feature_coverage(
    rows: Sequence[Mapping[str, Any]],
    pairs: Sequence[EvidencePair],
    audit_source_ids: AuditSourceMap,
) -> dict[str, Any]:
    all_source: set[tuple[str, str]] = set()
    extracted_source: set[tuple[str, str]] = set()
    matchable_source: set[tuple[str, str]] = set()
    audited_source = {
        (sample_id, source_id)
        for (sample_id, _backend_id), source_ids in audit_source_ids.items()
        for source_id in source_ids
    }
    source_occurrences: Counter[str] = Counter()
    decompiled_occurrences: Counter[str] = Counter()
    audited_pair_count = 0
    source_function_count = 0
    for row in rows:
        if row.get("source_status") != "ok":
            continue
        source_function_count += 1
        sample_id = str(row["sample_id"])
        source = FunctionEvidence.from_dict(row["source_evidence"])
        for variable in source.variables:
            source_key = (sample_id, variable.identity)
            all_source.add(source_key)
            if variable.usage_features:
                extracted_source.add(source_key)
            if has_usage_context(variable):
                matchable_source.add(source_key)
    for pair in pairs:
        pair_key = (pair.sample_id, pair.backend_id)
        audited_ids = audit_source_ids.get(pair_key, frozenset())
        if audited_ids:
            audited_pair_count += 1
        for variable in pair.source.variables:
            source_key = (pair.sample_id, variable.identity)
            source_occurrences["total"] += 1
            if variable.usage_features:
                source_occurrences["features_extracted"] += 1
            if has_usage_context(variable):
                source_occurrences["usage_matchable"] += 1
            if variable.identity in audited_ids:
                source_occurrences["frozen_audit"] += 1
                if variable.usage_features:
                    source_occurrences["frozen_audit_features_extracted"] += 1
                if has_usage_context(variable):
                    source_occurrences["frozen_audit_usage_matchable"] += 1
            elif has_usage_context(variable):
                source_occurrences["feature_only_usage_matchable"] += 1
        for variable in pair.decompiled.variables:
            decompiled_occurrences["total"] += 1
            if variable.usage_features:
                decompiled_occurrences["features_extracted"] += 1
            if has_usage_context(variable):
                decompiled_occurrences["usage_matchable"] += 1
            if variable.inferred_from_code:
                decompiled_occurrences["inferred_from_code"] += 1
                if has_usage_context(variable):
                    decompiled_occurrences["inferred_from_code_usage_matchable"] += 1
    return {
        "unit": (
            "occurrence counts are per source-function/backend pair; unique source counts "
            "deduplicate the same source variable across backends"
        ),
        "function_backend_pairs": len(pairs),
        "frozen_audit_function_backend_groups": len(audit_source_ids),
        "backend_ok_frozen_audit_pairs": audited_pair_count,
        "source_ok_functions": source_function_count,
        "pair_conditioned_source_occurrences": dict(sorted(source_occurrences.items())),
        "unique_source_variables": {
            "total": len(all_source),
            "features_extracted": len(extracted_source),
            "usage_matchable": len(matchable_source),
            "frozen_audit": len(audited_source),
            "feature_only_usage_matchable": len(matchable_source - audited_source),
        },
        "decompiled_occurrences": dict(sorted(decompiled_occurrences.items())),
    }


def _decisions(
    pairs: Sequence[EvidencePair],
    config: ModeConfig,
    *,
    audit_source_ids: AuditSourceMap,
    partition: str | None = None,
) -> tuple[DecisionMap, dict[str, Any]]:
    decisions: DecisionMap = {}
    stages: Counter[str] = Counter()
    source_count = 0
    decompiled_count = 0
    pair_count = 0
    frozen_source_count = 0
    for pair in pairs:
        if partition is not None and pair.partition != partition:
            continue
        audited_ids = audit_source_ids.get((pair.sample_id, pair.backend_id))
        if not audited_ids:
            continue
        source_variables = [
            variable for variable in pair.source.variables if variable.identity in audited_ids
        ]
        if len(source_variables) != len(audited_ids):
            raise ValueError(
                f"scorer lacks a frozen source candidate for {pair.sample_id}/{pair.backend_id}"
            )
        result = match_variables(
            source_variables,
            pair.decompiled.variables,
            **config.matcher_kwargs(),
        )
        pair_count += 1
        frozen_source_count += len(source_variables)
        source_count += result.source_count
        decompiled_count += result.decompiled_count
        for match in result.matches:
            key = (pair.sample_id, pair.backend_id, match.source_id)
            if key in decisions:
                raise ValueError(f"matcher produced duplicate source decision {key}")
            decisions[key] = match
            stages[match.stage] += 1
    return decisions, {
        "scope": "frozen address-observable semantic-audit universe",
        "function_backend_pairs": pair_count,
        "frozen_source_case_total": frozen_source_count,
        "matcher_eligible_source_total": source_count,
        "matcher_candidate_decompiled_total": decompiled_count,
        "accepted_in_audit_total": len(decisions),
        "accepted_by_stage": dict(sorted(stages.items())),
    }


def _confidence(match: VariableMatch) -> dict[str, float | None]:
    gaps = [
        gap
        for gap in (match.source_runner_up_gap, match.decompiled_runner_up_gap)
        if gap is not None
    ]
    return {
        "source_runner_up_gap": match.source_runner_up_gap,
        "decompiled_runner_up_gap": match.decompiled_runner_up_gap,
        "minimum_runner_up_gap": min(gaps) if gaps else None,
    }


def _replace_private_decisions(
    private_rows: Sequence[Mapping[str, Any]],
    decisions: Mapping[DecisionKey, VariableMatch],
) -> list[dict[str, Any]]:
    derived: list[dict[str, Any]] = []
    used_keys: set[DecisionKey] = set()
    for original in private_rows:
        row = dict(original)
        key = (
            str(row["sample_id"]),
            str(row["backend_id"]),
            str(row["source_id"]),
        )
        match = decisions.get(key)
        accepted: list[dict[str, Any]] = []
        if match is not None:
            inverse: dict[str, str] = {}
            for alias, identities in row["decompiled_audit_map"].items():
                for identity in identities:
                    if identity in inverse:
                        raise ValueError(f"case {row['case_id']}: ambiguous identity {identity}")
                    inverse[str(identity)] = str(alias)
            alias = inverse.get(match.decompiled_id)
            if alias is None:
                raise ValueError(
                    f"case {row['case_id']}: matcher selected {match.decompiled_id!r}, "
                    "which is outside the frozen audit catalog"
                )
            accepted.append(
                {
                    "decompiled_id": match.decompiled_id,
                    "decompiled_audit_id": alias,
                    "stage": match.stage,
                    "score": match.score,
                    "confidence": _confidence(match),
                }
            )
            used_keys.add(key)
        row["matcher_accepted"] = accepted
        derived.append(row)
    audited_keys = {
        (str(row["sample_id"]), str(row["backend_id"]), str(row["source_id"]))
        for row in private_rows
    }
    if set(decisions) - audited_keys:
        raise ValueError("matcher produced decisions outside the frozen audit universe")
    if used_keys != set(decisions):
        raise ValueError("derived matcher decisions were not consumed deterministically")
    return derived


def _package_subset(
    evidence_rows: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    private_rows: Sequence[Mapping[str, Any]],
    labels: Mapping[str, Mapping[str, Any]],
    *,
    partition: str,
) -> tuple[
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    dict[str, Mapping[str, Any]],
]:
    private_subset = [row for row in private_rows if row.get("partition") == partition]
    case_ids = {str(row["case_id"]) for row in private_subset}
    case_subset = [row for row in cases if str(row["case_id"]) in case_ids]
    evidence_ids = {str(row["evidence_id"]) for row in case_subset}
    evidence_subset = [row for row in evidence_rows if str(row["evidence_id"]) in evidence_ids]
    label_subset = {case_id: labels[case_id] for case_id in case_ids}
    return evidence_subset, case_subset, private_subset, label_subset


def _headline(statistics: Mapping[str, Any]) -> dict[str, Any]:
    conditional = statistics["matcher_conditional_on_backend_ok"]
    confusion = conditional["candidate_edge_confusion"]
    accepted = conditional["accepted_edges"]
    relations = conditional["source_relations"]
    return {
        "accepted": accepted["accepted_count"],
        "true_positive": confusion["true_positive"],
        "false_positive": confusion["false_positive"],
        "false_negative": confusion["false_negative"],
        "true_negative": confusion["true_negative"],
        "precision": confusion["metrics"]["precision"],
        "edge_recall": confusion["metrics"]["edge_recall"],
        "edge_f1": confusion["metrics"]["edge_f1"],
        "any_neighbor_recall": relations["metrics"]["matcher_relation_recall"],
        "full_relation_recall": relations["metrics"]["matcher_full_relation_recall"],
    }


def _evaluate(
    *,
    config: ModeConfig,
    pairs: Sequence[EvidencePair],
    manifest: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    private_rows: Sequence[Mapping[str, Any]],
    labels: Mapping[str, Mapping[str, Any]],
    audit_source_ids: AuditSourceMap,
    bootstrap_iterations: int,
    partition: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], DecisionMap, list[dict[str, Any]]]:
    decisions, coverage = _decisions(
        pairs,
        config,
        audit_source_ids=audit_source_ids,
        partition=partition,
    )
    derived_private = _replace_private_decisions(private_rows, decisions)
    active_evidence: Sequence[Mapping[str, Any]] = evidence_rows
    active_cases: Sequence[Mapping[str, Any]] = cases
    active_private: Sequence[Mapping[str, Any]] = derived_private
    active_labels: Mapping[str, Mapping[str, Any]] = labels
    if partition is not None:
        active_evidence, active_cases, active_private, active_labels = _package_subset(
            evidence_rows,
            cases,
            derived_private,
            labels,
            partition=partition,
        )
    joined = join_audit_rows(
        active_evidence,
        active_cases,
        active_private,
        active_labels,
    )
    report = make_audit_report(
        joined,
        manifest=manifest,
        bootstrap_iterations=bootstrap_iterations,
    )
    return report, coverage, decisions, joined


def _objective(headline: Mapping[str, Any], config: ModeConfig) -> tuple[float, ...]:
    f1 = headline["edge_f1"]["value"]
    precision = headline["precision"]["value"]
    recall = headline["edge_recall"]["value"]
    return (
        float(f1) if f1 is not None else -1.0,
        float(precision) if precision is not None else -1.0,
        float(recall) if recall is not None else -1.0,
        -float(headline["accepted"]),
        config.min_usage_similarity if config.mode == "usage" else config.min_combined_similarity,
        config.usage_ambiguity_margin,
        -abs(config.address_weight - 0.5),
    )


def _grid_configs(
    mode: MatcherMode,
    base: ModeConfig,
    thresholds: Sequence[float],
    margins: Sequence[float],
    address_weights: Sequence[float],
) -> list[ModeConfig]:
    if mode == "address":
        return [base]
    if mode == "usage":
        return [
            ModeConfig(
                **{
                    **asdict(base),
                    "min_usage_similarity": threshold,
                    "usage_ambiguity_margin": margin,
                }
            )
            for threshold in thresholds
            for margin in margins
        ]
    return [
        ModeConfig(
            **{
                **asdict(base),
                "min_combined_similarity": threshold,
                "usage_ambiguity_margin": margin,
                "address_weight": address_weight,
            }
        )
        for threshold in thresholds
        for margin in margins
        for address_weight in address_weights
    ]


def _tune_config(
    *,
    base: ModeConfig,
    thresholds: Sequence[float],
    margins: Sequence[float],
    address_weights: Sequence[float],
    pairs: Sequence[EvidencePair],
    manifest: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    private_rows: Sequence[Mapping[str, Any]],
    labels: Mapping[str, Mapping[str, Any]],
    audit_source_ids: AuditSourceMap,
) -> tuple[ModeConfig, dict[str, Any]]:
    trials: list[tuple[tuple[float, ...], ModeConfig, dict[str, Any]]] = []
    for config in _grid_configs(
        base.mode,
        base,
        thresholds,
        margins,
        address_weights,
    ):
        report, coverage, _decisions_by_source, _joined = _evaluate(
            config=config,
            pairs=pairs,
            manifest=manifest,
            evidence_rows=evidence_rows,
            cases=cases,
            private_rows=private_rows,
            labels=labels,
            audit_source_ids=audit_source_ids,
            bootstrap_iterations=0,
            partition="tuning",
        )
        headline = _headline(report["summary"])
        trials.append((_objective(headline, config), config, {**headline, "coverage": coverage}))
    trials.sort(key=lambda row: (row[0], canonical_sha256(asdict(row[1]))), reverse=True)
    selected = trials[0][1]
    leaderboard = [
        {
            "rank": index,
            "config": asdict(config),
            "tuning": headline,
        }
        for index, (_score, config, headline) in enumerate(trials[:10], start=1)
    ]
    return selected, {
        "selection_partition": "tuning",
        "objective": "candidate-edge F1, then precision, recall, abstention, threshold",
        "trial_count": len(trials),
        "grid": {
            "thresholds": list(thresholds),
            "margins": list(margins),
            "address_weights": list(address_weights) if base.mode == "address+usage" else [],
        },
        "leaderboard": leaderboard,
    }


def _legacy_parity(
    private_rows: Sequence[Mapping[str, Any]],
    decisions: Mapping[DecisionKey, VariableMatch],
) -> dict[str, Any]:
    expected: set[tuple[str, str, str, str, str]] = set()
    for row in private_rows:
        for match in row.get("matcher_accepted", []):
            expected.add(
                (
                    str(row["sample_id"]),
                    str(row["backend_id"]),
                    str(row["source_id"]),
                    str(match["decompiled_id"]),
                    str(match["stage"]),
                )
            )
    actual = {
        (sample_id, backend_id, source_id, match.decompiled_id, match.stage)
        for (sample_id, backend_id, source_id), match in decisions.items()
        if any(
            row["sample_id"] == sample_id
            and row["backend_id"] == backend_id
            and row["source_id"] == source_id
            for row in private_rows
        )
    }
    return {
        "passed": actual == expected,
        "legacy_accepted": len(expected),
        "derived_accepted_in_audit_universe": len(actual),
        "missing": len(expected - actual),
        "added": len(actual - expected),
    }


def _decision_payload(decisions: Mapping[DecisionKey, VariableMatch]) -> list[dict[str, Any]]:
    return [
        {
            "sample_id": key[0],
            "backend_id": key[1],
            "source_id": key[2],
            "decompiled_id": match.decompiled_id,
            "stage": match.stage,
            "score": match.score,
        }
        for key, match in sorted(decisions.items())
    ]


def _edge_cluster_counts(
    joined: Sequence[Mapping[str, Any]],
) -> dict[str, tuple[int, int, int]]:
    valid = {"correct", "split", "merge", "many-to-many"}
    counts: dict[str, list[int]] = {}
    for row in joined:
        if row.get("backend_status") != "ok":
            continue
        oracle = row["oracle"]
        if oracle.get("status") == "oracle_unknown" or oracle.get("ambiguous_alias_selection"):
            continue
        sample_id = str(row["audit_sample_id"])
        cluster = counts.setdefault(sample_id, [0, 0, 0])
        accepted = row["matcher"]["accepted"]
        true_positive = sum(match.get("classification") in valid for match in accepted)
        false_positive = sum(match.get("classification") == "incorrect" for match in accepted)
        positive_count = (
            len(oracle.get("selected_decompiled_audit_ids", []))
            if oracle.get("status") == "mapped"
            else 0
        )
        cluster[0] += true_positive
        cluster[1] += false_positive
        cluster[2] += positive_count - true_positive
    return {sample_id: (values[0], values[1], values[2]) for sample_id, values in counts.items()}


def _edge_metrics(counts: Iterable[tuple[int, int, int]]) -> dict[str, float | None]:
    true_positive = false_positive = false_negative = 0
    for tp, fp, fn in counts:
        true_positive += tp
        false_positive += fp
        false_negative += fn
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    f1_denominator = 2 * true_positive + false_positive + false_negative
    return {
        "precision": true_positive / precision_denominator if precision_denominator else None,
        "edge_recall": true_positive / recall_denominator if recall_denominator else None,
        "edge_f1": 2 * true_positive / f1_denominator if f1_denominator else None,
    }


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _paired_deltas(
    joined_by_mode: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    bootstrap_iterations: int,
) -> dict[str, Any]:
    if "address" not in joined_by_mode:
        return {}
    partitions = sorted(
        {
            str(row["partition"])
            for joined in joined_by_mode.values()
            for row in joined
            if row.get("partition")
        }
    )
    scoped = {
        "overall": joined_by_mode,
        **{
            partition: {
                mode: [row for row in joined if row.get("partition") == partition]
                for mode, joined in joined_by_mode.items()
            }
            for partition in partitions
        },
    }
    by_scope: dict[str, Any] = {}
    for scope, scoped_rows in scoped.items():
        counts_by_mode = {
            mode: _edge_cluster_counts(joined) for mode, joined in scoped_rows.items()
        }
        clusters = sorted({sample for counts in counts_by_mode.values() for sample in counts})
        baseline_metrics = _edge_metrics(counts_by_mode["address"].values())
        comparisons: dict[str, Any] = {}
        for mode in sorted(set(counts_by_mode) - {"address"}):
            actual = _edge_metrics(counts_by_mode[mode].values())
            point: dict[str, float | None] = {}
            for metric, baseline_value in baseline_metrics.items():
                actual_value = actual[metric]
                point[metric] = (
                    actual_value - baseline_value
                    if actual_value is not None and baseline_value is not None
                    else None
                )
            intervals: dict[str, list[float] | None] = {metric: None for metric in point}
            if bootstrap_iterations > 0 and clusters:
                rng = random.Random(
                    int(
                        stable_hash(
                            "local-variable-mode-paired-bootstrap-v1",
                            scope,
                            mode,
                            bootstrap_iterations,
                        ),
                        16,
                    )
                )
                samples: dict[str, list[float]] = {metric: [] for metric in point}
                for _iteration in range(bootstrap_iterations):
                    selected = [rng.choice(clusters) for _cluster in clusters]
                    base_sample = _edge_metrics(
                        counts_by_mode["address"].get(cluster, (0, 0, 0)) for cluster in selected
                    )
                    mode_sample = _edge_metrics(
                        counts_by_mode[mode].get(cluster, (0, 0, 0)) for cluster in selected
                    )
                    for metric in samples:
                        base_value = base_sample[metric]
                        mode_value = mode_sample[metric]
                        if base_value is not None and mode_value is not None:
                            samples[metric].append(mode_value - base_value)
                intervals = {
                    metric: (
                        [_quantile(values, 0.025), _quantile(values, 0.975)] if values else None
                    )
                    for metric, values in samples.items()
                }
            comparisons[f"{mode}_minus_address"] = {
                metric: {
                    "value": point[metric],
                    "paired_clustered_bootstrap_ci95": intervals[metric],
                }
                for metric in point
            }
        by_scope[scope] = {
            "cluster_count": len(clusters),
            "comparisons": comparisons,
        }
    return {
        "cluster_unit": "source function (audit_sample_id), paired across modes",
        "iterations": bootstrap_iterations,
        "by_scope": by_scope,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.bootstrap_iterations < 0:
        print("error: bootstrap iterations must be non-negative", file=sys.stderr)
        return 2
    try:
        rows, aggregate = _load_scorer(args.scorer, args.aggregate)
        pairs = _evidence_pairs(rows)
        manifest, evidence_rows, cases, private_rows, labels = load_completed_audit_package(
            args.audit_package,
            labels_path=args.labels,
            merge_provenance_path=args.merge_provenance,
        )
        audit_binding = _validate_audit_binding(rows, aggregate, manifest, private_rows)
        frozen_config = aggregate["provenance"]["score_config"]
        frozen_min_overlap = float(frozen_config["min_overlap"])
        frozen_ambiguity_margin = float(frozen_config["ambiguity_margin"])
        min_overlap = frozen_min_overlap if args.min_overlap is None else args.min_overlap
        ambiguity_margin = (
            frozen_ambiguity_margin if args.ambiguity_margin is None else args.ambiguity_margin
        )
        if min_overlap != frozen_min_overlap or ambiguity_margin != frozen_ambiguity_margin:
            raise ValueError(
                "evaluator address thresholds must equal the frozen scorer/audit config"
            )
        audit_source_ids = _audit_source_map(private_rows)
        feature_coverage = _feature_coverage(rows, pairs, audit_source_ids)
        modes = tuple(cast(MatcherMode, value) for value in (args.mode or MATCHER_MODES))
        results: dict[str, Any] = {}
        joined_by_mode: dict[str, list[dict[str, Any]]] = {}
        for mode in modes:
            base = ModeConfig(
                mode=mode,
                min_overlap=min_overlap,
                ambiguity_margin=ambiguity_margin,
                min_usage_similarity=args.min_usage_similarity,
                usage_ambiguity_margin=args.usage_ambiguity_margin,
                min_combined_similarity=args.min_combined_similarity,
                address_weight=args.address_weight,
            )
            tuning = None
            selected = base
            if args.tune and mode != "address":
                selected, tuning = _tune_config(
                    base=base,
                    thresholds=args.threshold_grid,
                    margins=args.margin_grid,
                    address_weights=args.address_weight_grid,
                    pairs=pairs,
                    manifest=manifest,
                    evidence_rows=evidence_rows,
                    cases=cases,
                    private_rows=private_rows,
                    labels=labels,
                    audit_source_ids=audit_source_ids,
                )
            report, coverage, decisions, joined = _evaluate(
                config=selected,
                pairs=pairs,
                manifest=manifest,
                evidence_rows=evidence_rows,
                cases=cases,
                private_rows=private_rows,
                labels=labels,
                audit_source_ids=audit_source_ids,
                bootstrap_iterations=args.bootstrap_iterations,
            )
            parity = _legacy_parity(private_rows, decisions) if mode == "address" else None
            if parity is not None and not parity["passed"]:
                raise ValueError(f"address mode failed legacy parity: {parity}")
            results[mode] = {
                "selected_config": asdict(selected),
                "tuning": tuning,
                "coverage": coverage,
                "decision_sha256": canonical_sha256(_decision_payload(decisions)),
                "legacy_parity": parity,
                "headline": {
                    "overall": _headline(report["summary"]),
                    **{
                        partition: _headline(statistics)
                        for partition, statistics in report["by_partition"].items()
                    },
                },
                "audit_report": report,
            }
            joined_by_mode[mode] = joined

        import decbench.experimental.local_variable_checkpoint as scorer_module
        import decbench.experimental.local_variable_semantic_audit as audit_module
        import decbench.metrics.variable_features as feature_module
        import decbench.metrics.variable_match as matcher_module

        labels_path = args.labels or args.audit_package / "audit_labels.jsonl"
        merge_provenance_path = (
            args.merge_provenance or args.audit_package / "label_merge_provenance.json"
        )
        payload = {
            "schema_version": 1,
            "kind": "local-variable-matcher-mode-comparison",
            "provenance": {
                "scorer_path": str(args.scorer),
                "scorer_sha256": file_sha256(args.scorer),
                "aggregate_path": str(args.aggregate),
                "aggregate_sha256": file_sha256(args.aggregate),
                "scorer_run_binding_sha256": aggregate["provenance"]["run_binding_sha256"],
                "audit_package": str(args.audit_package),
                "audit_manifest_payload_sha256": manifest["manifest_payload_sha256"],
                "audit_manifest_file_sha256": file_sha256(args.audit_package / "manifest.json"),
                "audit_labels_path": str(labels_path),
                "audit_labels_sha256": file_sha256(labels_path),
                "label_merge_provenance_path": str(merge_provenance_path),
                "label_merge_provenance_sha256": file_sha256(merge_provenance_path),
                "matcher_implementation_sha256": file_sha256(Path(matcher_module.__file__)),
                "feature_implementation_sha256": file_sha256(Path(feature_module.__file__)),
                "scorer_implementation_sha256": file_sha256(Path(scorer_module.__file__)),
                "evaluator_implementation_sha256": file_sha256(Path(__file__).resolve()),
                "semantic_audit_implementation_sha256": file_sha256(Path(audit_module.__file__)),
                "parser_versions": {
                    "tree-sitter": version("tree-sitter"),
                    "tree-sitter-c": version("tree-sitter-c"),
                },
                "scorer_audit_binding": audit_binding,
            },
            "methodology": {
                "selection": (
                    "usage and address+usage parameters selected only by the frozen tuning "
                    "partition's candidate-edge F1"
                    if args.tune
                    else "parameters supplied directly; no evaluator tuning"
                ),
                "evaluation_universe": (
                    "source candidates are filtered before matching to the existing "
                    "address-observable semantic-audit cases; feature-only variables neither "
                    "receive decisions nor compete for decompiler candidates"
                ),
                "development_caveat": (
                    "the existing audit labels are reused development data for this new matcher, "
                    "not a pristine confirmatory held-out audit"
                ),
            },
            "feature_coverage": feature_coverage,
            "bootstrap_iterations": args.bootstrap_iterations,
            "paired_deltas": _paired_deltas(
                joined_by_mode,
                bootstrap_iterations=args.bootstrap_iterations,
            ),
            "results": results,
        }
        write_json(args.output, payload)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"wrote {args.output}")
    for result_mode, result in results.items():
        held_out = result["headline"].get("held_out", result["headline"]["overall"])
        print(
            f"{result_mode}: accepted={held_out['accepted']} "
            f"precision={held_out['precision']['value']!r} "
            f"recall={held_out['edge_recall']['value']!r} "
            f"f1={held_out['edge_f1']['value']!r}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
