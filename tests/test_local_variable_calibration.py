from __future__ import annotations

import json
from pathlib import Path

import pytest

from decbench.caching import stable_hash
from decbench.experimental.local_variable_distance import (
    FunctionEvidence,
    VariableEvidence,
    match_variables,
)
from scripts.calibrate_local_variable_matcher import (
    CalibrationConfig,
    CalibrationTarget,
    aggregate_group,
    build_name_oracle,
    build_report,
    calibrate_function,
    deterministic_sample,
    freeze_target_partitions,
    load_sample_manifest,
    validate_imported_scorer_rows,
    write_resolved_manifest,
)


def _variable(identity: str, name: str, address: int) -> VariableEvidence:
    return VariableEvidence(
        identity=identity,
        name=name,
        addresses=frozenset({address}),
        size=4,
    )


def _target(
    name: str,
    address: int,
    binary: str = "echo",
    partition: str | None = None,
) -> CalibrationTarget:
    return CalibrationTarget(
        "coreutils",
        "O2",
        binary,
        address,
        name,
        partition,
    )


@pytest.mark.parametrize(
    "name",
    ["Var1", "pVar2", "ppVar3", "ppuVar4", "iVar5", "pcVar6"],
)
def test_ghidra_default_var_names_are_synthetic(name: str) -> None:
    source = [_variable("source", name, 0x1000)]
    decompiled = [_variable("decompiled", name, 0x1000)]

    oracle = build_name_oracle(source, decompiled)

    assert oracle["source_status"]["source"] == "synthetic"
    assert oracle["decompiled_status"]["decompiled"] == "synthetic"


def test_stable_hash_sample_is_order_independent() -> None:
    targets = [_target(f"fn_{index}", 0x1000 + index) for index in range(20)]
    first = deterministic_sample(targets, size=7, seed="fixed")
    second = deterministic_sample(list(reversed(targets)), size=7, seed="fixed")
    assert first == second
    assert len(first) == 7
    assert deterministic_sample(targets, size=0, seed="fixed") == deterministic_sample(
        list(reversed(targets)),
        size=0,
        seed="fixed",
    )


def test_scorer_jsonl_manifest_preserves_exact_address_set(tmp_path: Path) -> None:
    scorer_output = tmp_path / "local_variable_distance_sample.jsonl"
    rows = [
        {
            "sample_id": "one",
            "partition": "held_out",
            "function": {
                "project": "coreutils",
                "optimization": "O2",
                "binary": "printf",
                "address": "0x1234",
                "name": "print_esc",
            },
        },
        {
            "sample_id": "other-opt",
            "partition": "tuning",
            "function": {
                "project": "coreutils",
                "optimization": "O0",
                "binary": "printf",
                "address": "0x9999",
                "name": "ignored",
            },
        },
    ]
    scorer_output.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    assert load_sample_manifest(
        scorer_output,
        project="coreutils",
        optimization="O2",
    ) == [_target("print_esc", 0x1234, "printf", partition="held_out")]


def test_standard_name_manifest_requires_unique_dwarf_resolution(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "sample_set_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "functions": [
                    {
                        "project": "coreutils",
                        "opt": "O2",
                        "binary": "yes",
                        "function": "main",
                    }
                ]
            }
        )
    )
    universe = [_target("main", 0x1010, "yes")]
    assert (
        load_sample_manifest(
            manifest,
            project="coreutils",
            optimization="O2",
            universe=universe,
        )
        == universe
    )

    with pytest.raises(ValueError, match="did not resolve uniquely"):
        load_sample_manifest(
            manifest,
            project="coreutils",
            optimization="O2",
            universe=[*universe, _target("main", 0x2020, "yes")],
        )


def _oracle_fixture() -> tuple[FunctionEvidence, FunctionEvidence]:
    source = FunctionEvidence(
        "fixture",
        0x1000,
        0x1100,
        [
            _variable("s:alpha", "alpha", 1),
            _variable("s:beta", "beta", 2),
            _variable("s:gamma", "gamma", 3),
            _variable("s:dup1", "i", 4),
            _variable("s:dup2", "i", 5),
            _variable("s:lost", "lost", 6),
        ],
    )
    decompiled = FunctionEvidence(
        "fixture",
        0x1000,
        0x1100,
        [
            _variable("d:alpha", "alpha", 1),
            _variable("d:beta", "gamma", 2),
            _variable("d:gamma", "beta", 3),
            _variable("d:dup1", "i", 4),
            _variable("d:dup2", "i", 5),
            _variable("d:lost", "v1", 6),
        ],
    )
    return source, decompiled


def test_matcher_receives_only_blinded_names_then_oracle_is_conservative() -> None:
    source, decompiled = _oracle_fixture()
    matcher_returned = False

    def spying_matcher(source_variables, decompiled_variables, **kwargs):
        nonlocal matcher_returned
        assert all(variable.name.startswith("__blind_source_") for variable in source_variables)
        assert all(
            variable.name.startswith("__blind_decompiled_") for variable in decompiled_variables
        )
        assert not {
            "alpha",
            "beta",
            "gamma",
            "i",
            "lost",
            "v1",
        } & {variable.name for variable in [*source_variables, *decompiled_variables]}
        result = match_variables(source_variables, decompiled_variables, **kwargs)
        matcher_returned = True
        return result

    pairs, function = calibrate_function(
        _target("fixture", 0x1000),
        "ida",
        source,
        decompiled,
        CalibrationConfig(bootstrap_iterations=0),
        matcher=spying_matcher,
    )
    assert matcher_returned
    assert len(pairs) == 6
    assert {pair["oracle"]["verdict"] for pair in pairs} == {"correct", "incorrect", "unknown"}
    assert function["correct"] == 1
    assert function["incorrect"] == 2
    assert function["unknown"] == 3
    assert function["oracle_decidable_source"] == 3
    assert all(pair["stage"] == "overlap" for pair in pairs)

    oracle = build_name_oracle(source.variables, decompiled.variables)
    assert oracle["eligible_names"] == ["alpha", "beta", "gamma"]
    assert oracle["source_status"]["s:dup1"] == "duplicate_lexical_name"
    assert oracle["source_status"]["s:lost"] == "not_retained_on_other_side"
    assert oracle["decompiled_status"]["d:lost"] == "synthetic"


def test_group_metrics_bins_and_cluster_bootstrap() -> None:
    source, decompiled = _oracle_fixture()
    config = CalibrationConfig(bootstrap_iterations=50, bootstrap_seed="fixed")
    pairs, function = calibrate_function(
        _target("fixture", 0x1000),
        "ghidra",
        source,
        decompiled,
        config,
    )
    group = aggregate_group(
        [function],
        pairs,
        config,
        dimensions=("all", "O2", "ghidra"),
    )
    overall = group["overall"]
    assert overall["accepted"] == 6
    assert overall["correct"] == 1
    assert overall["incorrect"] == 2
    assert overall["unknown"] == 3
    assert overall["micro"]["precision"] == pytest.approx(1 / 3)
    assert overall["micro"]["decidable_error_rate"] == pytest.approx(2 / 3)
    assert overall["micro"]["recall"] == pytest.approx(1 / 3)
    assert overall["micro"]["coverage"] == 1.0
    assert overall["micro"]["abstention"] == 0.0
    assert overall["micro"]["oracle_retention_rate"] == 0.5
    assert overall["micro"]["unknown_rate"] == 0.5
    assert overall["micro"]["error_rate_lower_bound"] == pytest.approx(2 / 6)
    assert overall["micro"]["error_rate_upper_bound"] == pytest.approx(5 / 6)
    assert overall["macro_by_function"] == overall["micro"]
    assert overall["bootstrap_95_function_cluster"]["micro"]["precision"]["interval_95"] == [
        pytest.approx(1 / 3),
        pytest.approx(1 / 3),
    ]
    assert overall["bootstrap_95_function_cluster"]["micro"]["precision"]["valid_replicates"] == 50
    assert sum(row["accepted"] for row in overall["score_calibration_bins"]) == 6
    assert sum(row["accepted"] for row in overall["runner_up_gap_calibration_bins"]) == 6
    assert group["by_stage"]["argument"]["accepted"] == 0
    assert group["by_stage"]["overlap"]["accepted"] == 6
    assert group["by_stage"]["overlap"]["micro"]["recall"] is None
    assert group["by_stage"]["overlap"]["micro"]["coverage"] is None
    assert group["by_stage"]["overlap"]["micro"]["abstention"] is None
    assert (
        "undefined"
        in group["by_stage"]["overlap"]["undefined_source_denominator_metrics"]["recall"]
    )


def test_report_is_explicitly_calibration_not_recovery() -> None:
    source, decompiled = _oracle_fixture()
    config = CalibrationConfig(bootstrap_iterations=0)
    target = _target("fixture", 0x1000)
    pairs, function = calibrate_function(
        target,
        "ida",
        source,
        decompiled,
        config,
    )
    report = build_report(
        [function],
        pairs,
        targets=[target],
        backends=["ida"],
        config=config,
        source_manifest=Path("sample.jsonl"),
    )
    assert report["lane"] == "debug-visible-blinded-name-calibration"
    assert report["realistic_recovery_measurement"] is False
    assert "must not be reported" in report["disclaimer"]
    assert report["blinding"]["duplicates_excluded"] is True
    all_row = next(row for row in report["rows"] if row["partition"] == "all")
    assert all_row["overall"]["accepted"] == 6
    assert all_row["common_retained_name_subset"]["common_retained_source_names"] == 3


def test_resolved_manifest_refuses_sample_drift(tmp_path: Path) -> None:
    manifest = tmp_path / "calibration_manifest.json"
    first = [_target("a", 0x10)]
    write_resolved_manifest(
        manifest,
        first,
        source_manifest=None,
        config=CalibrationConfig(sample_seed="fixed", bootstrap_iterations=0),
        backends=["ida"],
        compiled_artifacts=[{"binary": "echo", "sha256": "a"}],
        implementation_hashes={"matcher.py": "b"},
    )
    write_resolved_manifest(
        manifest,
        first,
        source_manifest=None,
        config=CalibrationConfig(sample_seed="fixed", bootstrap_iterations=0),
        backends=["ida"],
        compiled_artifacts=[{"binary": "echo", "sha256": "a"}],
        implementation_hashes={"matcher.py": "b"},
    )
    with pytest.raises(ValueError, match="would change"):
        write_resolved_manifest(
            manifest,
            first,
            source_manifest=None,
            config=CalibrationConfig(
                sample_seed="fixed",
                min_overlap=0.2,
                bootstrap_iterations=0,
            ),
            backends=["ida"],
            compiled_artifacts=[{"binary": "echo", "sha256": "a"}],
            implementation_hashes={"matcher.py": "b"},
        )
    with pytest.raises(ValueError, match="would change"):
        write_resolved_manifest(
            manifest,
            first,
            source_manifest=None,
            config=CalibrationConfig(
                sample_seed="fixed",
                bootstrap_iterations=0,
            ),
            backends=["ida"],
            compiled_artifacts=[{"binary": "echo", "sha256": "changed"}],
            implementation_hashes={"matcher.py": "b"},
        )
    with pytest.raises(ValueError, match="would change"):
        write_resolved_manifest(
            manifest,
            [_target("b", 0x20)],
            source_manifest=None,
            config=CalibrationConfig(
                sample_seed="fixed",
                bootstrap_iterations=0,
            ),
            backends=["ida"],
            compiled_artifacts=[{"binary": "echo", "sha256": "a"}],
            implementation_hashes={"matcher.py": "b"},
        )


def test_imported_scorer_partition_ids_and_thresholds_are_frozen() -> None:
    config = CalibrationConfig(sample_seed="fixed", bootstrap_iterations=0)
    target = freeze_target_partitions([_target("main", 0x1234, "yes")], config)[0]
    row = {
        "sample_id": stable_hash(
            "lved-function-v1",
            target.project,
            target.hash_parts(),
        ),
        "sample_rank": stable_hash(
            "sha256-rank-v1",
            config.sample_seed,
            target.hash_parts(),
        ),
        "partition": target.partition,
        "function": target.to_dict(),
        "decompilers": {
            "ida": {
                "matching": {
                    "thresholds": {
                        "min_overlap": config.min_overlap,
                        "ambiguity_margin": config.ambiguity_margin,
                    }
                }
            }
        },
    }
    validate_imported_scorer_rows([row], [target], config)

    drifted = dict(row)
    drifted["partition"] = "held_out" if target.partition == "tuning" else "tuning"
    with pytest.raises(ValueError, match="partition changed"):
        validate_imported_scorer_rows([drifted], [target], config)


def test_duplicate_manifest_target_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "sample.jsonl"
    row = {
        "function": {
            "project": "coreutils",
            "optimization": "O2",
            "binary": "yes",
            "address": "0x1234",
            "name": "main",
        }
    }
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="duplicate function target"):
        load_sample_manifest(
            path,
            project="coreutils",
            optimization="O2",
        )


def test_nameless_evidenceful_variable_is_blinded_and_oracle_unknown() -> None:
    source = FunctionEvidence(
        "fixture",
        0x1000,
        0x1010,
        [
            VariableEvidence(
                identity="s:arg",
                name="named",
                arg_index=0,
                kind="arg",
            )
        ],
    )
    decompiled = FunctionEvidence(
        "fixture",
        0x1000,
        0x1010,
        [
            VariableEvidence(
                identity="d:arg",
                name="",
                arg_index=0,
                kind="arg",
            )
        ],
    )
    pairs, function = calibrate_function(
        _target("fixture", 0x1000),
        "ida",
        source,
        decompiled,
        CalibrationConfig(bootstrap_iterations=0),
        instructions=frozenset(),
    )
    assert len(pairs) == 1
    assert pairs[0]["oracle"]["verdict"] == "unknown"
    assert pairs[0]["oracle"]["unknown_reason"]["decompiled"] == "synthetic"
    assert function["controls"]["rename_invariance"]["passed"] is True
    assert function["controls"]["disjoint_address_overlap_zero"]["passed"] is True
    assert function["controls"]["fake_local_increases_distance_by_one"]["passed"] is True
    assert function["controls"]["addresses_are_instructions"]["passed"] is True
    assert function["controls"]["repeated_pair_set_identical"]["passed"] is True


def test_backend_failure_keeps_source_denominator_and_bootstrap_counts() -> None:
    source, decompiled = _oracle_fixture()
    config = CalibrationConfig(bootstrap_iterations=200, bootstrap_seed="two")
    pairs, successful = calibrate_function(
        _target("fixture", 0x1000),
        "ida",
        source,
        decompiled,
        config,
    )
    failed_target = _target("other", 0x2000)
    failed = {
        **successful,
        "status": "backend_error",
        "function": failed_target.to_dict(),
        "cluster_id": failed_target.cluster_id,
        "source_observable": 4,
        "accepted": 0,
        "correct": 0,
        "incorrect": 0,
        "unknown": 0,
        "oracle_decidable_source": 0,
        "oracle_eligible_name_values": [],
    }
    source_error_target = _target("source_bad", 0x3000)
    source_error = {
        **failed,
        "status": "source_error",
        "function": source_error_target.to_dict(),
        "cluster_id": source_error_target.cluster_id,
        "source_observable": None,
    }
    group = aggregate_group(
        [successful, failed, source_error],
        pairs,
        config,
        dimensions=("all", "O2", "ida"),
    )
    overall = group["overall"]
    assert overall["denominators"]["observable_source"] == 10
    assert overall["denominators"]["backend_failure_observable_source_included"] == 4
    assert overall["denominators"]["source_extraction_failures_excluded"] == 1
    assert overall["micro"]["coverage"] == 0.6
    precision_bootstrap = overall["bootstrap_95_function_cluster"]["micro"]["precision"]
    assert 0 < precision_bootstrap["valid_replicates"] < 200
    assert precision_bootstrap["interval_95"] is not None
