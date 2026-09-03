"""Tests for the full-tree GED reevaluation audit."""

import json
import pickle
from pathlib import Path
from types import SimpleNamespace

import networkx as nx
import pytest

from scripts import reeval_ged
from scripts.reeval_ged import (
    LEGACY_AMBIGUOUS,
    LEGACY_RAW,
    LEGACY_SANITIZED,
    build_large_graph_audit,
    build_tasks,
    checkpoint_metadata,
    eval_one,
    historical_overlay_slices,
    load_published_ged_scores,
    migrate_compatible_checkpoints,
    select_ambiguous_legacy_cfg,
    select_legacy_parse_mode,
    source_cache_path,
)


def _large_record(
    *,
    source_nodes: int,
    decompiled_nodes: int,
    method: str,
    isomorphic: bool,
    value: float,
) -> dict:
    return {
        "historical_source_nodes": source_nodes,
        "historical_source_edges": source_nodes + 1,
        "historical_decompiled_nodes": decompiled_nodes,
        "historical_decompiled_edges": decompiled_nodes + 1,
        "historical_over_60": source_nodes > 60 or decompiled_nodes > 60,
        "corrected_source_nodes": source_nodes,
        "corrected_source_edges": source_nodes + 1,
        "corrected_decompiled_nodes": decompiled_nodes,
        "corrected_decompiled_edges": decompiled_nodes + 1,
        "corrected_over_60": source_nodes > 60 or decompiled_nodes > 60,
        "new_value": value,
        "new_perfect": value == 0.0,
        "method": method,
        "isomorphic": isomorphic,
        "approximated": method == "size_lower_bound",
    }


def _graph(nodes: int, edges: int) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_nodes_from(range(nodes))
    candidates = (
        (source, target) for source in range(nodes) for target in range(nodes) if source != target
    )
    for edge in candidates:
        if graph.number_of_edges() == edges:
            break
        graph.add_edge(*edge)
    return graph


def test_promoted_decompilers_keep_builtins_and_selected_external_ids() -> None:
    promoted = reeval_ged.promoted_decompilers(("angr", "mydec", "ghidra@12.1"))

    assert promoted[: len(reeval_ged.CANONICAL_DECOMPILERS)] == (reeval_ged.CANONICAL_DECOMPILERS)
    assert promoted.count("angr") == 1
    assert promoted[-2:] == ("mydec", "ghidra@12.1")


@pytest.mark.parametrize(
    ("baseline", "historical_slices"),
    [
        (None, None),
        ("baseline.json", None),
        (None, "historical-slices.json"),
    ],
)
def test_main_requires_both_frozen_provenance_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    baseline: str | None,
    historical_slices: str | None,
) -> None:
    monkeypatch.setattr(
        reeval_ged.sys,
        "argv",
        ["scripts/reeval_ged.py", str(tmp_path)],
    )
    monkeypatch.delenv("DECBENCH_GED_BASELINE", raising=False)
    monkeypatch.delenv("DECBENCH_GED_HISTORICAL_SLICES", raising=False)
    if baseline is not None:
        monkeypatch.setenv("DECBENCH_GED_BASELINE", baseline)
    if historical_slices is not None:
        monkeypatch.setenv(
            "DECBENCH_GED_HISTORICAL_SLICES",
            historical_slices,
        )

    with pytest.raises(RuntimeError, match="are both required"):
        reeval_ged.main()


def test_legacy_parse_mode_uses_published_candidate_coverage() -> None:
    source = {"f": _graph(136, 196)}
    sanitized = {"f": _graph(98, 148)}

    mode, reason = select_legacy_parse_mode(
        "O2::bash::bash::binja",
        source,
        {},
        sanitized,
        {"f": 86.0},
        sanitizer_changed=True,
    )

    assert mode == LEGACY_SANITIZED
    assert reason == "f:published_candidate_coverage"


def test_checkpoint_metadata_binds_legacy_score_evidence() -> None:
    signature = {
        "schema_version": 6,
        "source_cache_schema": 1,
        "metric_cache_version": "3",
        "ged_max_nodes": 200,
        "audit_threshold": 60,
        "historical_candidate_parse": "legacy-overlay-evidence-reconciled-v3",
    }

    first = checkpoint_metadata(signature, True, {"f": 1.0})
    second = checkpoint_metadata(signature, True, {"f": 2.0})

    assert first["historical_score_evidence_sha256"] != second["historical_score_evidence_sha256"]
    assert (
        checkpoint_metadata(signature, False, {"f": 1.0})["historical_score_evidence_sha256"]
        == "not_applicable"
    )


def test_legacy_parse_mode_reconciles_fallback_sort_style_mismatch() -> None:
    source = {"f": _graph(136, 196)}
    raw = {"f": _graph(95, 144)}
    sanitized = {"f": _graph(98, 148)}

    mode, reason = select_legacy_parse_mode(
        "O2::bash::bash::binja",
        source,
        raw,
        sanitized,
        {"f": 86.0},
        sanitizer_changed=True,
    )

    assert mode == LEGACY_SANITIZED
    assert reason == "f:published_fallback_identity"


def test_legacy_parse_mode_uses_pre_cutoff_vj_score_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = {"copy_attr": _graph(13, 17)}
    raw = {"copy_attr": _graph(27, 37)}
    sanitized = {"copy_attr": _graph(28, 37)}

    def fake_vj_ged(_source: nx.DiGraph, candidate: nx.DiGraph) -> float:
        return 60.0 if candidate.number_of_nodes() == 27 else 61.0

    monkeypatch.setattr("decbench.metrics.vj_ged.vj_ged", fake_vj_ged)

    mode, reason = select_legacy_parse_mode(
        "O0::coreutils::cp::binja",
        source,
        raw,
        sanitized,
        {"copy_attr": 60.0},
        sanitizer_changed=True,
    )

    assert mode == LEGACY_RAW
    assert reason == "copy_attr:published_vj_ged_identity"


def test_legacy_parse_mode_rejects_conflicting_slice_evidence() -> None:
    source = {"raw": _graph(70, 80), "sanitized": _graph(70, 80)}
    raw = {"raw": _graph(65, 75)}
    sanitized = {"sanitized": _graph(65, 75)}

    with pytest.raises(RuntimeError, match="conflicting legacy parse evidence"):
        select_legacy_parse_mode(
            "O2::proj::bin::binja",
            source,
            raw,
            sanitized,
            {"raw": 10.0, "sanitized": 10.0},
            sanitizer_changed=True,
        )


def test_ambiguous_legacy_parse_requires_count_equivalence() -> None:
    source = _graph(136, 196)
    raw = _graph(95, 144)
    sanitized = _graph(94, 145)

    mode, _reason = select_legacy_parse_mode(
        "O2::proj::bin::binja",
        {"f": source},
        {"f": raw},
        {"f": sanitized},
        {"f": 93.0},
        sanitizer_changed=True,
    )

    assert mode == LEGACY_AMBIGUOUS
    with pytest.raises(RuntimeError, match="ambiguous legacy graph sizes"):
        select_ambiguous_legacy_cfg(
            "O2::proj::bin::binja::f",
            source,
            raw,
            sanitized,
            93.0,
        )


def test_ambiguous_small_legacy_graphs_do_not_affect_large_census() -> None:
    source = _graph(13, 17)
    raw = _graph(27, 37)
    sanitized = _graph(28, 37)

    selected = select_ambiguous_legacy_cfg(
        "O0::coreutils::cp::binja::copy_attr",
        source,
        raw,
        sanitized,
        60.0,
    )

    assert selected is raw


def test_large_graph_audit_counts_changes_by_decompiler() -> None:
    angr_key = "O2::bzip2::bzip2::angr::fallbackSort"
    ida_key = "O2::bzip2::bzip2::ida::fallbackSort"
    old = {
        angr_key: {"value": 69.0, "perfect": False},
        ida_key: {"value": 0.0, "perfect": True},
    }
    new = {
        angr_key: {"value": 5.0, "perfect": False},
        ida_key: {"value": 1.0, "perfect": False},
    }
    large = {
        angr_key: _large_record(
            source_nodes=78,
            decompiled_nodes=50,
            method="vj_ged",
            isomorphic=False,
            value=5.0,
        ),
        ida_key: _large_record(
            source_nodes=78,
            decompiled_nodes=78,
            method="size_lower_bound",
            isomorphic=False,
            value=1.0,
        ),
    }

    audit = build_large_graph_audit(
        old,
        new,
        large,
        {
            "schema_version": 4,
            "source_cache_schema": 1,
            "metric_cache_version": "3",
            "ged_max_nodes": 200,
            "audit_threshold": 60,
        },
    )

    total = audit["summary"]["total"]
    assert total["pairs_over_60"] == 2
    assert total["graphs_over_60"] == 3
    assert total["corrected_pairs_over_60"] == 2
    assert total["historical_and_corrected_over_60"] == 2
    assert total["changed_scores"] == 2
    assert total["improved_scores"] == 1
    assert total["worsened_scores"] == 1
    assert total["lost_perfect"] == 1
    assert audit["summary"]["by_decompiler"]["angr"]["new_vj_ged"] == 1
    assert audit["summary"]["by_decompiler"]["ida"]["new_size_lower_bound"] == 1


def test_build_tasks_requires_matching_optimization_source_cache(
    tmp_path: Path,
) -> None:
    root = tmp_path / "results"
    src_dir = root / "ged_src" / "v1"
    o0_cache = source_cache_path(src_dir, "O0", "proj")
    o0_cache.parent.mkdir(parents=True)
    o0_cache.write_bytes(b"cache")
    historical_cache = root / "ged_src" / "proj.pkl"
    historical_cache.write_bytes(b"historical")
    artifacts = [
        ("O0", "proj", "bin", "angr", "/tmp/o0.c"),
        ("O2", "proj", "bin", "angr", "/tmp/o2.c"),
    ]

    tasks, missing = build_tasks(
        root,
        src_dir,
        artifacts,
        old_scores={"O0::proj::bin::angr::f": {"value": 7.0}},
    )

    assert len(tasks) == 1
    assert tasks[0][0] == "O0"
    assert tasks[0][5] == str(o0_cache)
    assert tasks[0][6] == str(historical_cache)
    assert tasks[0][7] is False
    assert tasks[0][8] == {"f": 7.0}
    assert missing == [("O2", "proj")]


def test_large_graph_audit_separates_historical_and_corrected_thresholds() -> None:
    historical_key = "O2::proj::bin::angr::historical"
    corrected_key = "O2::proj::bin::angr::corrected"
    historical = _large_record(
        source_nodes=70,
        decompiled_nodes=50,
        method="vj_ged",
        isomorphic=False,
        value=2.0,
    )
    historical["corrected_source_nodes"] = 50
    historical["corrected_over_60"] = False
    corrected = _large_record(
        source_nodes=50,
        decompiled_nodes=50,
        method="vj_ged",
        isomorphic=False,
        value=2.0,
    )
    corrected["corrected_source_nodes"] = 70
    corrected["corrected_over_60"] = True
    audit = build_large_graph_audit(
        {
            historical_key: {"value": 10.0, "perfect": False},
            corrected_key: {"value": 10.0, "perfect": False},
        },
        {
            historical_key: {"value": 2.0, "perfect": False},
            corrected_key: {"value": 2.0, "perfect": False},
        },
        {historical_key: historical, corrected_key: corrected},
        {
            "schema_version": 4,
            "source_cache_schema": 1,
            "metric_cache_version": "3",
            "ged_max_nodes": 200,
            "audit_threshold": 60,
        },
    )

    total = audit["summary"]["total"]
    assert total["pairs_over_60"] == 1
    assert total["corrected_pairs_over_60"] == 1
    assert total["historical_only_over_60"] == 1
    assert total["corrected_only_over_60"] == 1


def test_large_graph_audit_accepts_missing_corrected_score() -> None:
    key = "O2::proj::bin::angr::large"
    record = _large_record(
        source_nodes=61,
        decompiled_nodes=62,
        method="vj_ged",
        isomorphic=False,
        value=1.0,
    )
    record.update(
        {
            "corrected_decompiled_nodes": None,
            "corrected_decompiled_edges": None,
            "corrected_over_60": False,
            "new_value": None,
            "new_perfect": None,
            "method": None,
            "isomorphic": None,
            "approximated": None,
        }
    )

    audit = build_large_graph_audit(
        {key: {"value": 2.0, "perfect": False}},
        {},
        {key: record},
        {
            "schema_version": 4,
            "source_cache_schema": 1,
            "metric_cache_version": "3",
            "ged_max_nodes": 200,
            "audit_threshold": 60,
        },
    )

    total = audit["summary"]["total"]
    assert total["new_score_missing"] == 1
    assert total["confirmed_isomorphic"] == 0


def test_historical_overlay_sidecar_is_authoritative(tmp_path: Path) -> None:
    (tmp_path / "ged_new.json").write_text('{"O0::proj::bin::angr::f": {"value": 0.0}}')
    (tmp_path / "ged_new.slices.json").write_text('["O2::proj::bin::claude-code"]')

    assert historical_overlay_slices(tmp_path) == {"O2::proj::bin::claude-code"}


def test_published_scores_can_use_a_frozen_baseline(tmp_path: Path) -> None:
    root = tmp_path / "results"
    root.mkdir()
    current = {
        "groups": [
            {
                "opt_level": "O0",
                "project": "proj",
                "binary": "bin",
                "functions": [
                    {
                        "function": "func",
                        "values": {"angr": {"ged": 7.0}},
                        "perfects": {"angr": {"ged": False}},
                    }
                ],
            }
        ]
    }
    frozen = {
        "groups": [
            {
                "opt_level": "O0",
                "project": "proj",
                "binary": "bin",
                "functions": [
                    {
                        "function": "func",
                        "values": {"angr": {"ged": 3.0}},
                        "perfects": {"angr": {"ged": False}},
                    }
                ],
            }
        ]
    }
    (root / "function_results.json").write_text(json.dumps(current))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(frozen))

    assert load_published_ged_scores(root)["O0::proj::bin::angr::func"]["value"] == 7.0
    assert (
        load_published_ged_scores(root, baseline_path)["O0::proj::bin::angr::func"]["value"] == 3.0
    )


def test_schema5_migration_replays_only_legacy_sanitizer_changes(
    tmp_path: Path,
) -> None:
    checkpoint_dir = tmp_path / "reeval_ged"
    checkpoint_dir.mkdir()
    source = tmp_path / "current.pkl"
    historical = tmp_path / "historical.pkl"
    source.write_bytes(b"current")
    historical.write_bytes(b"historical")
    plain = tmp_path / "plain.c"
    sensitive = tmp_path / "sensitive.c"
    plain.write_text("int f(void) { return 0; }\n")
    sensitive.write_text("__int128 f(void) { return 0; }\n")
    signature = {
        "schema_version": 6,
        "source_cache_schema": 1,
        "metric_cache_version": "3",
        "ged_max_nodes": 200,
        "audit_threshold": 60,
        "historical_candidate_parse": "legacy-overlay-evidence-reconciled-v3",
    }
    prior = dict(signature)
    prior["schema_version"] = 5
    prior["historical_candidate_parse"] = "legacy-overlay-raw-v1"
    tasks = [
        (
            "O2",
            "proj",
            "plain",
            "ida",
            str(plain),
            str(source),
            str(historical),
            True,
            {},
        ),
        (
            "O2",
            "proj",
            "sensitive",
            "ida",
            str(sensitive),
            str(source),
            str(historical),
            True,
            {},
        ),
    ]
    for task in tasks:
        key = f"{task[0]}__{task[1]}__{task[2]}__{task[3]}"
        (checkpoint_dir / f"{key}.json").write_text(
            json.dumps({"_meta": prior, "scores": {}, "over_previous_limit": {}})
        )

    migrated, require_replay = migrate_compatible_checkpoints(
        checkpoint_dir,
        tasks,
        signature,
    )

    assert (migrated, require_replay) == (1, 1)
    plain_payload = json.loads((checkpoint_dir / "O2__proj__plain__ida.json").read_text())
    sensitive_payload = json.loads((checkpoint_dir / "O2__proj__sensitive__ida.json").read_text())
    assert plain_payload["_meta"] == checkpoint_metadata(signature, True)
    assert sensitive_payload["_meta"] == prior


def test_checkpoint_migration_rejects_stored_source_basis_disagreement(
    tmp_path: Path,
) -> None:
    checkpoint_dir = tmp_path / "reeval_ged"
    checkpoint_dir.mkdir()
    artifact = tmp_path / "candidate.c"
    source = tmp_path / "current.pkl"
    historical = tmp_path / "historical.pkl"
    artifact.write_text("int f(void) { return 0; }\n")
    source.write_bytes(b"current")
    historical.write_bytes(b"historical")
    signature = {
        "schema_version": 6,
        "source_cache_schema": 1,
        "metric_cache_version": "3",
        "ged_max_nodes": 200,
        "audit_threshold": 60,
        "historical_candidate_parse": "legacy-overlay-evidence-reconciled-v3",
    }
    prior = dict(signature)
    prior["schema_version"] = 5
    prior["historical_candidate_parse"] = "legacy-overlay-raw-v1"
    checkpoint = checkpoint_dir / "O2__proj__bin__angr.json"
    checkpoint.write_text(
        json.dumps(
            {
                "_meta": prior,
                "scores": {},
                "over_previous_limit": {"f": {"historical_source_basis": "legacy_overlay"}},
            }
        )
    )
    task = (
        "O2",
        "proj",
        "bin",
        "angr",
        str(artifact),
        str(source),
        str(historical),
        False,
        {},
    )

    migrated, require_replay = migrate_compatible_checkpoints(
        checkpoint_dir,
        [task],
        signature,
    )

    assert (migrated, require_replay) == (0, 1)
    assert json.loads(checkpoint.read_text())["_meta"] == prior


def test_schema5_inline_checkpoint_migrates_despite_sanitizer_change(
    tmp_path: Path,
) -> None:
    checkpoint_dir = tmp_path / "reeval_ged"
    checkpoint_dir.mkdir()
    artifact = tmp_path / "candidate.c"
    source = tmp_path / "current.pkl"
    historical = tmp_path / "historical.pkl"
    artifact.write_text("__int128 f(void) { return 0; }\n")
    source.write_bytes(b"current")
    historical.write_bytes(b"historical")
    signature = {
        "schema_version": 6,
        "source_cache_schema": 1,
        "metric_cache_version": "3",
        "ged_max_nodes": 200,
        "audit_threshold": 60,
        "historical_candidate_parse": "legacy-overlay-evidence-reconciled-v3",
    }
    prior_signature = dict(signature)
    prior_signature["schema_version"] = 5
    prior_signature["historical_candidate_parse"] = "legacy-overlay-raw-v1"
    checkpoint = checkpoint_dir / "O2__proj__bin__angr.json"
    checkpoint.write_text(
        json.dumps(
            {
                "_meta": {
                    **prior_signature,
                    "historical_source_basis": "same_opt_inline",
                },
                "scores": {},
                "over_previous_limit": {
                    "f": {
                        "historical_source_basis": "same_opt_inline",
                        "historical_decompiled_nodes": 61,
                    }
                },
            }
        )
    )
    task = (
        "O2",
        "proj",
        "bin",
        "angr",
        str(artifact),
        str(source),
        str(historical),
        False,
        {},
    )

    migrated, require_replay = migrate_compatible_checkpoints(
        checkpoint_dir,
        [task],
        signature,
    )

    assert (migrated, require_replay) == (1, 0)
    payload = json.loads(checkpoint.read_text())
    assert payload["_meta"] == checkpoint_metadata(signature, False)
    record = payload["over_previous_limit"]["f"]
    assert record["historical_decompiled_parse_mode"] == "sanitized_without_macro_expansion"
    assert record["historical_raw_candidate_present"] is False
    assert record["historical_sanitized_candidate_present"] is True


def test_eval_one_requires_every_frozen_row_to_be_reconstructable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "candidate.c"
    artifact.write_text(
        "// Function: present @ 0x1\n"
        "int present(void) { return 0; }\n"
        "// Function: missing @ 0x2\n"
        "int missing(void) { return 0; }\n"
    )
    source_cfgs = {
        "present": _graph(2, 1),
        "missing": _graph(2, 1),
    }
    current_source = tmp_path / "current.pkl"
    historical_source = tmp_path / "historical.pkl"
    current_source.write_bytes(pickle.dumps({"bin": source_cfgs}))
    historical_source.write_bytes(pickle.dumps({"bin": source_cfgs}))
    candidate_cfgs = {"present": _graph(2, 1)}

    monkeypatch.setattr(
        "decbench.utils.cfg.extract_cfgs_from_source",
        lambda *_args, **_kwargs: candidate_cfgs,
    )

    task = (
        "O2",
        "proj",
        "bin",
        "angr",
        str(artifact),
        str(current_source),
        str(historical_source),
        True,
        {"present": 0.0, "missing": 0.0},
    )

    with pytest.raises(
        RuntimeError,
        match=r"cannot reconstruct all published legacy scores: .*candidates=\['missing'\]",
    ):
        eval_one(task)


def test_eval_one_rejects_reconstructed_fallback_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "candidate.c"
    artifact.write_text("// Function: f @ 0x1\n" "int f(void) { return 0; }\n")
    source_cfgs = {"f": _graph(61, 62)}
    candidate_cfgs = {"f": _graph(60, 60)}
    current_source = tmp_path / "current.pkl"
    historical_source = tmp_path / "historical.pkl"
    current_source.write_bytes(pickle.dumps({"bin": source_cfgs}))
    historical_source.write_bytes(pickle.dumps({"bin": source_cfgs}))

    monkeypatch.setattr(
        "decbench.utils.cfg.extract_cfgs_from_source",
        lambda *_args, **_kwargs: candidate_cfgs,
    )
    monkeypatch.setattr(
        "decbench.metrics.ged.GEDMetric.compute_for_function",
        lambda *_args, **_kwargs: SimpleNamespace(
            value=3.0,
            metadata={
                "method": "vj_ged",
                "isomorphic": False,
                "approximated": False,
            },
        ),
    )

    task = (
        "O2",
        "proj",
        "bin",
        "angr",
        str(artifact),
        str(current_source),
        str(historical_source),
        True,
        {"f": 4.0},
    )

    with pytest.raises(
        RuntimeError,
        match=r"cannot reproduce published fallback 4\.0: reconstructed=3",
    ):
        eval_one(task)


def test_eval_one_uses_dwarf_tu_ownership_for_corrected_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decompiled = tmp_path / "O0" / "shadow" / "decompiled"
    decompiled.mkdir(parents=True)
    artifact = decompiled / "angr_new_subid_range.c"
    artifact.write_text("// Function: main @ 0x12da\nint main(void) { return 0; }\n")
    current_source = tmp_path / "current.pkl"
    current_source.write_bytes(
        pickle.dumps(
            {
                "per_stem": {
                    "new_subid_range-new_subid_range": {"main": _graph(4, 3)},
                    "login": {"main": _graph(40, 39)},
                }
            }
        )
    )
    candidate_cfg = _graph(4, 3)
    monkeypatch.setattr(
        "decbench.utils.results_tree.resolve_binary",
        lambda *_args: tmp_path / "O0" / "shadow" / "compiled" / "new_subid_range",
    )
    monkeypatch.setattr(
        "decbench.utils.binfmt.source_function_owners",
        lambda *_args, **_kwargs: {0x12DA: ("main", "new_subid_range-new_subid_range")},
    )
    monkeypatch.setattr(
        "decbench.utils.cfg.extract_cfgs_from_source",
        lambda *_args, **_kwargs: {"main": candidate_cfg},
    )
    seen: list[int] = []

    def compute(_self, _result, *, source_cfg, decompiled_cfg):
        assert decompiled_cfg is candidate_cfg
        seen.append(source_cfg.number_of_nodes())
        return SimpleNamespace(
            value=0.0,
            metadata={"method": "vj_ged", "isomorphic": True, "approximated": False},
        )

    monkeypatch.setattr("decbench.metrics.ged.GEDMetric.compute_for_function", compute)

    key, scores, _audit = eval_one(
        (
            "O0",
            "shadow",
            "new_subid_range",
            "angr",
            str(artifact),
            str(current_source),
            "",
            False,
            {},
        )
    )

    assert key == "O0::shadow::new_subid_range::angr"
    assert scores == {"main": {"value": 0.0, "perfect": True}}
    assert seen == [4]


def test_checkpoint_schema_tracks_dwarf_tu_ownership(tmp_path: Path) -> None:
    assert reeval_ged.checkpoint_signature()["schema_version"] == 7

    checkpoint_dir = tmp_path / "reeval_ged"
    checkpoint_dir.mkdir()
    artifact = tmp_path / "candidate.c"
    source = tmp_path / "current.pkl"
    historical = tmp_path / "historical.pkl"
    artifact.write_text("int f(void) { return 0; }\n")
    source.write_bytes(b"current")
    historical.write_bytes(b"historical")
    signature = reeval_ged.checkpoint_signature()
    prior = dict(signature)
    prior["schema_version"] = 5
    prior["historical_candidate_parse"] = "legacy-overlay-raw-v1"
    checkpoint = checkpoint_dir / "O2__proj__bin__angr.json"
    checkpoint.write_text(json.dumps({"_meta": prior, "scores": {}, "over_previous_limit": {}}))
    task = (
        "O2",
        "proj",
        "bin",
        "angr",
        str(artifact),
        str(source),
        str(historical),
        False,
        {},
    )

    migrated, require_replay = migrate_compatible_checkpoints(
        checkpoint_dir,
        [task],
        signature,
    )

    assert (migrated, require_replay) == (0, 0)
    assert json.loads(checkpoint.read_text())["_meta"] == prior


def test_checkpoint_migration_rejects_stored_fallback_mismatch(
    tmp_path: Path,
) -> None:
    checkpoint_dir = tmp_path / "reeval_ged"
    checkpoint_dir.mkdir()
    artifact = tmp_path / "candidate.c"
    current_source = tmp_path / "current.pkl"
    historical_source = tmp_path / "historical.pkl"
    artifact.write_text("int f(void) { return 0; }\n")
    current_source.write_bytes(b"current")
    historical_source.write_bytes(b"historical")
    signature = {
        "schema_version": 6,
        "source_cache_schema": 1,
        "metric_cache_version": "3",
        "ged_max_nodes": 200,
        "audit_threshold": 60,
        "historical_candidate_parse": "legacy-overlay-evidence-reconciled-v3",
    }
    prior = dict(signature)
    prior["schema_version"] = 5
    prior["historical_candidate_parse"] = "legacy-overlay-raw-v1"
    checkpoint = checkpoint_dir / "O2__proj__bin__angr.json"
    checkpoint.write_text(
        json.dumps(
            {
                "_meta": {
                    **prior,
                    "historical_source_basis": "same_opt_inline",
                },
                "scores": {},
                "over_previous_limit": {
                    "f": {
                        "historical_source_basis": "same_opt_inline",
                        "historical_over_60": True,
                        "historical_source_nodes": 70,
                        "historical_source_edges": 80,
                        "historical_decompiled_nodes": 65,
                        "historical_decompiled_edges": 75,
                    }
                },
            }
        )
    )
    task = (
        "O2",
        "proj",
        "bin",
        "angr",
        str(artifact),
        str(current_source),
        str(historical_source),
        False,
        {"f": 9.0},
    )

    migrated, require_replay = migrate_compatible_checkpoints(
        checkpoint_dir,
        [task],
        signature,
    )

    assert (migrated, require_replay) == (0, 1)
    assert json.loads(checkpoint.read_text())["_meta"] == {
        **prior,
        "historical_source_basis": "same_opt_inline",
    }
