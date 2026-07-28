"""Tests for the standalone historical large-CFG isomorphism audit."""

from __future__ import annotations

import hashlib
import json
import pickle
from pathlib import Path

import networkx as nx
import pytest

from scripts import audit_historical_ged_iso as historical_iso


def _record(
    *,
    historical_source: tuple[int, int],
    historical_decompiled: tuple[int, int],
    corrected_isomorphic: bool = False,
) -> dict:
    return {
        "historical_source_nodes": historical_source[0],
        "historical_source_edges": historical_source[1],
        "historical_decompiled_nodes": historical_decompiled[0],
        "historical_decompiled_edges": historical_decompiled[1],
        "historical_over_60": True,
        "historical_source_basis": "legacy_overlay",
        "historical_decompiled_parse_mode": "legacy_raw",
        "historical_parse_selection_reason": "sanitizer_noop",
        "historical_raw_candidate_present": True,
        "historical_sanitized_candidate_present": True,
        "corrected_source_nodes": historical_source[0],
        "corrected_source_edges": historical_source[1],
        "corrected_decompiled_nodes": historical_decompiled[0],
        "corrected_decompiled_edges": historical_decompiled[1],
        "corrected_over_60": True,
        "new_value": 0.0 if corrected_isomorphic else 1.0,
        "new_perfect": corrected_isomorphic,
        "method": "isomorphism" if corrected_isomorphic else "vj_ged",
        "isomorphic": corrected_isomorphic,
        "approximated": False,
    }


def _path_graph(nodes: int) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_nodes_from(range(nodes))
    graph.add_edges_from((index, index + 1) for index in range(nodes - 1))
    return graph


def _cycle_partition(nodes: int, split: int) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_nodes_from(range(nodes))
    first = list(range(split))
    second = list(range(split, nodes))
    graph.add_edges_from(zip(first, first[1:] + first[:1], strict=True))
    graph.add_edges_from(zip(second, second[1:] + second[:1], strict=True))
    return graph


def _write_source_cache(path: Path, graph: nx.DiGraph) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pickle.dumps({"per_stem": {"bin": {"f": graph}}}))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _audit_for_record(key: str, record: dict, old_value: float) -> dict:
    return {
        "summary": {
            "total": {"confirmed_isomorphic": 0},
            "by_decompiler": {"angr": {"confirmed_isomorphic": 0}},
        },
        "records": {
            key: {
                **record,
                "old_value": old_value,
                "old_perfect": old_value == 0.0,
                "new_value": record["new_value"],
                "new_perfect": record["new_perfect"],
                "changed": old_value != record["new_value"],
            }
        },
    }


def _networkx_proof(
    *,
    isomorphic: bool = False,
    counts_match: bool = True,
    ambiguous: bool = False,
) -> dict:
    return {
        "historical_isomorphic": isomorphic,
        "historical_iso_proof": (
            "directed_role_aware_networkx_replay_both_legacy_modes"
            if ambiguous
            else "directed_role_aware_networkx_replay"
        ),
        "historical_replay_verified": True,
        "historical_networkx_calls": 2 if ambiguous else 1,
        "historical_graph_counts_match": counts_match,
    }


def _proof_counts(
    *,
    pairs: int = 1,
    calls: int = 1,
    mismatches: int = 0,
    slices: int = 1,
) -> dict[str, int]:
    return {
        "historical_large_pairs": pairs,
        "networkx_replayed_pairs": pairs,
        "networkx_isomorphism_calls": calls,
        "networkx_replay_slices": slices,
        "count_mismatch_networkx_replays": mismatches,
    }


def test_every_historical_large_pair_is_a_replay_target() -> None:
    node_key = "O2::proj::bin::angr::nodes"
    edge_key = "O2::proj::bin::angr::edges"
    equal_key = "O2::proj::bin::angr::equal"
    records = {
        node_key: _record(
            historical_source=(61, 70),
            historical_decompiled=(62, 70),
        ),
        edge_key: _record(
            historical_source=(61, 70),
            historical_decompiled=(61, 71),
        ),
        equal_key: _record(
            historical_source=(61, 70),
            historical_decompiled=(61, 70),
        ),
    }

    replay = historical_iso.historical_iso_targets(records)

    assert set(replay) == {"O2::proj::bin::angr"}
    assert set(replay["O2::proj::bin::angr"]) == {"nodes", "edges", "equal"}


@pytest.mark.parametrize(
    ("candidate", "candidate_size"),
    [
        (_path_graph(62), (62, 61)),
        (nx.cycle_graph(61, create_using=nx.DiGraph), (61, 61)),
    ],
)
def test_unequal_count_replay_calls_exact_isomorphism(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate: nx.DiGraph,
    candidate_size: tuple[int, int],
) -> None:
    source = _path_graph(61)
    legacy = tmp_path / "legacy.pkl"
    _write_source_cache(legacy, source)
    artifact = tmp_path / "angr_bin.c"
    artifact.write_text("// Function: f @ 0x1000\nint f(void) { return 0; }\n")
    monkeypatch.setattr(
        historical_iso,
        "extract_cfgs_from_source",
        lambda *_args, **_kwargs: {"f": candidate},
    )
    calls: list[tuple[tuple[int, int], tuple[int, int]]] = []

    def replay(source_cfg: nx.DiGraph, decompiled_cfg: nx.DiGraph) -> bool:
        calls.append(
            (
                (source_cfg.number_of_nodes(), source_cfg.number_of_edges()),
                (
                    decompiled_cfg.number_of_nodes(),
                    decompiled_cfg.number_of_edges(),
                ),
            )
        )
        return False

    monkeypatch.setattr(historical_iso, "_is_isomorphic", replay)
    record = _record(
        historical_source=(61, 60),
        historical_decompiled=candidate_size,
    )
    task: historical_iso.ReplayTask = (
        "O2::proj::bin::angr",
        str(artifact),
        "",
        str(legacy),
        {"f": record},
        {},
    )

    _slice, proofs, _metadata = historical_iso.eval_historical_iso_one(task)

    assert calls == [((61, 60), candidate_size)]
    assert proofs["f"] == _networkx_proof(counts_match=False)


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        (nx.relabel_nodes(nx.cycle_graph(61, create_using=nx.DiGraph), lambda n: n + 100), True),
        (_cycle_partition(61, 30), False),
    ],
)
def test_equal_count_replay_runs_exact_isomorphism(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate: nx.DiGraph,
    expected: bool,
) -> None:
    source = nx.cycle_graph(61, create_using=nx.DiGraph)
    legacy = tmp_path / "legacy.pkl"
    _write_source_cache(legacy, source)
    artifact = tmp_path / "angr_bin.c"
    artifact.write_text("// Function: f @ 0x1000\nint f(void) { return 0; }\n")
    monkeypatch.setattr(
        historical_iso,
        "extract_cfgs_from_source",
        lambda *_args, **_kwargs: {"f": candidate},
    )
    record = _record(
        historical_source=(61, 61),
        historical_decompiled=(61, 61),
    )
    task: historical_iso.ReplayTask = (
        "O2::proj::bin::angr",
        str(artifact),
        "",
        str(legacy),
        {"f": record},
        {"signature": "test"},
    )

    _slice, proofs, metadata = historical_iso.eval_historical_iso_one(task)

    assert proofs["f"]["historical_isomorphic"] is expected
    assert proofs["f"]["historical_replay_verified"] is True
    assert metadata == {"signature": "test"}


def test_replay_rejects_changed_graph_sizes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _path_graph(61)
    legacy = tmp_path / "legacy.pkl"
    _write_source_cache(legacy, source)
    artifact = tmp_path / "angr_bin.c"
    artifact.write_text("// Function: f @ 0x1000\nint f(void) { return 0; }\n")
    monkeypatch.setattr(
        historical_iso,
        "extract_cfgs_from_source",
        lambda *_args, **_kwargs: {"f": _path_graph(60)},
    )
    record = _record(
        historical_source=(61, 60),
        historical_decompiled=(61, 60),
    )
    task: historical_iso.ReplayTask = (
        "O2::proj::bin::angr",
        str(artifact),
        "",
        str(legacy),
        {"f": record},
        {},
    )

    with pytest.raises(RuntimeError, match="decompiled sizes changed"):
        historical_iso.eval_historical_iso_one(task)


def test_replay_uses_same_optimization_source_basis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _path_graph(61)
    current = tmp_path / "current.pkl"
    _write_source_cache(current, source)
    artifact = tmp_path / "angr_bin.c"
    artifact.write_text("// Function: f @ 0x1000\nint f(void) { return 0; }\n")
    monkeypatch.setattr(
        historical_iso,
        "extract_cfgs_from_source",
        lambda *_args, **_kwargs: {"f": nx.relabel_nodes(source, lambda node: node + 100)},
    )
    record = _record(
        historical_source=(61, 60),
        historical_decompiled=(61, 60),
    )
    record["historical_source_basis"] = "same_opt_inline"
    task: historical_iso.ReplayTask = (
        "O2::proj::bin::angr",
        str(artifact),
        str(current),
        "",
        {"f": record},
        {},
    )

    _slice, proofs, _metadata = historical_iso.eval_historical_iso_one(task)

    assert proofs["f"]["historical_isomorphic"] is True


def test_replay_uses_raw_candidate_for_legacy_overlay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _path_graph(61)
    legacy = tmp_path / "legacy.pkl"
    _write_source_cache(legacy, source)
    artifact = tmp_path / "ida_bin.c"
    artifact.write_text("// Function: f @ 0x1000\n__int128 f(void) { return 0; }\n")
    calls: list[bool] = []

    def extract(*_args: object, **kwargs: object) -> dict:
        calls.append(bool(kwargs["sanitize_decompiled"]))
        return {"f": source}

    monkeypatch.setattr(historical_iso, "extract_cfgs_from_source", extract)
    record = _record(
        historical_source=(61, 60),
        historical_decompiled=(61, 60),
    )
    task: historical_iso.ReplayTask = (
        "O2::proj::bin::ida",
        str(artifact),
        "",
        str(legacy),
        {"f": record},
        {},
    )

    historical_iso.eval_historical_iso_one(task)

    assert calls == [False]


def test_replay_uses_sanitized_candidate_for_reconciled_legacy_overlay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _path_graph(61)
    legacy = tmp_path / "legacy.pkl"
    _write_source_cache(legacy, source)
    artifact = tmp_path / "binja_bin.c"
    artifact.write_text("// Function: f @ 0x1000\nint f(void) { return 0; }\n")
    calls: list[tuple[bool, bool]] = []

    def extract(*_args: object, **kwargs: object) -> dict:
        calls.append(
            (
                bool(kwargs["sanitize_decompiled"]),
                bool(kwargs["preprocess_decompiled"]),
            )
        )
        return {"f": source}

    monkeypatch.setattr(historical_iso, "extract_cfgs_from_source", extract)
    record = _record(
        historical_source=(61, 60),
        historical_decompiled=(61, 60),
    )
    record["historical_decompiled_parse_mode"] = "legacy_sanitized"
    task: historical_iso.ReplayTask = (
        "O2::proj::bin::binja",
        str(artifact),
        "",
        str(legacy),
        {"f": record},
        {},
    )

    historical_iso.eval_historical_iso_one(task)

    assert calls == [(True, False)]


def test_ambiguous_legacy_replay_requires_both_modes_to_agree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _path_graph(61)
    legacy = tmp_path / "legacy.pkl"
    _write_source_cache(legacy, source)
    artifact = tmp_path / "binja_bin.c"
    artifact.write_text("// Function: f @ 0x1000\nint f(void) { return 0; }\n")
    calls: list[bool] = []

    def extract(*_args: object, **kwargs: object) -> dict:
        calls.append(bool(kwargs["sanitize_decompiled"]))
        return {"f": nx.relabel_nodes(source, lambda node: node + len(calls) * 100)}

    monkeypatch.setattr(historical_iso, "extract_cfgs_from_source", extract)
    record = _record(
        historical_source=(61, 60),
        historical_decompiled=(61, 60),
    )
    record["historical_decompiled_parse_mode"] = "legacy_raw_or_sanitized_same_fallback"
    task: historical_iso.ReplayTask = (
        "O2::proj::bin::binja",
        str(artifact),
        "",
        str(legacy),
        {"f": record},
        {},
    )

    _slice, proofs, _metadata = historical_iso.eval_historical_iso_one(task)

    assert calls == [False, True]
    assert proofs["f"]["historical_isomorphic"] is True
    assert (
        proofs["f"]["historical_iso_proof"]
        == "directed_role_aware_networkx_replay_both_legacy_modes"
    )
    assert proofs["f"]["historical_networkx_calls"] == 2


def test_replay_propagates_strict_parser_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = tmp_path / "legacy.pkl"
    _write_source_cache(legacy, _path_graph(61))
    artifact = tmp_path / "angr_bin.c"
    artifact.write_text("// Function: f @ 0x1000\nint f(void) { return 0; }\n")

    def fail_parse(*_args: object, **_kwargs: object) -> dict:
        raise RuntimeError("strict Joern failure")

    monkeypatch.setattr(historical_iso, "extract_cfgs_from_source", fail_parse)
    record = _record(
        historical_source=(61, 60),
        historical_decompiled=(61, 60),
    )
    task: historical_iso.ReplayTask = (
        "O2::proj::bin::angr",
        str(artifact),
        "",
        str(legacy),
        {"f": record},
        {},
    )

    with pytest.raises(RuntimeError, match="strict Joern failure"):
        historical_iso.eval_historical_iso_one(task)


def test_replay_dependency_metadata_invalidates_changed_inputs(tmp_path: Path) -> None:
    root = tmp_path / "results"
    artifact = root / "O2/proj/decompiled/angr_bin.c"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("first")
    score_checkpoint = root / "reeval_ged/O2__proj__bin__angr.json"
    score_checkpoint.parent.mkdir()
    score_checkpoint.write_text("{}")
    legacy = root / "ged_src/proj.pkl"
    legacy.parent.mkdir()
    legacy.write_bytes(b"source")
    targets = {
        "f": _record(
            historical_source=(61, 61),
            historical_decompiled=(61, 61),
        )
    }

    before = historical_iso.replay_dependency_meta(
        root,
        "O2::proj::bin::angr",
        artifact,
        score_checkpoint,
        targets,
    )
    artifact.write_text("second")
    after = historical_iso.replay_dependency_meta(
        root,
        "O2::proj::bin::angr",
        artifact,
        score_checkpoint,
        targets,
    )

    assert before["artifact_sha256"] != after["artifact_sha256"]
    assert before["ged_checkpoint_sha256"] == after["ged_checkpoint_sha256"]
    assert before["source_cache_sha256"] == after["source_cache_sha256"]


def test_replay_checkpoint_must_cover_exact_targets(tmp_path: Path) -> None:
    path = tmp_path / "proof.json"
    metadata = {"schema_version": 1}
    proof = _networkx_proof()
    path.write_text(json.dumps({"_meta": metadata, "proofs": {"f": proof}}))

    assert historical_iso.valid_replay_checkpoint(path, metadata, {"f"}) == {"f": proof}
    assert historical_iso.valid_replay_checkpoint(path, metadata, {"f", "g"}) is None
    assert (
        historical_iso.valid_replay_checkpoint(
            path,
            {"schema_version": 2},
            {"f"},
        )
        is None
    )


def test_corrected_status_uses_historical_over_60_population() -> None:
    key = "O2::proj::bin::angr::f"
    record = _record(
        historical_source=(61, 70),
        historical_decompiled=(60, 69),
        corrected_isomorphic=True,
    )
    record.update(
        {
            "corrected_source_nodes": 50,
            "corrected_source_edges": 55,
            "corrected_decompiled_nodes": 50,
            "corrected_decompiled_edges": 55,
            "corrected_over_60": False,
        }
    )
    proof = _networkx_proof(counts_match=False)

    enriched = historical_iso.enrich_audit(
        _audit_for_record(key, record, old_value=2.0),
        {key: record},
        {key: proof},
        _proof_counts(mismatches=1),
    )

    total = enriched["summary"]["total"]
    assert total["corrected_isomorphic_for_historical_over_60"] == 1
    assert total["corrected_nonisomorphic_for_historical_over_60"] == 0
    assert total["corrected_isomorphism_unavailable_for_historical_over_60"] == 0


def test_equal_count_nonisomorphic_old_zero_is_false_perfect() -> None:
    key = "O2::proj::bin::angr::f"
    record = _record(
        historical_source=(61, 61),
        historical_decompiled=(61, 61),
    )
    proof = _networkx_proof()

    enriched = historical_iso.enrich_audit(
        _audit_for_record(key, record, old_value=0.0),
        {key: record},
        {key: proof},
        _proof_counts(),
    )

    total = enriched["summary"]["total"]
    assert total["historical_confirmed_nonisomorphic"] == 1
    assert total["historical_false_perfect"] == 1
    assert enriched["summary"]["by_decompiler"]["angr"]["historical_false_perfect"] == 1


def test_published_fallback_mismatch_does_not_claim_reconstructed_identity() -> None:
    key = "O2::coreutils::factor::ida::factor_using_pollard_rho2"
    record = _record(
        historical_source=(112, 178),
        historical_decompiled=(64, 95),
    )
    reconstructed_proof = _networkx_proof(counts_match=False)

    enriched = historical_iso.enrich_audit(
        _audit_for_record(key, record, old_value=138.0),
        {key: record},
        {key: reconstructed_proof},
        _proof_counts(mismatches=1),
    )

    enriched_record = enriched["records"][key]
    assert enriched_record["historical_size_fallback_expected_from_reconstruction"] == 131
    assert enriched_record["historical_size_fallback_matches_published"] is False
    assert (
        enriched_record["historical_size_reconstruction_provenance"]
        == "published_fallback_differs_from_reconstructed_sizes"
    )
    assert enriched_record["historical_isomorphic"] is False
    assert enriched_record["historical_iso_proof"] == "directed_role_aware_networkx_replay"
    total = enriched["summary"]["total"]
    assert total["historical_count_mismatch_networkx_replays"] == 1
    assert total["historical_reconstructed_fallback_mismatches_published"] == 1


def test_fallback_mismatch_is_not_counted_as_historical_false_perfect() -> None:
    key = "O2::proj::bin::angr::f"
    record = _record(
        historical_source=(61, 70),
        historical_decompiled=(60, 69),
    )
    proof = _networkx_proof(counts_match=False)

    enriched = historical_iso.enrich_audit(
        _audit_for_record(key, record, old_value=0.0),
        {key: record},
        {key: proof},
        _proof_counts(mismatches=1),
    )

    assert enriched["summary"]["total"]["historical_false_perfect"] == 0
    assert (
        enriched["summary"]["total"]["historical_reconstructed_fallback_mismatches_published"] == 1
    )


def test_new_only_historical_reconstruction_has_no_published_identity() -> None:
    key = "O2::proj::bin::manifold::f"
    record = _record(
        historical_source=(61, 70),
        historical_decompiled=(60, 69),
    )
    proof = _networkx_proof(counts_match=False)
    audit = _audit_for_record(key, record, old_value=2.0)
    audit["records"][key]["old_value"] = None
    audit["records"][key]["old_perfect"] = False
    audit["summary"]["by_decompiler"] = {"manifold": audit["summary"]["by_decompiler"].pop("angr")}

    enriched = historical_iso.enrich_audit(
        audit,
        {key: record},
        {key: proof},
        _proof_counts(mismatches=1),
    )

    enriched_record = enriched["records"][key]
    assert enriched_record["historical_size_fallback_matches_published"] is None
    assert enriched_record["historical_size_reconstruction_provenance"] == "no_published_baseline"
    assert enriched_record["historical_isomorphic"] is False
    assert (
        enriched["summary"]["total"]["historical_reconstructed_fallback_without_published_score"]
        == 1
    )


def test_standalone_pass_enriches_only_audit(tmp_path: Path) -> None:
    root = tmp_path / "results"
    artifact = root / "O0/proj/decompiled/angr_bin.c"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("// Function: f @ 0x1000\nint f(void) { return 0; }\n")
    source_cache = root / "ged_src/v1/projects/O0/proj.pkl"
    _write_source_cache(source_cache, _path_graph(61))
    legacy_source_cache = root / "ged_src/proj.pkl"
    _write_source_cache(legacy_source_cache, _path_graph(61))

    slice_key = "O0::proj::bin::angr"
    function_key = f"{slice_key}::f"
    record = _record(
        historical_source=(61, 60),
        historical_decompiled=(60, 59),
    )
    score = {"value": 1.0, "perfect": False}
    score_checkpoint = historical_iso.checkpoint_path(root, slice_key)
    score_checkpoint.parent.mkdir()
    score_checkpoint.write_text(
        json.dumps(
            {
                "_meta": historical_iso.checkpoint_metadata(
                    historical_iso.checkpoint_signature(),
                    True,
                    {"f": 2.0},
                ),
                "scores": {"f": score},
                "over_previous_limit": {"f": record},
            }
        )
    )
    replay_metadata = historical_iso.replay_dependency_meta(
        root,
        slice_key,
        artifact,
        score_checkpoint,
        {"f": record},
    )
    replay_checkpoint = historical_iso.replay_checkpoint_path(root, slice_key)
    replay_checkpoint.parent.mkdir()
    replay_checkpoint.write_text(
        json.dumps(
            {
                "_meta": replay_metadata,
                "proofs": {"f": _networkx_proof(counts_match=False)},
            }
        )
    )
    overlay = root / "ged_new.json"
    sidecar = root / "ged_new.slices.json"
    overlay.write_text(json.dumps({function_key: score}))
    sidecar.write_text(json.dumps([slice_key]))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "groups": [
                    {
                        "opt_level": "O0",
                        "project": "proj",
                        "binary": "bin",
                        "functions": [
                            {
                                "function": "f",
                                "values": {"angr": {"ged": 2.0}},
                                "perfects": {"angr": {"ged": False}},
                            }
                        ],
                    }
                ]
            }
        )
    )
    historical_manifest = tmp_path / "historical-slices.json"
    historical_manifest.write_text(json.dumps([slice_key]))
    audit_path = root / "ged_large_graph_audit.json"
    audit_path.write_text(
        json.dumps(
            {
                "new_evaluator": historical_iso.checkpoint_signature(),
                "comparison_baseline": {
                    "path": str(baseline_path),
                    "sha256": _sha(baseline_path),
                },
                "historical_overlay_manifest": {
                    "path": str(historical_manifest),
                    "sha256": _sha(historical_manifest),
                    "slice_count": 1,
                },
                "coverage": {
                    "published_scores_before": 1,
                    "scores_after_reevaluation": 1,
                },
                "summary": {
                    "total": {"confirmed_isomorphic": 0},
                    "by_decompiler": {"angr": {"confirmed_isomorphic": 0}},
                },
                "records": {
                    function_key: {
                        **record,
                        "old_value": 2.0,
                        "old_perfect": False,
                        "new_value": 1.0,
                        "new_perfect": False,
                        "changed": True,
                    }
                },
            }
        )
    )
    protected = {
        score_checkpoint: _sha(score_checkpoint),
        overlay: _sha(overlay),
        sidecar: _sha(sidecar),
    }

    enriched = historical_iso.run_audit(root, workers=1)

    assert all(_sha(path) == digest for path, digest in protected.items())
    enriched_record = enriched["records"][function_key]
    assert enriched_record["historical_isomorphic"] is False
    assert enriched_record["historical_iso_proof"] == "directed_role_aware_networkx_replay"
    assert enriched_record["historical_replay_verified"] is True
    assert enriched_record["historical_networkx_calls"] == 1
    assert enriched_record["historical_size_fallback_matches_published"] is True
    assert enriched_record["corrected_isomorphic"] is False
    assert "isomorphic" not in enriched_record
    total = enriched["summary"]["total"]
    assert total["historical_confirmed_nonisomorphic"] == 1
    assert total["historical_networkx_replayed_pairs"] == 1
    assert total["historical_count_mismatch_networkx_replays"] == 1
    assert total["historical_false_perfect"] == 0
    assert total["corrected_nonisomorphic_for_historical_over_60"] == 1
    assert "confirmed_isomorphic" not in total
    assert enriched["historical_isomorphism_audit"] == {
        "schema_version": 4,
        "isomorphism_semantics": "directed-role-aware-networkx-all-large-pairs-v3",
        "historical_large_pairs": 1,
        "networkx_replayed_pairs": 1,
        "networkx_isomorphism_calls": 1,
        "networkx_replay_slices": 1,
        "count_mismatch_networkx_replays": 1,
    }
