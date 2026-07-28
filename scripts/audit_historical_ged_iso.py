#!/usr/bin/env python
"""Prove historical large-CFG isomorphism and enrich the GED audit.

This pass is intentionally independent of GED scoring. It reads canonical
schema-6 score checkpoints, replays every reconstructable historical pair
through directed role-aware NetworkX isomorphism, and writes resumable proof
checkpoints below ``reeval_ged_historical_iso/``. It never changes GED score
checkpoints, overlays, or their slice sidecar.

Usage:
    python scripts/audit_historical_ged_iso.py results/full_run [workers]
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import multiprocessing as mp
import pickle
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from decbench.metrics.ged import _is_isomorphic
from decbench.utils.cfg import (
    best_source_by_name,
    extract_cfgs_from_source,
    resolved_source_for_binary,
)

if __package__:
    from scripts.reeval_ged import (
        CANONICAL_DECOMPILERS,
        INLINE_SANITIZED,
        LEGACY_AMBIGUOUS,
        LEGACY_RAW,
        LEGACY_SANITIZED,
        SOURCE_CACHE_SCHEMA_VERSION,
        build_artifacts,
        checkpoint_large_graphs,
        checkpoint_metadata,
        checkpoint_scores,
        checkpoint_signature,
        load_historical_slice_manifest,
        load_published_ged_scores,
        source_cache_path,
        write_json_atomic,
    )
else:
    from reeval_ged import (  # type: ignore[no-redef]
        CANONICAL_DECOMPILERS,
        INLINE_SANITIZED,
        LEGACY_AMBIGUOUS,
        LEGACY_RAW,
        LEGACY_SANITIZED,
        SOURCE_CACHE_SCHEMA_VERSION,
        build_artifacts,
        checkpoint_large_graphs,
        checkpoint_metadata,
        checkpoint_scores,
        checkpoint_signature,
        load_historical_slice_manifest,
        load_published_ged_scores,
        source_cache_path,
        write_json_atomic,
    )

HISTORICAL_ISO_SCHEMA_VERSION = 4
HISTORICAL_ISO_SEMANTICS = "directed-role-aware-networkx-all-large-pairs-v3"
_MARKER = re.compile(r"^// Function: (\S+) @ 0x[0-9a-fA-F]+\s*$", re.M)

Artifact = tuple[str, str, str, str, str]
ReplayTask = tuple[str, str, str, str, dict[str, dict[str, Any]], dict[str, Any]]


def file_sha256(path: Path, cache: dict[Path, str] | None = None) -> str:
    """Hash a dependency, optionally memoizing repeated source-cache paths."""
    if cache is not None and path in cache:
        return cache[path]
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    value = digest.hexdigest()
    if cache is not None:
        cache[path] = value
    return value


def checkpoint_path(root: Path, slice_key: str) -> Path:
    """Return the schema-6 GED checkpoint path for a slice."""
    return root / "reeval_ged" / f"{slice_key.replace('::', '__')}.json"


def replay_checkpoint_path(root: Path, slice_key: str) -> Path:
    """Return the historical-isomorphism checkpoint path for a slice."""
    return root / "reeval_ged_historical_iso" / f"{slice_key.replace('::', '__')}.json"


def full_key_parts(key: str) -> tuple[str, str, str, str, str]:
    """Split a function key, rejecting malformed keys."""
    parts = key.split("::", 4)
    if len(parts) != 5:
        raise ValueError(f"malformed GED function key: {key}")
    return parts[0], parts[1], parts[2], parts[3], parts[4]


def graph_sizes(record: dict[str, Any], prefix: str) -> tuple[int, int]:
    """Read and validate one historical graph's node and edge counts."""
    nodes = record.get(f"historical_{prefix}_nodes")
    edges = record.get(f"historical_{prefix}_edges")
    if not isinstance(nodes, int) or not isinstance(edges, int):
        raise ValueError(f"missing historical {prefix} graph sizes")
    if nodes < 0 or edges < 0:
        raise ValueError(f"negative historical {prefix} graph sizes")
    return nodes, edges


def historical_fallback_provenance(
    record: dict[str, Any],
    old_value: Any,
) -> tuple[int, bool | None, str]:
    """Compare reconstructed sizes with the published 60-node fallback score."""
    source_size = graph_sizes(record, "source")
    decompiled_size = graph_sizes(record, "decompiled")
    expected = abs(source_size[0] - decompiled_size[0]) + abs(source_size[1] - decompiled_size[1])
    if old_value is None:
        return expected, None, "no_published_baseline"
    if (
        isinstance(old_value, bool)
        or not isinstance(old_value, (int, float))
        or not math.isfinite(old_value)
        or old_value < 0
    ):
        raise ValueError(f"invalid published historical GED value: {old_value!r}")
    if float(old_value) == float(expected):
        return expected, True, "published_fallback_matches_reconstructed_sizes"
    return expected, False, "published_fallback_differs_from_reconstructed_sizes"


def historical_iso_targets(
    large_graph_records: dict[str, dict[str, Any]],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Group every historical-large pair into a literal replay slice."""
    replay: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for key, record in sorted(large_graph_records.items()):
        if not record.get("historical_over_60"):
            continue
        source_size = graph_sizes(record, "source")
        decompiled_size = graph_sizes(record, "decompiled")
        if max(source_size[0], decompiled_size[0]) <= 60:
            raise ValueError(f"historical_over_60 has no graph over 60: {key}")
        opt, project, stem, decompiler, function = full_key_parts(key)
        slice_key = f"{opt}::{project}::{stem}::{decompiler}"
        replay[slice_key][function] = record
    return dict(replay)


def source_paths_for_targets(
    root: Path,
    slice_key: str,
    targets: dict[str, dict[str, Any]],
) -> dict[str, Path]:
    """Resolve every source-cache basis needed by a replay slice."""
    opt, project, _stem, _decompiler = slice_key.split("::", 3)
    paths: dict[str, Path] = {}
    bases = {record.get("historical_source_basis") for record in targets.values()}
    unknown = bases - {"legacy_overlay", "same_opt_inline"}
    if unknown:
        raise ValueError(f"{slice_key} has unknown historical source basis: {unknown}")
    if "legacy_overlay" in bases:
        paths["legacy_overlay"] = root / "ged_src" / f"{project}.pkl"
    if "same_opt_inline" in bases:
        paths["same_opt_inline"] = source_cache_path(
            root / "ged_src" / f"v{SOURCE_CACHE_SCHEMA_VERSION}",
            opt,
            project,
        )
    for basis, path in paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"{slice_key} missing {basis} source cache: {path}")
    return paths


def replay_dependency_meta(
    root: Path,
    slice_key: str,
    artifact: Path,
    score_checkpoint: Path,
    targets: dict[str, dict[str, Any]],
    hash_cache: dict[Path, str] | None = None,
) -> dict[str, Any]:
    """Build content-hash metadata controlling replay checkpoint reuse."""
    source_paths = source_paths_for_targets(root, slice_key, targets)
    return {
        "schema_version": HISTORICAL_ISO_SCHEMA_VERSION,
        "isomorphism_semantics": HISTORICAL_ISO_SEMANTICS,
        "ged_checkpoint_signature": checkpoint_signature(),
        "ged_checkpoint_sha256": file_sha256(score_checkpoint, hash_cache),
        "artifact_sha256": file_sha256(artifact, hash_cache),
        "source_cache_sha256": {
            basis: file_sha256(path, hash_cache) for basis, path in sorted(source_paths.items())
        },
        "target_functions": sorted(targets),
    }


def load_source_map(path: Path, stem: str) -> dict[str, Any]:
    """Load and TU-resolve one historical source-CFG cache."""
    payload = pickle.loads(path.read_bytes())
    if not isinstance(payload, dict):
        raise ValueError(f"invalid source cache payload: {path}")
    per_stem = payload.get("per_stem", payload)
    if not isinstance(per_stem, dict):
        raise ValueError(f"invalid per-stem source cache payload: {path}")
    return resolved_source_for_binary(stem, per_stem, best_source_by_name(per_stem))


def eval_historical_iso_one(task: ReplayTask) -> tuple[str, dict[str, dict], dict[str, Any]]:
    """Strictly replay every historical-large pair in one slice."""
    slice_key, c_path, same_opt_path, legacy_path, targets, metadata = task
    _opt, _project, stem, _decompiler = slice_key.split("::", 3)
    artifact = Path(c_path)
    text = artifact.read_text(errors="replace")
    markers = set(_MARKER.findall(text))
    missing_markers = set(targets) - markers
    if missing_markers:
        raise RuntimeError(f"{slice_key} missing function markers: {sorted(missing_markers)}")

    parse_modes = {record.get("historical_decompiled_parse_mode") for record in targets.values()}
    unknown_modes = parse_modes - {
        LEGACY_RAW,
        LEGACY_SANITIZED,
        LEGACY_AMBIGUOUS,
        INLINE_SANITIZED,
    }
    if unknown_modes:
        raise ValueError(f"{slice_key} has unknown historical parse modes: {unknown_modes}")
    decompiled_maps: dict[str, dict[str, Any]] = {}
    if LEGACY_RAW in parse_modes or LEGACY_AMBIGUOUS in parse_modes:
        decompiled_maps[LEGACY_RAW] = extract_cfgs_from_source(
            artifact,
            sanitize_decompiled=False,
            preprocess_decompiled=False,
            raise_on_error=True,
        )
    if (
        LEGACY_SANITIZED in parse_modes
        or LEGACY_AMBIGUOUS in parse_modes
        or INLINE_SANITIZED in parse_modes
    ):
        sanitized_map = extract_cfgs_from_source(
            artifact,
            sanitize_decompiled=True,
            preprocess_decompiled=False,
            raise_on_error=True,
        )
        decompiled_maps[LEGACY_SANITIZED] = sanitized_map
        decompiled_maps[INLINE_SANITIZED] = sanitized_map
    source_maps: dict[str, dict[str, Any]] = {}
    if any(r["historical_source_basis"] == "same_opt_inline" for r in targets.values()):
        source_maps["same_opt_inline"] = load_source_map(Path(same_opt_path), stem)
    if any(r["historical_source_basis"] == "legacy_overlay" for r in targets.values()):
        source_maps["legacy_overlay"] = load_source_map(Path(legacy_path), stem)

    proofs: dict[str, dict] = {}
    for function, record in sorted(targets.items()):
        source_cfg = source_maps[record["historical_source_basis"]].get(function)
        parse_mode = record["historical_decompiled_parse_mode"]
        if parse_mode == LEGACY_AMBIGUOUS:
            candidate_cfgs = [
                decompiled_maps[LEGACY_RAW].get(function),
                decompiled_maps[LEGACY_SANITIZED].get(function),
            ]
        else:
            candidate_cfgs = [decompiled_maps[parse_mode].get(function)]
        decompiled_cfg = candidate_cfgs[0]
        if source_cfg is None or decompiled_cfg is None:
            raise RuntimeError(f"{slice_key}::{function} missing replayed historical CFG")
        expected_source = graph_sizes(record, "source")
        expected_decompiled = graph_sizes(record, "decompiled")
        actual_source = (source_cfg.number_of_nodes(), source_cfg.number_of_edges())
        actual_decompiled = (
            decompiled_cfg.number_of_nodes(),
            decompiled_cfg.number_of_edges(),
        )
        if actual_source != expected_source:
            raise RuntimeError(
                f"{slice_key}::{function} source sizes changed: "
                f"{actual_source} != {expected_source}"
            )
        if actual_decompiled != expected_decompiled:
            raise RuntimeError(
                f"{slice_key}::{function} decompiled sizes changed: "
                f"{actual_decompiled} != {expected_decompiled}"
            )
        if parse_mode == LEGACY_AMBIGUOUS:
            if candidate_cfgs[1] is None:
                raise RuntimeError(f"{slice_key}::{function} missing sanitized ambiguous CFG")
            alternate_size = (
                candidate_cfgs[1].number_of_nodes(),
                candidate_cfgs[1].number_of_edges(),
            )
            if alternate_size != expected_decompiled:
                raise RuntimeError(
                    f"{slice_key}::{function} ambiguous graph sizes differ: "
                    f"{actual_decompiled} != {alternate_size}"
                )
            isomorphic_results = {
                bool(_is_isomorphic(source_cfg, candidate)) for candidate in candidate_cfgs
            }
            if len(isomorphic_results) != 1:
                raise RuntimeError(
                    f"{slice_key}::{function} legacy parse modes disagree on "
                    "historical isomorphism"
                )
            historical_isomorphic = isomorphic_results.pop()
            proof_method = "directed_role_aware_networkx_replay_both_legacy_modes"
            networkx_calls = 2
        else:
            historical_isomorphic = bool(_is_isomorphic(source_cfg, decompiled_cfg))
            proof_method = "directed_role_aware_networkx_replay"
            networkx_calls = 1
        proofs[function] = {
            "historical_isomorphic": historical_isomorphic,
            "historical_iso_proof": proof_method,
            "historical_replay_verified": True,
            "historical_networkx_calls": networkx_calls,
            "historical_graph_counts_match": expected_source == expected_decompiled,
        }
    return slice_key, proofs, metadata


def valid_replay_checkpoint(
    path: Path,
    metadata: dict[str, Any],
    target_functions: set[str],
) -> dict[str, dict] | None:
    """Return proofs from a complete current replay checkpoint."""
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    proofs = payload.get("proofs")
    if payload.get("_meta") != metadata or not isinstance(proofs, dict):
        return None
    if set(proofs) != target_functions:
        return None
    for proof in proofs.values():
        if not isinstance(proof, dict):
            return None
        proof_method = proof.get("historical_iso_proof")
        expected_calls = (
            2 if proof_method == "directed_role_aware_networkx_replay_both_legacy_modes" else 1
        )
        if (
            not isinstance(proof.get("historical_isomorphic"), bool)
            or proof_method
            not in {
                "directed_role_aware_networkx_replay",
                "directed_role_aware_networkx_replay_both_legacy_modes",
            }
            or proof.get("historical_replay_verified") is not True
            or proof.get("historical_networkx_calls") != expected_calls
            or not isinstance(proof.get("historical_graph_counts_match"), bool)
        ):
            return None
    return proofs


def verify_audit_projection(
    audit: dict[str, Any],
    signature: dict[str, Any],
    merged_scores: dict[str, dict],
    large_graph_records: dict[str, dict],
    old_scores: dict[str, dict],
) -> None:
    """Require the frozen-baseline audit to describe the checkpoint projection."""
    if audit.get("new_evaluator") != signature:
        raise RuntimeError("GED audit evaluator signature does not match checkpoints")
    coverage = audit.get("coverage") or {}
    if coverage.get("published_scores_before") != len(old_scores):
        raise RuntimeError("GED audit baseline coverage does not match frozen scores")
    if coverage.get("scores_after_reevaluation") != len(merged_scores):
        raise RuntimeError("GED audit score coverage does not match checkpoints")
    audit_records = audit.get("records")
    if not isinstance(audit_records, dict) or set(audit_records) != set(large_graph_records):
        raise RuntimeError("GED audit large-graph keys do not match checkpoints")

    aliases = {
        "isomorphic": "corrected_isomorphic",
        "method": "corrected_method",
        "approximated": "corrected_approximated",
    }
    for key, expected in large_graph_records.items():
        actual = audit_records[key]
        for field, value in expected.items():
            alias = aliases.get(field)
            if field in actual:
                observed = actual[field]
            elif alias is not None and alias in actual:
                observed = actual[alias]
            else:
                raise RuntimeError(f"GED audit record {key} is missing {field}")
            if observed != value:
                raise RuntimeError(f"GED audit record {key} differs at {field}")
        score = merged_scores.get(key)
        expected_value = float(score["value"]) if score is not None else None
        if actual.get("new_value") != expected_value:
            raise RuntimeError(f"GED audit record {key} has a stale new score")
        old_score = old_scores.get(key)
        expected_old_value = float(old_score["value"]) if old_score is not None else None
        expected_old_perfect = expected_old_value == 0.0 if expected_old_value is not None else None
        if actual.get("old_value") != expected_old_value:
            raise RuntimeError(f"GED audit record {key} has a stale old score")
        if actual.get("old_perfect") != expected_old_perfect:
            raise RuntimeError(f"GED audit record {key} has stale old perfectness")


def checkpoint_projection(
    root: Path,
    artifacts: list[Artifact],
    signature: dict[str, Any],
    historical_overlay_slices: set[str],
    old_scores: dict[str, dict],
) -> tuple[dict[str, Path], dict[str, dict], dict[str, dict]]:
    """Load and validate every canonical schema-6 checkpoint."""
    old_values_by_slice: dict[str, dict[str, float]] = defaultdict(dict)
    for key, score in old_scores.items():
        slice_key, function = key.rsplit("::", 1)
        old_values_by_slice[slice_key][function] = float(score["value"])
    checkpoints: dict[str, Path] = {}
    merged: dict[str, dict] = {}
    large: dict[str, dict] = {}
    for opt, project, stem, decompiler, c_path in artifacts:
        slice_key = f"{opt}::{project}::{stem}::{decompiler}"
        if slice_key in checkpoints:
            raise RuntimeError(f"duplicate canonical artifact slice: {slice_key}")
        path = checkpoint_path(root, slice_key)
        if not path.is_file():
            raise RuntimeError(f"missing schema-6 GED checkpoint: {slice_key}")
        try:
            payload = json.loads(path.read_text())
        except (OSError, ValueError) as error:
            raise RuntimeError(f"unreadable GED checkpoint: {path}") from error
        historical_overlay_covered = slice_key in historical_overlay_slices
        if payload.get("_meta") != checkpoint_metadata(
            signature,
            historical_overlay_covered,
            old_values_by_slice.get(slice_key, {}),
        ):
            raise RuntimeError(f"stale GED checkpoint signature: {slice_key}")
        current_source = source_cache_path(
            root / "ged_src" / f"v{SOURCE_CACHE_SCHEMA_VERSION}",
            opt,
            project,
        )
        if not current_source.is_file():
            raise RuntimeError(f"missing current source cache: {current_source}")
        dependencies = [Path(c_path), current_source]
        legacy_source = root / "ged_src" / f"{project}.pkl"
        if legacy_source.is_file():
            dependencies.append(legacy_source)
        if path.stat().st_mtime_ns < max(dep.stat().st_mtime_ns for dep in dependencies):
            raise RuntimeError(f"GED checkpoint is older than an input: {slice_key}")
        checkpoints[slice_key] = path
        for function, score in checkpoint_scores(payload).items():
            merged[f"{slice_key}::{function}"] = score
        expected_basis = "legacy_overlay" if historical_overlay_covered else "same_opt_inline"
        for function, record in checkpoint_large_graphs(payload).items():
            if record.get("historical_source_basis") != expected_basis:
                raise RuntimeError(f"incoherent historical source basis: {slice_key}::{function}")
            parse_mode = record.get("historical_decompiled_parse_mode")
            allowed_modes = (
                {LEGACY_RAW, LEGACY_SANITIZED, LEGACY_AMBIGUOUS}
                if historical_overlay_covered
                else {INLINE_SANITIZED}
            )
            if parse_mode not in allowed_modes:
                raise RuntimeError(f"incoherent historical parse mode: {slice_key}::{function}")
            raw_present = record.get("historical_raw_candidate_present")
            sanitized_present = record.get("historical_sanitized_candidate_present")
            if not isinstance(raw_present, bool) or not isinstance(sanitized_present, bool):
                raise RuntimeError(
                    f"missing historical candidate evidence: {slice_key}::{function}"
                )
            historical_candidate_recorded = record.get("historical_decompiled_nodes") is not None
            if historical_candidate_recorded and parse_mode == LEGACY_RAW and not raw_present:
                raise RuntimeError(f"raw historical candidate is absent: {slice_key}::{function}")
            if (
                historical_candidate_recorded
                and parse_mode in {LEGACY_SANITIZED, INLINE_SANITIZED}
                and not sanitized_present
            ):
                raise RuntimeError(
                    f"sanitized historical candidate is absent: {slice_key}::{function}"
                )
            if (
                historical_candidate_recorded
                and parse_mode == LEGACY_AMBIGUOUS
                and not (raw_present and sanitized_present)
            ):
                raise RuntimeError(
                    f"ambiguous historical candidates are incomplete: " f"{slice_key}::{function}"
                )
            large[f"{slice_key}::{function}"] = record
    return checkpoints, merged, large


def audit_bound_inputs(audit: dict[str, Any]) -> set[str]:
    """Verify the frozen score baseline and historical overlay manifest."""
    baseline = audit.get("comparison_baseline")
    manifest = audit.get("historical_overlay_manifest")
    for name, descriptor in (
        ("comparison baseline", baseline),
        ("historical overlay manifest", manifest),
    ):
        if not isinstance(descriptor, dict):
            raise RuntimeError(f"GED audit is missing its {name} descriptor")
        path_value = descriptor.get("path")
        expected_sha256 = descriptor.get("sha256")
        if not isinstance(path_value, str) or not isinstance(expected_sha256, str):
            raise RuntimeError(f"GED audit has an invalid {name} descriptor")
        path = Path(path_value)
        if not path.is_file() or file_sha256(path) != expected_sha256:
            raise RuntimeError(f"GED audit {name} no longer matches: {path}")
    manifest_path = Path(manifest["path"])
    slices = load_historical_slice_manifest(manifest_path)
    if manifest.get("slice_count") != len(slices):
        raise RuntimeError("GED audit historical overlay manifest count differs")
    return slices


def verify_overlay_projection(
    root: Path,
    slice_keys: set[str],
    merged_scores: dict[str, dict],
) -> None:
    """Require the canonical overlay and sidecar to match score checkpoints."""
    overlay_path = root / "ged_new.json"
    sidecar_path = root / "ged_new.slices.json"
    if not overlay_path.is_file() or not sidecar_path.is_file():
        raise RuntimeError("GED overlay or slice sidecar is missing")
    if json.loads(overlay_path.read_text()) != merged_scores:
        raise RuntimeError("GED overlay does not match schema-6 checkpoints")
    if set(json.loads(sidecar_path.read_text())) != slice_keys:
        raise RuntimeError("GED slice sidecar does not match canonical artifact slices")


def build_replay_tasks(
    root: Path,
    artifacts: dict[str, Path],
    score_checkpoints: dict[str, Path],
    replay_targets: dict[str, dict[str, dict[str, Any]]],
    hash_cache: dict[Path, str] | None = None,
) -> tuple[list[ReplayTask], dict[str, dict[str, Any]]]:
    """Build replay tasks and their exact expected metadata."""
    tasks: list[ReplayTask] = []
    metadata_by_slice: dict[str, dict[str, Any]] = {}
    for slice_key, targets in sorted(replay_targets.items()):
        artifact = artifacts.get(slice_key)
        score_checkpoint = score_checkpoints.get(slice_key)
        if artifact is None or score_checkpoint is None:
            raise RuntimeError(f"replay target is outside canonical slices: {slice_key}")
        source_paths = source_paths_for_targets(root, slice_key, targets)
        metadata = replay_dependency_meta(
            root,
            slice_key,
            artifact,
            score_checkpoint,
            targets,
            hash_cache,
        )
        metadata_by_slice[slice_key] = metadata
        tasks.append(
            (
                slice_key,
                str(artifact),
                str(source_paths.get("same_opt_inline", "")),
                str(source_paths.get("legacy_overlay", "")),
                targets,
                metadata,
            )
        )
    return tasks, metadata_by_slice


def collect_historical_iso_proofs(
    root: Path,
    artifacts: dict[str, Path],
    score_checkpoints: dict[str, Path],
    large_graph_records: dict[str, dict],
    workers: int,
) -> tuple[dict[str, dict], dict[str, int]]:
    """Resume literal NetworkX replays and return proofs for every historical pair."""
    replay_targets = historical_iso_targets(large_graph_records)
    proof_dir = root / "reeval_ged_historical_iso"
    proof_dir.mkdir(exist_ok=True)
    tasks, metadata_by_slice = build_replay_tasks(
        root,
        artifacts,
        score_checkpoints,
        replay_targets,
        {},
    )
    pending = [
        task
        for task in tasks
        if valid_replay_checkpoint(
            replay_checkpoint_path(root, task[0]),
            task[5],
            set(task[4]),
        )
        is None
    ]
    print(
        f"[ged/historical-iso] {len(replay_targets)} all-pair slices, {len(pending)} pending",
        flush=True,
    )
    if pending:
        context = mp.get_context("spawn")
        with context.Pool(processes=workers, maxtasksperchild=8) as pool:
            for slice_key, proofs, metadata in pool.imap_unordered(
                eval_historical_iso_one,
                pending,
            ):
                write_json_atomic(
                    replay_checkpoint_path(root, slice_key),
                    {"_meta": metadata, "proofs": proofs},
                )

    _, final_metadata = build_replay_tasks(
        root,
        artifacts,
        score_checkpoints,
        replay_targets,
        {},
    )
    if final_metadata != metadata_by_slice:
        raise RuntimeError("historical-isomorphism inputs changed during replay")

    proofs: dict[str, dict] = {}
    for slice_key, targets in sorted(replay_targets.items()):
        replayed = valid_replay_checkpoint(
            replay_checkpoint_path(root, slice_key),
            final_metadata[slice_key],
            set(targets),
        )
        if replayed is None:
            raise RuntimeError(f"historical-isomorphism replay is incomplete: {slice_key}")
        for function, proof in replayed.items():
            proofs[f"{slice_key}::{function}"] = proof

    historical_keys = {
        key for key, record in large_graph_records.items() if record.get("historical_over_60")
    }
    if set(proofs) != historical_keys:
        raise RuntimeError("historical-isomorphism proof coverage is incomplete")
    for key, proof in proofs.items():
        record = large_graph_records[key]
        source_size = graph_sizes(record, "source")
        decompiled_size = graph_sizes(record, "decompiled")
        if proof["historical_graph_counts_match"] != (source_size == decompiled_size):
            raise RuntimeError(f"historical graph-count diagnostic differs: {key}")
        ambiguous = record["historical_decompiled_parse_mode"] == LEGACY_AMBIGUOUS
        expected_calls = 2 if ambiguous else 1
        expected_proof = (
            "directed_role_aware_networkx_replay_both_legacy_modes"
            if ambiguous
            else "directed_role_aware_networkx_replay"
        )
        if (
            proof["historical_networkx_calls"] != expected_calls
            or proof["historical_iso_proof"] != expected_proof
        ):
            raise RuntimeError(f"historical replay mode differs: {key}")
    count_mismatch_replays = sum(
        not proof["historical_graph_counts_match"] for proof in proofs.values()
    )
    counts = {
        "historical_large_pairs": len(historical_keys),
        "networkx_replayed_pairs": len(proofs),
        "networkx_isomorphism_calls": sum(
            proof["historical_networkx_calls"] for proof in proofs.values()
        ),
        "networkx_replay_slices": len(replay_targets),
        "count_mismatch_networkx_replays": count_mismatch_replays,
    }
    return proofs, counts


def _iso_summary_counts() -> dict[str, int]:
    return {
        "historical_confirmed_isomorphic": 0,
        "historical_confirmed_nonisomorphic": 0,
        "historical_isomorphism_unavailable": 0,
        "historical_false_perfect": 0,
        "historical_networkx_replayed_pairs": 0,
        "historical_networkx_isomorphism_calls": 0,
        "historical_count_mismatch_networkx_replays": 0,
        "historical_reconstructed_fallback_matches_published": 0,
        "historical_reconstructed_fallback_mismatches_published": 0,
        "historical_reconstructed_fallback_without_published_score": 0,
        "corrected_isomorphic_for_historical_over_60": 0,
        "corrected_nonisomorphic_for_historical_over_60": 0,
        "corrected_isomorphism_unavailable_for_historical_over_60": 0,
    }


def enrich_audit(
    audit: dict[str, Any],
    large_graph_records: dict[str, dict],
    proofs: dict[str, dict],
    proof_counts: dict[str, int],
) -> dict[str, Any]:
    """Return an audit with unambiguous historical and corrected iso fields."""
    enriched = copy.deepcopy(audit)
    records = enriched["records"]
    per_decompiler: dict[str, dict[str, int]] = defaultdict(_iso_summary_counts)
    total = _iso_summary_counts()

    for key, graph_record in large_graph_records.items():
        record = records[key]
        corrected_isomorphic = graph_record.get("isomorphic")
        corrected_method = graph_record.get("method")
        corrected_approximated = graph_record.get("approximated")
        record.pop("isomorphic", None)
        record.pop("method", None)
        record.pop("approximated", None)
        record["corrected_isomorphic"] = corrected_isomorphic
        record["corrected_method"] = corrected_method
        record["corrected_approximated"] = corrected_approximated

        proof = proofs.get(key)
        historical_over_60 = graph_record.get("historical_over_60") is True
        fallback_matches: bool | None = None
        if historical_over_60:
            if proof is None:
                raise RuntimeError(f"missing historical isomorphism proof: {key}")
            expected, fallback_matches, provenance = historical_fallback_provenance(
                graph_record,
                record.get("old_value"),
            )
            record["historical_size_fallback_expected_from_reconstruction"] = expected
            record["historical_size_fallback_matches_published"] = fallback_matches
            record["historical_size_reconstruction_provenance"] = provenance
        else:
            record["historical_size_fallback_expected_from_reconstruction"] = None
            record["historical_size_fallback_matches_published"] = None
            record["historical_size_reconstruction_provenance"] = "not_historical_over_60"
        record["historical_isomorphic"] = (
            proof["historical_isomorphic"] if proof is not None else None
        )
        record["historical_iso_proof"] = (
            proof["historical_iso_proof"] if proof is not None else None
        )
        record["historical_replay_verified"] = (
            proof["historical_replay_verified"] if proof is not None else None
        )
        record["historical_networkx_calls"] = (
            proof["historical_networkx_calls"] if proof is not None else None
        )
        record["historical_graph_counts_match"] = (
            proof["historical_graph_counts_match"] if proof is not None else None
        )

        decompiler = full_key_parts(key)[3]
        increments = _iso_summary_counts()
        if historical_over_60:
            increments["historical_confirmed_isomorphic"] = int(
                proof is not None and proof["historical_isomorphic"] is True
            )
            increments["historical_confirmed_nonisomorphic"] = int(
                proof is not None and proof["historical_isomorphic"] is False
            )
            increments["historical_isomorphism_unavailable"] = int(
                proof is not None and proof["historical_isomorphic"] is None
            )
            increments["historical_false_perfect"] = int(
                proof is not None
                and proof["historical_isomorphic"] is False
                and record.get("old_value") == 0.0
                and fallback_matches is True
            )
            increments["historical_networkx_replayed_pairs"] = int(
                proof is not None and proof["historical_replay_verified"] is True
            )
            increments["historical_networkx_isomorphism_calls"] = (
                proof["historical_networkx_calls"] if proof is not None else 0
            )
            increments["historical_count_mismatch_networkx_replays"] = int(
                proof is not None
                and proof["historical_graph_counts_match"] is False
                and proof["historical_replay_verified"] is True
            )
            increments["historical_reconstructed_fallback_matches_published"] = int(
                fallback_matches is True
            )
            increments["historical_reconstructed_fallback_mismatches_published"] = int(
                fallback_matches is False
            )
            increments["historical_reconstructed_fallback_without_published_score"] = int(
                fallback_matches is None
            )
            increments["corrected_isomorphic_for_historical_over_60"] = int(
                corrected_isomorphic is True
            )
            increments["corrected_nonisomorphic_for_historical_over_60"] = int(
                corrected_isomorphic is False
            )
            increments["corrected_isomorphism_unavailable_for_historical_over_60"] = int(
                corrected_isomorphic is None
            )
        for name, increment in increments.items():
            per_decompiler[decompiler][name] += increment
            total[name] += increment

    historical_classifications = (
        total["historical_confirmed_isomorphic"]
        + total["historical_confirmed_nonisomorphic"]
        + total["historical_isomorphism_unavailable"]
    )
    if historical_classifications != proof_counts["historical_large_pairs"]:
        raise RuntimeError("historical isomorphism summary coverage is incomplete")
    if (
        total["historical_networkx_replayed_pairs"] != proof_counts["networkx_replayed_pairs"]
        or total["historical_networkx_isomorphism_calls"]
        != proof_counts["networkx_isomorphism_calls"]
        or total["historical_count_mismatch_networkx_replays"]
        != proof_counts["count_mismatch_networkx_replays"]
    ):
        raise RuntimeError("historical NetworkX replay summary is inconsistent")
    fallback_classifications = (
        total["historical_reconstructed_fallback_matches_published"]
        + total["historical_reconstructed_fallback_mismatches_published"]
        + total["historical_reconstructed_fallback_without_published_score"]
    )
    if fallback_classifications != proof_counts["historical_large_pairs"]:
        raise RuntimeError("historical fallback provenance coverage is incomplete")

    summary = enriched["summary"]
    summary["total"].pop("confirmed_isomorphic", None)
    summary["total"].update(total)
    for decompiler, counts in summary["by_decompiler"].items():
        counts.pop("confirmed_isomorphic", None)
        counts.update(per_decompiler[decompiler])

    enriched.setdefault("census_basis", {})["historical"] = (
        "Published evaluator inputs: legacy project cache for overlay scores, "
        "same-optimization source for inline scores, evidence-reconciled raw or "
        "sanitized generated C for legacy-overlay scores, and sanitized generated "
        "C without local macro expansion for inline-only scores"
    )
    enriched["historical_isomorphism_audit"] = {
        "schema_version": HISTORICAL_ISO_SCHEMA_VERSION,
        "isomorphism_semantics": HISTORICAL_ISO_SEMANTICS,
        **proof_counts,
    }
    return enriched


def run_audit(root: Path, workers: int) -> dict[str, Any]:
    """Run the standalone historical-isomorphism audit."""
    signature = checkpoint_signature()
    audit_path = root / "ged_large_graph_audit.json"
    if not audit_path.is_file():
        raise RuntimeError(f"GED large-graph audit is missing: {audit_path}")
    audit_sha256 = file_sha256(audit_path)
    audit = json.loads(audit_path.read_text())
    historical_overlay_slices = audit_bound_inputs(audit)
    baseline_path = Path(audit["comparison_baseline"]["path"])
    old_scores = load_published_ged_scores(root, baseline_path)
    artifact_rows = build_artifacts(root, CANONICAL_DECOMPILERS, None)
    artifacts = {
        f"{opt}::{project}::{stem}::{decompiler}": Path(c_path)
        for opt, project, stem, decompiler, c_path in artifact_rows
    }
    if len(artifacts) != len(artifact_rows):
        raise RuntimeError("canonical artifact list contains duplicate slices")
    score_checkpoints, merged_scores, large_graph_records = checkpoint_projection(
        root,
        artifact_rows,
        signature,
        historical_overlay_slices,
        old_scores,
    )
    verify_overlay_projection(root, set(artifacts), merged_scores)

    verify_audit_projection(
        audit,
        signature,
        merged_scores,
        large_graph_records,
        old_scores,
    )
    proofs, proof_counts = collect_historical_iso_proofs(
        root,
        artifacts,
        score_checkpoints,
        large_graph_records,
        workers,
    )
    enriched = enrich_audit(
        audit,
        large_graph_records,
        proofs,
        proof_counts,
    )
    if enriched["summary"]["total"]["historical_reconstructed_fallback_mismatches_published"]:
        raise RuntimeError(
            "historical fallback reconstruction differs from frozen published scores"
        )
    verify_audit_projection(
        enriched,
        signature,
        merged_scores,
        large_graph_records,
        old_scores,
    )
    if file_sha256(audit_path) != audit_sha256:
        raise RuntimeError("GED large-graph audit changed during historical replay")
    write_json_atomic(audit_path, enriched, indent=2)
    print(
        f"[ged/historical-iso] enriched {audit_path} with "
        f"{proof_counts['historical_large_pairs']} classifications",
        flush=True,
    )
    return enriched


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", type=Path)
    parser.add_argument("workers", nargs="?", type=int, default=12)
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("workers must be at least 1")
    run_audit(args.tree, args.workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
