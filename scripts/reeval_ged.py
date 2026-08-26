"""Recompute ONLY the GED metric over an existing results tree, using the new
header-stripped source CFGs (decbench.utils.cfg.strip_system_headers).

Why: GED's source CFGs were extracted from full preprocessed .i files, which are
80-98% inlined system headers — Joern timed out on the big ones, so a huge share
of functions had NO source CFG and silently dropped out of GED (looked like the
decompilers' fault). Stripping the headers (keeping the compiler's own ifdef/macro
resolution) makes Joern fast and complete, so GED can be measured on far more
functions. This re-scores GED to reflect that.

Two stages, both parallel via the 'spawn' context (fork deadlocks once angr's
threads are live):
  A. source CFGs per (optimization, project), content-deduplicated across
     identical stripped .i files and cached below <results>/ged_src/v*/
  B. per (opt, project, binary, dec): parse the stored decompiled .c, compute GED
     for every function whose source CFG exists -> <results>/ged_new.json mapping
     opt::project::binary::dec::func -> {"value": float, "perfect": bool}.

The pass also writes ged_large_graph_audit.json. It separately records the
historical CFG inputs that crossed the published 60-node cutoff and the
corrected same-optimization/macro-expanded inputs, plus old/new score changes
for the whole published GED column.

Usage:  python scripts/reeval_ged.py results/full_run [workers] [only-projects...]

Requires DECBENCH_GED_BASELINE and DECBENCH_GED_HISTORICAL_SLICES so every
checkpoint is bound to immutable published score and overlay provenance.
"""

from __future__ import annotations

import hashlib
import json
import math
import multiprocessing as mp
import os
import pickle
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from decbench.utils.langs import preprocessed_by_stem  # noqa: E402

PREVIOUS_GED_MAX_NODES = 60
CHECKPOINT_SCHEMA_VERSION = 7
SOURCE_CACHE_SCHEMA_VERSION = 1
HISTORICAL_CANDIDATE_PARSE = "legacy-overlay-evidence-reconciled-v3"

LEGACY_RAW = "legacy_raw"
LEGACY_SANITIZED = "legacy_sanitized"
LEGACY_AMBIGUOUS = "legacy_raw_or_sanitized_same_fallback"
INLINE_SANITIZED = "sanitized_without_macro_expansion"

CANONICAL_DECOMPILERS = (
    "angr",
    "ghidra",
    "ida",
    "binja",
    "kuna",
    "r2dec",
    "dewolf",
    "codex",
    "claude-code",
    "manifold",
)
SELECTED_DECOMPILERS = CANONICAL_DECOMPILERS
if os.environ.get("DECBENCH_REEVAL_DECOMPILERS"):
    SELECTED_DECOMPILERS = tuple(
        d.strip() for d in os.environ["DECBENCH_REEVAL_DECOMPILERS"].split(",") if d.strip()
    )
OPT_LEVELS = ("O0", "O2", "O2-noinline")
SRC_OPT = "O0"


def promoted_decompilers(
    selected: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    """Return built-in columns plus any explicitly selected external columns."""
    requested = SELECTED_DECOMPILERS if selected is None else selected
    return tuple(dict.fromkeys((*CANONICAL_DECOMPILERS, *requested)))


def checkpoint_signature() -> dict[str, int | str]:
    from decbench.metrics.ged import GED_MAX_NODES, GEDMetric

    return {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "source_cache_schema": SOURCE_CACHE_SCHEMA_VERSION,
        "metric_cache_version": GEDMetric.cache_version,
        "ged_max_nodes": GED_MAX_NODES,
        "audit_threshold": PREVIOUS_GED_MAX_NODES,
        "historical_candidate_parse": HISTORICAL_CANDIDATE_PARSE,
    }


def checkpoint_metadata(
    signature: dict[str, int | str],
    historical_overlay_covered: bool,
    old_values: dict[str, float] | None = None,
) -> dict[str, int | str]:
    metadata: dict[str, int | str] = {
        **signature,
        "historical_source_basis": (
            "legacy_overlay" if historical_overlay_covered else "same_opt_inline"
        ),
    }
    if historical_overlay_covered:
        encoded = json.dumps(
            sorted((old_values or {}).items()),
            separators=(",", ":"),
        ).encode()
        metadata["historical_score_evidence_sha256"] = hashlib.sha256(encoded).hexdigest()
    else:
        metadata["historical_score_evidence_sha256"] = "not_applicable"
    return metadata


def _size_fallback_value(source_cfg: Any, decompiled_cfg: Any) -> int | None:
    if source_cfg is None or decompiled_cfg is None:
        return None
    if (
        source_cfg.number_of_nodes() <= PREVIOUS_GED_MAX_NODES
        and decompiled_cfg.number_of_nodes() <= PREVIOUS_GED_MAX_NODES
    ):
        return None
    return abs(source_cfg.number_of_nodes() - decompiled_cfg.number_of_nodes()) + abs(
        source_cfg.number_of_edges() - decompiled_cfg.number_of_edges()
    )


def _vj_candidate_signature(cfg: Any) -> tuple[tuple[bool, bool, int, int], ...]:
    return tuple(
        sorted(
            (
                bool(getattr(node, "is_entrypoint", False)),
                bool(getattr(node, "is_exitpoint", False)),
                cfg.in_degree(node),
                cfg.out_degree(node),
            )
            for node in cfg.nodes()
        )
    )


def _historical_ged_value(source_cfg: Any, decompiled_cfg: Any) -> tuple[float, str]:
    fallback = _size_fallback_value(source_cfg, decompiled_cfg)
    if fallback is not None:
        return float(fallback), "fallback"

    from decbench.metrics.vj_ged import vj_ged

    return float(vj_ged(source_cfg, decompiled_cfg)), "vj_ged"


def select_legacy_parse_mode(
    slice_key: str,
    source_cfgs: dict,
    raw_cfgs: dict,
    sanitized_cfgs: dict,
    old_values: dict[str, float],
    *,
    sanitizer_changed: bool,
) -> tuple[str, str]:
    """Recover which legacy candidate parse produced a published slice."""
    if not sanitizer_changed:
        return LEGACY_RAW, "sanitizer_noop"

    raw_evidence: list[str] = []
    sanitized_evidence: list[str] = []
    for function, old_value in old_values.items():
        source_cfg = source_cfgs.get(function)
        if source_cfg is None:
            continue
        raw_cfg = raw_cfgs.get(function)
        sanitized_cfg = sanitized_cfgs.get(function)
        if raw_cfg is None and sanitized_cfg is not None:
            sanitized_evidence.append(f"{function}:published_candidate_coverage")
            continue
        if sanitized_cfg is None and raw_cfg is not None:
            raw_evidence.append(f"{function}:published_candidate_coverage")
            continue
        if raw_cfg is None or sanitized_cfg is None:
            continue
        raw_fallback = _size_fallback_value(source_cfg, raw_cfg)
        sanitized_fallback = _size_fallback_value(source_cfg, sanitized_cfg)
        if (
            raw_fallback is None
            and sanitized_fallback is None
            and _vj_candidate_signature(raw_cfg) == _vj_candidate_signature(sanitized_cfg)
        ):
            continue
        raw_score, raw_method = _historical_ged_value(source_cfg, raw_cfg)
        sanitized_score, sanitized_method = _historical_ged_value(
            source_cfg,
            sanitized_cfg,
        )
        raw_matches = raw_score == old_value
        sanitized_matches = sanitized_score == old_value
        if raw_matches and not sanitized_matches:
            raw_evidence.append(f"{function}:published_{raw_method}_identity")
        elif sanitized_matches and not raw_matches:
            sanitized_evidence.append(f"{function}:published_{sanitized_method}_identity")

    if raw_evidence and sanitized_evidence:
        raise RuntimeError(
            f"{slice_key} has conflicting legacy parse evidence: "
            f"raw={raw_evidence[:5]}, sanitized={sanitized_evidence[:5]}"
        )
    if sanitized_evidence:
        return LEGACY_SANITIZED, sanitized_evidence[0]
    if raw_evidence:
        return LEGACY_RAW, raw_evidence[0]
    return LEGACY_AMBIGUOUS, "published_outputs_do_not_distinguish_parse_mode"


def select_ambiguous_legacy_cfg(
    full_key: str,
    source_cfg: Any,
    raw_cfg: Any,
    sanitized_cfg: Any,
    old_value: float | None,
) -> Any:
    """Choose a count-equivalent graph while preserving parse ambiguity."""
    if raw_cfg is None:
        return sanitized_cfg
    if sanitized_cfg is None:
        return raw_cfg
    raw_size = (raw_cfg.number_of_nodes(), raw_cfg.number_of_edges())
    sanitized_size = (
        sanitized_cfg.number_of_nodes(),
        sanitized_cfg.number_of_edges(),
    )
    historical_sizes = (
        (
            source_cfg.number_of_nodes(),
            raw_cfg.number_of_nodes(),
            sanitized_cfg.number_of_nodes(),
        )
        if source_cfg is not None
        else ()
    )
    if (
        raw_size != sanitized_size
        and historical_sizes
        and max(historical_sizes) > PREVIOUS_GED_MAX_NODES
    ):
        raise RuntimeError(
            f"{full_key} has ambiguous legacy graph sizes for published fallback "
            f"{old_value}: raw={raw_size}, sanitized={sanitized_size}"
        )
    raw_fallback = _size_fallback_value(source_cfg, raw_cfg)
    sanitized_fallback = _size_fallback_value(source_cfg, sanitized_cfg)
    if old_value is not None and (raw_fallback is not None or sanitized_fallback is not None):
        raw_matches = raw_fallback is not None and float(raw_fallback) == old_value
        sanitized_matches = (
            sanitized_fallback is not None and float(sanitized_fallback) == old_value
        )
        if raw_matches != sanitized_matches:
            return raw_cfg if raw_matches else sanitized_cfg
        if not raw_matches:
            raise RuntimeError(
                f"{full_key} cannot reconstruct published fallback {old_value}: "
                f"raw={raw_fallback}, sanitized={sanitized_fallback}"
            )
    return raw_cfg


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_historical_slice_manifest(path: Path) -> set[str]:
    if not path.is_file():
        raise FileNotFoundError(f"historical GED slice manifest is missing: {path}")
    payload = json.loads(path.read_text())
    if not isinstance(payload, list) or any(
        not isinstance(value, str) or len(value.split("::")) != 4 for value in payload
    ):
        raise ValueError(f"invalid historical GED slice manifest: {path}")
    slices = set(payload)
    if len(slices) != len(payload):
        raise ValueError(f"duplicate slices in historical GED manifest: {path}")
    return slices


def checkpoint_scores(payload: dict) -> dict:
    if payload.get("_meta") and isinstance(payload.get("scores"), dict):
        return payload["scores"]
    return payload


def checkpoint_large_graphs(payload: dict) -> dict:
    if payload.get("_meta") and isinstance(payload.get("over_previous_limit"), dict):
        return payload["over_previous_limit"]
    return {}


def write_json_atomic(path: Path, payload: Any, *, indent: int | None = None) -> None:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, indent=indent))
    temp_path.replace(path)


def empty_audit_counts() -> dict[str, int]:
    return {
        "pairs_over_60": 0,
        "graphs_over_60": 0,
        "source_graphs_over_60": 0,
        "decompiled_graphs_over_60": 0,
        "both_graphs_over_60": 0,
        "corrected_pairs_over_60": 0,
        "corrected_graphs_over_60": 0,
        "corrected_source_graphs_over_60": 0,
        "corrected_decompiled_graphs_over_60": 0,
        "corrected_both_graphs_over_60": 0,
        "historical_only_over_60": 0,
        "corrected_only_over_60": 0,
        "historical_and_corrected_over_60": 0,
        "historical_legacy_raw": 0,
        "historical_legacy_sanitized": 0,
        "historical_legacy_parse_ambiguous": 0,
        "historical_same_opt_inline": 0,
        "old_score_present": 0,
        "old_score_missing": 0,
        "new_score_missing": 0,
        "changed_scores": 0,
        "unchanged_scores": 0,
        "improved_scores": 0,
        "worsened_scores": 0,
        "became_perfect": 0,
        "lost_perfect": 0,
        "confirmed_isomorphic": 0,
        "new_vj_ged": 0,
        "new_size_lower_bound": 0,
    }


def empty_change_counts() -> dict[str, int]:
    return {
        "comparable_scores": 0,
        "unchanged_scores": 0,
        "changed_scores": 0,
        "improved_scores": 0,
        "worsened_scores": 0,
        "became_perfect": 0,
        "lost_perfect": 0,
        "new_scores": 0,
        "missing_scores": 0,
    }


def build_large_graph_audit(
    old_scores: dict[str, dict],
    new_scores: dict[str, dict],
    large_graphs: dict[str, dict],
    signature: dict[str, int | str],
) -> dict[str, Any]:
    per_decompiler: dict[str, dict[str, int]] = defaultdict(empty_audit_counts)
    total = empty_audit_counts()
    records: dict[str, dict[str, Any]] = {}

    for key, graph_record in sorted(large_graphs.items()):
        _opt, _project, _binary, decompiler, _function = key.split("::", 4)
        old_record = old_scores.get(key)
        new_record = new_scores.get(key)
        old_value = float(old_record["value"]) if old_record is not None else None
        new_value = float(new_record["value"]) if new_record is not None else None
        old_perfect = old_value == 0.0 if old_value is not None else None
        new_perfect = new_value == 0.0 if new_value is not None else None
        changed = old_value is not None and new_value is not None and old_value != new_value

        historical_large = bool(graph_record["historical_over_60"])
        corrected_large = bool(graph_record["corrected_over_60"])
        historical_source_large = (
            graph_record.get("historical_source_nodes") is not None
            and graph_record["historical_source_nodes"] > PREVIOUS_GED_MAX_NODES
        )
        historical_decompiled_large = (
            graph_record.get("historical_decompiled_nodes") is not None
            and graph_record["historical_decompiled_nodes"] > PREVIOUS_GED_MAX_NODES
        )
        corrected_source_large = (
            graph_record.get("corrected_source_nodes") is not None
            and graph_record["corrected_source_nodes"] > PREVIOUS_GED_MAX_NODES
        )
        corrected_decompiled_large = (
            graph_record.get("corrected_decompiled_nodes") is not None
            and graph_record["corrected_decompiled_nodes"] > PREVIOUS_GED_MAX_NODES
        )
        increments = {
            "pairs_over_60": int(historical_large),
            "graphs_over_60": int(historical_large)
            * (int(historical_source_large) + int(historical_decompiled_large)),
            "source_graphs_over_60": int(historical_large and historical_source_large),
            "decompiled_graphs_over_60": int(historical_large and historical_decompiled_large),
            "both_graphs_over_60": int(
                historical_large and historical_source_large and historical_decompiled_large
            ),
            "corrected_pairs_over_60": int(corrected_large),
            "corrected_graphs_over_60": int(corrected_large)
            * (int(corrected_source_large) + int(corrected_decompiled_large)),
            "corrected_source_graphs_over_60": int(corrected_large and corrected_source_large),
            "corrected_decompiled_graphs_over_60": int(
                corrected_large and corrected_decompiled_large
            ),
            "corrected_both_graphs_over_60": int(
                corrected_large and corrected_source_large and corrected_decompiled_large
            ),
            "historical_only_over_60": int(historical_large and not corrected_large),
            "corrected_only_over_60": int(corrected_large and not historical_large),
            "historical_and_corrected_over_60": int(historical_large and corrected_large),
            "historical_legacy_raw": int(
                historical_large
                and graph_record.get("historical_decompiled_parse_mode") == LEGACY_RAW
            ),
            "historical_legacy_sanitized": int(
                historical_large
                and graph_record.get("historical_decompiled_parse_mode") == LEGACY_SANITIZED
            ),
            "historical_legacy_parse_ambiguous": int(
                historical_large
                and graph_record.get("historical_decompiled_parse_mode") == LEGACY_AMBIGUOUS
            ),
            "historical_same_opt_inline": int(
                historical_large
                and graph_record.get("historical_decompiled_parse_mode") == INLINE_SANITIZED
            ),
            "old_score_present": int(historical_large and old_value is not None),
            "old_score_missing": int(historical_large and old_value is None),
            "new_score_missing": int(historical_large and new_value is None),
            "changed_scores": int(historical_large and changed),
            "unchanged_scores": int(
                historical_large and old_value is not None and new_value is not None and not changed
            ),
            "improved_scores": int(historical_large and changed and new_value < old_value),
            "worsened_scores": int(historical_large and changed and new_value > old_value),
            "became_perfect": int(historical_large and changed and new_perfect),
            "lost_perfect": int(
                historical_large and changed and old_perfect is True and not new_perfect
            ),
            "confirmed_isomorphic": int(
                historical_large and graph_record.get("isomorphic") is True
            ),
            "new_vj_ged": int(historical_large and graph_record["method"] == "vj_ged"),
            "new_size_lower_bound": int(
                historical_large and graph_record["method"] == "size_lower_bound"
            ),
        }
        for name, increment in increments.items():
            per_decompiler[decompiler][name] += increment
            total[name] += increment

        records[key] = {
            **graph_record,
            "old_value": old_value,
            "old_perfect": old_perfect,
            "new_value": new_value,
            "new_perfect": new_perfect,
            "changed": changed,
        }

    missing_old_keys = sorted(set(old_scores) - set(new_scores))
    missing_by_decompiler: dict[str, int] = defaultdict(int)
    for key in missing_old_keys:
        missing_by_decompiler[key.split("::", 4)[3]] += 1

    all_change_total = empty_change_counts()
    all_changes_by_decompiler: dict[str, dict[str, int]] = defaultdict(empty_change_counts)
    changed_records: dict[str, dict[str, Any]] = {}
    for key in sorted(set(old_scores) | set(new_scores)):
        decompiler = key.split("::", 4)[3]
        counts = all_changes_by_decompiler[decompiler]
        old_record = old_scores.get(key)
        new_record = new_scores.get(key)
        if old_record is None:
            increments = {"new_scores": 1}
        elif new_record is None:
            increments = {"missing_scores": 1}
        else:
            old_value = float(old_record["value"])
            new_value = float(new_record["value"])
            changed = old_value != new_value
            increments = {
                "comparable_scores": 1,
                "unchanged_scores": int(not changed),
                "changed_scores": int(changed),
                "improved_scores": int(changed and new_value < old_value),
                "worsened_scores": int(changed and new_value > old_value),
                "became_perfect": int(changed and new_value == 0.0),
                "lost_perfect": int(changed and old_value == 0.0 and new_value != 0.0),
            }
            if changed:
                changed_records[key] = {
                    "old_value": old_value,
                    "new_value": new_value,
                    "old_perfect": old_value == 0.0,
                    "new_perfect": new_value == 0.0,
                    "over_previous_limit": key in large_graphs,
                }
        for name, increment in increments.items():
            counts[name] += increment
            all_change_total[name] += increment

    return {
        "previous_ged_max_nodes": PREVIOUS_GED_MAX_NODES,
        "new_evaluator": signature,
        "census_basis": {
            "historical": (
                "Published evaluator inputs: legacy project cache for overlay scores, "
                "same-optimization source for inline scores, evidence-reconciled raw "
                "or sanitized generated C for legacy-overlay scores, and sanitized "
                "generated C without local macro expansion for inline-only scores"
            ),
            "corrected": (
                "Same-optimization source CFGs and sanitized generated C with local "
                "macro expansion"
            ),
        },
        "coverage": {
            "published_scores_before": len(old_scores),
            "scores_after_reevaluation": len(new_scores),
            "published_scores_missing_after_reevaluation": len(missing_old_keys),
            "missing_by_decompiler": dict(sorted(missing_by_decompiler.items())),
            "missing_keys": missing_old_keys,
        },
        "all_score_changes": {
            "total": all_change_total,
            "by_decompiler": {
                decompiler: all_changes_by_decompiler[decompiler]
                for decompiler in sorted(all_changes_by_decompiler)
            },
            "changed_records": changed_records,
        },
        "summary": {
            "total": total,
            "by_decompiler": {
                decompiler: per_decompiler[decompiler] for decompiler in sorted(per_decompiler)
            },
        },
        "records": records,
    }


def load_published_ged_scores(
    root: Path,
    baseline_path: Path | None = None,
) -> dict[str, dict]:
    path = baseline_path or root / "function_results.json"
    if not path.exists():
        return {}
    function_data = json.loads(path.read_text())
    scores: dict[str, dict] = {}
    for group in function_data.get("groups", []):
        prefix = f"{group['opt_level']}::{group['project']}::{group['binary']}"
        for function in group.get("functions", []):
            name = function["function"]
            for decompiler, values in function.get("values", {}).items():
                value = values.get("ged")
                if value is None or not math.isfinite(value):
                    continue
                key = f"{prefix}::{decompiler}::{name}"
                perfect = function.get("perfects", {}).get(decompiler, {}).get("ged", value == 0.0)
                scores[key] = {"value": float(value), "perfect": bool(perfect)}
    return scores


def historical_overlay_slices(root: Path) -> set[str]:
    """Slices whose published GED column was replaced by the pre-update overlay."""
    sidecar = root / "ged_new.slices.json"
    if sidecar.exists():
        return load_historical_slice_manifest(sidecar)
    overlay = root / "ged_new.json"
    if not overlay.exists():
        return set()
    return {"::".join(key.split("::", 4)[:4]) for key in json.loads(overlay.read_text())}


def src_cfgs_for_i(i_path: str) -> tuple[str, dict]:
    """Worker: extract source CFGs from one stripped preprocessed unit."""
    from decbench.utils.cfg import extract_cfgs_from_source

    cfgs = extract_cfgs_from_source(Path(i_path), raise_on_error=True) or {}
    return i_path, cfgs


def source_cache_path(src_dir: Path, opt: str, project: str) -> Path:
    return src_dir / "projects" / opt / f"{project}.pkl"


def _source_inputs(root: Path, opt: str, project: str) -> list[Path]:
    compiled = root / opt / project / "compiled"
    if not compiled.is_dir():
        return []
    return [
        path
        for path in sorted(preprocessed_by_stem(compiled).values())
        if "conftest" not in path.name and not path.name.startswith("a-")
    ]


def _stripped_source_sha(path: Path) -> str:
    from decbench.utils.cfg import strip_system_headers

    text = strip_system_headers(path.read_text(errors="replace"))
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _write_pickle_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_bytes(pickle.dumps(payload))
    temp_path.replace(path)


def _project_cache_is_current(path: Path, inputs: dict[str, str]) -> bool:
    if not path.exists():
        return False
    try:
        payload = pickle.loads(path.read_bytes())
    except Exception:  # noqa: BLE001
        return False
    return (
        isinstance(payload, dict)
        and payload.get("_meta")
        == {
            "source_cache_schema": SOURCE_CACHE_SCHEMA_VERSION,
            "inputs": inputs,
        }
        and isinstance(payload.get("per_stem"), dict)
    )


def _seed_content_cache_from_legacy(
    root: Path,
    src_dir: Path,
    inputs: dict[tuple[str, str], dict[str, tuple[Path, str]]],
) -> int:
    """Reuse current legacy O0 project caches without carrying their cross-opt bug."""
    seeded = 0
    projects = sorted({project for _opt, project in inputs})
    content_dir = src_dir / "by_content"
    content_dir.mkdir(parents=True, exist_ok=True)
    for project in projects:
        legacy_path = root / "ged_src" / f"{project}.pkl"
        if not legacy_path.exists():
            continue
        legacy_opt = next(
            (
                opt
                for opt in (
                    SRC_OPT,
                    *(level for level in OPT_LEVELS if level != SRC_OPT),
                )
                if _source_inputs(root, opt, project)
            ),
            None,
        )
        if legacy_opt is None or (legacy_opt, project) not in inputs:
            continue
        try:
            payload = pickle.loads(legacy_path.read_bytes())
        except Exception:  # noqa: BLE001
            continue
        per_stem = payload.get("per_stem", payload) if isinstance(payload, dict) else {}
        for stem, (source_path, digest) in inputs[(legacy_opt, project)].items():
            content_path = content_dir / f"{digest}.pkl"
            if (
                content_path.exists()
                or stem not in per_stem
                or legacy_path.stat().st_mtime < source_path.stat().st_mtime
            ):
                continue
            _write_pickle_atomic(content_path, per_stem[stem])
            seeded += 1
    return seeded


def build_source_cfgs(
    root: Path,
    required: set[tuple[str, str]],
    workers: int,
) -> Path:
    """Build optimization-specific source caches, deduplicated by stripped `.i` content."""
    src_dir = root / "ged_src" / f"v{SOURCE_CACHE_SCHEMA_VERSION}"
    src_dir.mkdir(parents=True, exist_ok=True)
    inputs: dict[tuple[str, str], dict[str, tuple[Path, str]]] = {}
    rebuild: set[tuple[str, str]] = set()
    for opt, project in sorted(required):
        paths = _source_inputs(root, opt, project)
        stem_inputs = {path.stem: (path, _stripped_source_sha(path)) for path in paths}
        inputs[(opt, project)] = stem_inputs
        digests = {stem: digest for stem, (_path, digest) in stem_inputs.items()}
        if not _project_cache_is_current(
            source_cache_path(src_dir, opt, project),
            digests,
        ):
            rebuild.add((opt, project))

    if not rebuild:
        print("[ged/src] all optimization-specific source-CFG caches present", flush=True)
        return src_dir

    seeded = _seed_content_cache_from_legacy(root, src_dir, inputs)
    content_dir = src_dir / "by_content"
    representatives: dict[str, Path] = {}
    for pair in rebuild:
        for path, digest in inputs[pair].values():
            if not (content_dir / f"{digest}.pkl").exists():
                representatives.setdefault(digest, path)
    print(
        f"[ged/src] {len(rebuild)} opt/project caches need assembly; "
        f"seeded {seeded} TUs from valid legacy caches; "
        f"parsing {len(representatives)} unique source files with {workers} workers",
        flush=True,
    )

    if representatives:
        digest_by_path = {str(path): digest for digest, path in representatives.items()}
        ctx = mp.get_context("spawn")
        done = 0
        with ctx.Pool(processes=workers, maxtasksperchild=8) as pool:
            for source_path, cfgs in pool.imap_unordered(
                src_cfgs_for_i,
                list(digest_by_path),
            ):
                digest = digest_by_path[source_path]
                _write_pickle_atomic(content_dir / f"{digest}.pkl", cfgs)
                done += 1
                if done % 50 == 0 or done == len(representatives):
                    print(
                        f"[ged/src] {done}/{len(representatives)} unique source files",
                        flush=True,
                    )

    for opt, project in sorted(rebuild):
        stem_inputs = inputs[(opt, project)]
        per_stem = {
            stem: pickle.loads((content_dir / f"{digest}.pkl").read_bytes())
            for stem, (_path, digest) in stem_inputs.items()
        }
        digests = {stem: digest for stem, (_path, digest) in stem_inputs.items()}
        path = source_cache_path(src_dir, opt, project)
        _write_pickle_atomic(
            path,
            {
                "_meta": {
                    "source_cache_schema": SOURCE_CACHE_SCHEMA_VERSION,
                    "inputs": digests,
                },
                "per_stem": per_stem,
            },
        )
        nfun = sum(len(cfgs) for cfgs in per_stem.values())
        print(
            f"[ged/src] {opt}/{project}: {len(per_stem)} TUs, " f"{nfun} source functions cached",
            flush=True,
        )
    return src_dir


_SRC_CACHE: dict[str, tuple[dict, dict]] = {}


def _load_src(src_pkl: str) -> tuple[dict, dict]:
    if src_pkl not in _SRC_CACHE:
        from decbench.utils.cfg import best_source_by_name

        payload = pickle.loads(Path(src_pkl).read_bytes())
        per_stem = payload.get("per_stem", payload)
        _SRC_CACHE[src_pkl] = (per_stem, best_source_by_name(per_stem))
    return _SRC_CACHE[src_pkl]


def eval_one(
    task: tuple[str, str, str, str, str, str, str, bool, dict[str, float]],
) -> tuple[str, dict, dict]:
    """Worker: recompute GED for every function of one (binary, dec).

    ``task`` = (opt, project, stem, dec, decompiled_c_path,
    corrected_src_pkl_path, historical_src_pkl_path, historical_overlay_covered,
    published_old_values).
    Resolves each function's source CFG TU-aware (own TU first, cross-TU fallback)
    and DROPS non-finite (empty-prototype/degenerate source) results so they are
    excluded from GED's denominator instead of counting as failures.
    """
    import re

    (
        opt,
        project,
        stem,
        dec,
        c_path,
        src_pkl,
        historical_src_pkl,
        historical_overlay_covered,
        old_values,
    ) = task
    from decbench.metrics.ged import GEDMetric
    from decbench.utils import binfmt
    from decbench.utils.cfg import (
        extract_cfgs_from_source,
        needs_decompiled_preprocessing,
        resolved_source_for_binary,
        sanitize_decompiled_c,
    )
    from decbench.utils.results_tree import resolve_binary

    per_stem, best_by_name = _load_src(src_pkl)
    compiled = Path(c_path).parent.parent / "compiled"
    binary = resolve_binary(compiled, stem)
    function_owners = (
        binfmt.source_function_owners(binary, set(per_stem)) if binary is not None else None
    )
    src_cfgs = resolved_source_for_binary(
        stem,
        per_stem,
        best_by_name,
        function_owners=function_owners,
    )
    historical_src_cfgs: dict = {}
    if historical_src_pkl:
        historical_per_stem, historical_best = _load_src(historical_src_pkl)
        historical_src_cfgs = resolved_source_for_binary(
            stem,
            historical_per_stem,
            historical_best,
        )
    decompiled_text = Path(c_path).read_text(errors="replace")
    sanitizer_changed = sanitize_decompiled_c(decompiled_text) != decompiled_text
    has_preprocessor_control = needs_decompiled_preprocessing(decompiled_text)
    dec_cfgs = (
        extract_cfgs_from_source(
            Path(c_path),
            sanitize_decompiled=True,
            raise_on_error=True,
        )
        or {}
    )
    raw_dec_cfgs: dict = {}
    sanitized_dec_cfgs = dec_cfgs
    historical_parse_mode = INLINE_SANITIZED
    historical_parse_reason = "same_optimization_inline"
    if historical_overlay_covered:
        if not sanitizer_changed and not has_preprocessor_control:
            raw_dec_cfgs = dec_cfgs
        else:
            raw_dec_cfgs = (
                extract_cfgs_from_source(
                    Path(c_path),
                    sanitize_decompiled=False,
                    preprocess_decompiled=False,
                    raise_on_error=True,
                )
                or {}
            )
        if not sanitizer_changed:
            sanitized_dec_cfgs = raw_dec_cfgs
        elif has_preprocessor_control:
            sanitized_dec_cfgs = (
                extract_cfgs_from_source(
                    Path(c_path),
                    sanitize_decompiled=True,
                    preprocess_decompiled=False,
                    raise_on_error=True,
                )
                or {}
            )
        historical_parse_mode, historical_parse_reason = select_legacy_parse_mode(
            f"{opt}::{project}::{stem}::{dec}",
            historical_src_cfgs,
            raw_dec_cfgs,
            sanitized_dec_cfgs,
            old_values,
            sanitizer_changed=sanitizer_changed,
        )
    elif has_preprocessor_control:
        sanitized_dec_cfgs = (
            extract_cfgs_from_source(
                Path(c_path),
                sanitize_decompiled=True,
                preprocess_decompiled=False,
                raise_on_error=True,
            )
            or {}
        )
    # Joern keys CFGs by the parsed BODY name, which can differ from the marker name
    # (ida's `_rl_set_screen_size` over a `rl_set_screen_size` body). Emitting only
    # marker-declared functions avoids attributing a row the decompiler never owned.
    markers = set(
        re.findall(
            r"^// Function: (\S+) @ 0x[0-9a-fA-F]+\s*$",
            decompiled_text,
            re.M,
        )
    )
    if old_values:
        selected_source_functions = (
            set(historical_src_cfgs) if historical_overlay_covered else set(src_cfgs)
        )
        if historical_parse_mode == LEGACY_RAW:
            selected_historical_functions = set(raw_dec_cfgs)
        elif historical_parse_mode == LEGACY_SANITIZED:
            selected_historical_functions = set(sanitized_dec_cfgs)
        elif historical_parse_mode == LEGACY_AMBIGUOUS:
            selected_historical_functions = set(raw_dec_cfgs) | set(sanitized_dec_cfgs)
        else:
            selected_historical_functions = set(sanitized_dec_cfgs)
        missing_markers = set(old_values) - markers
        missing_sources = set(old_values) - selected_source_functions
        missing_candidates = set(old_values) - selected_historical_functions
        if missing_markers or missing_sources or missing_candidates:
            raise RuntimeError(
                f"{opt}::{project}::{stem}::{dec} cannot reconstruct all published "
                "legacy scores: "
                f"markers={sorted(missing_markers)[:5]}, "
                f"sources={sorted(missing_sources)[:5]}, "
                f"candidates={sorted(missing_candidates)[:5]}"
            )
    metric = GEDMetric()
    perfect_val = metric.perfect_value
    out: dict[str, dict] = {}
    over_previous_limit: dict[str, dict] = {}
    parsed_functions = (set(dec_cfgs) | set(raw_dec_cfgs) | set(sanitized_dec_cfgs)) & markers
    for fn in sorted(parsed_functions):
        dcfg = dec_cfgs.get(fn)
        scfg = src_cfgs.get(fn)
        mv = None
        if scfg is not None and dcfg is not None:
            try:
                candidate = metric.compute_for_function(
                    None,
                    source_cfg=scfg,
                    decompiled_cfg=dcfg,
                )
            except Exception:  # noqa: BLE001
                candidate = None
            if candidate is not None and math.isfinite(candidate.value):
                mv = candidate
                out[fn] = {
                    "value": float(mv.value),
                    "perfect": bool(mv.value == perfect_val),
                }

        historical_scfg = (
            historical_src_cfgs.get(fn) if historical_overlay_covered else src_cfgs.get(fn)
        )
        record_parse_mode = historical_parse_mode
        record_parse_reason = historical_parse_reason
        if historical_parse_mode == LEGACY_RAW:
            historical_dcfg = raw_dec_cfgs.get(fn)
        elif historical_parse_mode == LEGACY_SANITIZED:
            historical_dcfg = sanitized_dec_cfgs.get(fn)
        elif historical_parse_mode == LEGACY_AMBIGUOUS:
            raw_candidate = raw_dec_cfgs.get(fn)
            sanitized_candidate = sanitized_dec_cfgs.get(fn)
            old_value = old_values.get(fn)
            if old_value is None and ((raw_candidate is None) != (sanitized_candidate is None)):
                historical_dcfg = None
                record_parse_reason = "one_sided_candidate_without_published_score"
            else:
                historical_dcfg = select_ambiguous_legacy_cfg(
                    f"{opt}::{project}::{stem}::{dec}::{fn}",
                    historical_scfg,
                    raw_candidate,
                    sanitized_candidate,
                    old_value,
                )
        else:
            historical_dcfg = sanitized_dec_cfgs.get(fn)
        historical_over = bool(
            historical_scfg is not None
            and historical_dcfg is not None
            and (
                historical_scfg.number_of_nodes() > PREVIOUS_GED_MAX_NODES
                or historical_dcfg.number_of_nodes() > PREVIOUS_GED_MAX_NODES
            )
        )
        old_value = old_values.get(fn)
        if historical_over and old_value is not None:
            reconstructed_fallback = _size_fallback_value(
                historical_scfg,
                historical_dcfg,
            )
            if reconstructed_fallback is None or float(reconstructed_fallback) != old_value:
                raise RuntimeError(
                    f"{opt}::{project}::{stem}::{dec}::{fn} cannot reproduce "
                    f"published fallback {old_value}: "
                    f"reconstructed={reconstructed_fallback}, "
                    f"parse_mode={record_parse_mode}"
                )
        corrected_over = bool(
            scfg is not None
            and dcfg is not None
            and (
                scfg.number_of_nodes() > PREVIOUS_GED_MAX_NODES
                or dcfg.number_of_nodes() > PREVIOUS_GED_MAX_NODES
            )
        )
        if historical_over or corrected_over:
            over_previous_limit[fn] = {
                "historical_source_nodes": (
                    historical_scfg.number_of_nodes() if historical_scfg is not None else None
                ),
                "historical_source_edges": (
                    historical_scfg.number_of_edges() if historical_scfg is not None else None
                ),
                "historical_decompiled_nodes": (
                    historical_dcfg.number_of_nodes() if historical_dcfg is not None else None
                ),
                "historical_decompiled_edges": (
                    historical_dcfg.number_of_edges() if historical_dcfg is not None else None
                ),
                "historical_over_60": historical_over,
                "historical_source_basis": (
                    "legacy_overlay" if historical_overlay_covered else "same_opt_inline"
                ),
                "historical_decompiled_parse_mode": (record_parse_mode),
                "historical_parse_selection_reason": record_parse_reason,
                "historical_raw_candidate_present": fn in raw_dec_cfgs,
                "historical_sanitized_candidate_present": fn in sanitized_dec_cfgs,
                "corrected_source_nodes": (scfg.number_of_nodes() if scfg is not None else None),
                "corrected_source_edges": (scfg.number_of_edges() if scfg is not None else None),
                "corrected_decompiled_nodes": (
                    dcfg.number_of_nodes() if dcfg is not None else None
                ),
                "corrected_decompiled_edges": (
                    dcfg.number_of_edges() if dcfg is not None else None
                ),
                "corrected_over_60": corrected_over,
                "new_value": float(mv.value) if mv is not None else None,
                "new_perfect": (bool(mv.value == perfect_val) if mv is not None else None),
                "method": mv.metadata.get("method") if mv is not None else None,
                "isomorphic": (bool(mv.metadata.get("isomorphic")) if mv is not None else None),
                "approximated": (bool(mv.metadata.get("approximated")) if mv is not None else None),
            }
    key = f"{opt}::{project}::{stem}::{dec}"
    return key, out, over_previous_limit


def build_artifacts(
    root: Path,
    decompilers: tuple[str, ...],
    only: set[str] | None,
) -> list[tuple[str, str, str, str, str]]:
    artifacts: list[tuple[str, str, str, str, str]] = []
    for opt in OPT_LEVELS:
        odir = root / opt
        if not odir.is_dir():
            continue
        for proj in sorted(p for p in odir.iterdir() if p.is_dir()):
            if only and proj.name not in only:
                continue
            dec_dir = proj / "decompiled"
            if not dec_dir.is_dir():
                continue
            for dec in decompilers:
                for cf in sorted(dec_dir.glob(f"{dec}_*.c")):
                    stem = cf.name[len(dec) + 1 : -2]
                    artifacts.append((opt, proj.name, stem, dec, str(cf)))
    return artifacts


def build_tasks(
    root: Path,
    src_dir: Path,
    artifacts: list[tuple[str, str, str, str, str]],
    historical_covered: set[str] | None = None,
    old_scores: dict[str, dict] | None = None,
) -> tuple[
    list[tuple[str, str, str, str, str, str, str, bool, dict[str, float]]],
    list[tuple[str, str]],
]:
    tasks: list[tuple[str, str, str, str, str, str, str, bool, dict[str, float]]] = []
    missing: set[tuple[str, str]] = set()
    old_values_by_slice: dict[str, dict[str, float]] = defaultdict(dict)
    for key, record in (old_scores or {}).items():
        slice_key, function = key.rsplit("::", 1)
        old_values_by_slice[slice_key][function] = float(record["value"])
    for opt, project, stem, decompiler, c_path in artifacts:
        src_pkl = source_cache_path(src_dir, opt, project)
        if not src_pkl.exists():
            missing.add((opt, project))
            continue
        historical_src = root / "ged_src" / f"{project}.pkl"
        slice_key = f"{opt}::{project}::{stem}::{decompiler}"
        tasks.append(
            (
                opt,
                project,
                stem,
                decompiler,
                c_path,
                str(src_pkl),
                str(historical_src) if historical_src.exists() else "",
                slice_key in (historical_covered or set()),
                old_values_by_slice.get(slice_key, {}),
            )
        )
    return tasks, sorted(missing)


def _checkpoint_stale(path: Path, task: tuple) -> bool:
    return path.stat().st_mtime_ns < max(
        Path(task[4]).stat().st_mtime_ns,
        Path(task[5]).stat().st_mtime_ns,
        Path(task[6]).stat().st_mtime_ns if task[6] else 0,
    )


def migrate_compatible_checkpoints(
    checkpoint_dir: Path,
    tasks: list[tuple],
    signature: dict[str, int | str],
) -> tuple[int, int]:
    """Upgrade checkpoints whose stored and requested historical bases agree."""
    from decbench.utils.cfg import sanitize_decompiled_c

    # The compatibility proof below is specifically for the schema 4/5 -> 6
    # historical-parse transition. Later schemas change corrected-score inputs
    # and must be replayed, not relabeled as current.
    if signature.get("schema_version") != 6:
        return 0, 0

    schema5_signature = dict(signature)
    schema5_signature["schema_version"] = 5
    schema5_signature["historical_candidate_parse"] = "legacy-overlay-raw-v1"
    schema4_signature = dict(schema5_signature)
    schema4_signature["schema_version"] = 4
    schema4_signature.pop("historical_candidate_parse")
    migrated = 0
    require_replay = 0
    for task in tasks:
        slice_key = f"{task[0]}::{task[1]}::{task[2]}::{task[3]}"
        path = checkpoint_dir / f"{slice_key.replace('::', '__')}.json"
        if not path.is_file() or _checkpoint_stale(path, task):
            continue
        try:
            payload = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        expected_basis = "legacy_overlay" if task[7] else "same_opt_inline"
        schema5_metadata = {
            **schema5_signature,
            "historical_source_basis": expected_basis,
        }
        schema4_metadata = {
            **schema4_signature,
            "historical_source_basis": expected_basis,
        }
        allowed_metadata = (
            schema5_metadata,
            schema4_metadata,
            schema5_signature,
            schema4_signature,
        )
        if payload.get("_meta") not in allowed_metadata:
            continue
        records = checkpoint_large_graphs(payload)
        if any(
            record.get("historical_source_basis") != expected_basis for record in records.values()
        ):
            require_replay += 1
            continue
        if task[7] and task[8]:
            require_replay += 1
            continue
        fallback_mismatch = False
        for function, record in records.items():
            old_value = task[8].get(function)
            if not record.get("historical_over_60") or old_value is None:
                continue
            values = (
                record.get("historical_source_nodes"),
                record.get("historical_source_edges"),
                record.get("historical_decompiled_nodes"),
                record.get("historical_decompiled_edges"),
            )
            if not all(isinstance(value, int) for value in values):
                fallback_mismatch = True
                break
            source_nodes, source_edges, decompiled_nodes, decompiled_edges = values
            reconstructed = abs(source_nodes - decompiled_nodes) + abs(
                source_edges - decompiled_edges
            )
            if float(reconstructed) != old_value:
                fallback_mismatch = True
                break
        if fallback_mismatch:
            require_replay += 1
            continue
        if task[7]:
            text = Path(task[4]).read_text(errors="replace")
            if sanitize_decompiled_c(text) != text:
                require_replay += 1
                continue
        parse_mode = LEGACY_RAW if task[7] else INLINE_SANITIZED
        parse_reason = "sanitizer_noop" if task[7] else "same_optimization_inline"
        for record in records.values():
            record["historical_decompiled_parse_mode"] = parse_mode
            record["historical_parse_selection_reason"] = parse_reason
            present = record.get("historical_decompiled_nodes") is not None
            record["historical_raw_candidate_present"] = bool(task[7] and present)
            record["historical_sanitized_candidate_present"] = present
        payload["_meta"] = checkpoint_metadata(signature, task[7], task[8])
        write_json_atomic(path, payload)
        migrated += 1
    return migrated, require_replay


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/full_run")
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    only = {a for a in sys.argv[3:] if not a.lstrip("-").isdigit()} or None
    signature = checkpoint_signature()
    baseline_env = os.environ.get("DECBENCH_GED_BASELINE")
    baseline_path = Path(baseline_env) if baseline_env else None
    historical_manifest_env = os.environ.get("DECBENCH_GED_HISTORICAL_SLICES")
    historical_manifest_path = Path(historical_manifest_env) if historical_manifest_env else None
    if baseline_path is None or historical_manifest_path is None:
        raise RuntimeError(
            "DECBENCH_GED_BASELINE and DECBENCH_GED_HISTORICAL_SLICES are both "
            "required for evidence-bound GED reevaluation"
        )
    if not baseline_path.is_file():
        raise FileNotFoundError(f"GED comparison baseline is missing: {baseline_path}")
    baseline_sha256 = file_sha256(baseline_path)
    historical_covered = load_historical_slice_manifest(historical_manifest_path)
    historical_manifest_sha256 = file_sha256(historical_manifest_path)
    old_scores = load_published_ged_scores(root, baseline_path)
    selected_artifacts = build_artifacts(root, SELECTED_DECOMPILERS, only)
    canonical_artifacts = build_artifacts(root, promoted_decompilers(), None)
    required_sources = {
        (opt, project) for opt, project, _stem, _decompiler, _path in selected_artifacts
    }
    src_dir = build_source_cfgs(root, required_sources, workers)

    ckpt_dir = root / "reeval_ged"
    ckpt_dir.mkdir(exist_ok=True)
    tasks, missing_selected_sources = build_tasks(
        root,
        src_dir,
        selected_artifacts,
        historical_covered,
        old_scores,
    )
    all_tasks, missing_canonical_sources = build_tasks(
        root,
        src_dir,
        canonical_artifacts,
        historical_covered,
        old_scores,
    )
    migrated, require_replay = migrate_compatible_checkpoints(
        ckpt_dir,
        all_tasks,
        signature,
    )
    if migrated or require_replay:
        print(
            f"[ged] migrated {migrated} compatible legacy checkpoints; "
            f"{require_replay} need raw historical replay",
            flush=True,
        )
    if missing_selected_sources:
        print(
            f"[ged] cannot evaluate: {len(missing_selected_sources)} selected "
            f"opt/project source caches are missing",
            flush=True,
        )
        return
    current_slices = {
        f"{opt}::{project}::{stem}::{decompiler}"
        for opt, project, stem, decompiler, _c_path in canonical_artifacts
    }

    def _pending(t: tuple) -> bool:
        ckpt = ckpt_dir / (f"{t[0]}::{t[1]}::{t[2]}::{t[3]}".replace("::", "__") + ".json")
        if not ckpt.exists():
            return True
        try:
            payload = json.loads(ckpt.read_text())
        except (OSError, ValueError):
            return True
        if payload.get("_meta") != checkpoint_metadata(signature, t[7], t[8]):
            return True
        # A checkpoint older than its artifact was computed against a PREVIOUS decompile
        # and may reference functions the artifact no longer holds.
        return _checkpoint_stale(ckpt, t)

    pending = [t for t in tasks if _pending(t)]
    pending_old_values = {
        f"{task[0]}::{task[1]}::{task[2]}::{task[3]}": task[8] for task in pending
    }
    print(
        f"[ged] {len(tasks)} tasks, {len(pending)} pending, {workers} workers",
        flush=True,
    )

    ctx = mp.get_context("spawn")
    done = 0
    # maxtasksperchild bounds the per-worker _SRC_CACHE: without recycling, workers
    # accumulate every project pickle they touch and 40 of them OOM a 256 GB box.
    with ctx.Pool(processes=workers, maxtasksperchild=8) as pool:
        for key, result, large_graphs in pool.imap_unordered(eval_one, pending):
            checkpoint_path = ckpt_dir / (key.replace("::", "__") + ".json")
            write_json_atomic(
                checkpoint_path,
                {
                    "_meta": checkpoint_metadata(
                        signature,
                        key in historical_covered,
                        pending_old_values[key],
                    ),
                    "scores": result,
                    "over_previous_limit": large_graphs,
                },
            )
            done += 1
            if done % 25 == 0 or done == len(pending):
                print(f"[ged] {done}/{len(pending)} (binary,dec) done", flush=True)

    all_tasks, missing_canonical_sources = build_tasks(
        root,
        src_dir,
        canonical_artifacts,
        historical_covered,
        old_scores,
    )
    stale_after = [task for task in all_tasks if _pending(task)]
    if stale_after or missing_canonical_sources:
        print(
            f"[ged] semantic refresh incomplete: {len(stale_after)} current slices "
            f"still use older checkpoints and {len(missing_canonical_sources)} "
            "opt/project source caches are missing; canonical overlays were not changed",
            flush=True,
        )
        return

    merged: dict[str, dict] = {}
    large_graph_records: dict[str, dict] = {}
    slices: list[str] = []
    for cp in ckpt_dir.glob("*.json"):
        key = cp.stem.replace("__", "::")
        if key not in current_slices:
            continue
        slices.append(key)
        payload = json.loads(cp.read_text())
        for func, v in checkpoint_scores(payload).items():
            merged[f"{key}::{func}"] = v
        for func, record in checkpoint_large_graphs(payload).items():
            large_graph_records[f"{key}::{func}"] = record
    out_path = root / "ged_new.json"
    write_json_atomic(out_path, merged)
    # Sidecar of EVERY slice this reeval evaluated, including empty ones, so the
    # overlay merge can tell "evaluated, found nothing" (clears stale inline values)
    # from "never evaluated" (keeps them).
    sidecar_path = root / "ged_new.slices.json"
    write_json_atomic(sidecar_path, sorted(slices))
    audit_path = root / "ged_large_graph_audit.json"
    audit = build_large_graph_audit(old_scores, merged, large_graph_records, signature)
    audit["comparison_baseline"] = {
        "path": str(baseline_path.resolve()),
        "sha256": baseline_sha256,
    }
    audit["historical_overlay_manifest"] = {
        "path": str(historical_manifest_path.resolve()),
        "sha256": historical_manifest_sha256,
        "slice_count": len(historical_covered),
    }
    audit["promoted_slice_manifest"] = {
        "path": str(sidecar_path.resolve()),
        "sha256": file_sha256(sidecar_path),
        "slice_count": len(slices),
    }
    write_json_atomic(audit_path, audit, indent=2)
    perf = sum(1 for v in merged.values() if v.get("perfect"))
    print(
        f"[ged] wrote {out_path} ({len(merged)} funcs over {len(slices)} slices, "
        f"{perf} perfect = {100*perf/max(1,len(merged)):.1f}%)",
        flush=True,
    )
    audit_total = audit["summary"]["total"]
    print(
        f"[ged/audit] wrote {audit_path} ({audit_total['pairs_over_60']} pairs over "
        f"the old 60-node limit, {audit_total['changed_scores']} changed scores)",
        flush=True,
    )


if __name__ == "__main__":
    os.environ.setdefault("PYTHONWARNINGS", "ignore")
    main()
