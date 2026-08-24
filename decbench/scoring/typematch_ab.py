"""Reproducible A/B summaries for TypeMatch correspondence modes."""

from __future__ import annotations

import hashlib
import json
import math
import pickle
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from decbench.models.decompilation import (
    VARIABLE_OCCURRENCE_POLICIES,
    VARIABLE_OCCURRENCE_POLICY_SCHEMA,
)
from decbench.models.function_data import VARIABLE_MATCH_EVIDENCE
from decbench.results_store import read_typematch_overlay
from decbench.utils import binfmt
from decbench.utils.results_tree import compiled_dir, resolve_binary

FunctionKey = tuple[str, str, str, str]
ProducerKey = tuple[str, FunctionKey]

SCORE_EPSILON = 1e-9
REPORT_SCHEMA = "decbench-typematch-ab-report-v2"
PRODUCER_OCCURRENCE_POLICIES = (*VARIABLE_OCCURRENCE_POLICIES, "undeclared")


@dataclass(frozen=True)
class FunctionFact:
    """One selected function and its frozen reporting stratum."""

    key: FunctionKey
    stratum: str


@dataclass(frozen=True)
class ScoreEntry:
    """One finite TypeMatch score and its coarse accepted-evidence marker."""

    value: float
    evidence: str
    producer_occurrence_policy: str = "unreported"
    structured_occurrence_mode: str = "unreported"


@dataclass(frozen=True)
class ModeOverlay:
    """One named mode overlay after validation and key normalization."""

    name: str
    path: Path
    sha256: str
    provenance: dict[str, Any] | None
    scores: dict[str, dict[FunctionKey, ScoreEntry]]
    raw_entry_count: int


@dataclass(frozen=True)
class ProducerEvidence:
    """Line-map evidence stored by a decompiler for one function."""

    function_found: bool = False
    line_mapping_rows: int = 0
    mapped_addresses: int = 0
    variable_count: int = 0
    variables_with_lines: int = 0
    variables_with_addresses: int = 0

    @property
    def line_map_present(self) -> bool:
        return self.mapped_addresses > 0

    @property
    def variable_address_present(self) -> bool:
        return self.variables_with_addresses > 0


@dataclass(frozen=True)
class Universe:
    """Frozen function universe used for every backend and mode."""

    selected: dict[FunctionKey, FunctionFact]
    measurable: dict[FunctionKey, FunctionFact]
    missing_manifest_keys: tuple[FunctionKey, ...]
    perfect_value: float


def file_sha256(path: Path) -> str:
    """Return the SHA-256 digest of a file without loading it all at once."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def key_text(key: FunctionKey) -> str:
    """Serialize a function identity in the overlay's established format."""

    return "::".join(key)


def parse_key(value: str) -> FunctionKey:
    """Parse one overlay function key."""

    parts = value.split("::", 3)
    if len(parts) != 4 or any(not part for part in parts):
        raise ValueError(f"invalid TypeMatch function key: {value!r}")
    return parts[0], parts[1], parts[2], parts[3]


def keyset_sha256(keys: Iterable[FunctionKey]) -> str:
    """Bind a report to an exact, order-independent set of function keys."""

    payload = "\n".join(key_text(key) for key in sorted(keys)).encode()
    return hashlib.sha256(payload).hexdigest()


def load_manifest(path: Path) -> set[FunctionKey]:
    """Load and strictly validate a sample-set manifest."""

    try:
        payload = json.loads(path.read_text())
        rows = payload["functions"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"invalid sample manifest {path}: {exc}") from exc
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"sample manifest has no functions: {path}")
    keys: list[FunctionKey] = []
    try:
        for row in rows:
            keys.append(
                (
                    str(row["project"]),
                    str(row["opt"]),
                    str(row["binary"]),
                    str(row["function"]),
                )
            )
    except (KeyError, TypeError) as exc:
        raise ValueError(f"invalid sample manifest row in {path}: {exc}") from exc
    if len(keys) != len(set(keys)):
        raise ValueError(f"sample manifest contains duplicate function keys: {path}")
    if any(any(not part for part in key) for key in keys):
        raise ValueError(f"sample manifest contains an empty function-key field: {path}")
    return set(keys)


def _finite_type_value(values: Mapping[str, Any]) -> bool:
    for per_decompiler in values.values():
        if not isinstance(per_decompiler, Mapping):
            continue
        value = per_decompiler.get("type_match")
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        ):
            return True
    return False


def _binary_stratum(
    results_root: Path,
    project: str,
    optimization: str,
    binary: str,
    recorded_arch: Any,
) -> str:
    path = resolve_binary(compiled_dir(results_root, optimization, project), binary)
    info = binfmt.detect(path) if path is not None else None
    fmt = info.fmt if info is not None else "unknown"
    arch = info.arch if info is not None else str(recorded_arch or "unknown")
    return f"{fmt}/{arch}"


def load_universe(
    function_data_path: Path,
    *,
    selected_keys: set[FunctionKey] | None,
    results_root: Path,
) -> Universe:
    """Load the shared TypeMatch denominator from ``function_results.json``."""

    try:
        payload = json.loads(function_data_path.read_text())
        groups = payload["groups"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"invalid function data {function_data_path}: {exc}") from exc

    selected: dict[FunctionKey, FunctionFact] = {}
    measurable: dict[FunctionKey, FunctionFact] = {}
    for group in groups:
        project = str(group["project"])
        optimization = str(group["opt_level"])
        binary = str(group["binary"])
        stratum = _binary_stratum(
            results_root,
            project,
            optimization,
            binary,
            group.get("arch"),
        )
        for function in group.get("functions", []):
            key = (project, optimization, binary, str(function["function"]))
            if selected_keys is not None and key not in selected_keys:
                continue
            if key in selected:
                raise ValueError(f"function data contains duplicate key: {key_text(key)}")
            fact = FunctionFact(key, stratum)
            selected[key] = fact
            if _finite_type_value(function.get("values") or {}):
                measurable[key] = fact

    expected = selected_keys or set(selected)
    missing = tuple(sorted(expected - set(selected)))
    perfect_values = payload.get("perfect_values") or {}
    perfect_value = float(perfect_values.get("type_match", 1.0))
    if not math.isfinite(perfect_value):
        raise ValueError("type_match perfect value must be finite")
    return Universe(selected, measurable, missing, perfect_value)


def load_mode_overlay(name: str, path: Path) -> ModeOverlay:
    """Load one digest-validated overlay and normalize all finite entries."""

    payload, provenance = read_typematch_overlay(path)
    scores: dict[str, dict[FunctionKey, ScoreEntry]] = {}
    entry_count = 0
    evidence_reporting = provenance is not None
    for backend, records in payload.items():
        normalized: dict[FunctionKey, ScoreEntry] = {}
        for raw_key, raw_entry in records.items():
            entry_count += 1
            if isinstance(raw_entry, Mapping):
                value = raw_entry.get("value")
                raw_evidence = raw_entry.get("variable_match_evidence")
                raw_occurrence_policy = raw_entry.get("producer_variable_occurrence_policy")
                raw_structured_mode = raw_entry.get("structured_occurrence_mode")
            else:
                value = raw_entry
                raw_evidence = None
                raw_occurrence_policy = None
                raw_structured_mode = None
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"{path}: non-numeric score at {backend}/{raw_key}")
            number = float(value)
            if not math.isfinite(number):
                raise ValueError(f"{path}: non-finite score at {backend}/{raw_key}")
            if raw_evidence in VARIABLE_MATCH_EVIDENCE:
                evidence = str(raw_evidence)
            else:
                evidence = "none" if evidence_reporting else "unreported"
            occurrence_policy = (
                str(raw_occurrence_policy)
                if raw_occurrence_policy in PRODUCER_OCCURRENCE_POLICIES
                else "unreported"
            )
            normalized[parse_key(raw_key)] = ScoreEntry(
                number,
                evidence,
                occurrence_policy,
                str(raw_structured_mode) if raw_structured_mode == "producer" else "unreported",
            )
        scores[str(backend)] = normalized
    return ModeOverlay(
        name=name,
        path=path,
        sha256=file_sha256(path),
        provenance=provenance,
        scores=scores,
        raw_entry_count=entry_count,
    )


def _find_function(result: Any, function_name: str) -> Any | None:
    functions = getattr(result, "functions", None)
    if not isinstance(functions, Mapping):
        return None
    direct = functions.get(function_name)
    if direct is not None:
        return direct
    return next(
        (
            function
            for function in functions.values()
            if getattr(function, "name", None) == function_name
        ),
        None,
    )


def load_producer_evidence(
    checkpoint_dir: Path,
    keys: Iterable[FunctionKey],
    backends: Sequence[str],
) -> tuple[dict[ProducerKey, ProducerEvidence], list[str]]:
    """Read optional per-function line-map coverage from checkpoint pickles."""

    import decbench.decompilers  # noqa: F401

    requested: defaultdict[str, list[FunctionKey]] = defaultdict(list)
    for key in keys:
        requested[key[0]].append(key)
    evidence: dict[ProducerKey, ProducerEvidence] = {}
    warnings: list[str] = []
    for project, project_keys in sorted(requested.items()):
        checkpoint = checkpoint_dir / f"{project}.pkl"
        if not checkpoint.is_file():
            warnings.append(f"missing producer checkpoint: {checkpoint}")
            continue
        try:
            with checkpoint.open("rb") as stream:
                payload = pickle.load(stream)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"could not load producer checkpoint {checkpoint}: {exc}")
            continue
        decompile = {
            getattr(optimization, "value", str(optimization)): binaries
            for optimization, binaries in payload.get("decompile", {}).items()
        }
        for key in project_keys:
            _project, optimization, binary, function_name = key
            per_backend = decompile.get(optimization, {}).get(binary, {})
            for backend in backends:
                function = _find_function(per_backend.get(backend), function_name)
                if function is None:
                    continue
                mappings = list(getattr(function, "line_mappings", []) or [])
                variables = list(getattr(function, "variables", []) or [])
                evidence[(backend, key)] = ProducerEvidence(
                    function_found=True,
                    line_mapping_rows=sum(
                        bool(getattr(row, "addresses", []) or []) for row in mappings
                    ),
                    mapped_addresses=len(
                        {
                            int(address)
                            for row in mappings
                            for address in (getattr(row, "addresses", []) or [])
                        }
                    ),
                    variable_count=len(variables),
                    variables_with_lines=sum(
                        bool(getattr(variable, "line_numbers", []) or []) for variable in variables
                    ),
                    variables_with_addresses=sum(
                        bool(getattr(variable, "addresses", []) or []) for variable in variables
                    ),
                )
    return evidence, warnings


def _evidence_summary(
    rows: Sequence[tuple[str, FunctionKey, ScoreEntry]],
    producer: Mapping[ProducerKey, ProducerEvidence],
) -> dict[str, Any]:
    categories = Counter(entry.evidence for _backend, _key, entry in rows)
    occurrence_policies = Counter(
        entry.producer_occurrence_policy for _backend, _key, entry in rows
    )
    occurrence_modes = Counter(entry.structured_occurrence_mode for _backend, _key, entry in rows)
    site_caveated = sum(categories[kind] for kind in ("mixed", "fallback_only"))
    producer_unmapped = 0
    producer_unknown = 0
    potential: set[tuple[str, FunctionKey]] = set()
    for backend, key, entry in rows:
        identity = (backend, key)
        item = producer.get(identity)
        if item is None:
            producer_unknown += 1
        elif not item.variable_address_present:
            producer_unmapped += 1
            potential.add(identity)
        if entry.evidence in {"mixed", "fallback_only", "none"}:
            potential.add(identity)
    return {
        "accepted_categories": dict(sorted(categories.items())),
        "producer_occurrence_policies": {
            policy: occurrence_policies[policy]
            for policy in (*PRODUCER_OCCURRENCE_POLICIES, "unreported")
        },
        "structured_occurrence_modes": {
            mode: occurrence_modes[mode] for mode in ("producer", "unreported")
        },
        "site_caveated": site_caveated,
        "site_caveated_rate_over_measured": site_caveated / len(rows) if rows else None,
        "no_accepted_correspondence": categories["none"],
        "evidence_unreported": categories["unreported"],
        "producer_variable_addresses_missing": producer_unmapped,
        "producer_status_unknown": producer_unknown,
        "potential_undercount": len(potential),
        "asterisk_recommended": bool(potential),
    }


def _score_stats(
    mode: ModeOverlay,
    keys: set[FunctionKey],
    backends: Sequence[str],
    perfect_value: float,
    producer: Mapping[ProducerKey, ProducerEvidence],
) -> dict[str, Any]:
    backend_rows: dict[str, Any] = {}
    all_rows: list[tuple[str, FunctionKey, ScoreEntry]] = []
    for backend in backends:
        per_backend = mode.scores.get(backend, {})
        rows = [(backend, key, per_backend[key]) for key in sorted(keys & set(per_backend))]
        all_rows.extend(rows)
        score_sum = sum(entry.value for _backend, _key, entry in rows)
        perfect = sum(entry.value >= perfect_value for _backend, _key, entry in rows)
        denominator = len(keys)
        backend_rows[backend] = {
            "coverage": {
                "measured": len(rows),
                "missing": denominator - len(rows),
                "shared_denominator": denominator,
            },
            "conditional_partial": {
                "mean": score_sum / len(rows) if rows else None,
                "sum": score_sum,
                "n": len(rows),
            },
            "shared_partial": {
                "zero_filled_mean": score_sum / denominator if denominator else None,
                "denominator": denominator,
            },
            "published_perfect": {
                "count": perfect,
                "denominator": denominator,
                "rate": perfect / denominator if denominator else None,
            },
            "evidence": _evidence_summary(rows, producer),
        }

    denominator = len(keys) * len(backends)
    score_sum = sum(entry.value for _backend, _key, entry in all_rows)
    perfect = sum(entry.value >= perfect_value for _backend, _key, entry in all_rows)
    aggregate = {
        "coverage": {
            "measured": len(all_rows),
            "missing": denominator - len(all_rows),
            "shared_denominator": denominator,
            "backend_count": len(backends),
        },
        "conditional_partial": {
            "mean": score_sum / len(all_rows) if all_rows else None,
            "sum": score_sum,
            "n": len(all_rows),
        },
        "shared_partial": {
            "zero_filled_mean": score_sum / denominator if denominator else None,
            "denominator": denominator,
        },
        "published_perfect": {
            "count": perfect,
            "denominator": denominator,
            "rate": perfect / denominator if denominator else None,
        },
        "evidence": _evidence_summary(all_rows, producer),
    }
    return {"all_backends": aggregate, "backends": backend_rows}


def _producer_stats(
    keys: set[FunctionKey],
    backends: Sequence[str],
    producer: Mapping[ProducerKey, ProducerEvidence],
) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    for backend in backends:
        found = [producer[(backend, key)] for key in keys if (backend, key) in producer]
        rows[backend] = {
            "shared_denominator": len(keys),
            "functions_found": len(found),
            "functions_missing": len(keys) - len(found),
            "functions_with_line_maps": sum(item.line_map_present for item in found),
            "functions_with_variable_lines": sum(item.variables_with_lines > 0 for item in found),
            "functions_with_variable_addresses": sum(
                item.variable_address_present for item in found
            ),
            "line_mapping_rows": sum(item.line_mapping_rows for item in found),
            "mapped_addresses": sum(item.mapped_addresses for item in found),
            "variables": sum(item.variable_count for item in found),
            "variables_with_lines": sum(item.variables_with_lines for item in found),
            "variables_with_addresses": sum(item.variables_with_addresses for item in found),
        }
    return rows


def _producer_evidence_sha256(producer: Mapping[ProducerKey, ProducerEvidence]) -> str:
    rows = [
        [
            backend,
            *key,
            item.function_found,
            item.line_mapping_rows,
            item.mapped_addresses,
            item.variable_count,
            item.variables_with_lines,
            item.variables_with_addresses,
        ]
        for (backend, key), item in sorted(producer.items())
    ]
    payload = json.dumps(rows, allow_nan=False, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _comparison_stats(
    baseline: ModeOverlay,
    candidate: ModeOverlay,
    keys: set[FunctionKey],
    backends: Sequence[str],
    perfect_value: float,
    *,
    regression_limit: int,
    include_examples: bool,
) -> dict[str, Any]:
    backend_rows: dict[str, Any] = {}
    combined_pairs: list[tuple[str, FunctionKey]] = [
        (backend, key) for backend in backends for key in sorted(keys)
    ]

    def summarize(pairs: Sequence[tuple[str, FunctionKey]]) -> dict[str, Any]:
        paired: list[tuple[str, FunctionKey, ScoreEntry, ScoreEntry]] = []
        baseline_only: list[tuple[str, FunctionKey]] = []
        candidate_only: list[tuple[str, FunctionKey]] = []
        both_missing = 0
        for backend, key in pairs:
            left = baseline.scores.get(backend, {}).get(key)
            right = candidate.scores.get(backend, {}).get(key)
            if left is not None and right is not None:
                paired.append((backend, key, left, right))
            elif left is not None:
                baseline_only.append((backend, key))
            elif right is not None:
                candidate_only.append((backend, key))
            else:
                both_missing += 1
        deltas = [right.value - left.value for _backend, _key, left, right in paired]
        denominator = len(pairs)
        left_sum = sum(
            baseline.scores.get(backend, {}).get(key, ScoreEntry(0.0, "missing")).value
            for backend, key in pairs
        )
        right_sum = sum(
            candidate.scores.get(backend, {}).get(key, ScoreEntry(0.0, "missing")).value
            for backend, key in pairs
        )
        left_perfect = {
            (backend, key)
            for backend, key in pairs
            if (entry := baseline.scores.get(backend, {}).get(key)) is not None
            and entry.value >= perfect_value
        }
        right_perfect = {
            (backend, key)
            for backend, key in pairs
            if (entry := candidate.scores.get(backend, {}).get(key)) is not None
            and entry.value >= perfect_value
        }
        transitions = Counter(
            f"{left.evidence}->{right.evidence}" for _backend, _key, left, right in paired
        )
        result: dict[str, Any] = {
            "shared_denominator": denominator,
            "coverage": {
                "paired_measured": len(paired),
                "baseline_only": len(baseline_only),
                "candidate_only": len(candidate_only),
                "both_missing": both_missing,
            },
            "paired_partial": {
                "baseline_mean": (
                    sum(left.value for _backend, _key, left, _right in paired) / len(paired)
                    if paired
                    else None
                ),
                "candidate_mean": (
                    sum(right.value for _backend, _key, _left, right in paired) / len(paired)
                    if paired
                    else None
                ),
                "delta_percentage_points": (100.0 * sum(deltas) / len(deltas) if deltas else None),
                "improved": sum(delta > SCORE_EPSILON for delta in deltas),
                "regressed": sum(delta < -SCORE_EPSILON for delta in deltas),
                "unchanged": sum(abs(delta) <= SCORE_EPSILON for delta in deltas),
            },
            "shared_partial": {
                "baseline_zero_filled_mean": left_sum / denominator if denominator else None,
                "candidate_zero_filled_mean": right_sum / denominator if denominator else None,
                "delta_percentage_points": (
                    100.0 * (right_sum - left_sum) / denominator if denominator else None
                ),
            },
            "published_perfect": {
                "baseline_count": len(left_perfect),
                "candidate_count": len(right_perfect),
                "gained": len(right_perfect - left_perfect),
                "lost": len(left_perfect - right_perfect),
                "baseline_rate": len(left_perfect) / denominator if denominator else None,
                "candidate_rate": len(right_perfect) / denominator if denominator else None,
                "delta_percentage_points": (
                    100.0 * (len(right_perfect) - len(left_perfect)) / denominator
                    if denominator
                    else None
                ),
            },
            "evidence_transitions": dict(sorted(transitions.items())),
        }
        if include_examples:
            regressions = sorted(
                (
                    right.value - left.value,
                    backend,
                    key,
                    left,
                    right,
                )
                for backend, key, left, right in paired
                if right.value < left.value - SCORE_EPSILON
            )
            result["regression_examples"] = [
                {
                    "backend": backend,
                    "function_key": key_text(key),
                    "baseline": left.value,
                    "candidate": right.value,
                    "delta": delta,
                    "evidence_transition": f"{left.evidence}->{right.evidence}",
                }
                for delta, backend, key, left, right in regressions[:regression_limit]
            ]
            result["coverage_loss_examples"] = [
                {"backend": backend, "function_key": key_text(key)}
                for backend, key in baseline_only[:regression_limit]
            ]
        return result

    for backend in backends:
        backend_rows[backend] = summarize([(backend, key) for key in sorted(keys)])
    return {
        "all_backends": summarize(combined_pairs),
        "backends": backend_rows,
    }


def _provenance_identity(provenance: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if provenance is None:
        return None
    return {
        key: provenance.get(key)
        for key in (
            "policy_schema",
            "policy",
            "metric_cache_version",
            "structured_occurrence_mode",
            "variable_occurrence_policy_schema",
        )
    }


def build_report(
    *,
    function_data_path: Path,
    results_root: Path,
    manifest_path: Path | None,
    modes: Sequence[tuple[str, Path]],
    baseline_mode: str,
    requested_backends: Sequence[str] = (),
    checkpoint_dir: Path | None = None,
    regression_limit: int = 100,
) -> dict[str, Any]:
    """Build one deterministic multi-mode TypeMatch A/B report."""

    if regression_limit < 0:
        raise ValueError("regression_limit must be non-negative")
    if not modes:
        raise ValueError("at least one mode overlay is required")
    mode_names = [name for name, _path in modes]
    if len(mode_names) != len(set(mode_names)):
        raise ValueError("mode names must be unique")
    if baseline_mode not in mode_names:
        raise ValueError(f"baseline mode {baseline_mode!r} was not provided")

    selected_keys = load_manifest(manifest_path) if manifest_path is not None else None
    universe = load_universe(
        function_data_path,
        selected_keys=selected_keys,
        results_root=results_root,
    )
    overlays = [load_mode_overlay(name, path) for name, path in modes]
    overlays_by_name = {overlay.name: overlay for overlay in overlays}
    available_backends = sorted({backend for overlay in overlays for backend in overlay.scores})
    backends = list(dict.fromkeys(requested_backends or available_backends))
    if not backends:
        raise ValueError("mode overlays contain no decompilers")

    validation_errors: list[str] = []
    warnings: list[str] = []
    if universe.missing_manifest_keys:
        validation_errors.append(
            f"{len(universe.missing_manifest_keys)} manifest keys are absent from function data"
        )
    backend_sets = [
        {backend for backend in overlay.scores if backend in backends} for overlay in overlays
    ]
    if any(backends_set != set(backends) for backends_set in backend_sets):
        validation_errors.append("requested backend coverage differs across mode overlays")
    identities = [_provenance_identity(overlay.provenance) for overlay in overlays]
    if any(identity is None for identity in identities):
        validation_errors.append("one or more mode overlays lack digest-bound provenance")
    elif any(identity != identities[0] for identity in identities[1:]):
        validation_errors.append("mode overlays use incompatible matcher policy or cache versions")
    for overlay in overlays:
        if overlay.provenance is None:
            continue
        if str(overlay.provenance.get("metric_cache_version")) == "11":
            if overlay.provenance.get("structured_occurrence_mode") != "producer":
                validation_errors.append(
                    f"v11 mode {overlay.name!r} does not declare producer occurrence mode"
                )
            if (
                overlay.provenance.get("variable_occurrence_policy_schema")
                != VARIABLE_OCCURRENCE_POLICY_SCHEMA
            ):
                validation_errors.append(
                    f"v11 mode {overlay.name!r} does not declare the occurrence-policy schema"
                )
            unreported = sum(
                entry.producer_occurrence_policy == "unreported"
                or entry.structured_occurrence_mode != "producer"
                for backend in backends
                for entry in overlay.scores.get(backend, {}).values()
            )
            if unreported:
                validation_errors.append(
                    f"v11 mode {overlay.name!r} has {unreported} entries without complete "
                    "producer occurrence provenance"
                )
        declared = {
            str(overlay.provenance.get("mode")),
            str(overlay.provenance.get("resolved_mode")),
        }
        if overlay.name == "stacked" and "address+usage" in declared:
            continue
        if overlay.name not in declared:
            validation_errors.append(
                f"mode label {overlay.name!r} disagrees with {overlay.path} provenance"
            )

    denominator_keys = set(universe.measurable)
    for backend in backends:
        keysets = [denominator_keys & set(overlay.scores.get(backend, {})) for overlay in overlays]
        if any(keyset != keysets[0] for keyset in keysets[1:]):
            validation_errors.append(f"measured key coverage differs across modes for {backend}")

    producer: dict[ProducerKey, ProducerEvidence] = {}
    if checkpoint_dir is not None:
        producer, producer_warnings = load_producer_evidence(
            checkpoint_dir,
            denominator_keys,
            backends,
        )
        warnings.extend(producer_warnings)
    else:
        warnings.append("producer checkpoints were not provided; line-map coverage is unavailable")

    strata: defaultdict[str, set[FunctionKey]] = defaultdict(set)
    for key, fact in universe.measurable.items():
        strata[fact.stratum].add(key)
    optimization_levels: defaultdict[str, set[FunctionKey]] = defaultdict(set)
    for key in universe.measurable:
        optimization_levels[key[1]].add(key)
    unknown_strata = sum(len(keys) for name, keys in strata.items() if "unknown" in name)
    if unknown_strata:
        warnings.append(
            f"could not resolve architecture or format for {unknown_strata} denominator functions"
        )

    mode_report: dict[str, Any] = {}
    for overlay in overlays:
        mode_report[overlay.name] = {
            "overall": _score_stats(
                overlay,
                denominator_keys,
                backends,
                universe.perfect_value,
                producer,
            ),
            "strata": {
                stratum: _score_stats(
                    overlay,
                    keys,
                    backends,
                    universe.perfect_value,
                    producer,
                )
                for stratum, keys in sorted(strata.items())
            },
            "optimization_levels": {
                optimization: _score_stats(
                    overlay,
                    keys,
                    backends,
                    universe.perfect_value,
                    producer,
                )
                for optimization, keys in sorted(optimization_levels.items())
            },
        }

    baseline = overlays_by_name[baseline_mode]
    comparisons: dict[str, Any] = {}
    for candidate in overlays:
        if candidate.name == baseline_mode:
            continue
        comparisons[f"{candidate.name}_minus_{baseline_mode}"] = {
            "baseline": baseline_mode,
            "candidate": candidate.name,
            "overall": _comparison_stats(
                baseline,
                candidate,
                denominator_keys,
                backends,
                universe.perfect_value,
                regression_limit=regression_limit,
                include_examples=True,
            ),
            "strata": {
                stratum: _comparison_stats(
                    baseline,
                    candidate,
                    keys,
                    backends,
                    universe.perfect_value,
                    regression_limit=0,
                    include_examples=False,
                )
                for stratum, keys in sorted(strata.items())
            },
            "optimization_levels": {
                optimization: _comparison_stats(
                    baseline,
                    candidate,
                    keys,
                    backends,
                    universe.perfect_value,
                    regression_limit=0,
                    include_examples=False,
                )
                for optimization, keys in sorted(optimization_levels.items())
            },
        }

    selected_count = len(universe.selected) + len(universe.missing_manifest_keys)
    report = {
        "schema": REPORT_SCHEMA,
        "provenance": {
            "function_data": {
                "path": str(function_data_path),
                "sha256": file_sha256(function_data_path),
            },
            "results_root": str(results_root),
            "manifest": (
                {
                    "path": str(manifest_path),
                    "sha256": file_sha256(manifest_path),
                }
                if manifest_path is not None
                else None
            ),
            "checkpoint_evidence": (
                {
                    "directory": str(checkpoint_dir),
                    "selected_entry_count": len(producer),
                    "selected_evidence_sha256": _producer_evidence_sha256(producer),
                }
                if checkpoint_dir is not None
                else None
            ),
            "modes": {
                overlay.name: {
                    "path": str(overlay.path),
                    "sha256": overlay.sha256,
                    "raw_entry_count": overlay.raw_entry_count,
                    "overlay_provenance": overlay.provenance,
                }
                for overlay in overlays
            },
        },
        "methodology": {
            "conditional_partial_mean": "sum of finite scores divided by measured scores",
            "shared_partial_mean": "missing backend scores count as zero",
            "published_perfect_rate": (
                "perfect scores divided by the shared function denominator; missing scores "
                "are not-perfect misses"
            ),
            "optimization_level_strata": (
                "the shared function denominator partitioned by recorded optimization level"
            ),
            "evidence_caveat": (
                "site_caveated counts accepted mixed/fallback_only evidence; potential_undercount "
                "also includes no accepted correspondence and checkpointed functions without "
                "variable-address evidence"
            ),
            "comparison_epsilon": SCORE_EPSILON,
        },
        "scope": {
            "selected_functions": selected_count,
            "globally_type_measurable_functions": len(denominator_keys),
            "globally_unmeasurable_functions": selected_count - len(denominator_keys),
            "selected_key_sha256": keyset_sha256(universe.selected),
            "shared_denominator_key_sha256": keyset_sha256(denominator_keys),
            "backends": backends,
            "strata": {name: len(keys) for name, keys in sorted(strata.items())},
            "optimization_levels": {
                name: len(keys) for name, keys in sorted(optimization_levels.items())
            },
            "missing_manifest_keys": [key_text(key) for key in universe.missing_manifest_keys],
        },
        "producer_evidence": {
            "status": "loaded" if checkpoint_dir is not None else "not_provided",
            "overall": _producer_stats(denominator_keys, backends, producer),
            "strata": {
                stratum: _producer_stats(keys, backends, producer)
                for stratum, keys in sorted(strata.items())
            },
            "optimization_levels": {
                optimization: _producer_stats(keys, backends, producer)
                for optimization, keys in sorted(optimization_levels.items())
            },
        },
        "modes": mode_report,
        "comparisons": comparisons,
        "validation": {
            "valid_for_apples_to_apples": not validation_errors,
            "errors": validation_errors,
            "warnings": warnings,
        },
    }
    return report


def _percentage(value: float | None) -> str:
    return "n/a" if value is None else f"{100.0 * value:.2f}%"


def _points(value: float | None) -> str:
    return "n/a" if value is None else f"{value:+.2f} pp"


def _perfect_transition(row: Mapping[str, Any]) -> str:
    perfect = row["published_perfect"]
    return (
        f"{_percentage(perfect['baseline_rate'])} → "
        f"{_percentage(perfect['candidate_rate'])} "
        f"({_points(perfect['delta_percentage_points'])})"
    )


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render the headline parts of a JSON report as review-friendly Markdown."""

    scope = report["scope"]
    lines = [
        "# TypeMatch mode A/B",
        "",
        f"Shared denominator: **{scope['globally_type_measurable_functions']:,}** of "
        f"{scope['selected_functions']:,} selected functions, identically applied to every "
        "backend.",
        "",
        "## Overall scores",
        "",
        "| Backend | Mode | Measured | Missing | Conditional partial mean | "
        "Shared zero-filled mean | Perfect / shared | Caveat coverage |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    backends = scope["backends"]
    for mode, mode_result in report["modes"].items():
        backend_rows = mode_result["overall"]["backends"]
        displayed = [("ALL (micro)", mode_result["overall"]["all_backends"])]
        displayed.extend((backend, backend_rows[backend]) for backend in backends)
        for backend, row in displayed:
            coverage = row["coverage"]
            partial = row["conditional_partial"]
            shared = row["shared_partial"]
            perfect = row["published_perfect"]
            evidence = row["evidence"]
            marker = "*" if evidence["asterisk_recommended"] else ""
            lines.append(
                f"| {backend} | `{mode}` | {coverage['measured']:,} | "
                f"{coverage['missing']:,} | {_percentage(partial['mean'])} | "
                f"{_percentage(shared['zero_filled_mean'])} | {perfect['count']:,} / "
                f"{perfect['denominator']:,} ({_percentage(perfect['rate'])}) | "
                f"{evidence['potential_undercount']:,}{marker} |"
            )

    lines.extend(
        [
            "",
            "## Paired comparisons",
            "",
            "| Comparison | Backend | Paired | Better / worse / same | Coverage + / - | "
            "Paired partial delta | Perfect-rate delta |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, comparison in report["comparisons"].items():
        backend_rows = comparison["overall"]["backends"]
        displayed = [("ALL (micro)", comparison["overall"]["all_backends"])]
        displayed.extend((backend, backend_rows[backend]) for backend in backends)
        for backend, row in displayed:
            coverage = row["coverage"]
            partial = row["paired_partial"]
            perfect = row["published_perfect"]
            lines.append(
                f"| `{name}` | {backend} | {coverage['paired_measured']:,} | "
                f"{partial['improved']:,} / {partial['regressed']:,} / "
                f"{partial['unchanged']:,} | {coverage['candidate_only']:,} / "
                f"{coverage['baseline_only']:,} | "
                f"{_points(partial['delta_percentage_points'])} | "
                f"{_points(perfect['delta_percentage_points'])} |"
            )

    optimization_levels = list(scope["optimization_levels"])
    if optimization_levels and report["comparisons"]:
        lines.extend(
            [
                "",
                "## Optimization levels",
                "",
                "Each cell is the baseline → candidate published perfect rate and its "
                "percentage-point delta over that optimization level's shared function set.",
            ]
        )
        for name, comparison in report["comparisons"].items():
            headers = " | ".join(
                f"`{optimization}` ({scope['optimization_levels'][optimization]:,} functions)"
                for optimization in optimization_levels
            )
            lines.extend(
                [
                    "",
                    f"### `{name}`",
                    "",
                    f"| Backend | {headers} |",
                    f"| --- | {' | '.join('---:' for _ in optimization_levels)} |",
                ]
            )
            optimization_backends = ["ALL (micro)", *backends]
            for backend in optimization_backends:
                cells: list[str] = []
                for optimization in optimization_levels:
                    scoped = comparison["optimization_levels"][optimization]
                    row = (
                        scoped["all_backends"]
                        if backend == "ALL (micro)"
                        else scoped["backends"][backend]
                    )
                    cells.append(_perfect_transition(row))
                lines.append(f"| {backend} | {' | '.join(cells)} |")

    lines.extend(["", "## Producer evidence", ""])
    if report["producer_evidence"]["status"] == "not_provided":
        lines.append("Checkpoint evidence was not provided; line-map coverage is unavailable.")
    else:
        lines.extend(
            [
                "| Backend | Functions found | Line maps | Variable lines | Variable addresses |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for backend in backends:
            row = report["producer_evidence"]["overall"][backend]
            lines.append(
                f"| {backend} | {row['functions_found']:,} | "
                f"{row['functions_with_line_maps']:,} | "
                f"{row['functions_with_variable_lines']:,} | "
                f"{row['functions_with_variable_addresses']:,} |"
            )

    lines.extend(
        [
            "",
            "## Producer occurrence policy",
            "",
            "| Mode | Backend | Exact | Direct | Unavailable | Undeclared | Unreported |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for mode, mode_result in report["modes"].items():
        for backend in backends:
            policies = mode_result["overall"]["backends"][backend]["evidence"][
                "producer_occurrence_policies"
            ]
            lines.append(
                f"| `{mode}` | {backend} | {policies['exact']:,} | "
                f"{policies['direct']:,} | {policies['unavailable']:,} | "
                f"{policies['undeclared']:,} | {policies['unreported']:,} |"
            )

    lines.extend(["", "## Architecture / format", ""])
    lines.append("| Stratum | Shared functions |")
    lines.append("| --- | ---: |")
    for stratum, count in scope["strata"].items():
        lines.append(f"| `{stratum}` | {count:,} |")
    if report["comparisons"]:
        lines.extend(
            [
                "",
                "| Stratum | Comparison | Shared backend/function pairs | Paired | "
                "Partial delta | Perfect-rate delta |",
                "| --- | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for name, comparison in report["comparisons"].items():
            for stratum, scoped in comparison["strata"].items():
                row = scoped["all_backends"]
                lines.append(
                    f"| `{stratum}` | `{name}` | {row['shared_denominator']:,} | "
                    f"{row['coverage']['paired_measured']:,} | "
                    f"{_points(row['paired_partial']['delta_percentage_points'])} | "
                    f"{_points(row['published_perfect']['delta_percentage_points'])} |"
                )

    validation = report["validation"]
    lines.extend(
        [
            "",
            "## Validation",
            "",
            f"Apples-to-apples: **{'yes' if validation['valid_for_apples_to_apples'] else 'no'}**.",
        ]
    )
    for error in validation["errors"]:
        lines.append(f"- Error: {error}")
    for warning in validation["warnings"]:
        lines.append(f"- Warning: {warning}")
    lines.extend(
        [
            "",
            "Conditional partial means exclude missing scores. Shared zero-filled means and "
            "perfect rates use the benchmark's shared denominator. `*` marks potential "
            "measurement undercount, not a score adjustment.",
            "",
        ]
    )
    return "\n".join(lines)


def json_payload(report: Mapping[str, Any]) -> str:
    """Serialize a report deterministically."""

    return json.dumps(report, allow_nan=False, indent=2, sort_keys=True) + "\n"
