"""Re-evaluate type_match from checkpoints without running decompilers.

Correspondence is always address evidence. Scoped or experimental replays can be
compared in place, or written to an explicitly named output file for A/B analysis.
Only ``--emit`` may write the canonical ``type_match_new.json`` overlay. Every
written overlay has a digest-bound ``.meta.json`` companion recording its matcher
mode, policy schema, policy values, and metric cache version.

Usage::

    python scripts/reeval_typematch.py results/full_run
    python scripts/reeval_typematch.py results/full_run \
        --output results/full_run/type_match_address.json sample-set
    python scripts/reeval_typematch.py results/full_run --emit
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pickle
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TypedDict

import decbench.decompilers  # noqa: F401 (register backends so pickles load)
from decbench.decompilers.final_render_provenance import (
    enrich_final_render_variable_provenance,
    is_frozen_phoenix_render,
)
from decbench.decompilers.provenance import (
    NativeProvenanceContext,
    sanitize_native_provenance,
)
from decbench.metrics.base import MetricConfig
from decbench.metrics.type_match import TypeMatchMetric
from decbench.models.decompilation import (
    VARIABLE_OCCURRENCE_POLICIES,
    VARIABLE_OCCURRENCE_POLICY_SCHEMA,
    DecompilationResult,
)
from decbench.models.function_data import VARIABLE_MATCH_EVIDENCE
from decbench.results_store import (
    TYPEMATCH_MATCHER_MODE,
    TypeMatchOverlayError,
    merge_typematch_overlay,
    read_typematch_overlay,
    typematch_overlay_manifest_path,
    typematch_overlay_provenance,
    write_typematch_overlay_atomic,
)
from decbench.utils import binfmt
from decbench.utils.langs import preprocessed_by_stem

PRODUCER_OCCURRENCE_POLICIES = frozenset((*VARIABLE_OCCURRENCE_POLICIES, "undeclared"))
SampleKey = tuple[str, str, str, str]
ScoreKey = tuple[str, str, str, str, str]


class AggregateRow(TypedDict):
    o: float
    n: float
    c: int
    imp: int
    wor: int


class CanonicalPromotionError(RuntimeError):
    """Raised when a canonical type-match overlay cannot be promoted safely."""


class BinaryRelocationError(RuntimeError):
    """Raised when a checkpoint binary cannot be rebound to the selected tree."""


def _paths_alias(left: Path, right: Path) -> bool:
    if left.resolve() == right.resolve():
        return True
    try:
        return os.path.samefile(left, right)
    except (FileNotFoundError, OSError):
        return False


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("projects", nargs="*")
    parser.add_argument(
        "--manifest",
        type=Path,
        help="limit an A/B run to functions in a sample-set manifest",
    )
    parser.add_argument(
        "--backend",
        action="append",
        default=[],
        help="limit a non-canonical replay to this exact backend id; repeatable",
    )
    parser.add_argument(
        "--function-data",
        type=Path,
        help=(
            "explicit frozen function_results.json denominator for a non-canonical replay "
            "(default: RESULTS_DIR/function_results.json)"
        ),
    )
    outputs = parser.add_mutually_exclusive_group()
    outputs.add_argument(
        "--emit",
        action="store_true",
        help="write the canonical type_match_new.json overlay",
    )
    outputs.add_argument(
        "--output",
        type=Path,
        help="write an explicitly named A/B overlay without touching the canonical one",
    )
    args = parser.parse_args(argv)
    if args.emit and args.manifest is not None:
        parser.error("--manifest is for partial A/B runs and cannot be combined with --emit")
    if args.emit and args.backend:
        parser.error("--backend is for non-canonical A/B runs and cannot be combined with --emit")
    if args.backend and args.output is None:
        parser.error("--backend requires an explicitly named --output A/B overlay")
    if args.function_data is not None and args.output is None:
        parser.error("--function-data requires an explicitly named --output A/B overlay")
    if args.output is not None:
        canonical = args.results_dir / "type_match_new.json"
        function_data = args.function_data or args.results_dir / "function_results.json"
        protected = [canonical, typematch_overlay_manifest_path(canonical), function_data]
        if args.manifest is not None:
            protected.append(args.manifest)
        candidates = (args.output, typematch_overlay_manifest_path(args.output))
        if any(_paths_alias(candidate, target) for candidate in candidates for target in protected):
            parser.error(
                "--output and its metadata must not alias the canonical overlay, "
                "function data, or selected manifest"
            )
    return args


def _sample_keys(path: Path) -> set[SampleKey]:
    try:
        payload = json.loads(path.read_text())
        functions = payload["functions"]
        keys = {
            (
                str(row["project"]),
                str(row["opt"]),
                str(row["binary"]),
                str(row["function"]),
            )
            for row in functions
        }
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"invalid sample-set manifest {path}: {exc}") from exc
    if not isinstance(functions, list) or not keys:
        raise ValueError(f"sample-set manifest has no functions: {path}")
    return keys


def _validate_checkpoint_decompilation(
    decompilation: object,
    *,
    binary_name: str,
    backend_name: str,
    coordinate: str,
) -> DecompilationResult:
    """Require checkpoint container keys to agree with the stored model identity."""

    if not isinstance(decompilation, DecompilationResult):
        raise BinaryRelocationError(
            f"checkpoint result is not a DecompilationResult at {coordinate}"
        )
    if decompilation.binary_name != binary_name:
        raise BinaryRelocationError(
            f"checkpoint binary identity mismatch at {coordinate}: "
            f"outer={binary_name!r}, inner={decompilation.binary_name!r}"
        )
    if decompilation.decompiler.decompiler_name != backend_name:
        raise BinaryRelocationError(
            f"checkpoint backend identity mismatch at {coordinate}: "
            f"outer={backend_name!r}, inner={decompilation.decompiler.decompiler_name!r}"
        )
    for function_name, function in decompilation.functions.items():
        if not isinstance(function_name, str) or function_name != function.name:
            raise BinaryRelocationError(
                f"checkpoint function identity mismatch at {coordinate}: "
                f"outer={function_name!r}, inner={function.name!r}"
            )
    return decompilation


def _resolve_checkpoint_binary(
    root: Path,
    optimization: str,
    project: str,
    binary_name: str,
) -> Path:
    """Resolve one checkpoint binary strictly inside the selected results tree."""
    if not binary_name or Path(binary_name).name != binary_name:
        raise BinaryRelocationError(
            f"invalid checkpoint binary key {binary_name!r} for {project}/{optimization}"
        )

    compiled = root / optimization / project / "compiled"
    if not compiled.is_dir():
        raise BinaryRelocationError(f"missing compiled directory: {compiled}")

    exact = compiled / binary_name
    if exact.is_file() and not exact.is_symlink() and binfmt.detect(exact) is not None:
        return exact.resolve()

    candidates = sorted(
        path.resolve()
        for path in compiled.iterdir()
        if path.is_file()
        and not path.is_symlink()
        and path.stem == binary_name
        and binfmt.detect(path) is not None
    )
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise BinaryRelocationError(
            f"no compiled ELF/PE matches {project}/{optimization}/{binary_name} in {compiled}"
        )
    choices = ", ".join(path.name for path in candidates)
    raise BinaryRelocationError(
        f"ambiguous compiled binary for {project}/{optimization}/{binary_name}: {choices}"
    )


def _relocate_decompilation(decompilation: object, binary_path: Path) -> object:
    """Copy a checkpoint result while replacing its recorded binary path."""
    model_copy = getattr(decompilation, "model_copy", None)
    if not callable(model_copy):
        raise BinaryRelocationError(f"checkpoint decompilation cannot be rebound to {binary_path}")
    relocated = model_copy(deep=True, update={"binary_path": binary_path})
    if Path(getattr(relocated, "binary_path", "")) != binary_path:
        raise BinaryRelocationError(
            f"checkpoint decompilation did not accept binary path {binary_path}"
        )
    return relocated


def _prepare_decompilation(
    decompilation: object,
    _functions: set[str] | None,
    context: NativeProvenanceContext,
) -> object:
    relocated = _relocate_decompilation(decompilation, context.binary_path)
    if not isinstance(relocated, DecompilationResult):
        raise BinaryRelocationError(
            f"checkpoint decompilation is not a DecompilationResult for {context.binary_path}"
        )
    sanitize_native_provenance(
        relocated,
        context.binary_path,
        context=context,
    )
    if is_frozen_phoenix_render(relocated):
        enrich_final_render_variable_provenance(relocated)
    return relocated


def _function_data_scope(
    root: Path,
    function_data_path: Path | None = None,
) -> tuple[dict[ScoreKey, float], set[SampleKey], set[SampleKey]]:
    """Load historical scores and the frozen global TypeMatch denominator once."""

    path = function_data_path or root / "function_results.json"
    with open(path) as file:
        function_data = json.load(file)
    old: dict[ScoreKey, float] = {}
    selected: set[SampleKey] = set()
    measurable: set[SampleKey] = set()
    try:
        groups = function_data["groups"]
        for group in groups:
            function_prefix = (
                str(group["project"]),
                str(group["opt_level"]),
                str(group["binary"]),
            )
            for function in group["functions"]:
                function_key = (*function_prefix, str(function["function"]))
                if function_key in selected:
                    raise ValueError(
                        "function data contains duplicate function key: " + "::".join(function_key)
                    )
                selected.add(function_key)
                for decompiler, values in (function.get("values") or {}).items():
                    if not isinstance(values, Mapping):
                        continue
                    raw_value = values.get("type_match")
                    if (
                        not isinstance(raw_value, (int, float))
                        or isinstance(raw_value, bool)
                        or not math.isfinite(float(raw_value))
                    ):
                        continue
                    measurable.add(function_key)
                    old[(*function_key, str(decompiler))] = float(raw_value)
    except (KeyError, TypeError) as exc:
        raise ValueError(f"invalid function data {path}: {exc}") from exc
    return old, selected, measurable


def _score_keys(
    scores: dict[str, dict[str, dict[str, float | int | str]]],
) -> set[ScoreKey]:
    keys: set[ScoreKey] = set()
    for decompiler, per_decompiler in scores.items():
        for score_key in per_decompiler:
            project, optimization, binary, function = score_key.split("::", 3)
            keys.add((project, optimization, binary, function, decompiler))
    return keys


def _without_scoped_scores(
    existing: dict[str, dict[str, object]],
    *,
    function_scope: set[SampleKey],
    backend_scope: set[str] | None,
) -> dict[str, dict[str, object]]:
    """Drop the evaluated scope before an additive, provenance-checked merge."""

    retained: dict[str, dict[str, object]] = {}
    for decompiler, per_decompiler in existing.items():
        if backend_scope is not None and decompiler not in backend_scope:
            retained[decompiler] = dict(per_decompiler)
            continue
        kept: dict[str, object] = {}
        for raw_key, entry in per_decompiler.items():
            parts = raw_key.split("::", 3)
            if len(parts) != 4 or any(not part for part in parts):
                raise TypeMatchOverlayError(
                    f"existing type-match overlay has an invalid function key: {raw_key!r}"
                )
            function_key = (parts[0], parts[1], parts[2], parts[3])
            if function_key not in function_scope:
                kept[raw_key] = entry
        if kept:
            retained[decompiler] = kept
    return retained


def _coverage_failure(
    expected: set[ScoreKey],
    new_scores: dict[str, dict[str, dict[str, float | int | str]]],
) -> str | None:
    return _coverage_difference(expected, _score_keys(new_scores))


def _coverage_difference(expected: set[ScoreKey], actual: set[ScoreKey]) -> str | None:
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if not missing and not unexpected:
        return None

    def samples(keys: list[ScoreKey]) -> str:
        return ", ".join("::".join(key) for key in keys[:3])

    details = [
        f"overlay coverage mismatch: expected {len(expected)} entries, got {len(actual)}",
    ]
    if missing:
        details.append(f"missing {len(missing)} ({samples(missing)})")
    if unexpected:
        details.append(f"unexpected {len(unexpected)} ({samples(unexpected)})")
    return "; ".join(details)


def _promotion_provenance(metric: TypeMatchMetric) -> dict[str, object]:
    return typematch_overlay_provenance(
        mode=TYPEMATCH_MATCHER_MODE,
        resolved_mode=TYPEMATCH_MATCHER_MODE,
        policy=metric.variable_match_policy,
        metric_cache_version=metric.cache_version,
        structured_occurrence_mode="producer",
        variable_occurrence_policy_schema=VARIABLE_OCCURRENCE_POLICY_SCHEMA,
    )


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    root: Path = args.results_dir.resolve()
    function_data_path = (
        args.function_data.resolve(strict=True)
        if args.function_data is not None
        else root / "function_results.json"
    )
    if not function_data_path.is_file():
        raise ValueError(f"function data is not a regular file: {function_data_path}")
    old, function_keys, measurable_keys = _function_data_scope(root, function_data_path)
    checkpoint_dir = root / "checkpoints"
    sample_keys = _sample_keys(args.manifest) if args.manifest is not None else None
    if sample_keys is not None:
        missing_manifest_keys = sorted(sample_keys - function_keys)
        if missing_manifest_keys:
            samples = ", ".join("::".join(key) for key in missing_manifest_keys[:3])
            raise ValueError(
                f"sample-set manifest has {len(missing_manifest_keys)} functions absent from "
                f"function data ({samples})"
            )
    manifest_projects = sorted({key[0] for key in sample_keys}) if sample_keys is not None else []
    measurable_projects = sorted(
        {key[0] for key in measurable_keys if sample_keys is None or key in sample_keys}
    )
    projects = list(dict.fromkeys(args.projects or manifest_projects or measurable_projects))
    metric = TypeMatchMetric(MetricConfig())
    provenance = _promotion_provenance(metric)
    aggregate: defaultdict[str, AggregateRow] = defaultdict(
        lambda: {"o": 0.0, "n": 0.0, "c": 0, "imp": 0, "wor": 0}
    )
    new_scores: dict[str, dict[str, dict[str, float | int | str]]] = {}
    write_requested = args.emit or args.output is not None
    write_failures: list[str] = []
    expected_score_keys: set[ScoreKey] = set()
    requested_backends = set(args.backend)
    scored_backends: set[str] = set()

    for project in projects:
        checkpoint_path = checkpoint_dir / f"{project}.pkl"
        if not checkpoint_path.is_file():
            message = f"missing checkpoint: {checkpoint_path}"
            print(f"  ! {message}")
            if write_requested:
                write_failures.append(message)
            continue
        with open(checkpoint_path, "rb") as file:
            data = pickle.load(file)
        for optimization, binaries in data.get("decompile", {}).items():
            opt_name = getattr(optimization, "value", str(optimization))
            compiled = root / opt_name / project / "compiled"
            sources = list(preprocessed_by_stem(compiled).values())
            for binary_name, decompilers in binaries.items():
                if not isinstance(binary_name, str):
                    raise BinaryRelocationError(
                        f"checkpoint binary key is not a string at {project}/{opt_name}: "
                        f"{binary_name!r}"
                    )
                selected_functions = (
                    {
                        function
                        for sample_project, sample_opt, sample_binary, function in sample_keys
                        if sample_project == project
                        and sample_opt == opt_name
                        and sample_binary == binary_name
                    }
                    if sample_keys is not None
                    else None
                )
                if selected_functions is not None and not selected_functions:
                    continue
                try:
                    binary_path = _resolve_checkpoint_binary(
                        root,
                        opt_name,
                        project,
                        binary_name,
                    )
                except BinaryRelocationError as exc:
                    context = f"{project}/{opt_name}/{binary_name}"
                    print(f"  ! {context}: {exc}")
                    if write_requested:
                        write_failures.append(f"binary relocation failed for {context}: {exc}")
                        continue
                    raise
                native_context = NativeProvenanceContext(binary_path)
                for decompiler_name, decompilation in decompilers.items():
                    if not isinstance(decompiler_name, str):
                        raise BinaryRelocationError(
                            "checkpoint backend key is not a string at "
                            f"{project}/{opt_name}/{binary_name}: {decompiler_name!r}"
                        )
                    if requested_backends and decompiler_name not in requested_backends:
                        continue
                    try:
                        validated = _validate_checkpoint_decompilation(
                            decompilation,
                            binary_name=binary_name,
                            backend_name=decompiler_name,
                            coordinate=f"{project}/{opt_name}/{binary_name}/{decompiler_name}",
                        )
                        prepared = _prepare_decompilation(
                            validated,
                            None,
                            native_context,
                        )
                        emitted_functions = set(prepared.functions)
                        if selected_functions is not None:
                            emitted_functions.intersection_update(selected_functions)
                        expected_score_keys.update(
                            (
                                project,
                                opt_name,
                                binary_name,
                                str(function_name),
                                str(decompiler_name),
                            )
                            for function_name in emitted_functions
                            if (project, opt_name, binary_name, str(function_name))
                            in measurable_keys
                        )
                        result = metric.compute_for_binary(
                            prepared,
                            preprocessed_sources=sources,
                        )
                    except Exception as exc:  # noqa: BLE001
                        context = f"{project}/{opt_name}/{binary_name}/{decompiler_name}"
                        print(f"  ! {context}: {exc}")
                        if write_requested:
                            write_failures.append(
                                f"metric exception for {context}: {type(exc).__name__}: {exc}"
                            )
                        continue
                    if result.errors:
                        context = f"{project}/{opt_name}/{binary_name}/{decompiler_name}"
                        for error in result.errors:
                            print(f"  ! {context}: {error}")
                        if write_requested:
                            write_failures.append(
                                f"metric reported {len(result.errors)} error(s) for {context}"
                            )
                    for function_name, value in result.function_results.items():
                        if function_name not in emitted_functions:
                            continue
                        scored_backends.add(decompiler_name)
                        key = (
                            project,
                            opt_name,
                            binary_name,
                            function_name,
                            decompiler_name,
                        )
                        if args.emit or args.output is not None:
                            metadata = value.metadata or {}
                            distance = int(metadata.get("fp", 0)) + int(metadata.get("fn", 0))
                            score_key = f"{project}::{opt_name}::{binary_name}::{function_name}"
                            entry: dict[str, float | int | str] = {
                                "value": value.value,
                                "dist": distance,
                            }
                            evidence = metadata.get("variable_match_evidence")
                            if evidence in VARIABLE_MATCH_EVIDENCE:
                                entry["variable_match_evidence"] = evidence
                            occurrence_policy = metadata.get(
                                "producer_variable_occurrence_policy",
                                "undeclared",
                            )
                            if occurrence_policy not in PRODUCER_OCCURRENCE_POLICIES:
                                raise ValueError(
                                    "metric returned an invalid producer variable-occurrence "
                                    f"policy for {decompiler_name}/{score_key}: "
                                    f"{occurrence_policy!r}"
                                )
                            entry["producer_variable_occurrence_policy"] = occurrence_policy
                            structured_mode = metadata.get(
                                "structured_occurrence_mode",
                                "producer",
                            )
                            if structured_mode != "producer":
                                raise ValueError(
                                    "metric returned a non-production structured occurrence "
                                    f"mode for {decompiler_name}/{score_key}: {structured_mode!r}"
                                )
                            entry["structured_occurrence_mode"] = structured_mode
                            new_scores.setdefault(decompiler_name, {})[score_key] = entry
                        if key not in old:
                            continue
                        previous = old[key]
                        row = aggregate[decompiler_name]
                        row["o"] += previous
                        row["n"] += value.value
                        row["c"] += 1
                        if value.value > previous + 1e-9:
                            row["imp"] += 1
                        elif value.value < previous - 1e-9:
                            row["wor"] += 1

    missing_backends = sorted(requested_backends - scored_backends)
    if missing_backends:
        raise ValueError("requested backend(s) produced no scores: " + ", ".join(missing_backends))

    print(f"\nmode: {TYPEMATCH_MATCHER_MODE}")
    if args.manifest is not None:
        digest = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
        print(f"manifest: {args.manifest} ({len(sample_keys or ())} functions, sha256={digest})")
    print(f"{'dec':9} {'n':>7} {'OLD mean':>9} {'NEW mean':>9} {'improved':>9} {'worse':>7}")
    for decompiler in sorted(aggregate):
        row = aggregate[decompiler]
        count = int(row["c"])
        divisor = count or 1
        print(
            f"{decompiler:9} {count:>7} {float(row['o']) / divisor:>9.3f} "
            f"{float(row['n']) / divisor:>9.3f} {int(row['imp']):>9} "
            f"{int(row['wor']):>7}"
        )

    if write_requested:
        coverage_failure = _coverage_failure(expected_score_keys, new_scores)
        if coverage_failure is not None:
            write_failures.append(coverage_failure)
        if write_failures:
            detail = "\n  - ".join(write_failures)
            message = "type-match overlay was not changed:\n  - " + detail
            if args.emit:
                raise CanonicalPromotionError(message)
            raise TypeMatchOverlayError(message)

    output_path = root / "type_match_new.json" if args.emit else args.output
    if output_path is None:
        return
    if args.projects:
        if output_path.is_file():
            existing, existing_provenance = read_typematch_overlay(output_path)
            if existing_provenance is None:
                raise TypeMatchOverlayError(
                    "scoped type-match merges require an existing provenance manifest; "
                    "run an unscoped reevaluation first"
                )
            project_scope = set(args.projects)
            function_scope = {
                key
                for key in function_keys
                if key[0] in project_scope and (sample_keys is None or key in sample_keys)
            }
            retained = _without_scoped_scores(
                existing,
                function_scope=function_scope,
                backend_scope=requested_backends or None,
            )
            new_scores = merge_typematch_overlay(
                retained,
                new_scores,
                existing_provenance=existing_provenance,
                fresh_provenance=provenance,
            )
            final_scope_keys = {
                key
                for key in _score_keys(new_scores)
                if key[:4] in function_scope
                and (not requested_backends or key[4] in requested_backends)
            }
            if final_scope_keys != expected_score_keys:
                failure = _coverage_difference(expected_score_keys, final_scope_keys)
                raise TypeMatchOverlayError(
                    "scoped type-match overlay was not changed: "
                    + (failure or "final scoped coverage mismatch")
                )
        elif args.emit:
            raise CanonicalPromotionError(
                "a scoped canonical promotion requires an existing full overlay; "
                "run an unscoped --emit first"
            )
    write_typematch_overlay_atomic(output_path, new_scores, provenance)
    print(f"\nwrote {output_path}")


if __name__ == "__main__":
    main()
