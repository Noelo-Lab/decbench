"""Re-evaluate type_match from checkpoints without running decompilers.

The default ``auto`` mode is the canonical stacked address+usage policy.
Experimental modes can be compared in place, or written to an explicitly
named output file for A/B analysis. Only ``--emit`` may write the canonical
``type_match_new.json`` overlay, and only in ``auto`` mode. Every written
overlay has a digest-bound ``.meta.json`` companion recording its matcher mode,
policy schema, policy values, and metric cache version.

Usage::

    python scripts/reeval_typematch.py results/full_run
    python scripts/reeval_typematch.py results/full_run --mode usage
    python scripts/reeval_typematch.py results/full_run --mode address \
        --output results/full_run/type_match_address.json sample-set
    python scripts/reeval_typematch.py results/full_run --emit
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import TypedDict

import decbench.decompilers  # noqa: F401 (register backends so pickles load)
from decbench.metrics.base import MetricConfig
from decbench.metrics.type_match import TypeMatchMetric
from decbench.models.function_data import VARIABLE_MATCH_EVIDENCE
from decbench.results_store import (
    TypeMatchOverlayError,
    merge_typematch_overlay,
    read_typematch_overlay,
    typematch_overlay_manifest_path,
    typematch_overlay_provenance,
    write_typematch_overlay_atomic,
)
from decbench.utils.langs import preprocessed_by_stem

MODES = ("auto", "address", "usage", "address+usage")


class AggregateRow(TypedDict):
    o: float
    n: float
    c: int
    imp: int
    wor: int


class CanonicalPromotionError(RuntimeError):
    """Raised when a canonical type-match overlay cannot be promoted safely."""


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
    parser.add_argument("--mode", choices=MODES, default="auto")
    outputs = parser.add_mutually_exclusive_group()
    outputs.add_argument(
        "--emit",
        action="store_true",
        help="write the canonical type_match_new.json overlay (auto mode only)",
    )
    outputs.add_argument(
        "--output",
        type=Path,
        help="write an explicitly named A/B overlay without touching the canonical one",
    )
    args = parser.parse_args(argv)
    if args.emit and args.mode != "auto":
        parser.error("--emit is reserved for the canonical auto mode; use --output for A/B modes")
    if args.output is not None:
        canonical = args.results_dir / "type_match_new.json"
        protected = (canonical, typematch_overlay_manifest_path(canonical))
        candidates = (args.output, typematch_overlay_manifest_path(args.output))
        if any(_paths_alias(candidate, target) for candidate in candidates for target in protected):
            parser.error(
                "--output must not alias the canonical type_match_new.json or its manifest; "
                "use --emit for canonical promotion"
            )
    return args


def _old_scores(root: Path) -> dict[tuple[str, str, str, str, str], float]:
    with open(root / "function_results.json") as file:
        function_data = json.load(file)
    old: dict[tuple[str, str, str, str, str], float] = {}
    for group in function_data["groups"]:
        for function in group["functions"]:
            for decompiler, values in (function.get("values") or {}).items():
                if values and values.get("type_match") is not None:
                    key = (
                        group["project"],
                        group["opt_level"],
                        group["binary"],
                        function["function"],
                        decompiler,
                    )
                    old[key] = float(values["type_match"])
    return old


def _score_keys(
    scores: dict[str, dict[str, dict[str, float | int | str]]],
) -> set[tuple[str, str, str, str, str]]:
    keys: set[tuple[str, str, str, str, str]] = set()
    for decompiler, per_decompiler in scores.items():
        for score_key in per_decompiler:
            project, optimization, binary, function = score_key.split("::", 3)
            keys.add((project, optimization, binary, function, decompiler))
    return keys


def _coverage_failure(
    old: dict[tuple[str, str, str, str, str], float],
    new_scores: dict[str, dict[str, dict[str, float | int | str]]],
    projects: Sequence[str] | None,
) -> str | None:
    scope = set(projects) if projects is not None else None
    expected = {key for key in old if scope is None or key[0] in scope}
    actual = _score_keys(new_scores)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if not missing and not unexpected:
        return None

    def samples(keys: list[tuple[str, str, str, str, str]]) -> str:
        return ", ".join("::".join(key) for key in keys[:3])

    details = [
        f"canonical coverage mismatch: expected {len(expected)} entries, got {len(actual)}",
    ]
    if missing:
        details.append(f"missing {len(missing)} ({samples(missing)})")
    if unexpected:
        details.append(f"unexpected {len(unexpected)} ({samples(unexpected)})")
    return "; ".join(details)


def _promotion_provenance(metric: TypeMatchMetric, mode: str) -> dict[str, object]:
    resolved_mode = "address+usage" if mode == "auto" else mode
    return typematch_overlay_provenance(
        mode=mode,
        resolved_mode=resolved_mode,
        policy=metric.variable_match_policy,
        metric_cache_version=metric.cache_version,
    )


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    root: Path = args.results_dir
    old = _old_scores(root)
    checkpoint_dir = root / "checkpoints"
    projects = list(
        dict.fromkeys(args.projects or sorted(path.stem for path in checkpoint_dir.glob("*.pkl")))
    )
    metric = TypeMatchMetric(MetricConfig(extra_options={"variable_match_mode": args.mode}))
    provenance = _promotion_provenance(metric, args.mode)
    aggregate: defaultdict[str, AggregateRow] = defaultdict(
        lambda: {"o": 0.0, "n": 0.0, "c": 0, "imp": 0, "wor": 0}
    )
    new_scores: dict[str, dict[str, dict[str, float | int | str]]] = {}
    promotion_failures: list[str] = []

    for project in projects:
        checkpoint_path = checkpoint_dir / f"{project}.pkl"
        if not checkpoint_path.is_file():
            message = f"missing checkpoint: {checkpoint_path}"
            print(f"  ! {message}")
            if args.emit:
                promotion_failures.append(message)
            continue
        with open(checkpoint_path, "rb") as file:
            data = pickle.load(file)
        for optimization, binaries in data.get("decompile", {}).items():
            opt_name = getattr(optimization, "value", str(optimization))
            compiled = root / opt_name / project / "compiled"
            sources = list(preprocessed_by_stem(compiled).values())
            for binary_name, decompilers in binaries.items():
                for decompiler_name, decompilation in decompilers.items():
                    try:
                        result = metric.compute_for_binary(
                            decompilation,
                            preprocessed_sources=sources,
                        )
                    except Exception as exc:  # noqa: BLE001
                        context = f"{project}/{opt_name}/{binary_name}/{decompiler_name}"
                        print(f"  ! {context}: {exc}")
                        if args.emit:
                            promotion_failures.append(
                                f"metric exception for {context}: {type(exc).__name__}: {exc}"
                            )
                        continue
                    if result.errors:
                        context = f"{project}/{opt_name}/{binary_name}/{decompiler_name}"
                        for error in result.errors:
                            print(f"  ! {context}: {error}")
                        if args.emit:
                            promotion_failures.append(
                                f"metric reported {len(result.errors)} error(s) for {context}"
                            )
                    for function_name, value in result.function_results.items():
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

    print(f"\nmode: {args.mode}")
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

    if args.emit:
        coverage_failure = _coverage_failure(
            old,
            new_scores,
            projects if args.projects else None,
        )
        if coverage_failure is not None:
            promotion_failures.append(coverage_failure)
        if promotion_failures:
            detail = "\n  - ".join(promotion_failures)
            raise CanonicalPromotionError(
                "canonical type-match overlay was not changed:\n  - " + detail
            )

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
            new_scores = merge_typematch_overlay(
                existing,
                new_scores,
                existing_provenance=existing_provenance,
                fresh_provenance=provenance,
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
