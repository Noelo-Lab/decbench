"""Re-evaluate type_match from checkpoints without running decompilers.

The default ``auto`` mode is the canonical stacked address+usage policy.
Experimental modes can be compared in place, or written to an explicitly
named output file for A/B analysis. Only ``--emit`` may write the canonical
``type_match_new.json`` overlay, and only in ``auto`` mode.

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
import pickle
from collections import defaultdict
from pathlib import Path
from typing import TypedDict

import decbench.decompilers  # noqa: F401 (register backends so pickles load)
from decbench.metrics.base import MetricConfig
from decbench.metrics.type_match import TypeMatchMetric
from decbench.models.function_data import VARIABLE_MATCH_EVIDENCE
from decbench.results_store import merge_typematch_overlay
from decbench.utils.langs import preprocessed_by_stem

MODES = ("auto", "address", "usage", "address+usage")


class AggregateRow(TypedDict):
    o: float
    n: float
    c: int
    imp: int
    wor: int


def parse_args() -> argparse.Namespace:
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
    args = parser.parse_args()
    if args.emit and args.mode != "auto":
        parser.error("--emit is reserved for the canonical auto mode; use --output for A/B modes")
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


def main() -> None:
    args = parse_args()
    root: Path = args.results_dir
    old = _old_scores(root)
    checkpoint_dir = root / "checkpoints"
    projects = args.projects or sorted(path.stem for path in checkpoint_dir.glob("*.pkl"))
    metric = TypeMatchMetric(MetricConfig(extra_options={"variable_match_mode": args.mode}))
    aggregate: defaultdict[str, AggregateRow] = defaultdict(
        lambda: {"o": 0.0, "n": 0.0, "c": 0, "imp": 0, "wor": 0}
    )
    new_scores: dict[str, dict[str, dict[str, float | int | str]]] = {}

    for project in projects:
        checkpoint_path = checkpoint_dir / f"{project}.pkl"
        if not checkpoint_path.is_file():
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
                        print(f"  ! {project}/{opt_name}/{binary_name}/{decompiler_name}: {exc}")
                        continue
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

    output_path = root / "type_match_new.json" if args.emit else args.output
    if output_path is None:
        return
    if args.projects and output_path.is_file():
        with open(output_path) as file:
            new_scores = merge_typematch_overlay(json.load(file), new_scores)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as file:
        json.dump(new_scores, file)
    print(f"\nwrote {output_path}")


if __name__ == "__main__":
    main()
