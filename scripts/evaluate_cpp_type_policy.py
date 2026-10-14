#!/usr/bin/env python3
"""Re-score one canonical producer artifact under the opt-in C++ proposal.

The original debug image and source units belong only to the evaluator. Missing
requested functions are empty recovery; this tool never calls a producer or
publishes a leaderboard. Use a separate output file for each source/ABI view.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from decbench.metrics.base import MetricConfig
from decbench.metrics.cpp_type_match import CppTypeMatchMetric
from decbench.models.decompilation import DecompilationResult


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="original debug oracle image")
    parser.add_argument(
        "--decompilation", type=Path, required=True, help="DecompilationResult JSON"
    )
    parser.add_argument(
        "--requested-functions",
        type=Path,
        required=True,
        help="fixed JSON list of objects with name and address",
    )
    parser.add_argument("--view", choices=["source", "abi"], required=True)
    parser.add_argument("--data-model", choices=["LP64", "LLP64", "ILP32"], required=True)
    parser.add_argument("--source", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = DecompilationResult.model_validate_json(args.decompilation.read_text())
    result.binary_path = args.binary.resolve()
    rows = json.loads(args.requested_functions.read_text())
    requested = [
        (r["name"], int(r["address"], 0) if isinstance(r["address"], str) else int(r["address"]))
        for r in rows
    ]
    if len({a for _, a in requested}) != len(requested):
        parser.error("requested function entries must have unique addresses")
    if any(a < 0 for _, a in requested):
        parser.error("negative requested address")
    metric = CppTypeMatchMetric(
        MetricConfig(
            use_cache=False, extra_options={"view": args.view, "data_model": args.data_model}
        )
    )
    score = metric.compute_for_binary(
        result, requested_functions=requested, preprocessed_sources=args.source
    )
    payload = {
        "official_score": False,
        "view": args.view,
        "data_model": args.data_model,
        "requested_functions": len(requested),
        "result": score.model_dump(mode="json"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n")


if __name__ == "__main__":
    main()
