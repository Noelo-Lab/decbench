#!/usr/bin/env python3
"""Audit a DecompilationResult JSON against preprocessed C++ and native debug.

Run with DECBENCH_NO_CACHE=1 for a fresh measurement. No corpus code is executed.
The output is a bounded diagnostic report, never a leaderboard/results overlay.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from decbench.models.decompilation import DecompilationResult
from decbench.pipeline.cpp_ged import evaluate_cpp_ged


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decompilation", type=Path)
    parser.add_argument("--requested-functions", type=Path, required=True)
    parser.add_argument("--compilation-database", type=Path)
    parser.add_argument("--source", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = DecompilationResult.model_validate_json(args.decompilation.read_text())
    rows = json.loads(args.requested_functions.read_text())
    requested = [
        (
            row["name"],
            int(row["address"], 0) if isinstance(row["address"], str) else int(row["address"]),
        )
        for row in rows
    ]
    report = evaluate_cpp_ged(
        result,
        args.source,
        requested_functions=requested,
        compilation_database=args.compilation_database,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2) + "\n")


if __name__ == "__main__":
    main()
