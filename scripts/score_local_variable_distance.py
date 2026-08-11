#!/usr/bin/env python
"""Score IDA/Ghidra local-variable evidence preserved in a benchmark checkpoint.

The default invocation implements the handoff's blinded O0, stable-hash sample:

    python scripts/score_local_variable_distance.py

Outputs:

* ``results/lved_coreutils/local_variable_distance_sample.jsonl`` — one blinded
  evidence/matching record per sampled source function;
* ``..._aggregate.json`` — coverage/LVED summaries and null oracle-accuracy
  fields until labels are supplied;
* ``..._labels.jsonl`` — a manual/storage-oracle template, created only when it
  does not already exist (reruns never overwrite audit work).

Use ``--labels FILE`` after an independent audit to populate precision, recall,
stage tables, held-out results, and clustered bootstrap intervals.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from decbench.experimental.local_variable_checkpoint import (
    DEFAULT_SAMPLE_SEED,
    ScoreConfig,
    load_audit_labels,
    score_checkpoint,
    write_json,
    write_jsonl,
)
from decbench.experimental.local_variable_distance import MATCHER_MODES


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=Path("results/lved_coreutils/checkpoints/coreutils.pkl"),
        help="checkpoint pickle retaining FunctionDecompilation variable evidence",
    )
    parser.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="results tree root (default: checkpoint's checkpoints/ parent)",
    )
    parser.add_argument("--project", default="coreutils")
    parser.add_argument(
        "--optimization",
        "--opt-level",
        dest="optimizations",
        action="append",
        help="optimization to include; repeat for several (default: O0)",
    )
    parser.add_argument(
        "--decompiler",
        dest="decompilers",
        action="append",
        help="base decompiler name; repeat as needed (default: ida, ghidra)",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=100,
        help="stable-hash sample size; 0 scores every checkpoint function",
    )
    parser.add_argument("--sample-seed", default=DEFAULT_SAMPLE_SEED)
    parser.add_argument(
        "--tuning-fraction",
        type=float,
        default=0.25,
        help="stable-hash tuning share; the remainder is held out",
    )
    parser.add_argument("--min-overlap", type=float, default=0.1)
    parser.add_argument("--ambiguity-margin", type=float, default=0.03)
    parser.add_argument(
        "--matcher-mode",
        choices=MATCHER_MODES,
        default="address",
        help="correspondence evidence to use (default preserves the legacy matcher)",
    )
    parser.add_argument("--min-usage-similarity", type=float, default=0.1)
    parser.add_argument("--usage-ambiguity-margin", type=float, default=0.03)
    parser.add_argument("--min-combined-similarity", type=float, default=0.1)
    parser.add_argument(
        "--address-weight",
        type=float,
        default=0.5,
        help="address contribution when both channels exist in address+usage mode",
    )
    parser.add_argument("--include-inlined", action="store_true")
    parser.add_argument(
        "--bootstrap-iterations",
        type=int,
        default=2000,
        help="clustered bootstrap resamples (0 disables intervals)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="per-function JSONL output",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="aggregate JSON output",
    )
    parser.add_argument(
        "--label-template",
        type=Path,
        default=None,
        help="oracle label-template JSONL (existing files are preserved)",
    )
    parser.add_argument(
        "--no-label-template",
        action="store_true",
        help="do not create the audit label template",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        help="completed independent audit-label JSONL used for accuracy fields",
    )
    parser.add_argument(
        "--fail-on-function-errors",
        action="store_true",
        help="return a nonzero status if any sampled source/decompiler extraction fails",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    checkpoint = args.checkpoint
    results_root = args.results_root or checkpoint.parent.parent
    output = args.output or results_root / "local_variable_distance_sample.jsonl"
    report_path = args.report or results_root / "local_variable_distance_aggregate.json"
    label_path = args.label_template or results_root / "local_variable_distance_labels.jsonl"
    try:
        config = ScoreConfig(
            project=args.project,
            optimizations=tuple(args.optimizations or ["O0"]),
            decompiler_bases=tuple(args.decompilers or ["ida", "ghidra"]),
            sample_size=args.sample_size,
            sample_seed=args.sample_seed,
            tuning_fraction=args.tuning_fraction,
            min_overlap=args.min_overlap,
            ambiguity_margin=args.ambiguity_margin,
            matcher_mode=args.matcher_mode,
            min_usage_similarity=args.min_usage_similarity,
            usage_ambiguity_margin=args.usage_ambiguity_margin,
            min_combined_similarity=args.min_combined_similarity,
            address_weight=args.address_weight,
            include_inlined=args.include_inlined,
            bootstrap_iterations=args.bootstrap_iterations,
        )
        labels = load_audit_labels(args.labels)
        records, report, label_template = score_checkpoint(
            checkpoint,
            results_root,
            config,
            labels=labels,
        )
        write_jsonl(output, records)
        write_json(report_path, report)
        label_message = "disabled"
        if not args.no_label_template:
            if label_path.exists():
                label_message = f"preserved existing {label_path}"
            else:
                write_jsonl(label_path, label_template)
                label_message = f"created {label_path}"
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    source_errors = sum(record["source_status"] != "ok" for record in records)
    decompiler_errors = sum(
        entry.get("status") == "error"
        for record in records
        for entry in record["decompilers"].values()
    )
    missing = sum(
        entry.get("status") == "missing"
        for record in records
        for entry in record["decompilers"].values()
    )
    print(
        f"scored {len(records)} functions: source_errors={source_errors} "
        f"decompiler_errors={decompiler_errors} missing_results={missing}"
    )
    print(f"per-function: {output}")
    print(f"aggregate:    {report_path}")
    print(f"labels:       {label_message}")
    if args.labels:
        print(f"oracle input: {args.labels}")
    if args.fail_on_function_errors and (source_errors or decompiler_errors):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
