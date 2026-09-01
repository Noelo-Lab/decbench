#!/usr/bin/env python
"""Report TypeMatch mode A/B scores with shared and optimization-level denominators."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from decbench.scoring.typematch_ab import build_report, json_payload, render_markdown


def _mode(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name or not raw_path:
        raise argparse.ArgumentTypeError("mode must be NAME=PATH")
    return name, Path(raw_path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--function-data", type=Path, required=True)
    parser.add_argument(
        "--results-root",
        type=Path,
        help="tree holding compiled binaries (defaults to --function-data parent)",
    )
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--mode", action="append", type=_mode, required=True)
    parser.add_argument("--baseline-mode", default="address")
    parser.add_argument("--backend", action="append", default=[])
    parser.add_argument(
        "--checkpoint-dir",
        type=Path,
        help="optional checkpoint directory for line-map/variable-address coverage",
    )
    parser.add_argument("--regression-limit", type=int, default=100)
    parser.add_argument("--run-scope")
    parser.add_argument("--scope-fairness")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument(
        "--allow-invalid",
        action="store_true",
        help="exit successfully even if overlay scopes or provenance are incompatible",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = build_report(
            function_data_path=args.function_data,
            results_root=args.results_root or args.function_data.parent,
            manifest_path=args.manifest,
            modes=args.mode,
            baseline_mode=args.baseline_mode,
            requested_backends=args.backend,
            checkpoint_dir=args.checkpoint_dir,
            regression_limit=args.regression_limit,
            run_scope=args.run_scope,
            scope_fairness=args.scope_fairness,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json_payload(report))
        if args.markdown is not None:
            args.markdown.parent.mkdir(parents=True, exist_ok=True)
            args.markdown.write_text(render_markdown(report))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    valid = report["validation"]["valid_for_apples_to_apples"]
    print(
        f"wrote {args.output}: "
        f"{report['scope']['globally_type_measurable_functions']} shared functions, "
        f"valid={'yes' if valid else 'no'}"
    )
    return 0 if valid or args.allow_invalid else 1


if __name__ == "__main__":
    raise SystemExit(main())
