#!/usr/bin/env python
"""Build, review, merge, and join an independent local-variable audit.

Build an address-free reviewer package:

    python scripts/audit_local_variable_semantics.py build \
      --scorer results/lved_coreutils/local_variable_distance_sample.jsonl \
      --checkpoint results/lved_coreutils/checkpoints/coreutils.pkl \
      --sample-manifest \
        results/lved_coreutils/local_variable_distance_aggregate.json \
      --output-dir results/lved_coreutils/semantic_audit

Give each reviewer only one file under ``reviewer_shards/``.  They can prepare
a compact decisions JSONL and apply it without any access to the package or
private join:

    python scripts/audit_local_variable_semantics.py apply-decisions \
      --shard shard_000.json --decisions decisions.jsonl \
      --reviewer reviewer-name --output shard_000.completed.json

Merge all completed shards, then join.  Never give
``matcher_join.private.jsonl`` to a reviewer.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from decbench.experimental.local_variable_semantic_audit import (
    ALIAS_SECRET_FILENAME,
    DEFAULT_AUDIT_SEED,
    DEFAULT_SHARD_COUNT,
    apply_reviewer_decisions,
    build_audit_package,
    join_audit_package,
    merge_reviewer_labels,
    validate_audit_package,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser(
        "build",
        help="create public cases, a private join, and a bound label template",
    )
    build.add_argument(
        "--scorer",
        type=Path,
        default=Path("results/lved_coreutils/local_variable_distance_sample.jsonl"),
        help="blinded scorer JSONL",
    )
    build.add_argument(
        "--checkpoint",
        type=Path,
        default=Path("results/lved_coreutils/checkpoints/coreutils.pkl"),
        help="trusted checkpoint retaining the original decompiler pseudocode",
    )
    build.add_argument(
        "--aggregate",
        "--sample-manifest",
        dest="aggregate",
        type=Path,
        default=Path("results/lved_coreutils/local_variable_distance_aggregate.json"),
        help="scorer aggregate carrying the canonical run provenance",
    )
    build.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/lved_coreutils/semantic_audit"),
    )
    build.add_argument(
        "--backend",
        dest="backends",
        action="append",
        help="exact checkpoint backend key; repeat (default: provenance list)",
    )
    build.add_argument("--audit-seed", default=DEFAULT_AUDIT_SEED)
    build.add_argument(
        "--context-lines",
        type=int,
        default=2,
        help="lines of context on each side of a variable use",
    )
    build.add_argument(
        "--shard-count",
        type=int,
        default=DEFAULT_SHARD_COUNT,
        help="maximum deterministic whole-relation reviewer shards",
    )

    apply = subparsers.add_parser(
        "apply-decisions",
        help="apply compact public decisions to one shard without private data",
        description=(
            "Apply one JSONL decision per shard case. Each row is: "
            '{"schema_version":2,"case_id":"case_...",'
            '"oracle_status":"mapped|none_recovered|oracle_unknown",'
            '"selected_decompiled_audit_ids":["dv_..."],'
            '"confidence":"high|medium|low","rationale":"..."}. '
            "The command supplies all hashes/schema bindings and writes a new "
            "completed public shard atomically; it cannot consume a private join."
        ),
    )
    apply.add_argument("--shard", type=Path, required=True)
    apply.add_argument("--decisions", type=Path, required=True)
    apply.add_argument("--reviewer", required=True)
    apply.add_argument("--output", type=Path, required=True)

    merge = subparsers.add_parser(
        "merge-labels",
        help="merge completed reviewer shards with strict conflict/coverage checks",
    )
    merge.add_argument("--package", type=Path, required=True)
    merge.add_argument(
        "--shard",
        dest="shards",
        type=Path,
        action="append",
        required=True,
        help="completed reviewer shard; repeat for every assigned shard",
    )
    merge.add_argument(
        "--output",
        type=Path,
        help="merged JSONL (default: PACKAGE/audit_labels.jsonl)",
    )
    merge.add_argument(
        "--allow-partial",
        action="store_true",
        help=(
            "allow progress inspection; requires an explicit noncanonical --output "
            "and never overwrites package labels"
        ),
    )

    validate = subparsers.add_parser(
        "validate",
        help="check public hashes, private joins, case coverage, and labels",
    )
    validate.add_argument("--package", type=Path, required=True)
    validate.add_argument(
        "--labels",
        type=Path,
        help="labels to validate (default: PACKAGE/audit_labels.jsonl)",
    )
    validate.add_argument(
        "--require-complete",
        action="store_true",
        help="reject every label whose oracle_status is still null",
    )

    join = subparsers.add_parser(
        "join",
        help="validate completed labels and privately join matcher decisions",
    )
    join.add_argument("--package", type=Path, required=True)
    join.add_argument(
        "--labels",
        type=Path,
        help="completed labels (default: PACKAGE/audit_labels.jsonl)",
    )
    join.add_argument(
        "--merge-provenance",
        type=Path,
        help="merge provenance (default: PACKAGE/label_merge_provenance.json)",
    )
    join.add_argument(
        "--bootstrap-iterations",
        type=int,
        default=2000,
        help="clustered bootstrap resamples; 0 disables intervals",
    )
    join.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="produce an explicitly unlabeled partial report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            manifest = build_audit_package(
                args.scorer,
                args.checkpoint,
                args.output_dir,
                sample_manifest_path=args.aggregate,
                backends=tuple(args.backends) if args.backends else None,
                audit_seed=args.audit_seed,
                context_lines=args.context_lines,
                shard_count=args.shard_count,
            )
            print(
                f"built {manifest['case_count']} address-free audit cases "
                f"for {manifest['source_function_count']} source functions"
            )
            print(f"public cases:  {args.output_dir / 'audit_cases.jsonl'}")
            print(f"label template:{args.output_dir / 'audit_labels.jsonl'}")
            print(
                "private join:  "
                f"{args.output_dir / 'matcher_join.private.jsonl'} "
                "(do not give this file to reviewers)"
            )
            print(
                "alias secret:  "
                f"{args.output_dir / ALIAS_SECRET_FILENAME} "
                "(owner-only; do not give this file to reviewers)"
            )
            print(f"reviewer shards:{args.output_dir / 'reviewer_shards'}")
        elif args.command == "apply-decisions":
            result = apply_reviewer_decisions(
                args.shard,
                args.decisions,
                args.output,
                reviewer=args.reviewer,
            )
            print(
                f"completed {result['shard_id']} with {result['case_count']} "
                f"decisions for {result['reviewer_assignment']}"
            )
            print(f"completed shard: {args.output}")
        elif args.command == "merge-labels":
            provenance = merge_reviewer_labels(
                args.package,
                args.shards,
                output_path=args.output,
                allow_partial=args.allow_partial,
            )
            print(
                f"merged {provenance['case_count']} labels; " f"complete={provenance['complete']}"
            )
            print("merge provenance: " f"{args.package / 'label_merge_provenance.json'}")
        elif args.command == "validate":
            validation = validate_audit_package(
                args.package,
                labels_path=args.labels,
                require_complete=args.require_complete,
            )
            print(
                f"validated {validation['case_count']} cases, "
                f"{validation['private_join_count']} private joins, and "
                f"{validation['label_count']} labels; "
                f"complete={validation['complete']}"
            )
            print(f"label statuses: {validation['label_statuses']}")
        else:
            report = join_audit_package(
                args.package,
                labels_path=args.labels,
                merge_provenance_path=args.merge_provenance,
                bootstrap_iterations=args.bootstrap_iterations,
                allow_incomplete=args.allow_incomplete,
            )
            matcher = report["summary"]["matcher_conditional_on_backend_ok"]
            metric = matcher["accepted_edges"]["metrics"]["valid_edge_precision"]["value"]
            error = matcher["accepted_edges"]["metrics"]["wrong_edge_error_decidable"]["value"]
            print(
                "joined completed audit; conditional matcher "
                f"valid-edge precision={metric} decidable wrong-edge error={error}"
            )
            print(f"joined rows: {args.package / 'joined_results.jsonl'}")
            print(f"report:      {args.package / 'report.json'}")
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
