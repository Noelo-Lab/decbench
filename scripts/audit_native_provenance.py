#!/usr/bin/env python
"""Read-only audit of native line and variable provenance in checkpoints."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from contextlib import suppress
from pathlib import Path

from decbench.auditing.native_provenance import (
    REPORT_SCHEMA,
    audit_results_tree,
    json_payload,
    summary_line,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_root", type=Path)
    parser.add_argument(
        "--checkpoint",
        action="append",
        type=Path,
        default=[],
        help="checkpoint pickle to inspect; repeatable (default: TREE/checkpoints/*.pkl)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="strict sample allowlist; selected backend functions outside it invalidate the audit",
    )
    parser.add_argument("--backend", action="append", default=[])
    parser.add_argument("--max-findings", type=int, default=200)
    parser.add_argument(
        "--output",
        type=Path,
        help="write JSON here; without this option JSON is emitted to stdout",
    )
    return parser.parse_args(argv)


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def _write_atomic(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output_is_safe = args.output is None
    try:
        output_is_safe = args.output is None or not _inside(args.output, args.results_root)
        if not output_is_safe:
            raise ValueError("--output must be outside the audited results tree")
        report = audit_results_tree(
            args.results_root,
            checkpoint_paths=args.checkpoint or None,
            manifest_path=args.manifest,
            requested_backends=args.backend,
            max_findings=args.max_findings,
        )
        payload = json_payload(report)
        if args.output is not None:
            _write_atomic(args.output, payload)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        fatal = {
            "schema": REPORT_SCHEMA,
            "valid": False,
            "fatal_error": f"{type(exc).__name__}: {exc}",
        }
        payload = json.dumps(fatal, indent=2, sort_keys=True) + "\n"
        if args.output is None or not output_is_safe:
            sys.stdout.write(payload)
        else:
            try:
                _write_atomic(args.output, payload)
            except OSError as output_error:
                sys.stdout.write(payload)
                print(f"could not write audit report: {output_error}", file=sys.stderr)
        print(f"native provenance audit failed: {exc}", file=sys.stderr)
        return 2

    if args.output is None:
        sys.stdout.write(payload)
        print(summary_line(report), file=sys.stderr)
    else:
        print(f"{summary_line(report)} -> {args.output}")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
