#!/usr/bin/env python
"""Canonical finalize for a results tree: rebuild the derived files from EVERY fragment.

Thin CLI over :func:`decbench.results_store.finalize_tree` / ``audit_tree``. This is the
ONE sanctioned way to (re)generate ``function_results.json`` + ``scoreboard.toml`` from
a tree's checkpoints + overlays — it is never scoped to a subset of projects, pins the
sample-set to the frozen manifest, and refuses to shrink published coverage unless told
the drop is intended.

Usage:
    finalize_results.py <results_tree>
        [--allow-drops]              accept printed coverage regressions
        [--exclude-project NAME]...  rebuild without these projects (guard-whitelisted)
        [--exclude-decompiler NAME]...  strip these decompilers (guard-whitelisted)
        [--audit]                    audit-only gap scan; writes nothing; exit 1 on
                                     SILENT-DROP findings
        [--render]                   also re-render report.html
        [--seed N]                   sample-set seed (only used when the tree has no
                                     sample_set_manifest.json)
"""

from __future__ import annotations

import argparse
import multiprocessing
import sys
from pathlib import Path

# Match the run drivers: 'fork' deadlocks once angr's threads are live, and library
# code reached from here may create pools.
if multiprocessing.get_start_method(allow_none=True) != "spawn":
    multiprocessing.set_start_method("spawn", force=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("tree", type=Path, help="results tree (holds checkpoints/, overlays)")
    ap.add_argument("--allow-drops", action="store_true")
    ap.add_argument("--exclude-project", action="append", default=[], metavar="NAME")
    ap.add_argument("--exclude-decompiler", action="append", default=[], metavar="NAME")
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--render", action="store_true")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    from decbench.results_store import CoverageRegressionError, audit_tree, finalize_tree

    if args.audit:
        gaps = audit_tree(args.tree)
        return 1 if any(g.kind == "SILENT-DROP" for g in gaps) else 0

    try:
        fd, scoreboard = finalize_tree(
            args.tree,
            exclude_projects=args.exclude_project,
            exclude_decompilers=args.exclude_decompiler,
            allow_drops=args.allow_drops,
            seed=args.seed,
        )
    except CoverageRegressionError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    from decbench.scoring.scoreboard import render_scoreboard_text

    print(render_scoreboard_text(scoreboard), flush=True)
    if args.render:
        from decbench.rendering.html import render_html_report

        report_path = args.tree / "report.html"
        render_html_report(scoreboard, report_path, fd)
        print(f"HTML report: {report_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
