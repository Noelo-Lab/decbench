#!/usr/bin/env python3
"""Publish a DecBench results tree as a HuggingFace-style dataset (contract §2).

Thin CLI over :mod:`decbench.publish`. Reads a completed results tree (anchored
on ``function_results.json``) and lays it out into a dataset-repo root:
binaries, stripped sources, decompiled results reorganized per decompiler, the
per-config manifests / filtered scores / ``dataset.toml`` index, and (behind
``--cfgs``) the source-CFG JSONs the GED metric consumed.

The build is idempotent and resumable: file copies skip when the destination
already exists with a matching size, and CFG JSONs skip when already present.
Nothing is committed or pushed — ``git add/commit/push`` is left to the user.

Examples::

    python scripts/publish_dataset.py results/full_run
    python scripts/publish_dataset.py results/full_run --cfgs --cfg-workers 8
    python scripts/publish_dataset.py results/full_run --only-config sample-set --max-binaries 8
"""

from __future__ import annotations

import argparse
import datetime
import sys
from collections import OrderedDict
from pathlib import Path

from decbench.publish import cfg_export, layout


def _parse_configs(raw: str | None, only: str | None) -> list[str]:
    """Resolve the configs to build (``--only-config`` wins over ``--configs``)."""
    if only:
        if only not in layout.DEFAULT_CONFIGS:
            raise SystemExit(f"unknown config {only!r}; choose from {layout.DEFAULT_CONFIGS}")
        return [only]
    if not raw:
        return list(layout.DEFAULT_CONFIGS)
    chosen = [c.strip() for c in raw.split(",") if c.strip()]
    for c in chosen:
        if c not in layout.DEFAULT_CONFIGS:
            raise SystemExit(f"unknown config {c!r}; choose from {layout.DEFAULT_CONFIGS}")
    return chosen


def _stems_by_project_opt(result: layout.LayoutResult) -> dict[str, dict[str, list[str]]]:
    """Group the processed binaries as ``{project: {opt: [stem, ...]}}`` for CFGs."""
    out: dict[str, dict[str, list[str]]] = OrderedDict()
    for group in result.groups:
        out.setdefault(group.project, OrderedDict()).setdefault(group.opt, []).append(group.binary)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_dir", type=Path, help="results tree (e.g. results/full_run)")
    parser.add_argument(
        "--dest",
        type=Path,
        default=Path.home() / "github" / "decbench-dataset",
        help="dataset repo root to populate (default: ~/github/decbench-dataset)",
    )
    parser.add_argument("--cfgs", action="store_true", help="also build source-CFG JSONs (slow)")
    parser.add_argument("--cfg-workers", type=int, default=1, help="parallel CFG workers")
    parser.add_argument("--configs", default=None, help="comma list: sample-set,large,unoptimized,optimized,inlined,full")
    parser.add_argument("--only-config", default=None, help="build a single config")
    parser.add_argument("--skip-binaries", action="store_true", help="do not copy binaries")
    parser.add_argument("--skip-results", action="store_true", help="do not copy decompiled output")
    parser.add_argument("--skip-sources", action="store_true", help="do not (re)write sources")
    parser.add_argument(
        "--max-binaries",
        type=int,
        default=None,
        help="debug: process only the first N selected groups",
    )
    args = parser.parse_args(argv)

    root = args.results_dir
    dest = args.dest
    if not (root / "function_results.json").is_file():
        raise SystemExit(f"no function_results.json under {root}")
    dest.mkdir(parents=True, exist_ok=True)

    configs = _parse_configs(args.configs, args.only_config)
    created = datetime.datetime.now().isoformat(timespec="seconds")
    log = lambda msg: print(msg, flush=True)  # noqa: E731

    log(f"[load] {root}/function_results.json")
    fd = layout.load_dataset(root)
    groups = layout.select_groups(fd, configs, max_binaries=args.max_binaries)
    log(f"[plan] configs={configs} selected {len(groups)} group(s)")

    result = layout.copy_artifacts(
        root,
        dest,
        fd,
        groups,
        configs,
        do_binaries=not args.skip_binaries,
        do_results=not args.skip_results,
        do_sources=not args.skip_sources,
        log=log,
    )
    log(
        f"[copy] {result.counts['binaries']} binaries, "
        f"{result.counts['results']} decompiled files, "
        f"{result.counts['sources']} source TUs, "
        f"{result.counts['unresolved']} unresolved"
    )

    cfg_paths: dict[tuple[str, str, str], str] = {}
    if args.cfgs:
        log("[cfg] generating source CFGs (this is the slow step)...")
        cfg_paths = cfg_export.export_all_cfgs(
            root,
            dest,
            _stems_by_project_opt(result),
            workers=args.cfg_workers,
            log=log,
        )
        log(f"[cfg] wrote/verified {len(cfg_paths)} CFG JSON(s)")
    layout.attach_source_cfgs(dest, result, cfg_paths)

    layout.write_manifests_and_index(
        root,
        dest,
        fd,
        result,
        configs,
        created,
        partial=args.max_binaries is not None,
        log=log,
    )

    log("\n=== summary ===")
    log(f"dest:      {dest}")
    log(f"binaries:  {result.counts['binaries']:>6}  ({result.bytes['binaries'] / 1e6:.1f} MB)")
    log(f"results:   {result.counts['results']:>6}  ({result.bytes['results'] / 1e6:.1f} MB)")
    log(f"sources:   {result.counts['sources']:>6}  ({result.bytes['sources'] / 1e6:.1f} MB)")
    log(f"cfgs:      {len(cfg_paths):>6}")
    log(f"configs:   {', '.join(configs)}")
    if result.unresolved:
        log(f"unresolved: {len(result.unresolved)} (see log above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
