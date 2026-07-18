#!/usr/bin/env python3
"""Backfill null ``source_code`` in a function_results.json WITHOUT re-decompiling.

Re-extracts each View sample's original source with the improved (K&R-tolerant,
``.i``-fallback) extractor and writes a patched :class:`FunctionData` copy to a
NEW path. Repairs samples the old extractor left blank: nested source trees kept
only ``.i`` next to the binary, and K&R definitions / macro-generated names
defeated the ``.c`` brace heuristic (see
``decbench/utils/source_extract.py::function_source_ex``).

Usage::

    scripts/repair_sample_sources.py IN_JSON TREE_ROOT OUT_JSON

``IN_JSON`` and ``TREE_ROOT`` are read-only — ``TREE_ROOT`` may be an actively
written ``results/`` tree, so nothing under it is touched. ``OUT_JSON`` must
differ from ``IN_JSON`` and must not live under a ``results/`` directory.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from decbench.models.function_data import FunctionData
from decbench.utils.results_tree import resolve_binary
from decbench.utils.source_extract import function_source_ex

# Human labels for the status codes returned by function_source_ex (plus the
# empty ".c" status), used only for the printed summary.
_STATUS_LABELS = {
    "": 'from .c ("")',
    "preprocessed": "from .i (preprocessed)",
    "binary_not_found": "binary_not_found",
    "no_source_files": "no_source_files",
    "func_not_in_sources": "func_not_in_sources",
    "extract_failed": "extract_failed",
}


def _under_results(path: Path) -> bool:
    """True if any component of the resolved path is a ``results`` directory."""
    return "results" in path.resolve().parts


def repair(in_json: Path, tree_root: Path, out_json: Path) -> dict[str, object]:
    """Re-extract source for every null-source sample; write patched copy.

    Samples that already carry ``source_code`` are left untouched. Returns a
    summary dict (counts + per-status ``Counter`` over the processed samples).
    """
    fd = FunctionData.from_json(in_json)
    total = len(fd.samples)
    before_null = sum(1 for s in fd.samples if s.source_code is None)

    bin_cache: dict[tuple[str, str, str], Path | None] = {}
    status_counts: Counter[str] = Counter()
    recovered = 0

    for sample in fd.samples:
        if sample.source_code is not None:
            continue  # leave already-populated samples alone
        key = (sample.opt_level, sample.project, sample.binary)
        if key not in bin_cache:
            bin_cache[key] = resolve_binary(
                tree_root / sample.opt_level / sample.project / "compiled", sample.binary
            )
        code, status = function_source_ex(bin_cache[key], sample.function)
        sample.source_code = code
        sample.source_status = status
        status_counts[status] += 1
        if code is not None:
            recovered += 1

    after_null = sum(1 for s in fd.samples if s.source_code is None)
    fd.to_json(out_json)
    return {
        "total": total,
        "before_null": before_null,
        "recovered": recovered,
        "after_null": after_null,
        "status_counts": status_counts,
    }


def _print_summary(in_json: Path, out_json: Path, summary: dict[str, object]) -> None:
    counts: Counter[str] = summary["status_counts"]  # type: ignore[assignment]
    print(f"repaired {in_json} -> {out_json}")
    print(f"  total samples:  {summary['total']:>6}")
    print(f"  null before:    {summary['before_null']:>6}")
    print(f"  recovered:      {summary['recovered']:>6}")
    print(f"  null after:     {summary['after_null']:>6}")
    print(f"  per-status (over {sum(counts.values())} processed):")
    for status, count in counts.most_common():
        print(f"    {_STATUS_LABELS.get(status, status):<24} {count:>6}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("in_json", type=Path, help="function_results.json to read (read-only)")
    ap.add_argument(
        "tree_root", type=Path, help="results tree root for binary/source lookup (read-only)"
    )
    ap.add_argument(
        "out_json", type=Path, help="patched function_results.json to write (NOT under results/)"
    )
    args = ap.parse_args()

    in_json: Path = args.in_json
    tree_root: Path = args.tree_root
    out_json: Path = args.out_json

    if not in_json.is_file():
        ap.error(f"IN_JSON not found: {in_json}")
    if not tree_root.is_dir():
        ap.error(f"TREE_ROOT not a directory: {tree_root}")
    if out_json.resolve() == in_json.resolve():
        ap.error("OUT_JSON must differ from IN_JSON (refusing to overwrite the input)")
    if _under_results(out_json):
        ap.error(f"refusing to write OUT_JSON under a results/ directory: {out_json}")
    # The tree may live anywhere (a `dataset materialize` copy has no "results"
    # component) — containment in the tree being read is refused regardless of name.
    if out_json.resolve().is_relative_to(tree_root.resolve()):
        ap.error(f"refusing to write OUT_JSON inside TREE_ROOT: {out_json}")

    summary = repair(in_json, tree_root, out_json)
    _print_summary(in_json, out_json, summary)


if __name__ == "__main__":
    main()
