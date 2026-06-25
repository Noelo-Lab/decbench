"""Curated dataset *presets* for the report's single dataset selector.

Rather than exposing dozens of label/binary toggles, the report offers four
fixed, meaningful views. This module tags every :class:`FunctionRecord` with the
presets it belongs to (``FunctionRecord.datasets``) and records the preset
metadata on the :class:`FunctionData`:

* **full** — everything (O0 + O2 + O2-noinline). The same source function at
  multiple opt levels counts multiple times; that double-counting is intended.
* **hard** — optimized, **no inlining** (O2-noinline), **large** functions only.
* **hard-inlined** — like *hard* but **with** inlining (plain O2), large only.
* **tiny** — ~100 functions total, evenly sampled from four categories
  (inlined=O2, optimized=O2-noinline, unoptimized=O0, large) and spread evenly
  across projects, so it is a fast, representative slice.

"Large" is the upper tail of the function-size bell curve (``mean + k·std`` over
decompiled line counts), matching :mod:`decbench.scoring.subset`. The majority
of functions are small, so this surfaces the genuinely hard, large ones.
"""

from __future__ import annotations

import statistics
from collections import OrderedDict
from typing import TYPE_CHECKING

from decbench.models.function_data import DatasetPreset

if TYPE_CHECKING:
    from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord

__all__ = ["assign_datasets", "large_threshold", "PRESETS"]

PRESETS: list[DatasetPreset] = [
    DatasetPreset(
        name="full",
        label="full",
        description="everything — O0 + O2 + O2-noinline (per-opt double-count ok)",
    ),
    DatasetPreset(
        name="hard",
        label="hard",
        description="optimized, no inlining (O2-noinline), large functions only",
    ),
    DatasetPreset(
        name="hard-inlined",
        label="hard-inlined",
        description="optimized WITH inlining (O2), large functions only",
    ),
    DatasetPreset(
        name="tiny",
        label="tiny",
        description="~100 functions evenly sampled across "
        "inlined/optimized/unoptimized/large and projects",
    ),
]

_O2 = "O2"
_O2_NOINLINE = "O2-noinline"
_O0 = "O0"


def large_threshold(function_data: FunctionData, k: float = 1.0) -> float | None:
    """Upper-tail size cutoff (``mean + k·std``) over decompiled line counts.

    Returns ``None`` when no function has a recorded size (then the ``large``
    auto-label is used as a fallback by :func:`assign_datasets`).
    """
    sizes = [
        f.size
        for g in function_data.groups
        for f in g.functions
        if f.size is not None
    ]
    if not sizes:
        return None
    mean = statistics.fmean(sizes)
    std = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
    return mean + k * std


def _round_robin_by_project(
    items: list[tuple[BinaryGroup, FunctionRecord]],
    quota: int,
    exclude: set[int],
) -> list[tuple[BinaryGroup, FunctionRecord]]:
    """Pick up to ``quota`` records, spread as evenly as possible over projects.

    Deterministic: candidates are sorted by (project, opt, binary, function) and
    drawn round-robin across projects. ``exclude`` (a set of ``id(record)``)
    keeps the four category buckets from picking the same function twice.
    """
    by_project: OrderedDict[str, list[tuple[BinaryGroup, FunctionRecord]]] = OrderedDict()
    ordered = sorted(
        items,
        key=lambda gf: (gf[0].project, gf[0].opt_level, gf[0].binary, gf[1].function),
    )
    for g, f in ordered:
        if id(f) in exclude:
            continue
        by_project.setdefault(g.project, []).append((g, f))

    projects = list(by_project.keys())
    picked: list[tuple[BinaryGroup, FunctionRecord]] = []
    i = 0
    while len(picked) < quota and any(by_project.values()):
        proj = projects[i % len(projects)]
        bucket = by_project[proj]
        if bucket:
            picked.append(bucket.pop(0))
        i += 1
    return picked


def assign_datasets(
    function_data: FunctionData, tiny_total: int = 100, k: float = 1.0
) -> FunctionData:
    """Tag every record with its dataset presets and set ``dataset_presets``.

    Idempotent: re-running re-derives membership from scratch.
    """
    threshold = large_threshold(function_data, k=k)

    def is_large(f: FunctionRecord) -> bool:
        if f.size is not None and threshold is not None:
            return f.size >= threshold
        return "large" in (f.labels or [])

    records: list[tuple[BinaryGroup, FunctionRecord]] = [
        (g, f) for g in function_data.groups for f in g.functions
    ]

    # full / hard / hard-inlined are rule-based.
    for g, f in records:
        ds = ["full"]
        if is_large(f):
            if g.opt_level == _O2_NOINLINE:
                ds.append("hard")
            elif g.opt_level == _O2:
                ds.append("hard-inlined")
        f.datasets = ds

    # tiny: even sample across four categories and across projects.
    buckets: dict[str, list[tuple[BinaryGroup, FunctionRecord]]] = {
        "inlined": [(g, f) for g, f in records if g.opt_level == _O2],
        "optimized": [(g, f) for g, f in records if g.opt_level == _O2_NOINLINE],
        "unoptimized": [(g, f) for g, f in records if g.opt_level == _O0],
        "large": [(g, f) for g, f in records if is_large(f)],
    }
    per_bucket = max(1, tiny_total // len(buckets))
    chosen: set[int] = set()
    for _name, items in buckets.items():
        for _g, f in _round_robin_by_project(items, per_bucket, chosen):
            chosen.add(id(f))
            if "tiny" not in f.datasets:
                f.datasets.append("tiny")

    function_data.dataset_presets = [p.model_copy() for p in PRESETS]
    return function_data
