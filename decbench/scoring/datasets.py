"""Curated dataset *presets* for the report's single dataset selector.

Rather than exposing dozens of label/binary toggles, the report offers four
fixed, meaningful views. This module tags every :class:`FunctionRecord` with the
presets it belongs to (``FunctionRecord.datasets``) and records the preset
metadata on the :class:`FunctionData`:

* **full** — everything (O0 + O2 + O2-noinline). The same source function at
  multiple opt levels counts multiple times; that double-counting is intended.
* **hard** — optimized, **no inlining** (O2-noinline), **large** functions only.
* **hard-inlined** — like *hard* but **with** inlining (plain O2), large only.
* **unoptimized** — O0 functions only, to surface simple structural differences
  without optimization noise.
* **tiny** — ~100 functions total, evenly sampled from four categories
  (inlined=O2, optimized=O2-noinline, unoptimized=O0, large), spread evenly
  across projects, and — while there are enough distinct binaries — taking **at
  most one function per binary**, so it is a fast, representative slice. The
  sample is a **seeded random** selection — stable across runs for a given seed,
  but changeable via ``DECBENCH_TINY_SEED`` (or ``assign_datasets(seed=...)``).

"Large" is the upper tail of the function-size bell curve (``mean + k·std`` over
decompiled line counts), matching :mod:`decbench.scoring.subset`. The majority
of functions are small, so this surfaces the genuinely hard, large ones.
"""

from __future__ import annotations

import os
import random
import statistics
from collections import OrderedDict
from typing import TYPE_CHECKING

from decbench.models.function_data import DatasetPreset

if TYPE_CHECKING:
    from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord

__all__ = ["assign_datasets", "large_threshold", "PRESETS", "DEFAULT_TINY_SEED"]

# Fixed default seed for the `tiny` sample so the selection is reproducible
# across runs/machines. Override per call (``assign_datasets(seed=...)``) or via
# the ``DECBENCH_TINY_SEED`` environment variable to roll a different sample.
DEFAULT_TINY_SEED = 1337


def _resolve_seed(seed: int | None) -> int:
    """Resolve the tiny-sample seed: explicit arg > env var > default."""
    if seed is not None:
        return seed
    env = os.environ.get("DECBENCH_TINY_SEED")
    if env:
        try:
            return int(env)
        except ValueError:
            pass
    return DEFAULT_TINY_SEED

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
        name="unoptimized",
        label="unoptimized",
        description="unoptimized only (O0) — surfaces simple structural differences",
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


def _binkey(g: BinaryGroup) -> tuple[str, str, str]:
    """Identity of a single compiled binary: (project, opt level, binary)."""
    return (g.project, g.opt_level, g.binary)


def _sample_even(
    items: list[tuple[BinaryGroup, FunctionRecord]],
    quota: int,
    chosen_fns: set[int],
    used_bins: set[tuple[str, str, str]],
    rng: random.Random,
) -> list[tuple[BinaryGroup, FunctionRecord]]:
    """Pick up to ``quota`` records as a *seeded random*, evenly-spread sample.

    Evenness on two axes:

    * **projects** — candidates are grouped by project and drawn round-robin so
      no project dominates.
    * **binaries** — *at most one function is taken from any one binary* while
      distinct binaries remain (a first pass enforces this); only if there are
      not enough binaries to meet ``quota`` does a second pass relax the rule
      and allow a second function from a binary.

    The member order within each project and the project visitation order are
    shuffled with ``rng`` (random but fully reproducible for a given seed).
    ``chosen_fns`` (``id(record)``) and ``used_bins`` (:func:`_binkey`) are
    shared across the four category buckets and **mutated** here, so the rules
    hold across the whole ``tiny`` sample, not just within one bucket.
    """
    by_project: OrderedDict[str, list[tuple[BinaryGroup, FunctionRecord]]] = OrderedDict()
    ordered = sorted(
        items,
        key=lambda gf: (gf[0].project, gf[0].opt_level, gf[0].binary, gf[1].function),
    )
    for g, f in ordered:
        if id(f) in chosen_fns:
            continue
        by_project.setdefault(g.project, []).append((g, f))

    for lst in by_project.values():
        rng.shuffle(lst)
    projects = list(by_project.keys())
    rng.shuffle(projects)

    picked: list[tuple[BinaryGroup, FunctionRecord]] = []

    def pass_once(one_per_binary: bool) -> None:
        advanced = True
        while len(picked) < quota and advanced:
            advanced = False
            for proj in projects:
                if len(picked) >= quota:
                    break
                lst = by_project[proj]
                idx = None
                for j, (g, f) in enumerate(lst):
                    if id(f) in chosen_fns:
                        continue
                    if one_per_binary and _binkey(g) in used_bins:
                        continue
                    idx = j
                    break
                if idx is not None:
                    g, f = lst.pop(idx)
                    picked.append((g, f))
                    chosen_fns.add(id(f))
                    used_bins.add(_binkey(g))
                    advanced = True

    pass_once(one_per_binary=True)  # at most one function per binary...
    pass_once(one_per_binary=False)  # ...relaxed only if binaries run short
    return picked


def assign_datasets(
    function_data: FunctionData,
    tiny_total: int = 100,
    k: float = 1.0,
    seed: int | None = None,
) -> FunctionData:
    """Tag every record with its dataset presets and set ``dataset_presets``.

    The ``tiny`` sample is a **seeded random** selection: deterministic for a
    given seed (so the chosen targets are stable across runs), but changeable.
    Seed resolution: ``seed`` arg > ``DECBENCH_TINY_SEED`` env var >
    :data:`DEFAULT_TINY_SEED`.

    Idempotent: re-running with the same seed re-derives identical membership.
    """
    rng = random.Random(_resolve_seed(seed))
    threshold = large_threshold(function_data, k=k)

    def is_large(f: FunctionRecord) -> bool:
        if f.size is not None and threshold is not None:
            return f.size >= threshold
        return "large" in (f.labels or [])

    records: list[tuple[BinaryGroup, FunctionRecord]] = [
        (g, f) for g in function_data.groups for f in g.functions
    ]

    # full / hard / hard-inlined / unoptimized are rule-based.
    for g, f in records:
        ds = ["full"]
        if g.opt_level == _O0:
            ds.append("unoptimized")
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
    used_bins: set[tuple[str, str, str]] = set()
    for _name, items in buckets.items():
        for _g, f in _sample_even(items, per_bucket, chosen, used_bins, rng):
            if "tiny" not in f.datasets:
                f.datasets.append("tiny")

    function_data.dataset_presets = [p.model_copy() for p in PRESETS]
    return function_data
