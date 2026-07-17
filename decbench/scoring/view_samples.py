"""Difficulty-tiered function selection for the report's View page.

The View page (which replaced the old Compare and Hardest views) shows the
original source next to a chosen decompiler's output for a curated set of
functions, bucketed into three **difficulty tiers**. Difficulty is derived from
structural (GED) agreement across decompilers — GED is the one metric measured
for every target format, and "the control flow came back exactly" is the
sharpest single read of whether a function was easy or hard to decompile:

* **easy** — most decompilers get it *essentially perfect* (GED 0): at least
  half of the decompilers with a measured GED — and no fewer than two — are
  perfect.
* **hard** — no decompiler is perfect; ranked worst-first by the mean GED
  distance across decompilers (the same farthest-from-perfect notion the old
  Hall of Shame used), with a per-project cap so one giant project cannot fill
  the tier.
* **medium** — in between: someone is perfect, but fewer than half.

Functions where fewer than two decompilers have a measured GED are skipped —
"perfect" with a single witness says more about the corpus than the function.

This module owns *selection only* (which functions land in which tier); the two
payload writers (:func:`decbench.scoring.report_extras.build_samples` and
``scripts/rebuild_function_data.py``) materialize the entries with their own
code lookups, so selection cannot drift between them. Selection is seeded and
deterministic (same seed → same tiers), and pools exclude ``excluded`` projects
(the malware targets) *before* sampling, so no top-up pass is needed.
"""

from __future__ import annotations

import random
from collections.abc import Iterable
from typing import TYPE_CHECKING

# Same-package internals: the sample-set's even-spread sampler and seed
# resolution, reused so the tiers obey the identical project/binary spread
# rules as the dataset presets.
from decbench.scoring.datasets import _resolve_seed, _sample_even

if TYPE_CHECKING:
    from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord

__all__ = ["DIFFICULTY_TIERS", "select_view_functions"]

#: Tier names, in display order.
DIFFICULTY_TIERS = ("easy", "medium", "hard")

#: At most this many hard-tier candidates come from any one project, so a single
#: pathological project cannot fill the whole tier. Relaxed only if the tier
#: would otherwise come up short.
_HARD_PER_PROJECT_CAP = 10


def _ged_stats(record: FunctionRecord, decompilers: list[str]) -> tuple[int, int]:
    """(#decompilers with a measured GED, #of those that are GED-perfect)."""
    present = 0
    perfect = 0
    for dec in decompilers:
        values = record.values.get(dec)
        if values is None or "ged" not in values or values["ged"] is None:
            continue
        present += 1
        if (record.perfects.get(dec) or {}).get("ged"):
            perfect += 1
    return present, perfect


def _mean_ged_distance(record: FunctionRecord, decompilers: list[str]) -> float:
    """Mean GED distance-to-perfect across decompilers (falls back to values).

    ``FunctionRecord.distances`` carries the raw edit distance where computed;
    for GED the raw value IS a distance, so it is an equivalent fallback.
    """
    total = 0.0
    n = 0
    for dec in decompilers:
        dmap = record.distances.get(dec) or {}
        value = dmap.get("ged")
        if value is None:
            value = (record.values.get(dec) or {}).get("ged")
        if value is None:
            continue
        total += float(value)
        n += 1
    return total / n if n else 0.0


def select_view_functions(
    function_data: FunctionData,
    per_tier: int = 100,
    seed: int | None = None,
    excluded: Iterable[str] | None = None,
    headroom: int = 2,
) -> dict[str, list[tuple[BinaryGroup, FunctionRecord]]]:
    """Pick each tier's candidates, in materialization order.

    Returns ``{tier: [(group, record), ...]}`` with up to ``per_tier *
    headroom`` candidates per tier — the writers walk each list in order and
    keep the first ``per_tier`` that actually have decompiled code on disk, so
    over-drawing here is what keeps the tiers full.

    ``easy``/``medium`` are seeded-random, evenly spread across projects and
    binaries (via the dataset presets' own sampler); ``hard`` is worst-first by
    mean GED distance under a per-project cap. ``excluded`` projects (malware)
    never enter a pool.
    """
    excluded_set = set(excluded or ())
    decompilers = function_data.decompilers
    rng = random.Random(_resolve_seed(seed))

    easy_pool: list[tuple[BinaryGroup, FunctionRecord]] = []
    medium_pool: list[tuple[BinaryGroup, FunctionRecord]] = []
    hard_pool: list[tuple[BinaryGroup, FunctionRecord, float]] = []

    for group in function_data.groups:
        if group.project in excluded_set:
            continue
        for record in group.functions:
            present, perfect = _ged_stats(record, decompilers)
            if present < 2:
                continue
            if perfect == 0:
                hard_pool.append((group, record, _mean_ged_distance(record, decompilers)))
            elif perfect >= max(2, (present + 1) // 2):
                easy_pool.append((group, record))
            else:
                medium_pool.append((group, record))

    quota = per_tier * headroom
    chosen: set[int] = set()
    used_bins: set[tuple[str, str, str]] = set()
    tiers: dict[str, list[tuple[BinaryGroup, FunctionRecord]]] = {
        "easy": _sample_even(easy_pool, quota, chosen, used_bins, rng),
        "medium": _sample_even(medium_pool, quota, chosen, used_bins, rng),
    }

    # hard: worst-first, capped per project (relax the cap only if short).
    hard_pool.sort(key=lambda t: -t[2])
    picked: list[tuple[BinaryGroup, FunctionRecord]] = []
    per_project: dict[str, int] = {}
    overflow: list[tuple[BinaryGroup, FunctionRecord]] = []
    for group, record, _distance in hard_pool:
        if len(picked) >= quota:
            break
        if per_project.get(group.project, 0) >= _HARD_PER_PROJECT_CAP:
            overflow.append((group, record))
            continue
        picked.append((group, record))
        per_project[group.project] = per_project.get(group.project, 0) + 1
    if len(picked) < quota:
        picked.extend(overflow[: quota - len(picked)])
    tiers["hard"] = picked
    return tiers
