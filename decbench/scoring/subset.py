"""Large-function subsetting over a :class:`FunctionData` dataset.

DecBench evaluates every function, but the interesting (and hard) decompilation
cases live in the **upper tail** of the function-size distribution. This module
computes that distribution, selects the large-function subset (without touching
binaries), and filters a :class:`FunctionData` down to just those functions so
the scoreboard / report can be recomputed on large functions alone.

Size is :attr:`FunctionRecord.size` (the representative decompiled line count).
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from pydantic import BaseModel, Field

from decbench.models.function_data import BinaryGroup, FunctionData

__all__ = [
    "SubsetManifest",
    "size_distribution",
    "compute_large_subset",
    "filter_function_data",
]


def _all_sizes(function_data: FunctionData) -> list[int]:
    """Collect every non-None :attr:`FunctionRecord.size` in the dataset."""
    sizes: list[int] = []
    for group in function_data.groups:
        for record in group.functions:
            if record.size is not None:
                sizes.append(record.size)
    return sizes


def _percentile(sorted_values: list[int], pct: float) -> float:
    """Linear-interpolation percentile (``pct`` in [0, 100])."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return float(sorted_values[lo])
    frac = rank - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def size_distribution(function_data: FunctionData) -> dict:
    """Summary statistics of the function-size distribution.

    Returns a dict with ``count``, ``mean``, ``std`` (population), ``min``,
    ``max`` and percentiles ``p50``/``p75``/``p90``/``p95``/``p99``. Returns
    zeroed stats when no function has a recorded size.
    """
    sizes = _all_sizes(function_data)
    if not sizes:
        return {
            "count": 0,
            "mean": 0.0,
            "std": 0.0,
            "min": 0,
            "max": 0,
            "p50": 0.0,
            "p75": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "p99": 0.0,
        }

    n = len(sizes)
    mean = sum(sizes) / n
    var = sum((s - mean) ** 2 for s in sizes) / n
    std = math.sqrt(var)
    ordered = sorted(sizes)

    return {
        "count": n,
        "mean": mean,
        "std": std,
        "min": ordered[0],
        "max": ordered[-1],
        "p50": _percentile(ordered, 50),
        "p75": _percentile(ordered, 75),
        "p90": _percentile(ordered, 90),
        "p95": _percentile(ordered, 95),
        "p99": _percentile(ordered, 99),
    }


class SubsetManifest(BaseModel):
    """A selected subset of functions (the large-function upper tail)."""

    method: str = Field(..., description="Selection method ('std' or 'percentile')")
    k: float = Field(..., description="Method parameter (std multiplier or percentile)")
    threshold: float = Field(..., description="Size cutoff; functions with size >= this")
    functions: list[dict] = Field(
        default_factory=list,
        description="Selected functions: {project, opt, binary, function}",
    )

    def to_json(self, path: Path) -> None:
        """Serialize this manifest to ``path``."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.model_dump(mode="json"), f, indent=2)

    @classmethod
    def from_json(cls, path: Path) -> SubsetManifest:
        """Load a manifest from ``path``."""
        with open(path) as f:
            data = json.load(f)
        return cls(**data)


def compute_large_subset(
    function_data: FunctionData,
    method: str = "std",
    k: float = 1.0,
) -> SubsetManifest:
    """Select the large-function subset (upper tail of the size distribution).

    Args:
        function_data: The per-function dataset.
        method: ``'std'`` -> threshold = mean + k*std; ``'percentile'`` ->
            threshold = the k-th percentile of sizes (e.g. ``k=90`` -> p90).
        k: Method parameter (std multiplier, or percentile in [0, 100]).

    Returns:
        A :class:`SubsetManifest` listing all functions with size >= threshold.
    """
    dist = size_distribution(function_data)

    if method == "percentile":
        threshold = _percentile(sorted(_all_sizes(function_data)), float(k))
    elif method == "std":
        threshold = dist["mean"] + k * dist["std"]
    else:
        raise ValueError(f"Unknown method: {method!r} (expected 'std' or 'percentile')")

    selected: list[dict] = []
    for group in function_data.groups:
        for record in group.functions:
            if record.size is not None and record.size >= threshold:
                selected.append(
                    {
                        "project": group.project,
                        "opt": group.opt_level,
                        "binary": group.binary,
                        "function": record.function,
                    }
                )

    return SubsetManifest(
        method=method,
        k=float(k),
        threshold=float(threshold),
        functions=selected,
    )


def filter_function_data(
    function_data: FunctionData,
    manifest: SubsetManifest,
) -> FunctionData:
    """Return a new :class:`FunctionData` with only the manifest's functions.

    Binary groups that retain no functions are dropped, so the scoreboard /
    report can be recomputed on just the large functions without touching any
    binaries.
    """
    wanted: set[tuple[str, str, str, str]] = {
        (f["project"], f["opt"], f["binary"], f["function"]) for f in manifest.functions
    }

    new_groups: list[BinaryGroup] = []
    for group in function_data.groups:
        kept = [
            record
            for record in group.functions
            if (group.project, group.opt_level, group.binary, record.function) in wanted
        ]
        if not kept:
            continue
        new_groups.append(
            BinaryGroup(
                project=group.project,
                opt_level=group.opt_level,
                binary=group.binary,
                labels=list(group.labels),
                functions=kept,
            )
        )

    return FunctionData(
        schema_version=function_data.schema_version,
        decompilers=list(function_data.decompilers),
        decompiler_versions=dict(function_data.decompiler_versions),
        metrics=list(function_data.metrics),
        perfect_values=dict(function_data.perfect_values),
        groups=new_groups,
        hardest=list(function_data.hardest),
        history=list(function_data.history),
    )
