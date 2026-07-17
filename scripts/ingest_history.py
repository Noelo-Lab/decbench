"""Ingest a multi-version run's per-version scores into a target's history.

The Historical page (``history`` view) plots how a decompiler's per-metric
perfect-rate moves across versions. Its data — ``FunctionData.history``, a list
of :class:`HistoryPoint` — was only ever populated by ``run_small.py`` from
``name@version`` columns inside ONE scoreboard. This script is the general
ingester: it reads a *versioned* benchmark run (e.g. the Ghidra GED-over-O0 run
with ``ghidra@12.1 ... ghidra@10.4`` columns), computes each version's perfect
rate per metric, and writes those points into a *target* results tree's
``function_results.json`` so the site it builds shows the chart.

The target keeps its own decompiler columns untouched — only ``.history`` is
replaced (or extended). The final ``rebuild_function_data`` pass preserves
``.history``, so ingesting before the rebuild is safe.

Usage:
    python scripts/ingest_history.py <versioned-run-dir> <target-results-dir>
        [--base ghidra] [--metrics ged] [--replace]

``<versioned-run-dir>`` is a results tree with a ``function_results.json`` whose
decompilers are ``<base>@<version>``. Points are emitted oldest-version-first so
the chart reads left-to-right in release order.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from decbench.models.function_data import FunctionData, HistoryPoint
from decbench.scoring.scoreboard import build_scoreboard_from_function_data

# Best-known Ghidra release dates (published date of the labeled line), for the
# HistoryPoint.date metadata. The chart orders by version, not date, so a missing
# entry only drops the tooltip date, never the point.
_GHIDRA_DATES = {
    "10.4": "2023-09-29",
    "11.0": "2023-12-22",
    "11.4": "2025-06-24",
    "12.0": "2025-09-05",
    "12.1": "2025-11-14",
}


def _version_key(version: str) -> tuple:
    """Sort key that orders version strings numerically (10.4 < 11.0 < 12.1)."""
    parts = []
    for chunk in version.split("."):
        parts.append(int(chunk) if chunk.isdigit() else chunk)
    return tuple(parts)


def build_points(run_dir: Path, base: str, metrics: list[str] | None) -> list[HistoryPoint]:
    """One HistoryPoint per ``<base>@<version>`` column in ``run_dir``."""
    fd = FunctionData.from_json(run_dir / "function_results.json")
    scoreboard = build_scoreboard_from_function_data(fd)

    points: list[tuple[tuple, HistoryPoint]] = []
    for dec_id, score in scoreboard.decompiler_scores.items():
        if "@" not in dec_id:
            continue
        dec_base, version = dec_id.split("@", 1)
        if dec_base != base:
            continue
        scores = {
            m: ms.perfect_percentage
            for m, ms in score.metric_scores.items()
            if metrics is None or m in metrics
        }
        if not scores:
            continue
        date = _GHIDRA_DATES.get(version) if base == "ghidra" else None
        points.append(
            (
                _version_key(version),
                HistoryPoint(
                    decompiler=dec_base,
                    version=version,
                    date=date,
                    scores=scores,
                    overall=score.overall_perfect_percentage,
                ),
            )
        )
    points.sort(key=lambda t: t[0])  # oldest version first
    return [p for _k, p in points]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path, help="versioned run (name@version columns)")
    parser.add_argument("target_dir", type=Path, help="results tree to inject history into")
    parser.add_argument("--base", default="ghidra", help="base decompiler name (default: ghidra)")
    parser.add_argument(
        "--metrics",
        default="ged",
        help="comma list of metrics to include (default: ged); 'all' for every metric",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace the target's history entirely (default: keep other bases' points)",
    )
    args = parser.parse_args()

    metrics = (
        None
        if args.metrics.strip().lower() == "all"
        else [m.strip() for m in args.metrics.split(",") if m.strip()]
    )

    points = build_points(args.run_dir, args.base, metrics)
    if not points:
        print(
            f"[ingest] no {args.base}@version columns with the requested metrics in {args.run_dir}"
        )
        return 1

    target_path = args.target_dir / "function_results.json"
    fd = FunctionData.from_json(target_path)
    # --replace clears everything; otherwise drop only this base's existing points
    # (re-ingest is idempotent) and keep any other bases'.
    kept = [] if args.replace else [h for h in fd.history if h.decompiler != args.base]
    fd.history = kept + points
    fd.to_json(target_path)

    print(f"[ingest] wrote {len(points)} {args.base} history point(s) -> {target_path}")
    for p in points:
        score_str = ", ".join(f"{m}={v:.1f}%" for m, v in p.scores.items())
        print(f"    {p.decompiler}@{p.version} ({p.date or '?'}): {score_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
