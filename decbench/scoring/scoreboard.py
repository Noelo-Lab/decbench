"""Scoreboard generation."""

from __future__ import annotations

import math
import statistics
from datetime import datetime
from typing import TYPE_CHECKING

from decbench.models.scoreboard import (
    DecompilerScore,
    MetricScore,
    Scoreboard,
)
from decbench.scoring.aggregator import AggregatedResults

if TYPE_CHECKING:
    from decbench.models.function_data import FunctionData


def build_scoreboard_from_function_data(
    fd: FunctionData,
    name: str = "DecBench Scoreboard",
    description: str = "",
    version: str = "2.0",
) -> Scoreboard:
    """Build a scoreboard from the per-function dataset — the single source of
    truth shared by the HTML report and ``scoreboard.toml``.

    Denominator policy (matches ``rendering/html.py`` ``recompute()``): for every
    (decompiler, metric) the denominator is the SAME shared universe — the set of
    functions where that metric is *measurable for anyone* (a finite value from
    some decompiler). A decompiler that failed to decompile a function, or was
    decompiled but has no value for a measurable metric, counts as a NOT-PERFECT
    miss IN the denominator (so every decompiler shares one denominator per
    metric). Only metrics unmeasurable for everyone — GED with no/degenerate
    source CFG, byte_match abstained, type_match with no DWARF ground truth — are
    excluded, uniformly. ``mean``/``median`` still summarize the *measured* values.

    The Union column (stored in the ``overall_*`` fields) is the share of
    functions a decompiler got perfect on AT LEAST ONE measurable metric, over
    the functions where at least one metric was measurable — the union dual of
    the old all-metrics-perfect Overall.
    """
    decs, metrics = fd.decompilers, fd.metrics

    def measurable(f: object, m: str) -> bool:
        for d in decs:
            v = getattr(f, "values", {}).get(d) or {}
            if m in v and math.isfinite(v[m]):
                return True
        return False

    vals: dict[str, dict[str, list[float]]] = {d: {m: [] for m in metrics} for d in decs}
    perf: dict[str, dict[str, int]] = {d: {m: 0 for m in metrics} for d in decs}
    tot: dict[str, dict[str, int]] = {d: {m: 0 for m in metrics} for d in decs}
    overall_perf = {d: 0 for d in decs}
    overall_tot = {d: 0 for d in decs}

    for g in fd.groups:
        for f in g.functions:
            meas = {m: measurable(f, m) for m in metrics}
            any_meas = any(meas.values())
            for d in decs:
                fp = f.perfects.get(d) or {}
                fv = f.values.get(d) or {}
                for m in metrics:
                    if not meas[m]:
                        continue
                    tot[d][m] += 1
                    if m in fv and math.isfinite(fv[m]):
                        vals[d][m].append(fv[m])
                    if fp.get(m):
                        perf[d][m] += 1
                if any_meas:
                    overall_tot[d] += 1
                    if any(fp.get(m) for m in metrics if meas[m]):
                        overall_perf[d] += 1

    sb = Scoreboard(
        name=name,
        description=description,
        version=version,
        generated_at=datetime.now(),
        projects_evaluated=sorted({g.project for g in fd.groups}),
        optimization_levels=sorted({g.opt_level for g in fd.groups}),
        decompilers=decs,
        metrics=metrics,
        total_functions=sum(len(g.functions) for g in fd.groups),
        total_binaries=len(fd.groups),
    )
    for d in decs:
        ds = DecompilerScore(name=d)
        for m in metrics:
            n = tot[d][m]
            ds.metric_scores[m] = MetricScore(
                metric_name=m,
                decompiler_name=d,
                perfect_count=perf[d][m],
                total_count=n,
                perfect_percentage=(100 * perf[d][m] / n) if n else 0.0,
                mean=statistics.fmean(vals[d][m]) if vals[d][m] else 0.0,
                median=statistics.median(vals[d][m]) if vals[d][m] else 0.0,
            )
        ds.overall_perfect_count = overall_perf[d]
        ds.overall_total_count = overall_tot[d]
        ds.overall_perfect_percentage = (
            100 * overall_perf[d] / overall_tot[d] if overall_tot[d] else 0.0
        )
        sb.decompiler_scores[d] = ds
    for m in metrics:
        for rank, (d, _) in enumerate(sb.get_metric_rankings(m), 1):
            sb.decompiler_scores[d].metric_scores[m].rank = rank
    for rank, (d, _) in enumerate(sb.get_overall_rankings(), 1):
        sb.decompiler_scores[d].overall_rank = rank
    return sb


def build_scoreboard(
    aggregated: AggregatedResults,
    projects: list[str] | None = None,
    optimization_levels: list[str] | None = None,
    decompilers: list[str] | None = None,
    name: str = "DecBench Scoreboard",
) -> Scoreboard:
    """Build a scoreboard from aggregated results."""
    if decompilers is None:
        decompilers = aggregated.decompilers

    scoreboard = Scoreboard(
        name=name,
        generated_at=datetime.now(),
        projects_evaluated=projects or [],
        optimization_levels=optimization_levels or [],
        decompilers=decompilers,
        metrics=aggregated.metrics,
        total_functions=aggregated.total_functions,
        total_binaries=aggregated.total_binaries,
    )

    # Build per-decompiler scores
    for dec_name in decompilers:
        if dec_name not in aggregated.by_decompiler:
            continue

        dec_metrics = aggregated.by_decompiler[dec_name]

        dec_score = DecompilerScore(
            name=dec_name,
            total_functions_evaluated=aggregated.total_functions,
            total_binaries_evaluated=aggregated.total_binaries,
        )

        # Per-metric scores
        for metric_name, agg_metric in dec_metrics.items():
            ms = MetricScore(
                metric_name=metric_name,
                decompiler_name=dec_name,
                perfect_count=agg_metric.perfect_count,
                total_count=agg_metric.total_count,
                perfect_percentage=agg_metric.perfect_percentage,
                mean=agg_metric.mean,
                median=agg_metric.median,
            )
            dec_score.metric_scores[metric_name] = ms

        # Compute Union: functions perfect on AT LEAST ONE metric, counted over
        # functions that were evaluated on at least one metric. A function whose
        # metrics all abstained (nothing measurable) is EXCLUDED rather than
        # counted as a failure — "couldn't measure" != "wrong".
        per_func = aggregated.per_function.get(dec_name, {})
        all_metric_names = aggregated.metrics

        overall_perfect = 0
        overall_total = 0

        for metric_perfects in per_func.values():
            evaluated = [m for m in all_metric_names if m in metric_perfects]
            if not evaluated:
                continue
            overall_total += 1
            if any(metric_perfects[m] for m in evaluated):
                overall_perfect += 1

        dec_score.overall_perfect_count = overall_perfect
        dec_score.overall_total_count = overall_total
        dec_score.overall_perfect_percentage = (
            (overall_perfect / overall_total * 100) if overall_total > 0 else 0.0
        )

        scoreboard.decompiler_scores[dec_name] = dec_score

    # Assign ranks per metric
    for metric_name in aggregated.metrics:
        rankings = scoreboard.get_metric_rankings(metric_name)
        for rank, (dec_name, _) in enumerate(rankings, 1):
            scoreboard.decompiler_scores[dec_name].metric_scores[metric_name].rank = rank

    # Assign overall ranks
    overall_rankings = scoreboard.get_overall_rankings()
    for rank, (dec_name, _) in enumerate(overall_rankings, 1):
        scoreboard.decompiler_scores[dec_name].overall_rank = rank

    return scoreboard


def render_scoreboard_text(scoreboard: Scoreboard) -> str:
    return scoreboard.render_text()


def render_scoreboard_markdown(scoreboard: Scoreboard) -> str:
    """Render scoreboard as Markdown."""
    lines = []

    lines.append(f"# {scoreboard.name}")
    lines.append("")
    lines.append(f"**Generated:** {scoreboard.generated_at.strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"**Functions evaluated:** {scoreboard.total_functions:,}")
    lines.append(f"**Binaries evaluated:** {scoreboard.total_binaries:,}")
    lines.append("")

    for metric_name in scoreboard.metrics:
        lines.append(f"## {metric_name}")
        lines.append("")
        lines.append("| Rank | Decompiler | Perfect % |")
        lines.append("|------|------------|-----------|")

        rankings = scoreboard.get_metric_rankings(metric_name)
        for i, (dec_name, pct) in enumerate(rankings, 1):
            lines.append(f"| {i} | {dec_name} | {pct:.1f}% |")
        lines.append("")

    lines.append("## Union (Perfect on At Least One Metric)")
    lines.append("")
    lines.append("| Rank | Decompiler | Perfect % |")
    lines.append("|------|------------|-----------|")

    for i, (dec_name, pct) in enumerate(scoreboard.get_overall_rankings(), 1):
        lines.append(f"| {i} | {dec_name} | {pct:.1f}% |")

    lines.append("")

    return "\n".join(lines)
