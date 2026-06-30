"""Scoreboard generation."""

from __future__ import annotations

from datetime import datetime

from decbench.models.scoreboard import (
    DecompilerScore,
    MetricScore,
    Scoreboard,
)
from decbench.scoring.aggregator import AggregatedResults


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

        # Compute Overall: functions perfect on ALL metrics, counted ONLY over
        # functions that were evaluated on every metric. A function missing a
        # metric (e.g. byte_match abstained for ARM/PE) is EXCLUDED from Overall
        # rather than counted as a failure — "couldn't measure" != "wrong".
        per_func = aggregated.per_function.get(dec_name, {})
        all_metric_names = aggregated.metrics

        overall_perfect = 0
        overall_total = 0

        for metric_perfects in per_func.values():
            if not all(m in metric_perfects for m in all_metric_names):
                continue
            overall_total += 1
            if all(metric_perfects[m] for m in all_metric_names):
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

    lines.append("## Overall (Perfect on All Metrics)")
    lines.append("")
    lines.append("| Rank | Decompiler | Perfect % |")
    lines.append("|------|------------|-----------|")

    for i, (dec_name, pct) in enumerate(scoreboard.get_overall_rankings(), 1):
        lines.append(f"| {i} | {dec_name} | {pct:.1f}% |")

    lines.append("")

    return "\n".join(lines)
