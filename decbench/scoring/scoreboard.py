"""Scoreboard generation."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from decbench.models.metrics import MetricCategory
from decbench.models.scoreboard import (
    CategoryBreakdown,
    DecompilerScore,
    Scoreboard,
)
from decbench.scoring.aggregator import AggregatedResults, compute_category_score

if TYPE_CHECKING:
    pass


def build_scoreboard(
    aggregated: AggregatedResults,
    projects: list[str] | None = None,
    optimization_levels: list[str] | None = None,
    decompilers: list[str] | None = None,
    name: str = "DecBench Scoreboard",
) -> Scoreboard:
    """Build a scoreboard from aggregated results.

    Args:
        aggregated: Aggregated evaluation results
        projects: List of project names included
        optimization_levels: Optimization levels included
        decompilers: Decompilers to include (None for all)
        name: Name for the scoreboard

    Returns:
        Complete Scoreboard ready for display
    """
    if decompilers is None:
        decompilers = aggregated.decompilers

    scoreboard = Scoreboard(
        name=name,
        generated_at=datetime.now(),
        projects_evaluated=projects or [],
        optimization_levels=optimization_levels or [],
        decompilers=decompilers,
        total_functions=aggregated.total_functions,
        total_binaries=aggregated.total_binaries,
    )

    # Build category breakdowns
    for category in MetricCategory:
        breakdown = CategoryBreakdown(category=category)

        for dec_name in decompilers:
            if dec_name not in aggregated.by_decompiler:
                continue

            cat_score = compute_category_score(aggregated, dec_name, category)
            breakdown.scores[dec_name] = cat_score

        # Compute rankings
        breakdown.compute_rankings()

        scoreboard.category_breakdowns[category] = breakdown

    # Build decompiler scores
    for dec_name in decompilers:
        dec_score = DecompilerScore(
            name=dec_name,
            total_functions_evaluated=aggregated.total_functions,
            total_binaries_evaluated=aggregated.total_binaries,
        )

        # Add category scores
        for category in MetricCategory:
            if category in scoreboard.category_breakdowns:
                breakdown = scoreboard.category_breakdowns[category]
                if dec_name in breakdown.scores:
                    dec_score.category_scores[category] = breakdown.scores[dec_name]

        # Compute overall score
        dec_score.compute_overall_score(scoreboard.category_weights)

        scoreboard.decompiler_scores[dec_name] = dec_score

    # Assign overall ranks
    overall_rankings = scoreboard.get_overall_rankings()
    for rank, (dec_name, _) in enumerate(overall_rankings, 1):
        scoreboard.decompiler_scores[dec_name].overall_rank = rank

    return scoreboard


def render_scoreboard_text(scoreboard: Scoreboard) -> str:
    """Render scoreboard as formatted text for terminal display.

    Args:
        scoreboard: The scoreboard to render

    Returns:
        Formatted text string
    """
    lines = []
    width = 60

    lines.append("=" * width)
    lines.append(f"  {scoreboard.name}")
    lines.append(f"  Generated: {scoreboard.generated_at.strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"  Functions: {scoreboard.total_functions:,}")
    lines.append(f"  Binaries: {scoreboard.total_binaries:,}")
    lines.append("=" * width)
    lines.append("")

    # Render each category
    for category in MetricCategory:
        if category not in scoreboard.category_breakdowns:
            continue

        breakdown = scoreboard.category_breakdowns[category]

        lines.append(f"{category.value.upper()}:")
        lines.append("-" * 40)

        for i, (dec_name, score) in enumerate(breakdown.rankings):
            cat_score = breakdown.scores[dec_name]
            display = cat_score.headline_display or f"{score:.2f}"

            rank_marker = "→" if i == 0 else " "
            lines.append(f"  {rank_marker} {dec_name:20} {display:>15}")

        lines.append("")

    # Overall rankings
    lines.append("OVERALL:")
    lines.append("-" * 40)

    for i, (dec_name, score) in enumerate(scoreboard.get_overall_rankings()):
        rank_marker = "→" if i == 0 else " "
        lines.append(f"  {rank_marker} {dec_name:20} {score:>15.2f}")

    lines.append("")
    lines.append("=" * width)

    return "\n".join(lines)


def render_scoreboard_markdown(scoreboard: Scoreboard) -> str:
    """Render scoreboard as Markdown for documentation.

    Args:
        scoreboard: The scoreboard to render

    Returns:
        Markdown string
    """
    lines = []

    lines.append(f"# {scoreboard.name}")
    lines.append("")
    lines.append(f"**Generated:** {scoreboard.generated_at.strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"**Functions evaluated:** {scoreboard.total_functions:,}")
    lines.append(f"**Binaries evaluated:** {scoreboard.total_binaries:,}")
    lines.append("")

    # Category tables
    for category in MetricCategory:
        if category not in scoreboard.category_breakdowns:
            continue

        breakdown = scoreboard.category_breakdowns[category]

        lines.append(f"## {category.value.title()}")
        lines.append("")
        lines.append("| Rank | Decompiler | Score |")
        lines.append("|------|------------|-------|")

        for i, (dec_name, score) in enumerate(breakdown.rankings, 1):
            cat_score = breakdown.scores[dec_name]
            display = cat_score.headline_display or f"{score:.2f}"
            lines.append(f"| {i} | {dec_name} | {display} |")

        lines.append("")

    # Overall
    lines.append("## Overall Rankings")
    lines.append("")
    lines.append("| Rank | Decompiler | Score |")
    lines.append("|------|------------|-------|")

    for i, (dec_name, score) in enumerate(scoreboard.get_overall_rankings(), 1):
        lines.append(f"| {i} | {dec_name} | {score:.2f} |")

    lines.append("")

    return "\n".join(lines)
