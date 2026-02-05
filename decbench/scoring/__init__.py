"""Scoring and aggregation for DecBench."""

from decbench.scoring.aggregator import aggregate_results, AggregatedResults
from decbench.scoring.scoreboard import build_scoreboard

__all__ = [
    "aggregate_results",
    "AggregatedResults",
    "build_scoreboard",
]
