"""Scoring and aggregation for DecBench."""

from decbench.scoring.aggregator import AggregatedResults, aggregate_results
from decbench.scoring.function_data_builder import build_function_data
from decbench.scoring.labels import (
    binary_labels_for,
    function_labels_for,
    opt_level_labels,
)
from decbench.scoring.scoreboard import build_scoreboard

__all__ = [
    "aggregate_results",
    "AggregatedResults",
    "build_scoreboard",
    "build_function_data",
    "binary_labels_for",
    "function_labels_for",
    "opt_level_labels",
]
