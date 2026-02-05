"""Metric result models."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class MetricCategory(str, Enum):
    """Categories for metric classification."""

    FAITHFUL = "faithful"  # How well the decompilation matches the source CFG (GED)
    SIMPLE = "simple"  # How readable/simple the code is (LOC, gotos, etc.)
    CORRECT = "correct"  # How semantically correct the output is (byte-match, etc.)


class AggregationType(str, Enum):
    """How to aggregate metric values across functions."""

    SUM = "sum"
    MEAN = "mean"
    MEDIAN = "median"
    MAX = "max"
    MIN = "min"
    COUNT = "count"  # Count of functions meeting criteria
    PERCENT = "percent"  # Percentage of functions meeting criteria


class MetricValue(BaseModel):
    """A single metric value with optional metadata."""

    value: float = Field(..., description="The metric value")
    raw_value: Any | None = Field(
        default=None,
        description="Raw value before normalization",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata about the computation",
    )

    @property
    def is_perfect(self) -> bool:
        """Check if this is a 'perfect' score (value == 0 for distance metrics)."""
        return self.value == 0.0


class FunctionMetrics(BaseModel):
    """All metrics for a single function."""

    function_name: str = Field(..., description="Name of the function")
    function_address: int = Field(..., description="Address of the function")

    # Metrics organized by name
    metrics: dict[str, MetricValue] = Field(
        default_factory=dict,
        description="Metric name to value mapping",
    )

    def get_metric(self, name: str) -> MetricValue | None:
        """Get a specific metric value."""
        return self.metrics.get(name)

    def set_metric(self, name: str, value: float, **metadata) -> None:
        """Set a metric value."""
        self.metrics[name] = MetricValue(value=value, metadata=metadata)


class MetricDefinition(BaseModel):
    """Definition of a metric."""

    name: str = Field(..., description="Unique metric identifier")
    display_name: str = Field(..., description="Human-readable name")
    description: str = Field(default="", description="Metric description")
    category: MetricCategory = Field(..., description="Category this metric belongs to")

    # Scoring configuration
    weight: float = Field(
        default=1.0,
        description="Weight for this metric in category scoring",
    )
    lower_is_better: bool = Field(
        default=True,
        description="Whether lower values indicate better performance",
    )
    perfect_value: float = Field(
        default=0.0,
        description="The 'perfect' score value",
    )
    aggregation: AggregationType = Field(
        default=AggregationType.MEAN,
        description="Default aggregation method",
    )

    # Normalization
    normalize: bool = Field(
        default=False,
        description="Whether to normalize values",
    )
    normalize_by: str | None = Field(
        default=None,
        description="Metric name to normalize by (e.g., 'graph_size' for GED)",
    )


class MetricResult(BaseModel):
    """Results of a metric computation for one decompiler on one binary."""

    metric_name: str = Field(..., description="Name of the metric")
    decompiler_name: str = Field(..., description="Decompiler that produced the output")
    binary_name: str = Field(..., description="Binary that was decompiled")

    # Per-function results
    function_results: dict[str, MetricValue] = Field(
        default_factory=dict,
        description="Metric values keyed by function name",
    )

    # Aggregated results
    total: float | None = Field(default=None, description="Sum of all values")
    mean: float | None = Field(default=None, description="Mean of all values")
    median: float | None = Field(default=None, description="Median of all values")

    # For perfect-match style metrics
    perfect_count: int = Field(
        default=0,
        description="Number of functions with perfect score",
    )
    perfect_percentage: float = Field(
        default=0.0,
        description="Percentage of functions with perfect score",
    )

    # Metadata
    computation_time_seconds: float = Field(
        default=0.0,
        description="Time taken to compute this metric",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Errors encountered during computation",
    )

    def compute_aggregates(self, perfect_value: float = 0.0) -> None:
        """Compute aggregate statistics from function results."""
        if not self.function_results:
            return

        values = [v.value for v in self.function_results.values()]

        self.total = sum(values)
        self.mean = self.total / len(values)

        sorted_values = sorted(values)
        n = len(sorted_values)
        if n % 2 == 0:
            self.median = (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2
        else:
            self.median = sorted_values[n // 2]

        self.perfect_count = sum(1 for v in values if v == perfect_value)
        self.perfect_percentage = (self.perfect_count / len(values)) * 100 if values else 0.0


class CategoryScore(BaseModel):
    """Aggregated score for a category (Faithful, Simple, Correct)."""

    category: MetricCategory = Field(..., description="The category")
    decompiler_name: str = Field(..., description="Decompiler name")

    # Individual metric contributions
    metric_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Individual metric scores (normalized and weighted)",
    )
    metric_weights: dict[str, float] = Field(
        default_factory=dict,
        description="Weights applied to each metric",
    )

    # Final score
    weighted_score: float = Field(
        default=0.0,
        description="Final weighted score for this category",
    )
    rank: int | None = Field(
        default=None,
        description="Rank among decompilers for this category",
    )

    # Display metrics (category-specific headline numbers)
    headline_metric: str | None = Field(
        default=None,
        description="The primary metric for display",
    )
    headline_value: float | None = Field(
        default=None,
        description="Value of the headline metric",
    )
    headline_display: str | None = Field(
        default=None,
        description="Formatted display string for headline",
    )

    def compute_weighted_score(self) -> None:
        """Compute the weighted score from individual metrics."""
        if not self.metric_scores:
            self.weighted_score = 0.0
            return

        total_weight = sum(self.metric_weights.values())
        if total_weight == 0:
            self.weighted_score = 0.0
            return

        weighted_sum = sum(
            self.metric_scores[name] * self.metric_weights.get(name, 1.0)
            for name in self.metric_scores
        )
        self.weighted_score = weighted_sum / total_weight
