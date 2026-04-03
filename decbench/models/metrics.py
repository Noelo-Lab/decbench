"""Metric result models."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AggregationType(str, Enum):
    """How to aggregate metric values across functions."""

    SUM = "sum"
    MEAN = "mean"
    MEDIAN = "median"
    MAX = "max"
    MIN = "min"
    COUNT = "count"
    PERCENT = "percent"


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

    metrics: dict[str, MetricValue] = Field(
        default_factory=dict,
        description="Metric name to value mapping",
    )

    def get_metric(self, name: str) -> MetricValue | None:
        return self.metrics.get(name)

    def set_metric(self, name: str, value: float, **metadata: Any) -> None:
        self.metrics[name] = MetricValue(value=value, metadata=metadata)


class MetricResult(BaseModel):
    """Results of a metric computation for one decompiler on one binary."""

    metric_name: str = Field(..., description="Name of the metric")
    decompiler_name: str = Field(..., description="Decompiler that produced the output")
    binary_name: str = Field(..., description="Binary that was decompiled")

    function_results: dict[str, MetricValue] = Field(
        default_factory=dict,
        description="Metric values keyed by function name",
    )

    total: float | None = Field(default=None, description="Sum of all values")
    mean: float | None = Field(default=None, description="Mean of all values")
    median: float | None = Field(default=None, description="Median of all values")

    perfect_count: int = Field(
        default=0,
        description="Number of functions with perfect score",
    )
    perfect_percentage: float = Field(
        default=0.0,
        description="Percentage of functions with perfect score",
    )

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
