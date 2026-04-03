"""Result aggregation for scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from decbench.models.metrics import MetricResult
from decbench.metrics.registry import MetricRegistry

if TYPE_CHECKING:
    from decbench.models.project import OptimizationLevel


@dataclass
class AggregatedMetric:
    """Aggregated values for a single metric across all functions."""

    metric_name: str
    decompiler_name: str

    total: float = 0.0
    mean: float = 0.0
    median: float = 0.0
    min_value: float = float("inf")
    max_value: float = float("-inf")

    perfect_count: int = 0
    total_count: int = 0

    @property
    def perfect_percentage(self) -> float:
        if self.total_count == 0:
            return 0.0
        return (self.perfect_count / self.total_count) * 100


@dataclass
class PerFunctionResults:
    """Per-function metric values across decompilers for computing Overall."""

    # function_key -> metric_name -> is_perfect
    function_perfects: dict[str, dict[str, bool]] = field(default_factory=dict)


@dataclass
class AggregatedResults:
    """Fully aggregated results ready for scoreboard generation."""

    # decompiler -> metric -> AggregatedMetric
    by_decompiler: dict[str, dict[str, AggregatedMetric]] = field(default_factory=dict)

    # decompiler -> function_key -> metric -> is_perfect
    per_function: dict[str, dict[str, dict[str, bool]]] = field(default_factory=dict)

    total_functions: int = 0
    total_binaries: int = 0
    decompilers: list[str] = field(default_factory=list)
    metrics: list[str] = field(default_factory=list)


def aggregate_results(
    evaluation_results: dict[
        str,
        dict[OptimizationLevel, dict[str, dict[str, dict[str, MetricResult]]]],
    ],
) -> AggregatedResults:
    """Aggregate evaluation results across all projects and binaries."""
    aggregated = AggregatedResults()

    # decompiler -> metric -> list of (value, is_perfect)
    all_values: dict[str, dict[str, list[tuple[float, bool]]]] = {}

    decompilers_seen: set[str] = set()
    metrics_seen: set[str] = set()
    binary_count = 0
    function_count = 0

    for project_name, opt_results in evaluation_results.items():
        for opt_level, binary_results in opt_results.items():
            for binary_name, dec_results in binary_results.items():
                binary_count += 1

                for dec_name, metric_results in dec_results.items():
                    decompilers_seen.add(dec_name)

                    if dec_name not in all_values:
                        all_values[dec_name] = {}
                    if dec_name not in aggregated.per_function:
                        aggregated.per_function[dec_name] = {}

                    for metric_name, result in metric_results.items():
                        metrics_seen.add(metric_name)

                        if metric_name not in all_values[dec_name]:
                            all_values[dec_name][metric_name] = []

                        try:
                            metric = MetricRegistry.get(metric_name)
                            perfect_value = metric.perfect_value
                        except KeyError:
                            perfect_value = 0.0

                        for func_name, value in result.function_results.items():
                            is_perfect = value.value == perfect_value
                            all_values[dec_name][metric_name].append(
                                (value.value, is_perfect)
                            )
                            function_count += 1

                            # Track per-function perfects for Overall computation
                            func_key = f"{binary_name}::{func_name}"
                            if func_key not in aggregated.per_function[dec_name]:
                                aggregated.per_function[dec_name][func_key] = {}
                            aggregated.per_function[dec_name][func_key][metric_name] = is_perfect

    # Compute aggregates
    for dec_name in all_values:
        aggregated.by_decompiler[dec_name] = {}

        for metric_name, values in all_values[dec_name].items():
            if not values:
                continue

            raw_values = [v[0] for v in values]
            perfect_flags = [v[1] for v in values]

            agg = AggregatedMetric(
                metric_name=metric_name,
                decompiler_name=dec_name,
                total=sum(raw_values),
                mean=sum(raw_values) / len(raw_values),
                min_value=min(raw_values),
                max_value=max(raw_values),
                perfect_count=sum(perfect_flags),
                total_count=len(values),
            )

            sorted_values = sorted(raw_values)
            n = len(sorted_values)
            if n % 2 == 0:
                agg.median = (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2
            else:
                agg.median = sorted_values[n // 2]

            aggregated.by_decompiler[dec_name][metric_name] = agg

    aggregated.total_binaries = binary_count
    aggregated.total_functions = function_count // max(len(decompilers_seen), 1)
    aggregated.decompilers = sorted(decompilers_seen)
    aggregated.metrics = sorted(metrics_seen)

    return aggregated
