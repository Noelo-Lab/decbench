"""Result aggregation for scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from decbench.models.metrics import (
    AggregationType,
    CategoryScore,
    MetricCategory,
    MetricResult,
)
from decbench.metrics.categories import CATEGORY_CONFIGS
from decbench.metrics.registry import MetricRegistry

if TYPE_CHECKING:
    from decbench.models.project import OptimizationLevel


@dataclass
class AggregatedMetric:
    """Aggregated values for a single metric across all functions."""

    metric_name: str
    decompiler_name: str

    # Aggregated values
    total: float = 0.0
    mean: float = 0.0
    median: float = 0.0
    min_value: float = float("inf")
    max_value: float = float("-inf")

    # Perfect match statistics
    perfect_count: int = 0
    total_count: int = 0

    @property
    def perfect_percentage(self) -> float:
        if self.total_count == 0:
            return 0.0
        return (self.perfect_count / self.total_count) * 100


@dataclass
class AggregatedResults:
    """Fully aggregated results ready for scoreboard generation."""

    # Aggregated by decompiler and metric
    # decompiler -> metric -> AggregatedMetric
    by_decompiler: dict[str, dict[str, AggregatedMetric]] = field(default_factory=dict)

    # Statistics
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
    """Aggregate evaluation results across all projects and binaries.

    Args:
        evaluation_results: Nested dict from evaluate_projects
            project -> opt -> binary -> decompiler -> metric -> MetricResult

    Returns:
        AggregatedResults ready for scoreboard
    """
    aggregated = AggregatedResults()

    # Collect all values by decompiler and metric
    # decompiler -> metric -> list of (value, is_perfect)
    all_values: dict[str, dict[str, list[tuple[float, bool]]]] = {}

    decompilers_seen = set()
    metrics_seen = set()
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

                    for metric_name, result in metric_results.items():
                        metrics_seen.add(metric_name)

                        if metric_name not in all_values[dec_name]:
                            all_values[dec_name][metric_name] = []

                        # Get perfect value for this metric
                        try:
                            metric = MetricRegistry.get(metric_name)
                            perfect_value = metric.perfect_value
                        except KeyError:
                            perfect_value = 0.0

                        # Add all function values
                        for func_name, value in result.function_results.items():
                            is_perfect = value.value == perfect_value
                            all_values[dec_name][metric_name].append(
                                (value.value, is_perfect)
                            )
                            function_count += 1

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

            # Compute median
            sorted_values = sorted(raw_values)
            n = len(sorted_values)
            if n % 2 == 0:
                agg.median = (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2
            else:
                agg.median = sorted_values[n // 2]

            aggregated.by_decompiler[dec_name][metric_name] = agg

    aggregated.total_binaries = binary_count
    # Avoid double-counting
    aggregated.total_functions = (
        function_count // max(len(decompilers_seen), 1)
    )
    aggregated.decompilers = sorted(decompilers_seen)
    aggregated.metrics = sorted(metrics_seen)

    return aggregated


def compute_category_score(
    aggregated: AggregatedResults,
    decompiler: str,
    category: MetricCategory,
) -> CategoryScore:
    """Compute the category score for a decompiler.

    Args:
        aggregated: Aggregated results
        decompiler: Decompiler name
        category: Category to score

    Returns:
        CategoryScore for this decompiler and category
    """
    config = CATEGORY_CONFIGS.get(category)
    if config is None:
        return CategoryScore(category=category, decompiler_name=decompiler)

    dec_results = aggregated.by_decompiler.get(decompiler, {})

    metric_scores = {}
    metric_weights = {}

    for metric_config in config.metrics:
        metric_name = metric_config.name

        if metric_name not in dec_results:
            continue

        agg_metric = dec_results[metric_name]

        # Get the appropriate aggregated value based on config
        if metric_config.aggregation == AggregationType.PERCENT:
            score = agg_metric.perfect_percentage
        elif metric_config.aggregation == AggregationType.MEAN:
            score = agg_metric.mean
        elif metric_config.aggregation == AggregationType.SUM:
            score = agg_metric.total
        elif metric_config.aggregation == AggregationType.MEDIAN:
            score = agg_metric.median
        else:
            score = agg_metric.mean

        # Invert if lower is better (to make higher score always better)
        try:
            metric = MetricRegistry.get(metric_name)
            if metric.lower_is_better:
                # For "lower is better" metrics, we need to transform
                # Use 100 - score for percentage-based
                # For raw values, normalization is more complex
                if metric_config.aggregation == AggregationType.PERCENT:
                    pass  # Perfect percentage is already "higher is better"
                else:
                    # Normalize: lower values become higher scores
                    # This is a simple approach; could be improved
                    score = -score
        except KeyError:
            pass

        metric_scores[metric_name] = score
        metric_weights[metric_name] = metric_config.weight

    # Build category score
    cat_score = CategoryScore(
        category=category,
        decompiler_name=decompiler,
        metric_scores=metric_scores,
        metric_weights=metric_weights,
    )

    cat_score.compute_weighted_score()

    # Set headline metric
    headline_metric = config.get_headline_metric()
    if headline_metric and headline_metric in dec_results:
        agg = dec_results[headline_metric]
        cat_score.headline_metric = headline_metric

        # Get appropriate value for headline
        headline_config = next(
            (m for m in config.metrics if m.name == headline_metric), None
        )
        if headline_config:
            if headline_config.aggregation == AggregationType.PERCENT:
                cat_score.headline_value = agg.perfect_percentage
                cat_score.headline_display = f"{agg.perfect_percentage:.1f}%"
            elif headline_config.aggregation == AggregationType.MEAN:
                cat_score.headline_value = agg.mean
                cat_score.headline_display = f"{agg.mean:.1f}"
            else:
                cat_score.headline_value = agg.total
                cat_score.headline_display = f"{agg.total:.0f}"

    return cat_score
