"""Category configurations for metrics."""

from __future__ import annotations

from pydantic import BaseModel, Field

from decbench.models.metrics import AggregationType, MetricCategory


class MetricWeightConfig(BaseModel):
    """Weight configuration for a metric within a category."""

    name: str = Field(..., description="Metric name")
    weight: float = Field(default=1.0, description="Weight for scoring")
    headline: bool = Field(
        default=False,
        description="Whether this is the headline metric for the category",
    )
    aggregation: AggregationType = Field(
        default=AggregationType.MEAN,
        description="Aggregation method for display",
    )


class CategoryConfig(BaseModel):
    """Configuration for a scoring category."""

    category: MetricCategory = Field(..., description="The category")
    display_name: str = Field(..., description="Display name")
    description: str = Field(default="", description="Category description")

    # Metric configuration
    metrics: list[MetricWeightConfig] = Field(
        default_factory=list,
        description="Metrics in this category with their weights",
    )

    # Display configuration
    headline_format: str = Field(
        default="{value:.1f}%",
        description="Format string for headline display",
    )
    higher_is_better: bool = Field(
        default=True,
        description="Whether higher scores are better for this category",
    )

    def get_headline_metric(self) -> str | None:
        """Get the headline metric name."""
        for m in self.metrics:
            if m.headline:
                return m.name
        return self.metrics[0].name if self.metrics else None

    def get_metric_weight(self, name: str) -> float:
        """Get weight for a specific metric."""
        for m in self.metrics:
            if m.name == name:
                return m.weight
        return 0.0


# Default category configurations
CATEGORY_CONFIGS: dict[MetricCategory, CategoryConfig] = {
    MetricCategory.FAITHFUL: CategoryConfig(
        category=MetricCategory.FAITHFUL,
        display_name="Faithful",
        description="How well the decompilation matches the source CFG structure",
        metrics=[
            MetricWeightConfig(
                name="ged",
                weight=1.0,
                headline=True,
                aggregation=AggregationType.PERCENT,  # % of perfect matches
            ),
            MetricWeightConfig(
                name="ged_normalized",
                weight=0.5,
                aggregation=AggregationType.MEAN,
            ),
        ],
        headline_format="{value:.1f}%",  # "72.3%" for percentage of GED==0
        higher_is_better=True,
    ),
    MetricCategory.SIMPLE: CategoryConfig(
        category=MetricCategory.SIMPLE,
        display_name="Simple",
        description="How readable and simple the decompiled code is",
        metrics=[
            MetricWeightConfig(
                name="loc",
                weight=1.0,
                headline=True,
                aggregation=AggregationType.MEAN,
            ),
            MetricWeightConfig(
                name="gotos",
                weight=0.8,
                aggregation=AggregationType.SUM,
            ),
            MetricWeightConfig(
                name="cyclomatic_complexity",
                weight=0.5,
                aggregation=AggregationType.MEAN,
            ),
        ],
        headline_format="{value:.0f} avg LOC",
        higher_is_better=False,  # Lower is better for simplicity
    ),
    MetricCategory.CORRECT: CategoryConfig(
        category=MetricCategory.CORRECT,
        display_name="Correct",
        description="How semantically correct the decompiled code is",
        metrics=[
            MetricWeightConfig(
                name="byte_match",
                weight=1.0,
                headline=True,
                aggregation=AggregationType.PERCENT,
            ),
        ],
        headline_format="{value:.1f}%",
        higher_is_better=True,
    ),
}


def get_category_metrics(category: MetricCategory) -> list[str]:
    """Get list of metric names for a category.

    Args:
        category: The metric category

    Returns:
        List of metric names
    """
    config = CATEGORY_CONFIGS.get(category)
    if config is None:
        return []
    return [m.name for m in config.metrics]


def get_all_metric_names() -> list[str]:
    """Get all metric names across all categories."""
    names = []
    for config in CATEGORY_CONFIGS.values():
        names.extend(m.name for m in config.metrics)
    return names
