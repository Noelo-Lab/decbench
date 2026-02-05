"""Metric plugin registry."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, TypeVar

from decbench.models.metrics import MetricCategory

if TYPE_CHECKING:
    from decbench.metrics.base import Metric, MetricConfig

T = TypeVar("T", bound="Metric")


class MetricRegistry:
    """Registry for metric plugins.

    This is a singleton that manages all registered metrics.

    Usage:
        # Get the registry
        registry = MetricRegistry()

        # List available metrics
        for name in registry.list_registered():
            print(name)

        # Get a specific metric
        ged = registry.get("ged")

        # Get all metrics for a category
        faithful_metrics = registry.get_by_category(MetricCategory.FAITHFUL)
    """

    _instance: MetricRegistry | None = None
    _metrics: dict[str, type[Metric]] = {}

    def __new__(cls) -> MetricRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def register(cls, name: str, metric_class: type[Metric]) -> None:
        """Register a metric class.

        Args:
            name: Unique identifier for the metric
            metric_class: The metric class to register
        """
        cls._metrics[name] = metric_class

    @classmethod
    def get(
        cls,
        name: str,
        config: MetricConfig | None = None,
    ) -> Metric:
        """Get an instance of a registered metric.

        Args:
            name: Name of the metric
            config: Optional configuration

        Returns:
            Metric instance

        Raises:
            KeyError: If metric is not registered
        """
        if name not in cls._metrics:
            available = ", ".join(cls._metrics.keys())
            raise KeyError(f"Metric '{name}' not found. Available: {available}")

        return cls._metrics[name](config)

    @classmethod
    def list_registered(cls) -> list[str]:
        """List all registered metric names."""
        return list(cls._metrics.keys())

    @classmethod
    def get_by_category(
        cls,
        category: MetricCategory,
        config: MetricConfig | None = None,
    ) -> dict[str, Metric]:
        """Get all metrics for a specific category.

        Args:
            category: The metric category
            config: Optional configuration

        Returns:
            Dictionary mapping names to metric instances
        """
        result = {}
        for name, metric_class in cls._metrics.items():
            if metric_class.category == category:
                result[name] = metric_class(config)
        return result

    @classmethod
    def get_all(
        cls,
        names: list[str] | None = None,
        config: MetricConfig | None = None,
    ) -> dict[str, Metric]:
        """Get multiple metric instances.

        Args:
            names: List of metric names, or None for all
            config: Optional configuration

        Returns:
            Dictionary mapping names to metric instances
        """
        if names is None:
            names = cls.list_registered()

        return {name: cls.get(name, config) for name in names if name in cls._metrics}

    @classmethod
    def get_categories(cls) -> dict[MetricCategory, list[str]]:
        """Get all metrics organized by category.

        Returns:
            Dictionary mapping categories to lists of metric names
        """
        result: dict[MetricCategory, list[str]] = {cat: [] for cat in MetricCategory}
        for name, metric_class in cls._metrics.items():
            result[metric_class.category].append(name)
        return result

    @classmethod
    def clear(cls) -> None:
        """Clear all registered metrics. Mainly for testing."""
        cls._metrics.clear()


def register_metric(name: str) -> Callable[[type[T]], type[T]]:
    """Decorator to register a metric class.

    Usage:
        @register_metric("my_metric")
        class MyMetric(Metric):
            ...

    Args:
        name: Unique identifier for the metric

    Returns:
        Decorator function
    """
    def decorator(cls: type[T]) -> type[T]:
        MetricRegistry.register(name, cls)
        return cls

    return decorator
