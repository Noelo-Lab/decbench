"""Metric plugin registry."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from decbench.metrics.base import Metric, MetricConfig

T = TypeVar("T", bound="Metric")


class MetricRegistry:
    """Registry for metric plugins (singleton)."""

    _instance: MetricRegistry | None = None
    _metrics: dict[str, type[Metric]] = {}

    def __new__(cls) -> MetricRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def register(cls, name: str, metric_class: type[Metric]) -> None:
        cls._metrics[name] = metric_class

    @classmethod
    def get(cls, name: str, config: MetricConfig | None = None) -> Metric:
        if name not in cls._metrics:
            available = ", ".join(cls._metrics.keys())
            raise KeyError(f"Metric '{name}' not found. Available: {available}")
        return cls._metrics[name](config)

    @classmethod
    def list_registered(cls) -> list[str]:
        return list(cls._metrics.keys())

    @classmethod
    def get_all(
        cls,
        names: list[str] | None = None,
        config: MetricConfig | None = None,
    ) -> dict[str, Metric]:
        if names is None:
            names = cls.list_registered()
        return {name: cls.get(name, config) for name in names if name in cls._metrics}

    @classmethod
    def clear(cls) -> None:
        cls._metrics.clear()


def register_metric(name: str) -> Callable[[type[T]], type[T]]:
    """Decorator to register a metric class."""
    def decorator(cls: type[T]) -> type[T]:
        MetricRegistry.register(name, cls)
        return cls

    return decorator
