"""Metrics system for DecBench."""

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import MetricRegistry, register_metric

# Import metric modules so @register_metric decorators run
try:
    from decbench.metrics import ged  # noqa: F401
except ImportError:
    pass

try:
    from decbench.metrics import type_match  # noqa: F401
except ImportError:
    pass

try:
    from decbench.metrics import byte_match  # noqa: F401
except ImportError:
    pass

__all__ = [
    "Metric",
    "MetricConfig",
    "MetricRegistry",
    "register_metric",
]
