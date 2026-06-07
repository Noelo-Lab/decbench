"""Shared pytest fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def restore_metric_registry():
    """Keep the metric registry populated across tests.

    Some registry unit tests call ``MetricRegistry.clear()`` and re-register
    only a single metric, which would leak into later tests (the registry is
    module-global). Re-register the built-in metrics after every test so test
    outcomes do not depend on execution order.
    """
    yield

    from decbench.metrics.byte_match import ByteMatchMetric
    from decbench.metrics.ged import GEDMetric
    from decbench.metrics.registry import MetricRegistry
    from decbench.metrics.type_match import TypeMatchMetric

    for metric_cls in (GEDMetric, TypeMatchMetric, ByteMatchMetric):
        MetricRegistry.register(metric_cls.name, metric_cls)
