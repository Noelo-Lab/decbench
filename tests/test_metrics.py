"""Tests for metrics system."""

import pytest

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import MetricRegistry, register_metric
from decbench.models.metrics import MetricCategory, MetricValue
from decbench.models.decompilation import FunctionDecompilation


class TestMetricRegistry:
    """Tests for the metric registry."""

    def setup_method(self):
        """Clear registry before each test."""
        MetricRegistry.clear()

    def test_register_metric(self):
        """Test registering a metric."""
        @register_metric("test_metric")
        class TestMetric(Metric):
            name = "test_metric"
            category = MetricCategory.SIMPLE

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        assert "test_metric" in MetricRegistry.list_registered()

    def test_get_metric(self):
        """Test getting a registered metric."""
        @register_metric("get_test")
        class GetTestMetric(Metric):
            name = "get_test"
            category = MetricCategory.FAITHFUL

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        metric = MetricRegistry.get("get_test")
        assert metric.name == "get_test"

    def test_get_unknown_metric(self):
        """Test getting an unregistered metric."""
        with pytest.raises(KeyError):
            MetricRegistry.get("nonexistent")

    def test_get_by_category(self):
        """Test getting metrics by category."""
        @register_metric("faithful1")
        class Faithful1(Metric):
            name = "faithful1"
            category = MetricCategory.FAITHFUL

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        @register_metric("simple1")
        class Simple1(Metric):
            name = "simple1"
            category = MetricCategory.SIMPLE

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        faithful = MetricRegistry.get_by_category(MetricCategory.FAITHFUL)
        assert "faithful1" in faithful
        assert "simple1" not in faithful


class TestBuiltinMetrics:
    """Tests for built-in metrics."""

    def test_loc_metric(self):
        """Test lines of code metric."""
        # Import to register
        from decbench.metrics.simple.loc import LOCMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int main() {\n    return 0;\n}\n",
        )

        metric = LOCMetric()
        result = metric.compute_for_function(func)

        # 3 non-empty lines
        assert result.value == 3.0

    def test_goto_metric(self):
        """Test goto count metric."""
        from decbench.metrics.simple.loc import GotoMetric

        func_no_goto = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int main() { return 0; }",
        )

        func_with_goto = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int main() { goto label; label: return 0; }",
        )

        metric = GotoMetric()

        result1 = metric.compute_for_function(func_no_goto)
        assert result1.value == 0.0

        result2 = metric.compute_for_function(func_with_goto)
        assert result2.value == 1.0

    def test_bool_ops_metric(self):
        """Test boolean operations metric."""
        from decbench.metrics.simple.loc import BooleanOperationsMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="if (a && b || c && d) return 1;",
        )

        metric = BooleanOperationsMetric()
        result = metric.compute_for_function(func)

        # 2 && and 1 ||
        assert result.value == 3.0


class TestMetricConfig:
    """Tests for metric configuration."""

    def test_default_config(self):
        """Test default metric configuration."""
        config = MetricConfig()
        assert config.function_timeout_seconds == 60.0
        assert config.use_cache is True

    def test_custom_config(self):
        """Test custom metric configuration."""
        config = MetricConfig(
            function_timeout_seconds=30.0,
            extra_options={"custom_opt": "value"},
        )
        assert config.function_timeout_seconds == 30.0
        assert config.extra_options["custom_opt"] == "value"
