"""Tests for metrics system."""

import pytest

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import MetricRegistry, register_metric
from decbench.models.metrics import MetricValue
from decbench.models.decompilation import FunctionDecompilation


class TestMetricRegistry:
    """Tests for the metric registry."""

    def setup_method(self) -> None:
        MetricRegistry.clear()

    def test_register_metric(self) -> None:
        @register_metric("test_metric")
        class TestMetric(Metric):
            name = "test_metric"

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        assert "test_metric" in MetricRegistry.list_registered()

    def test_get_metric(self) -> None:
        @register_metric("get_test")
        class GetTestMetric(Metric):
            name = "get_test"

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        metric = MetricRegistry.get("get_test")
        assert metric.name == "get_test"

    def test_get_unknown_metric(self) -> None:
        with pytest.raises(KeyError):
            MetricRegistry.get("nonexistent")

    def test_get_all(self) -> None:
        @register_metric("m1")
        class M1(Metric):
            name = "m1"

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        @register_metric("m2")
        class M2(Metric):
            name = "m2"

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        all_metrics = MetricRegistry.get_all()
        assert "m1" in all_metrics
        assert "m2" in all_metrics


class TestGEDMetric:
    """Tests for the GED metric."""

    def test_ged_metric_registration(self) -> None:
        MetricRegistry.clear()
        from decbench.metrics.ged import GEDMetric

        MetricRegistry.register("ged", GEDMetric)
        metric = MetricRegistry.get("ged")
        assert metric.name == "ged"
        assert metric.requires_source_cfg is True
        assert metric.requires_decompiled_cfg is True

    def test_ged_missing_cfg(self) -> None:
        from decbench.metrics.ged import GEDMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int test() { return 0; }",
        )

        metric = GEDMetric()
        result = metric.compute_for_function(func, source_cfg=None, decompiled_cfg=None)
        assert result.value == float("inf")

    def test_ged_identical_cfgs(self) -> None:
        """GED of identical graphs should be 0."""
        pytest.importorskip("cfgutils")
        from decbench.metrics.ged import GEDMetric
        import networkx as nx

        # cfgutils expects nodes with is_entrypoint attribute
        class CFGNode:
            def __init__(self, addr: int, is_entry: bool = False, is_exit: bool = False):
                self.addr = addr
                self.is_entrypoint = is_entry
                self.is_exitpoint = is_exit

            def __hash__(self) -> int:
                return hash(self.addr)

            def __eq__(self, other: object) -> bool:
                return isinstance(other, CFGNode) and self.addr == other.addr

        n0 = CFGNode(0, is_entry=True)
        n1 = CFGNode(1)
        n2 = CFGNode(2, is_exit=True)

        g = nx.DiGraph()
        g.add_edges_from([(n0, n1), (n1, n2)])

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int test() { return 0; }",
        )

        metric = GEDMetric()
        result = metric.compute_for_function(func, source_cfg=g, decompiled_cfg=g)
        assert result.value == 0.0


class TestTypeMatchMetric:
    """Tests for the type match metric."""

    def test_type_match_registration(self) -> None:
        MetricRegistry.clear()
        from decbench.metrics.type_match import TypeMatchMetric

        MetricRegistry.register("type_match", TypeMatchMetric)
        metric = MetricRegistry.get("type_match")
        assert metric.name == "type_match"
        assert metric.perfect_value == 1.0

    def test_type_normalization(self) -> None:
        from decbench.metrics.type_match import normalize_type

        forms = normalize_type("unsigned int")
        assert "int" in forms

        forms = normalize_type("__int64")
        assert "long long" in forms

        forms = normalize_type("_DWORD")
        assert "int" in forms

    def test_type_match_with_matching_types(self) -> None:
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int x;\nchar y;\nlong long z;\n",
        )

        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
            {"name": "y", "type": ["char"], "rbp_offset": [-5], "size": 1},
            {"name": "z", "type": ["long long"], "rbp_offset": [-16], "size": 8},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 1.0
        assert result.metadata["tp"] == 3

    def test_type_match_with_mismatched_types(self) -> None:
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int x;\nint y;\n",
        )

        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
            {"name": "y", "type": ["char"], "rbp_offset": [-5], "size": 1},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        # x matches, y doesn't
        assert result.value == pytest.approx(0.5)

    def test_type_match_no_ground_truth(self) -> None:
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int x;\n",
        )

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=None)
        assert result.value == 0.0

    def test_extract_types_from_code(self) -> None:
        from decbench.metrics.type_match import extract_types_from_decompiled_code

        code = """
int main() {
    int x;
    char *ptr;
    long long counter;
    return 0;
}
"""
        vars = extract_types_from_decompiled_code(code)
        names = [v["name"] for v in vars]
        assert "x" in names
        assert "counter" in names


class TestByteMatchMetric:
    """Tests for the byte match metric."""

    def test_byte_match_registration(self) -> None:
        MetricRegistry.clear()
        from decbench.metrics.byte_match import ByteMatchMetric

        MetricRegistry.register("byte_match", ByteMatchMetric)
        metric = MetricRegistry.get("byte_match")
        assert metric.name == "byte_match"
        assert metric.perfect_value == 1.0

    def test_byte_match_no_binary(self) -> None:
        from decbench.metrics.byte_match import ByteMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int test() { return 0; }",
        )

        metric = ByteMatchMetric()
        result = metric.compute_for_function(func)
        assert result.value == 0.0
        assert "error" in result.metadata

    def test_jaccard_similarity(self) -> None:
        from decbench.metrics.byte_match import _compute_jaccard_similarity

        # Identical
        lines = ["mov rax, rbx", "add rax, 1", "ret"]
        sim = _compute_jaccard_similarity(lines, lines)
        assert sim == 1.0

        # Completely different
        lines_a = ["mov rax, rbx", "ret"]
        lines_b = ["push rbp", "pop rbp"]
        sim = _compute_jaccard_similarity(lines_a, lines_b)
        assert sim == 0.0

        # Empty
        sim = _compute_jaccard_similarity([], [])
        assert sim == 1.0


class TestMetricConfig:
    """Tests for metric configuration."""

    def test_default_config(self) -> None:
        config = MetricConfig()
        assert config.function_timeout_seconds == 60.0
        assert config.use_cache is True

    def test_custom_config(self) -> None:
        config = MetricConfig(
            function_timeout_seconds=30.0,
            extra_options={"custom_opt": "value"},
        )
        assert config.function_timeout_seconds == 30.0
        assert config.extra_options["custom_opt"] == "value"
