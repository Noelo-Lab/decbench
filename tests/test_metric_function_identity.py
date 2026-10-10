"""Metric regressions for collision-qualified function storage keys."""

from pathlib import Path

import networkx as nx

from decbench.metrics.base import Metric
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.models.metrics import MetricValue


class _CfgMetric(Metric):
    name = "cfg_identity_test"
    requires_source_cfg = True
    requires_decompiled_cfg = True

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg=None,
        decompiled_cfg=None,
        **kwargs,
    ) -> MetricValue:
        assert source_cfg is not None
        assert decompiled_cfg is not None
        return MetricValue(value=1.0)


def _function(name: str, address: int) -> FunctionDecompilation:
    return FunctionDecompilation(
        name=name,
        address=address,
        decompiled_code=f"int {name}(void) {{ return 0; }}",
    )


def _result(tmp_path: Path) -> DecompilationResult:
    result = DecompilationResult(
        binary_path=tmp_path / "fixture",
        binary_name="fixture",
        decompiler=DecompilerMetadata(decompiler_name="identity-test"),
    )
    result.add_function(_function("same", 0x1000))
    result.add_function(_function("same", 0x2000))
    return result


def _graph() -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node(0)
    return graph


def test_cfg_metric_abstains_when_only_ambiguous_plain_name_exists(tmp_path: Path) -> None:
    result = _result(tmp_path)
    metric = _CfgMetric()

    scored = metric.compute_for_binary(
        result,
        source_cfgs={"same": _graph()},
        decompiled_cfgs={"same": _graph()},
    )

    assert scored.function_results == {}


def test_cfg_metric_uses_collision_qualified_keys_when_available(tmp_path: Path) -> None:
    result = _result(tmp_path)
    metric = _CfgMetric()
    cfgs = {
        "same@0x1000": _graph(),
        "same@0x2000": _graph(),
    }

    scored = metric.compute_for_binary(result, source_cfgs=cfgs, decompiled_cfgs=cfgs)

    assert set(scored.function_results) == {"same@0x1000", "same@0x2000"}
    assert all(value.value == 1.0 for value in scored.function_results.values())


def test_cfg_metric_keeps_legacy_name_lookup_for_unique_function(tmp_path: Path) -> None:
    result = DecompilationResult(
        binary_path=tmp_path / "fixture",
        binary_name="fixture",
        decompiler=DecompilerMetadata(decompiler_name="identity-test"),
    )
    result.add_function(_function("unique", 0x3000))
    metric = _CfgMetric()

    scored = metric.compute_for_binary(
        result,
        source_cfgs={"unique": _graph()},
        decompiled_cfgs={"unique": _graph()},
    )

    assert set(scored.function_results) == {"unique"}
