"""Graph Edit Distance metric for structural correctness."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import register_metric
from decbench.models.metrics import AggregationType, MetricValue

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import FunctionDecompilation


@register_metric("ged")
class GEDMetric(Metric):
    """Graph Edit Distance metric.

    Computes the edit distance between source and decompiled CFGs.
    A GED of 0 indicates a perfect structural match.
    """

    name = "ged"
    display_name = "Structural Correctness (GED)"
    description = "CFG edit distance between source and decompiled code"

    weight = 1.0
    lower_is_better = True
    perfect_value = 0.0
    default_aggregation = AggregationType.PERCENT

    requires_source_cfg = True
    requires_decompiled_cfg = True

    def __init__(self, config: MetricConfig | None = None):
        super().__init__(config)
        self._vj_ged = None

    def _get_vj_ged(self):  # type: ignore
        if self._vj_ged is None:
            try:
                from cfgutils.similarity import vj_ged
                self._vj_ged = vj_ged
            except ImportError:
                raise ImportError(
                    "cfgutils is required for GED metric. "
                    "Install with: pip install cfgutils"
                )
        return self._vj_ged

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        **kwargs: Any,
    ) -> MetricValue:
        if source_cfg is None or decompiled_cfg is None:
            return MetricValue(
                value=float("inf"),
                metadata={"error": "Missing CFG"},
            )

        vj_ged = self._get_vj_ged()

        try:
            ged_value = vj_ged(source_cfg, decompiled_cfg)

            source_size = source_cfg.number_of_nodes() + source_cfg.number_of_edges()
            decomp_size = decompiled_cfg.number_of_nodes() + decompiled_cfg.number_of_edges()

            return MetricValue(
                value=float(ged_value),
                raw_value=ged_value,
                metadata={
                    "source_nodes": source_cfg.number_of_nodes(),
                    "source_edges": source_cfg.number_of_edges(),
                    "source_size": source_size,
                    "decompiled_nodes": decompiled_cfg.number_of_nodes(),
                    "decompiled_edges": decompiled_cfg.number_of_edges(),
                    "decompiled_size": decomp_size,
                },
            )

        except Exception as e:
            return MetricValue(
                value=float("inf"),
                metadata={"error": str(e)},
            )
