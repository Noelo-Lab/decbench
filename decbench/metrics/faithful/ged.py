"""Graph Edit Distance metric for CFG similarity."""

from __future__ import annotations

from typing import TYPE_CHECKING

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import register_metric
from decbench.models.metrics import AggregationType, MetricCategory, MetricValue

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import FunctionDecompilation


@register_metric("ged")
class GEDMetric(Metric):
    """Graph Edit Distance metric.

    Computes the edit distance between source and decompiled CFGs
    using the cfgutils library.

    A GED of 0 indicates a perfect structural match.
    """

    name = "ged"
    display_name = "Graph Edit Distance"
    description = "CFG edit distance between source and decompiled code"
    category = MetricCategory.FAITHFUL

    weight = 1.0
    lower_is_better = True
    perfect_value = 0.0
    default_aggregation = AggregationType.PERCENT  # % with GED == 0

    requires_source_cfg = True
    requires_decompiled_cfg = True

    def __init__(self, config: MetricConfig | None = None):
        super().__init__(config)
        self._vj_ged = None

    def _get_vj_ged(self):  # type: ignore
        """Lazy load cfgutils similarity function."""
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
        **kwargs,
    ) -> MetricValue:
        """Compute GED for a single function.

        Args:
            decompiled: The decompiled function
            source_cfg: CFG from source code
            decompiled_cfg: CFG from decompiled code

        Returns:
            MetricValue with the GED value
        """
        if source_cfg is None or decompiled_cfg is None:
            return MetricValue(
                value=float("inf"),
                metadata={"error": "Missing CFG"},
            )

        vj_ged = self._get_vj_ged()

        try:
            # Compute GED
            ged_value = vj_ged(source_cfg, decompiled_cfg)

            # Compute graph sizes for context
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


@register_metric("ged_normalized")
class NormalizedGEDMetric(GEDMetric):
    """Normalized Graph Edit Distance metric.

    GED normalized by the maximum possible graph size,
    giving a value between 0 and 1.
    """

    name = "ged_normalized"
    display_name = "Normalized GED"
    description = "GED normalized by graph size"
    category = MetricCategory.FAITHFUL

    weight = 0.5
    lower_is_better = True
    perfect_value = 0.0
    default_aggregation = AggregationType.MEAN

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        **kwargs,
    ) -> MetricValue:
        """Compute normalized GED."""
        # Get raw GED first
        raw_result = super().compute_for_function(
            decompiled, source_cfg, decompiled_cfg, **kwargs
        )

        if raw_result.value == float("inf"):
            return raw_result

        # Normalize by max graph size
        source_size = raw_result.metadata.get("source_size", 0)
        decomp_size = raw_result.metadata.get("decompiled_size", 0)
        max_size = max(source_size, decomp_size)

        if max_size == 0:
            normalized = 0.0
        else:
            normalized = raw_result.value / max_size

        return MetricValue(
            value=normalized,
            raw_value=raw_result.value,
            metadata={
                **raw_result.metadata,
                "max_size": max_size,
            },
        )
