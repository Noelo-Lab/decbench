"""Graph Edit Distance metric for structural correctness."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import register_metric
from decbench.models.metrics import AggregationType, MetricValue

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import FunctionDecompilation


# Exact GED is super-polynomial; a handful of huge optimized CFGs can dominate a
# whole benchmark run. Above this node count we fall back to a cheap structural
# distance so the run stays bounded. Tunable via DECBENCH_GED_MAX_NODES.
GED_MAX_NODES = int(os.environ.get("DECBENCH_GED_MAX_NODES") or "60")


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
                    "cfgutils is required for GED metric. " "Install with: pip install cfgutils"
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

        # GED is a pure function of the two CFG structures (node/edge sets) and
        # the oversize threshold. Key on their canonical, sorted shapes so the
        # super-polynomial computation is never repeated for identical graphs.
        key_inputs = [
            sorted(str(n) for n in source_cfg.nodes()),
            sorted((str(u), str(v)) for u, v in source_cfg.edges()),
            sorted(str(n) for n in decompiled_cfg.nodes()),
            sorted((str(u), str(v)) for u, v in decompiled_cfg.edges()),
            GED_MAX_NODES,
        ]
        return self._cached_value(
            key_inputs,
            lambda: self._compute_uncached(source_cfg, decompiled_cfg),
        )

    def _compute_uncached(
        self,
        source_cfg: DiGraph,
        decompiled_cfg: DiGraph,
    ) -> MetricValue:
        s_nodes = source_cfg.number_of_nodes()
        d_nodes = decompiled_cfg.number_of_nodes()
        source_size = s_nodes + source_cfg.number_of_edges()
        decomp_size = d_nodes + decompiled_cfg.number_of_edges()
        base_meta = {
            "source_nodes": s_nodes,
            "source_edges": source_cfg.number_of_edges(),
            "source_size": source_size,
            "decompiled_nodes": d_nodes,
            "decompiled_edges": decompiled_cfg.number_of_edges(),
            "decompiled_size": decomp_size,
        }

        # Cheap structural fallback for oversized graphs: exact GED is too slow
        # and these are rarely a perfect match anyway. The size delta is a sound
        # lower bound on the true edit distance, so a 0 here is still a genuine
        # structural match.
        if s_nodes > GED_MAX_NODES or d_nodes > GED_MAX_NODES:
            approx = float(
                abs(s_nodes - d_nodes)
                + abs(source_cfg.number_of_edges() - decompiled_cfg.number_of_edges())
            )
            return MetricValue(
                value=approx,
                raw_value=approx,
                metadata={**base_meta, "approximated": True},
            )

        vj_ged = self._get_vj_ged()
        try:
            ged_value = vj_ged(source_cfg, decompiled_cfg)
            return MetricValue(
                value=float(ged_value),
                raw_value=ged_value,
                metadata=base_meta,
            )
        except Exception as e:
            return MetricValue(
                value=float("inf"),
                metadata={**base_meta, "error": str(e)},
            )
