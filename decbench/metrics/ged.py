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


# VJ-GED becomes expensive on large cost matrices, so non-isomorphic graphs above
# this node count fall back to a cheap structural distance.
GED_MAX_NODES = int(os.environ.get("DECBENCH_GED_MAX_NODES") or "200")


def _node_role(node: Any) -> tuple[bool, bool]:
    return (
        bool(getattr(node, "is_entrypoint", False)),
        bool(getattr(node, "is_exitpoint", False)),
    )


def _role_graph(cfg: DiGraph) -> DiGraph:
    import networkx as nx

    graph = nx.DiGraph()
    graph.add_nodes_from((node, {"role": _node_role(node)}) for node in cfg.nodes())
    graph.add_edges_from(cfg.edges())
    return graph


def _add_joint_refinement_colors(
    source_graph: DiGraph,
    decompiled_graph: DiGraph,
    *,
    rounds: int = 8,
) -> None:
    graphs = (source_graph, decompiled_graph)
    colors: list[dict[Any, int]] = [{}, {}]

    def assign(signatures: list[dict[Any, tuple[Any, ...]]]) -> list[dict[Any, int]]:
        palette: dict[tuple[Any, ...], int] = {}
        assigned: list[dict[Any, int]] = [{}, {}]
        for graph_index, graph in enumerate(graphs):
            for node in graph.nodes():
                signature = signatures[graph_index][node]
                assigned[graph_index][node] = palette.setdefault(
                    signature,
                    len(palette),
                )
        return assigned

    initial = [
        {
            node: (
                graph.nodes[node]["role"],
                graph.in_degree(node),
                graph.out_degree(node),
            )
            for node in graph.nodes()
        }
        for graph in graphs
    ]
    colors = assign(initial)

    for _ in range(rounds):
        refined = [
            {
                node: (
                    colors[graph_index][node],
                    tuple(
                        sorted(
                            colors[graph_index][predecessor]
                            for predecessor in graph.predecessors(node)
                        )
                    ),
                    tuple(
                        sorted(
                            colors[graph_index][successor] for successor in graph.successors(node)
                        )
                    ),
                )
                for node in graph.nodes()
            }
            for graph_index, graph in enumerate(graphs)
        ]
        new_colors = assign(refined)
        if all(
            len(set(new_colors[index].values())) == len(set(colors[index].values()))
            for index in range(2)
        ):
            colors = new_colors
            break
        colors = new_colors

    for graph_index, graph in enumerate(graphs):
        for node, color in colors[graph_index].items():
            graph.nodes[node]["iso_color"] = color


def _is_isomorphic(source_cfg: DiGraph, decompiled_cfg: DiGraph) -> bool:
    import networkx as nx

    source_graph = _role_graph(source_cfg)
    decompiled_graph = _role_graph(decompiled_cfg)
    _add_joint_refinement_colors(source_graph, decompiled_graph)
    node_match = nx.algorithms.isomorphism.categorical_node_match(
        ("role", "iso_color"),
        ((False, False), -1),
    )
    return bool(
        nx.is_isomorphic(
            source_graph,
            decompiled_graph,
            node_match=node_match,
        )
    )


def _graph_cache_input(cfg: DiGraph) -> dict[str, list[Any]]:
    nodes = list(cfg.nodes())
    node_ids = {node: index for index, node in enumerate(nodes)}
    return {
        "roles": [_node_role(node) for node in nodes],
        "edges": sorted((node_ids[src], node_ids[dst]) for src, dst in cfg.edges()),
    }


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

    cache_version = "3"

    def __init__(self, config: MetricConfig | None = None):
        super().__init__(config)
        self._vj_ged = None

    def _get_vj_ged(self):  # type: ignore
        if self._vj_ged is None:
            try:
                from decbench.metrics.vj_ged import vj_ged

                self._vj_ged = vj_ged
            except ImportError as e:
                raise ImportError(
                    "cfgutils and scipy are required for GED metric. "
                    "Install with: pip install cfgutils scipy"
                ) from e
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

        # A degenerate source CFG has no structure to compare against, so return
        # non-finite and let the recording layer drop it from GED's denominator rather
        # than count it as a per-decompiler failure. Checked BEFORE the cache so entries
        # recorded under the old (rewarding) semantics are never served.
        from decbench.utils.cfg import is_degenerate_source_cfg

        s_nodes = source_cfg.number_of_nodes()
        if is_degenerate_source_cfg(source_cfg):
            return MetricValue(
                value=float("inf"),
                metadata={
                    "error": f"degenerate source CFG (source_nodes={s_nodes})",
                    "source_nodes": s_nodes,
                    "decompiled_nodes": decompiled_cfg.number_of_nodes(),
                },
            )

        key_inputs = [
            _graph_cache_input(source_cfg),
            _graph_cache_input(decompiled_cfg),
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

        if _is_isomorphic(source_cfg, decompiled_cfg):
            return MetricValue(
                value=0.0,
                raw_value=0.0,
                metadata={**base_meta, "method": "isomorphism", "isomorphic": True},
            )

        if s_nodes > GED_MAX_NODES or d_nodes > GED_MAX_NODES:
            approx = max(
                1.0,
                float(
                    abs(s_nodes - d_nodes)
                    + abs(source_cfg.number_of_edges() - decompiled_cfg.number_of_edges())
                ),
            )
            return MetricValue(
                value=approx,
                raw_value=approx,
                metadata={
                    **base_meta,
                    "method": "size_lower_bound",
                    "isomorphic": False,
                    "approximated": True,
                },
            )

        vj_ged = self._get_vj_ged()
        try:
            raw_ged = float(vj_ged(source_cfg, decompiled_cfg))
            ged_value = max(1.0, raw_ged)
            metadata = {
                **base_meta,
                "method": "vj_ged",
                "isomorphic": False,
            }
            if raw_ged != ged_value:
                metadata["vj_ged_raw"] = raw_ged
            return MetricValue(
                value=ged_value,
                raw_value=raw_ged,
                metadata=metadata,
            )
        except Exception as e:
            return MetricValue(
                value=float("inf"),
                metadata={**base_meta, "error": str(e)},
            )
