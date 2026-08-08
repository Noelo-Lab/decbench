"""Accelerated VJ graph edit distance."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from networkx import DiGraph


def _node_role(node: object) -> tuple[bool, bool]:
    return (
        bool(getattr(node, "is_entrypoint", False)),
        bool(getattr(node, "is_exitpoint", False)),
    )


def vj_ged(source_cfg: DiGraph, decompiled_cfg: DiGraph) -> float:
    """Compute cfgutils' VJ-GED cost with a compiled assignment solver."""
    import numpy as np
    from cfgutils.similarity.ged import INVALID_CHOICE_PENALTY
    from scipy.optimize import linear_sum_assignment

    source_nodes = list(source_cfg.nodes)
    decompiled_nodes = list(decompiled_cfg.nodes)
    source_roles = [_node_role(node) for node in source_nodes]
    decompiled_roles = [_node_role(node) for node in decompiled_nodes]
    source_count = len(source_nodes)
    decompiled_count = len(decompiled_nodes)
    matrix_size = source_count + decompiled_count
    cost_matrix = np.zeros((matrix_size, matrix_size), dtype=float)

    cost_matrix[source_count:, :decompiled_count] = np.inf
    cost_matrix[:source_count, decompiled_count:] = np.inf

    for index, node in enumerate(decompiled_nodes):
        cost_matrix[source_count + index, index] = (
            1 + decompiled_cfg.in_degree(node) + decompiled_cfg.out_degree(node)
        )
    for index, node in enumerate(source_nodes):
        cost_matrix[index, decompiled_count + index] = (
            1 + source_cfg.in_degree(node) + source_cfg.out_degree(node)
        )

    for source_index, source_node in enumerate(source_nodes):
        for decompiled_index, decompiled_node in enumerate(decompiled_nodes):
            cost = abs(
                source_cfg.out_degree(source_node) - decompiled_cfg.out_degree(decompiled_node)
            )
            cost += abs(
                source_cfg.in_degree(source_node) - decompiled_cfg.in_degree(decompiled_node)
            )
            if source_roles[source_index] != decompiled_roles[decompiled_index]:
                cost += INVALID_CHOICE_PENALTY
            cost_matrix[source_index, decompiled_index] = cost

    row_indices, column_indices = linear_sum_assignment(cost_matrix)
    return float(cost_matrix[row_indices, column_indices].sum())
