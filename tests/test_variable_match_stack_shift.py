from __future__ import annotations

import random

import networkx as nx
import pytest

from decbench.metrics.variable_match import VariableEvidence, _stack_shift


def _reference_stack_shift(
    source: list[VariableEvidence],
    decompiled: list[VariableEvidence],
    *,
    use_size_compatibility: bool,
) -> int | None:
    def compatible(left: VariableEvidence, right: VariableEvidence) -> bool:
        return (
            not use_size_compatibility
            or left.size is None
            or right.size is None
            or left.size == right.size
        )

    shifts = {
        source_offset - decompiled_offset
        for source_var in source
        for decompiled_var in decompiled
        if compatible(source_var, decompiled_var)
        for source_offset in source_var.stack_offsets
        for decompiled_offset in decompiled_var.stack_offsets
    }
    if not shifts:
        return None

    ranked: list[tuple[int, int]] = []
    for shift in shifts:
        graph = nx.Graph()
        for source_var in source:
            graph.add_node(("s", source_var.identity), bipartite=0)
        for decompiled_var in decompiled:
            graph.add_node(("d", decompiled_var.identity), bipartite=1)
        for source_var in source:
            for decompiled_var in decompiled:
                if not compatible(source_var, decompiled_var):
                    continue
                if any(
                    decompiled_offset + shift == source_offset
                    for source_offset in source_var.stack_offsets
                    for decompiled_offset in decompiled_var.stack_offsets
                ):
                    graph.add_edge(
                        ("s", source_var.identity),
                        ("d", decompiled_var.identity),
                    )
        cardinality = len(nx.algorithms.matching.max_weight_matching(graph, maxcardinality=True))
        ranked.append((cardinality, shift))

    best_cardinality = max(row[0] for row in ranked)
    best = [row for row in ranked if row[0] == best_cardinality]
    if best_cardinality < 2 or len(best) != 1:
        return None
    return best[0][1]


def _random_variables(rng: random.Random, prefix: str) -> list[VariableEvidence]:
    variables: list[VariableEvidence] = []
    for index in range(rng.randrange(8)):
        variables.append(
            VariableEvidence(
                identity=f"{prefix}{index}",
                name="",
                stack_offsets=tuple(sorted(rng.sample(range(-6, 7), k=rng.randrange(4)))),
                size=rng.choice((None, 1, 4, 8)),
            )
        )
    return variables


@pytest.mark.parametrize("use_size_compatibility", [False, True])
def test_sparse_stack_shift_matches_reference(use_size_compatibility: bool) -> None:
    rng = random.Random(0xDECBE)
    for _ in range(250):
        source = _random_variables(rng, "s")
        decompiled = _random_variables(rng, "d")
        assert _stack_shift(
            source,
            decompiled,
            use_size_compatibility=use_size_compatibility,
        ) == _reference_stack_shift(
            source,
            decompiled,
            use_size_compatibility=use_size_compatibility,
        )
