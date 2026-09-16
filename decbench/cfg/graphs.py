"""Conversion between durable CFG records and GED's NetworkX boundary."""

from __future__ import annotations

from typing import TYPE_CHECKING

from decbench.cfg.models import CfgExtraction, ExtractedCfg

if TYPE_CHECKING:
    from networkx import DiGraph


class CfgNode:
    """Minimal GED node carrying entry and exit roles."""

    __slots__ = ("id", "is_entrypoint", "is_exitpoint")

    def __init__(self, node_id: int, *, entry: bool = False, exit: bool = False) -> None:
        self.id = node_id
        self.is_entrypoint = entry
        self.is_exitpoint = exit

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CfgNode) and self.id == other.id

    def __repr__(self) -> str:
        return f"n{self.id}"


def graph_from_record(record: ExtractedCfg, extraction: CfgExtraction) -> DiGraph:
    """Build one GED-ready graph and retain extraction provenance."""
    import networkx as nx

    entries = set(record.entry)
    exits = set(record.exit)
    by_id = {
        node_id: CfgNode(node_id, entry=node_id in entries, exit=node_id in exits)
        for node_id in record.nodes
    }
    graph = nx.DiGraph()
    graph.add_nodes_from(by_id.values())
    graph.add_edges_from((by_id[source], by_id[target]) for source, target in record.edges)
    graph.graph.update(
        degenerate=record.degenerate,
        cfg_extractor=extraction.provider,
        cfg_extractor_version=extraction.provider_version,
        cfg_schema=extraction.cfg_schema,
        extraction_policy=extraction.extraction_policy,
        cfg_language=extraction.language,
        extraction_status=extraction.status,
        diagnostic_count=len(extraction.diagnostics),
        partial_recovery=extraction.partial_recovery,
    )
    if extraction.preprocessing is not None:
        graph.graph.update(
            preprocessing_status=extraction.preprocessing.status,
            preprocessing_compiler=extraction.preprocessing.compiler,
            preprocessing_includes_removed=extraction.preprocessing.includes_removed,
        )
    return graph


def graphs_from_extraction(extraction: CfgExtraction) -> dict[str, DiGraph]:
    """Convert all function records from one successful extraction."""
    return {
        name: graph_from_record(record, extraction) for name, record in extraction.functions.items()
    }
