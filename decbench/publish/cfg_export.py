"""Source-CFG serialization for the published dataset (contract §5).

The GED metric (``cfgutils.similarity.vj_ged``) is almost purely structural — it
scores from per-node parent/child counts — but it also reads each node's
``is_entrypoint`` / ``is_exitpoint`` flags (an entry/exit mismatch penalty). So a
lossless serialization needs the graph topology **plus** those two flags, and
nothing else (labels are not used by GED). This module writes, per binary, the
``function -> CFG`` map that ``pipeline/evaluate.py`` builds as
``all_source_cfgs`` (the union, last-writer-wins, of a project's ``.i`` CFGs at
one opt level), each DiGraph relabeled to ``0..n-1`` with the entry/exit node
ids recorded. :func:`rebuild_cfg` reconstructs a GED-ready ``nx.DiGraph`` from
one serialized function, so the exact GED value is reproducible offline.

Cost model: Joern spawns a JVM per parse, so parsing dominates. We therefore
**deduplicate parses by stripped-content hash** — each unique translation unit
(shared across opt levels and binaries) is parsed once and cached. Output is
resumable: an existing ``<stem>.json`` is left untouched unless ``overwrite``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import multiprocessing as mp
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING

from decbench.utils.cfg import extract_cfgs_from_source, strip_system_headers
from decbench.utils.results_tree import OPT_LEVELS, compiled_dir

if TYPE_CHECKING:
    from networkx import DiGraph

logger = logging.getLogger(__name__)

Logger = Callable[[str], None]

# One function's serialized CFG: node ids (0..n-1), edges, readable labels, and
# the ids of the entry / exit nodes (the only node attributes GED reads).
CfgSerial = tuple[list[int], list[list[int]], dict[str, str], list[int], list[int]]


class CfgNode:
    """A minimal CFG node exposing the two flags ``vj_ged`` reads.

    Rebuilt graphs use these so GED reproduces exactly; identity is the node id.
    """

    __slots__ = ("id", "is_entrypoint", "is_exitpoint")

    def __init__(self, id: int, is_entrypoint: bool = False, is_exitpoint: bool = False) -> None:
        self.id = id
        self.is_entrypoint = is_entrypoint
        self.is_exitpoint = is_exitpoint

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CfgNode) and other.id == self.id

    def __repr__(self) -> str:
        return f"n{self.id}"


def relabel_cfg(cfg: DiGraph) -> CfgSerial:  # type: ignore[type-arg]
    """Relabel a CFG's nodes to ``0..n-1`` (stable order) -> serialized parts.

    Returns ``(nodes, edges, labels, entry, exit)``. Topology and the entry/exit
    node ids are what GED needs; ``labels`` (index -> ``str(node)``) is
    human-readable provenance only.
    """
    nodes = list(cfg.nodes())
    index = {node: i for i, node in enumerate(nodes)}
    node_ids = list(range(len(nodes)))
    edges = [[index[u], index[v]] for u, v in cfg.edges()]
    labels = {str(index[node]): str(node) for node in nodes}
    entry = [index[node] for node in nodes if getattr(node, "is_entrypoint", False)]
    exit_ = [index[node] for node in nodes if getattr(node, "is_exitpoint", False)]
    return node_ids, edges, labels, entry, exit_


def rebuild_cfg(func_cfg: dict) -> DiGraph:  # type: ignore[type-arg]
    """Reconstruct a GED-ready ``nx.DiGraph`` from one serialized function CFG.

    Nodes are :class:`CfgNode` instances carrying the stored entry/exit flags, so
    ``cfgutils.similarity.vj_ged`` runs on the result and reproduces the exact
    GED value the pipeline computed.
    """
    import networkx as nx

    entry = set(func_cfg.get("entry", []))
    exit_ = set(func_cfg.get("exit", []))
    node_by_id = {i: CfgNode(i, i in entry, i in exit_) for i in func_cfg["nodes"]}
    graph = nx.DiGraph()
    graph.add_nodes_from(node_by_id.values())
    for u, v in func_cfg["edges"]:
        graph.add_edge(node_by_id[u], node_by_id[v])
    return graph


def _stripped_sha(i_path: Path) -> str:
    """SHA-256 of a ``.i`` file after stripping inlined system headers."""
    stripped = strip_system_headers(i_path.read_text(errors="replace"))
    return hashlib.sha256(stripped.encode("utf-8", "replace")).hexdigest()


def _merged_cfgs_for_opt(
    root: Path,
    project: str,
    opt: str,
    cache: dict[str, dict[str, CfgSerial]],
) -> dict[str, CfgSerial]:
    """Union of a project's ``.i`` CFGs at ``opt`` (last-writer-wins on name).

    Mirrors ``pipeline/evaluate.py``'s ``all_source_cfgs``. ``cache`` maps a
    stripped-content SHA to its parsed CFGs so each unique TU is parsed once.
    """
    merged: dict[str, CfgSerial] = {}
    comp = compiled_dir(root, opt, project)
    if not comp.is_dir():
        return merged
    for i_path in sorted(comp.glob("*.i")):
        sha = _stripped_sha(i_path)
        if sha not in cache:
            parsed: dict[str, CfgSerial] = {}
            try:
                cfgs = extract_cfgs_from_source(i_path)
            except Exception as exc:  # noqa: BLE001
                logger.warning("CFG parse failed for %s: %s", i_path, exc)
                cfgs = {}
            for func_name, cfg in cfgs.items():
                parsed[func_name] = relabel_cfg(cfg)
            cache[sha] = parsed
        merged.update(cache[sha])
    return merged


def cfg_json_path(dest: Path, opt: str, project: str, stem: str) -> Path:
    """Path of a binary's source-CFG JSON under ``dest``."""
    return dest / "pipeline_data" / "source_cfgs" / opt / project / f"{stem}.json"


def _write_cfg_json(
    path: Path,
    opt: str,
    project: str,
    stem: str,
    merged: dict[str, CfgSerial],
    generator: str,
) -> None:
    """Serialize a binary's ``function -> CFG`` map (contract §5)."""
    functions = {
        func_name: {
            "nodes": nodes,
            "edges": edges,
            "labels": labels,
            "entry": entry,
            "exit": exit_,
        }
        for func_name, (nodes, edges, labels, entry, exit_) in merged.items()
    }
    data = {
        "opt": opt,
        "project": project,
        "binary": stem,
        "generator": generator,
        "functions": functions,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def export_project_cfgs(
    root: Path,
    dest: Path,
    project: str,
    stems_by_opt: dict[str, list[str]],
    *,
    overwrite: bool = False,
    generator: str = "pyjoern",
) -> dict[tuple[str, str], str]:
    """Write source-CFG JSONs for one project's binaries; return ``{(opt, stem): rel}``.

    All binaries of a ``(project, opt)`` share the same merged source CFGs, so
    the map is computed once per opt (only when some target JSON is missing) and
    written to each stem. Parses are deduplicated across opts via a project-local
    cache. Existing JSONs are skipped unless ``overwrite``.
    """
    out: dict[tuple[str, str], str] = {}
    cache: dict[str, dict[str, CfgSerial]] = {}
    for opt in [o for o in OPT_LEVELS if o in stems_by_opt]:
        stems = stems_by_opt[opt]
        if not stems:
            continue
        targets = {stem: cfg_json_path(dest, opt, project, stem) for stem in stems}
        merged: dict[str, CfgSerial] | None = None
        if overwrite or any(not p.exists() for p in targets.values()):
            merged = _merged_cfgs_for_opt(root, project, opt, cache)
        for stem, target in targets.items():
            if target.exists() and not overwrite:
                out[(opt, stem)] = target.relative_to(dest).as_posix()
                continue
            if merged is None:
                merged = _merged_cfgs_for_opt(root, project, opt, cache)
            _write_cfg_json(target, opt, project, stem, merged, generator)
            out[(opt, stem)] = target.relative_to(dest).as_posix()
    return out


def export_all_cfgs(
    root: Path,
    dest: Path,
    stems_by_project_opt: dict[str, dict[str, list[str]]],
    *,
    workers: int = 1,
    overwrite: bool = False,
    generator: str = "pyjoern",
    log: Logger = print,
) -> dict[tuple[str, str, str], str]:
    """Export source CFGs for many projects; return ``{(opt, project, stem): rel}``.

    Parallelizes across **projects** (one worker per project) so each worker
    keeps its own cross-opt parse cache. Uses a ``spawn`` context (fork is unsafe
    once threaded libs are imported, per the repo's multiprocessing guidance).
    """
    results: dict[tuple[str, str, str], str] = {}

    def _record(project: str, per: dict[tuple[str, str], str]) -> None:
        for (opt, stem), rel in per.items():
            results[(opt, project, stem)] = rel

    if workers and workers > 1 and len(stems_by_project_opt) > 1:
        ctx = mp.get_context("spawn")
        with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as executor:
            futures = {
                executor.submit(
                    export_project_cfgs,
                    root,
                    dest,
                    project,
                    sbo,
                    overwrite=overwrite,
                    generator=generator,
                ): project
                for project, sbo in stems_by_project_opt.items()
            }
            for future in as_completed(futures):
                project = futures[future]
                try:
                    _record(project, future.result())
                    log(f"[cfg] {project}: done")
                except Exception as exc:  # noqa: BLE001
                    log(f"[cfg] {project}: FAILED ({exc})")
    else:
        for project, sbo in stems_by_project_opt.items():
            try:
                _record(
                    project,
                    export_project_cfgs(
                        root, dest, project, sbo, overwrite=overwrite, generator=generator
                    ),
                )
                log(f"[cfg] {project}: done")
            except Exception as exc:  # noqa: BLE001
                log(f"[cfg] {project}: FAILED ({exc})")

    return results
