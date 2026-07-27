"""Source-CFG serialization for the published dataset (contract §5).

The GED metric (``cfgutils.similarity.vj_ged``) is almost purely structural — it
scores from per-node parent/child counts — but it also reads each node's
``is_entrypoint`` / ``is_exitpoint`` flags (an entry/exit mismatch penalty). So a
lossless serialization needs the graph topology **plus** those two flags, and
nothing else (labels are not used by GED). This module writes, per binary, the
``function -> CFG`` map that ``pipeline/evaluate.py`` scores that binary
against: the project's ``.i`` CFGs parsed **per translation unit** and then
resolved through :func:`decbench.utils.cfg.resolved_source_for_binary` — the
binary's own TU wins, other TUs are the fallback, and empty prototypes never
displace a real body. Each DiGraph is relabeled to ``0..n-1`` with the
entry/exit node ids and the degeneracy verdict recorded. :func:`rebuild_cfg`
reconstructs a GED-ready ``nx.DiGraph`` from one serialized function, so the
exact GED value is reproducible offline.

A project-wide, name-keyed, last-writer-wins union is NOT a valid export: a
declaration-only view of a function (Joern emits a single ``Nop`` block for it)
overwrites the defining TU's real body whenever it sorts later, and every binary
of a project ends up with an identical map, so per-program functions (``main``,
``usage``, static helpers) are scored against another binary's body. That was
the bug behind decbench#50 — it silently capped offline GED coverage at ~39%.

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

from decbench.utils.cfg import (
    best_source_by_name,
    extract_cfgs_from_source,
    is_degenerate_source_cfg,
    resolved_source_for_binary,
    strip_system_headers,
)
from decbench.utils.results_tree import OPT_LEVELS, compiled_dir

if TYPE_CHECKING:
    from networkx import DiGraph

logger = logging.getLogger(__name__)

Logger = Callable[[str], None]

CfgSerial = tuple[list[int], list[list[int]], dict[str, str], list[int], list[int], bool]


class RealStatement:
    """Marker statement standing in for a rebuilt node's real (non-``Nop``) content.

    :func:`decbench.utils.cfg.is_degenerate_source_cfg` decides a single-block CFG
    by looking for a non-``Nop`` statement, which serialization drops. Rebuilt
    non-degenerate nodes carry one of these so that verdict survives the round
    trip; without it every rebuilt 1-block function reads as an empty prototype.
    """

    __slots__ = ()


class CfgNode:
    """A minimal CFG node exposing the two flags ``vj_ged`` reads.

    Rebuilt graphs use these so GED reproduces exactly; identity is the node id.
    """

    __slots__ = ("id", "is_entrypoint", "is_exitpoint", "statements")

    def __init__(
        self,
        id: int,
        is_entrypoint: bool = False,
        is_exitpoint: bool = False,
        statements: tuple[RealStatement, ...] = (),
    ) -> None:
        self.id = id
        self.is_entrypoint = is_entrypoint
        self.is_exitpoint = is_exitpoint
        self.statements = statements

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CfgNode) and other.id == self.id

    def __repr__(self) -> str:
        return f"n{self.id}"


def relabel_cfg(cfg: DiGraph) -> CfgSerial:  # type: ignore[type-arg]
    """Relabel a CFG's nodes to ``0..n-1`` (stable order) -> serialized parts.

    Returns ``(nodes, edges, labels, entry, exit, degenerate)``. Topology and the
    entry/exit node ids are what GED needs, ``degenerate`` is what the offline
    TU resolution needs; ``labels`` (index -> ``str(node)``) is human-readable
    provenance only.
    """
    nodes = list(cfg.nodes())
    index = {node: i for i, node in enumerate(nodes)}
    node_ids = list(range(len(nodes)))
    edges = [[index[u], index[v]] for u, v in cfg.edges()]
    labels = {str(index[node]): str(node) for node in nodes}
    entry = [index[node] for node in nodes if getattr(node, "is_entrypoint", False)]
    exit_ = [index[node] for node in nodes if getattr(node, "is_exitpoint", False)]
    return node_ids, edges, labels, entry, exit_, is_degenerate_source_cfg(cfg)


def rebuild_cfg(func_cfg: dict) -> DiGraph:  # type: ignore[type-arg]
    """Reconstruct a GED-ready ``nx.DiGraph`` from one serialized function CFG.

    Nodes are :class:`CfgNode` instances carrying the stored entry/exit flags, so
    ``cfgutils.similarity.vj_ged`` runs on the result and reproduces the exact
    GED value the pipeline computed. A CFG recorded as non-degenerate also gets
    :class:`RealStatement` markers so
    :func:`decbench.utils.cfg.is_degenerate_source_cfg` agrees offline (JSONs
    written before that field existed simply keep the old behaviour).
    """
    import networkx as nx

    entry = set(func_cfg.get("entry", []))
    exit_ = set(func_cfg.get("exit", []))
    statements = () if func_cfg.get("degenerate", True) else (RealStatement(),)
    node_by_id = {i: CfgNode(i, i in entry, i in exit_, statements) for i in func_cfg["nodes"]}
    graph = nx.DiGraph()
    graph.add_nodes_from(node_by_id.values())
    for u, v in func_cfg["edges"]:
        graph.add_edge(node_by_id[u], node_by_id[v])
    return graph


def _stripped_sha(i_path: Path) -> str:
    """SHA-256 of a ``.i`` file after stripping inlined system headers."""
    stripped = strip_system_headers(i_path.read_text(errors="replace"))
    return hashlib.sha256(stripped.encode("utf-8", "replace")).hexdigest()


def _parse_tus_for_opt(
    root: Path,
    project: str,
    opt: str,
    cache: dict[str, dict[str, DiGraph]],  # type: ignore[type-arg]
) -> dict[str, dict[str, DiGraph]]:  # type: ignore[type-arg]
    """Parse a project's ``.i`` files at ``opt`` into ``{tu_stem: {function: CFG}}``.

    Keyed by ``.i`` stem exactly as the live pipeline keys
    ``project.preprocessed_sources`` (``pipeline/compile.py`` uses the source
    stem), which is what makes the binary <-> own-TU match work. ``cache`` maps a
    stripped-content SHA to its parsed CFGs so each unique TU is parsed once
    across opt levels.
    """
    by_tu: dict[str, dict[str, DiGraph]] = {}  # type: ignore[type-arg]
    comp = compiled_dir(root, opt, project)
    if not comp.is_dir():
        return by_tu
    for i_path in sorted(comp.glob("*.i")):
        sha = _stripped_sha(i_path)
        if sha not in cache:
            try:
                cache[sha] = extract_cfgs_from_source(i_path)
            except Exception as exc:  # noqa: BLE001
                logger.warning("CFG parse failed for %s: %s", i_path, exc)
                cache[sha] = {}
        by_tu[i_path.stem] = cache[sha]
    return by_tu


def _resolved_cfgs_for_opt(
    root: Path,
    project: str,
    opt: str,
    stems: list[str],
    cache: dict[str, dict[str, DiGraph]],  # type: ignore[type-arg]
) -> dict[str, dict[str, CfgSerial]]:
    """Per-binary source CFGs at ``opt``, resolved exactly as the pipeline resolves them.

    Delegates to the same :func:`best_source_by_name` /
    :func:`resolved_source_for_binary` pair ``pipeline/evaluate.py`` calls, so the
    export cannot drift from the scoring path. Serialization is memoized on graph
    identity because binaries of a project share most of their resolved CFGs.
    """
    by_tu = _parse_tus_for_opt(root, project, opt, cache)
    best_by_name = best_source_by_name(by_tu)

    serialized: dict[int, CfgSerial] = {}

    def _serialize(cfg: DiGraph) -> CfgSerial:  # type: ignore[type-arg]
        key = id(cfg)
        if key not in serialized:
            serialized[key] = relabel_cfg(cfg)
        return serialized[key]

    return {
        stem: {
            name: _serialize(cfg)
            for name, cfg in resolved_source_for_binary(stem, by_tu, best_by_name).items()
        }
        for stem in stems
    }


def cfg_json_path(dest: Path, opt: str, project: str, stem: str) -> Path:
    """Path of a binary's source-CFG JSON under ``dest``."""
    return dest / "pipeline_data" / "source_cfgs" / opt / project / f"{stem}.json"


def _write_cfg_json(
    path: Path,
    opt: str,
    project: str,
    stem: str,
    resolved: dict[str, CfgSerial],
    generator: str,
) -> None:
    """Serialize a binary's resolved ``function -> CFG`` map (contract §5)."""
    functions = {
        func_name: {
            "nodes": nodes,
            "edges": edges,
            "labels": labels,
            "entry": entry,
            "exit": exit_,
            "degenerate": degenerate,
        }
        for func_name, (nodes, edges, labels, entry, exit_, degenerate) in resolved.items()
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

    Each binary gets the CFGs *its own* TU resolution produces, so the JSONs of a
    ``(project, opt)`` differ wherever the binaries do. The whole opt level is
    resolved in one pass (only when some target JSON is missing) because the
    cross-TU fallback needs every TU of the project. Parses are deduplicated
    across opts via a project-local cache. Existing JSONs are skipped unless
    ``overwrite``.
    """
    out: dict[tuple[str, str], str] = {}
    cache: dict[str, dict[str, DiGraph]] = {}  # type: ignore[type-arg]
    for opt in [o for o in OPT_LEVELS if o in stems_by_opt]:
        stems = stems_by_opt[opt]
        if not stems:
            continue
        targets = {stem: cfg_json_path(dest, opt, project, stem) for stem in stems}
        pending = [stem for stem, p in targets.items() if overwrite or not p.exists()]
        resolved = _resolved_cfgs_for_opt(root, project, opt, pending, cache) if pending else {}
        for stem, target in targets.items():
            if stem in resolved:
                _write_cfg_json(target, opt, project, stem, resolved[stem], generator)
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
