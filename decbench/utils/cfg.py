"""CFG extraction utilities."""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import DecompilationResult


def extract_cfgs_from_source(source_path: Path) -> dict[str, DiGraph]:
    """Extract CFGs from a C source file using pyjoern.

    Args:
        source_path: Path to C source file (.c or .i)

    Returns:
        Dictionary mapping function names to CFG DiGraphs
    """
    try:
        from pyjoern import parse_source
    except ImportError:
        raise ImportError(
            "pyjoern is required for CFG extraction. "
            "Install with: pip install pyjoern"
        )

    cfgs = {}
    # Joern doesn't recognize .i files; copy to .c temp file if needed
    temp_c_path = None
    parse_path = source_path
    if source_path.suffix == ".i":
        temp_c_path = Path(tempfile.mktemp(suffix=".c"))
        shutil.copy2(source_path, temp_c_path)
        parse_path = temp_c_path

    try:
        # parse_source returns dict[str, Function] or dict[tuple[str,str], Function]
        parsed = parse_source(parse_path)

        if parsed is None:
            return cfgs

        # Extract CFGs for each function
        for key, func in parsed.items():
            func_name = func.name if hasattr(func, "name") else str(key)
            cfg = func.cfg if hasattr(func, "cfg") else None

            if cfg is not None:
                cfgs[func_name] = cfg

    except Exception as e:
        logger.warning("CFG extraction from source %s failed: %s", source_path, e)
    finally:
        if temp_c_path is not None:
            temp_c_path.unlink(missing_ok=True)

    return cfgs


def extract_cfgs_from_decompilation(
    decompilation: DecompilationResult,
) -> dict[str, DiGraph]:
    """Extract CFGs from decompiled code.

    Args:
        decompilation: Decompilation result

    Returns:
        Dictionary mapping function names to CFG DiGraphs
    """
    try:
        from pyjoern import parse_source
    except ImportError:
        raise ImportError(
            "pyjoern is required for CFG extraction. "
            "Install with: pip install pyjoern"
        )

    cfgs = {}

    # Write decompiled code to temp file and parse
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        # Write all functions
        for func in decompilation.functions.values():
            f.write(f"// Function: {func.name}\n")
            f.write(func.decompiled_code)
            f.write("\n\n")

        temp_path = Path(f.name)

    try:
        parsed = parse_source(temp_path)

        if parsed is not None:
            for key, func in parsed.items():
                func_name = func.name if hasattr(func, "name") else str(key)
                cfg = func.cfg if hasattr(func, "cfg") else None

                if cfg is not None:
                    cfgs[func_name] = cfg

    except Exception as e:
        logger.warning("CFG extraction from decompilation failed: %s", e)
    finally:
        temp_path.unlink(missing_ok=True)

    return cfgs


def cfg_to_dict(cfg: DiGraph) -> dict:  # type: ignore
    """Convert a CFG to a serializable dictionary.

    Args:
        cfg: NetworkX DiGraph

    Returns:
        Dictionary representation
    """
    return {
        "nodes": list(cfg.nodes()),
        "edges": list(cfg.edges()),
        "node_count": cfg.number_of_nodes(),
        "edge_count": cfg.number_of_edges(),
    }


def compute_cfg_stats(cfg: DiGraph) -> dict:  # type: ignore
    """Compute statistics about a CFG.

    Args:
        cfg: NetworkX DiGraph

    Returns:
        Dictionary of statistics
    """
    import networkx as nx

    nodes = cfg.number_of_nodes()
    edges = cfg.number_of_edges()

    stats = {
        "nodes": nodes,
        "edges": edges,
        "size": nodes + edges,
        "cyclomatic_complexity": edges - nodes + 2,
    }

    # Try to compute more stats
    try:
        if nodes > 0:
            stats["density"] = nx.density(cfg)

            # Find entry and exit nodes
            in_degrees = dict(cfg.in_degree())
            out_degrees = dict(cfg.out_degree())

            entry_nodes = [n for n, d in in_degrees.items() if d == 0]
            exit_nodes = [n for n, d in out_degrees.items() if d == 0]

            stats["entry_nodes"] = len(entry_nodes)
            stats["exit_nodes"] = len(exit_nodes)

            # Average branching factor
            if nodes > 0:
                stats["avg_out_degree"] = sum(out_degrees.values()) / nodes

    except Exception:
        pass

    return stats
