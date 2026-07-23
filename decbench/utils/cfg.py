"""CFG extraction utilities."""

from __future__ import annotations

import logging
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import DecompilationResult


_LINE_MARKER = re.compile(r'^#\s+\d+\s+"([^"]*)"')

# Aggregate/array return type: ``unsigned int [4] name(`` -> ``unsigned int name(``.
# angr/ghidra render a by-value aggregate/array return as ``T [N] name(...)``
# which is not valid C, so Joern parses NOTHING for such a function and it silently
# drops out of GED's denominator. Anchored at line start (re.M) so it only ever
# rewrites a top-level function SIGNATURE, never an in-body array declaration such as
# ``char buf[16];`` (which is indented and/or not followed by an identifier + ``(``).
_AGG_RETURN = re.compile(r"^([A-Za-z_][\w ]*?)\s*\[\d+\]\s+([A-Za-z_]\w*\s*\()", re.M)

# Binary Ninja register annotations: ``char arg3 @ rax`` -> ``char arg3``. ``@`` is
# not legal C, so its presence breaks Joern's parse for the whole function.
_REG_ANNOTATION = re.compile(r"\s*@\s*[a-z]\w+\b")


def sanitize_decompiled_c(text: str) -> str:
    """Clean decompiler-specific C quirks that break Joern's parser.

    GED only cares about CFG *structure*, so these edits are purely to make the
    body parseable — they never touch control flow. Three tool-specific quirks:

    * **Aggregate/array return type** (angr/ghidra): ``T [N] name(...)``
      is rewritten to ``T name(...)``. Anchored to the start of a line so a real
      in-body array declaration (``char buf[16];``) is never rewritten.
    * **Register annotation** (binja): `` @ rax`` (and friends) is stripped — ``@``
      is not valid C.
    * **128-bit types** (ida): ``__int128`` is widened to ``long long`` (the exact
      width is irrelevant to the CFG).
    """
    text = _AGG_RETURN.sub(r"\1 \2", text)
    text = _REG_ANNOTATION.sub("", text)
    text = text.replace("unsigned __int128", "unsigned long long").replace("__int128", "long long")
    return text


def _is_system_header(path: str) -> bool:
    """True if a preprocessor line-marker file is a system/toolchain header.

    Covers glibc (/usr/include), gcc internals (/usr/lib/gcc), the cross/mingw
    toolchains (also under /usr/...), and the preprocessor's synthetic files
    (<built-in>, <command-line>, stdc-predef.h).
    """
    return (
        not path
        or path.startswith("<")
        or path.startswith("/usr/")
        or "/usr/lib/gcc" in path
        or path.endswith("stdc-predef.h")
    )


def strip_system_headers(preprocessed: str) -> str:
    """Drop inlined system-header code from a preprocessed (.i) translation unit.

    A ``.i`` file is the project source with EVERY ``#include`` expanded inline,
    so it is dominated (80-98%) by glibc/toolchain headers. Joern then either
    times out parsing megabytes of headers or drowns the project's own functions
    in thousands of header inlines — which is why GED "source-parse failures"
    were really header-bloat timeouts, not real failures.

    Using the ``# <line> "<file>"`` markers gcc emits, we keep only lines that
    came from the project's own files. ``#ifdef`` selection and macro expansion
    have ALREADY been done by the real compiler, so the result is exactly the
    code that was compiled (the right ifdef branches) — fair and small.
    """
    keep: list[str] = []
    in_system = True  # before the first marker
    for line in preprocessed.splitlines():
        m = _LINE_MARKER.match(line)
        if m is not None:
            in_system = _is_system_header(m.group(1))
            continue  # drop the marker line itself
        if not in_system:
            keep.append(line)
    return "\n".join(keep) + "\n"


def is_degenerate_source_cfg(cfg: DiGraph) -> bool:  # type: ignore
    """True when a source CFG has no real structure to compare GED against.

    Two cases, both meaning "there is nothing to score": zero nodes, or a single
    block whose statements are ALL ``Nop`` (``FUNCTION_START``/``FUNCTION_END``) —
    an *empty prototype* Joern emitted from a declaration-only view of a function
    whose defining translation unit wasn't captured. A genuine single-block
    function (a straight-line ``return foo(...);``) has real statements and is NOT
    degenerate, so it stays scorable (a correct 1-block decompilation → GED 0).
    """
    n = cfg.number_of_nodes()
    if n == 0:
        return True
    if n >= 2:
        return False
    for node in cfg.nodes():
        for stmt in getattr(node, "statements", None) or []:
            if type(stmt).__name__ != "Nop":
                return False
    return True


def _source_rank(cfg: DiGraph) -> tuple[int, int]:  # type: ignore
    """Sort key preferring a non-degenerate, then larger, source CFG."""
    return (0 if is_degenerate_source_cfg(cfg) else 1, cfg.number_of_nodes())


def best_source_by_name(
    source_cfgs_by_binary: dict[str, dict[str, DiGraph]],
) -> dict[str, DiGraph]:  # type: ignore
    """Collapse per-TU source CFGs to one-per-name, preferring the real body.

    A function name that appears in several translation units (``main``, ``usage``,
    gnulib helpers) is reduced to its **non-degenerate, largest** CFG. Used as the
    cross-TU FALLBACK when a binary's own TU doesn't define a function (e.g. a
    statically-linked gnulib helper) — see :func:`resolved_source_for_binary`.
    """
    best: dict[str, DiGraph] = {}
    for cfgs in source_cfgs_by_binary.values():
        for name, cfg in (cfgs or {}).items():
            cur = best.get(name)
            if cur is None or _source_rank(cfg) > _source_rank(cur):
                best[name] = cfg
    return best


def resolved_source_for_binary(
    binary_stem: str,
    source_cfgs_by_binary: dict[str, dict[str, DiGraph]],
    best_by_name: dict[str, DiGraph],
) -> dict[str, DiGraph]:  # type: ignore
    """Source CFGs to score ONE binary against, TU-aware (fixes name collisions).

    Prefers the binary's **own translation unit** (``nologin`` binary ↔
    ``nologin.i``) for each function so per-program functions (``main``, ``usage``,
    static helpers) are compared against the RIGHT body — not an arbitrary
    same-named function from another binary of the project (the old project-wide,
    name-keyed, last-writer-wins union scored ``nologin``'s 5-node ``main`` against
    another binary's 56-node ``main``). Falls back to the cross-TU
    :func:`best_source_by_name` for functions the own TU doesn't define
    (statically-linked library code) or defines only as an empty prototype.
    """
    resolved = dict(best_by_name)
    for name, cfg in (source_cfgs_by_binary.get(binary_stem) or {}).items():
        if not is_degenerate_source_cfg(cfg):
            resolved[name] = cfg
    return resolved


def extract_cfgs_from_source(
    source_path: Path, sanitize_decompiled: bool = False
) -> dict[str, DiGraph]:
    """Extract CFGs from a C source file using pyjoern.

    Args:
        source_path: Path to C source file (.c or .i). For ``.i`` files the
            inlined system headers are stripped first (see
            :func:`strip_system_headers`) so Joern parses only the project's own
            (already-preprocessed, correctly-ifdef'd) code — fast and complete.
        sanitize_decompiled: When True and ``source_path`` is a *decompiled* ``.c``
            (i.e. NOT a ``.i`` ground-truth source), run its text through
            :func:`sanitize_decompiled_c` before parsing so decompiler-specific
            quirks don't drop the function from GED. Never applied to ``.i`` files
            — sanitizing ground truth would be wrong.

    Returns:
        Dictionary mapping function names to CFG DiGraphs
    """
    try:
        from pyjoern import parse_source
    except ImportError:
        raise ImportError(
            "pyjoern is required for CFG extraction. " "Install with: pip install pyjoern"
        )

    cfgs = {}
    # Always parse via a UNIQUE temp .c: Joern names its workspace after the input
    # file's basename, so parsing the same filename concurrently (e.g. the same
    # function file across opt levels) would collide. A unique temp name avoids
    # that. For .i we also strip the inlined system headers first.
    temp_c_path = Path(tempfile.mktemp(suffix=".c"))
    if source_path.suffix == ".i":
        temp_c_path.write_text(strip_system_headers(source_path.read_text(errors="replace")))
    else:
        text = source_path.read_text(errors="replace")
        if sanitize_decompiled:
            text = sanitize_decompiled_c(text)
        temp_c_path.write_text(text)
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
            "pyjoern is required for CFG extraction. " "Install with: pip install pyjoern"
        )

    cfgs = {}

    # Write decompiled code to temp file and parse
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        # Write all functions, sanitizing decompiler-specific C quirks that would
        # otherwise break Joern's parse and drop the function from GED coverage.
        for func in decompilation.functions.values():
            f.write(f"// Function: {func.name}\n")
            f.write(sanitize_decompiled_c(func.decompiled_code))
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
