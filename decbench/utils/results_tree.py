"""Navigate an on-disk benchmark results tree.

A results tree produced by the pipeline (``decbench run`` /
``scripts/run_benchmark.py``) is laid out as::

    <root>/<opt>/<project>/
        compiled/<binary>            # the ELF/PE binary (name may carry a suffix)
        decompiled/<dec>_<stem>.c    # decompiled C, function blocks delimited by
                                     #   "// Function: <name> @ 0x<addr>"
        decompiled/<dec>_<stem>.toml # per-function metadata (address, line_count)
        evaluated/<binary>.toml

(see :mod:`decbench.pipeline.compile` and :mod:`decbench.pipeline.decompile` for
where these paths are written). ``function_results.json`` identifies a function
only by ``(project, opt, binary_stem, function)`` and stores **no address**, so
this module centralises the mapping from that identity back to the concrete
compiled-binary path and the decompiler-emitted function address recorded in the
decompiled ``.c`` artifacts. Shared by ``scripts/reeval_bytematch.py`` and the
``decbench improvements`` CLI command.
"""

from __future__ import annotations

import re
from pathlib import Path

from decbench.utils import binfmt

# The header comment DecompilationResult.to_c_file writes before each function
# block: ``// Function: <name> @ 0x<addr>``.
FUNCTION_MARKER = re.compile(r"^// Function: (\S+) @ (0x[0-9a-fA-F]+)\s*$", re.M)

# Optimization sub-directories a results tree can contain (top level, per-opt).
OPT_LEVELS = ("O0", "O2", "O2-noinline")


def compiled_dir(root: Path, opt: str, project: str) -> Path:
    """Directory holding a project's compiled binaries for one opt level."""
    return root / opt / project / "compiled"


def decompiled_dir(root: Path, opt: str, project: str) -> Path:
    """Directory holding a project's decompiled artifacts for one opt level."""
    return root / opt / project / "decompiled"


def decompiled_c_path(root: Path, opt: str, project: str, decompiler: str, stem: str) -> Path:
    """Path to one decompiler's decompiled ``.c`` file for a binary stem.

    The artifact is named by the decompiler's unversioned ``name`` (not its
    ``name@version`` id), matching ``DecompilationResult.to_c_file``.
    """
    return decompiled_dir(root, opt, project) / f"{decompiler}_{stem}.c"


def split_functions(c_path: Path) -> dict[str, tuple[int, str]]:
    """``name -> (address, decompiled block)`` for one decompiled ``.c`` file."""
    text = c_path.read_text(errors="replace")
    out: dict[str, tuple[int, str]] = {}
    matches = list(FUNCTION_MARKER.finditer(text))
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out[m.group(1)] = (int(m.group(2), 16), text[start:end].strip())
    return out


def function_addresses(c_path: Path) -> dict[str, int]:
    """``name -> address`` parsed from a decompiled ``.c`` header (``{}`` if absent)."""
    if not c_path.is_file():
        return {}
    return {name: addr for name, (addr, _code) in split_functions(c_path).items()}


def resolve_binary(comp: Path, stem: str) -> Path | None:
    """Find the original binary for a decompiled stem inside ``comp`` (a compiled dir).

    The decompiled artifact is named ``{dec}_{stem}.c`` where ``stem`` =
    ``binary.stem``, but the on-disk binary keeps its full name — which may carry
    an extension (``mydoom.exe``, ``psize.aux``) or a version suffix
    (``libedit.so.0.0.70``). So fall back from an exact match to any sibling
    whose stem matches and which is a real ELF/PE. (Must agree with
    ``scripts/rebuild_function_data.DiskReader.binary``.)
    """
    exact = comp / stem
    if exact.is_file() and binfmt.detect(exact):
        return exact
    if comp.is_dir():
        for f in sorted(comp.iterdir()):
            if f.is_file() and f.stem == stem and binfmt.detect(f):
                return f
    return None
