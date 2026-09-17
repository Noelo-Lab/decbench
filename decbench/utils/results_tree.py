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
from decbench.utils.function_identity import parse_function_storage_key

FUNCTION_MARKER = re.compile(r"^// Function: (.+?) @ (0x[0-9a-fA-F]+)\s*$", re.M)

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
    """``storage key -> (address, decompiled block)`` for one ``.c`` artifact.

    New artifacts write collision-qualified storage keys directly. Historical
    artifacts wrote only semantic names, so if two markers share a name at
    different addresses, upgrade both to ``<name>@0x<address>`` while reading.
    """
    text = c_path.read_text(errors="replace")
    out: dict[str, tuple[int, str]] = {}
    matches = list(FUNCTION_MARKER.finditer(text))
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        marker_key = m.group(1)
        address = int(m.group(2), 16)
        code = text[start:end].strip()
        semantic_name, encoded_address = parse_function_storage_key(marker_key)

        if encoded_address is not None:
            out[marker_key] = (address, code)
            continue

        same_name = [
            (key, value)
            for key, value in out.items()
            if parse_function_storage_key(key)[0] == semantic_name
        ]
        duplicate = next(
            (key for key, (existing_address, _code) in same_name if existing_address == address),
            None,
        )
        if duplicate is not None:
            out[duplicate] = (address, code)
            continue
        if not same_name:
            out[semantic_name] = (address, code)
            continue

        for key, (existing_address, existing_code) in same_name:
            if key == semantic_name:
                del out[key]
                out[f"{semantic_name}@0x{existing_address:x}"] = (
                    existing_address,
                    existing_code,
                )
        out[f"{semantic_name}@0x{address:x}"] = (address, code)
    return out


def function_addresses(c_path: Path) -> dict[str, int]:
    """``storage key -> address`` parsed from a decompiled artifact."""
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
