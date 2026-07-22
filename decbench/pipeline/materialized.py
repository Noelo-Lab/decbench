"""Load a *materialized* dataset tree back into pipeline objects.

``decbench-data materialize <config> --dest TREE`` (the consumer CLI shipped in
the dataset repo) lays a downloaded config out as a decbench results tree:

    TREE/<opt>/<project>/compiled/<binary>              # the published binaries
    TREE/<opt>/<project>/decompiled/<dec>_<stem>.c      # published decompiled C
    TREE/<opt>/<project>/source_cfgs/<stem>.json        # published source CFGs

Such a tree has **no ``.i`` preprocessed sources** (the dataset ships
header-stripped ``.c`` per project, not per-binary ``.i``), so the evaluate
stage cannot re-extract source CFGs — instead it consumes the published CFG
JSONs via :func:`load_source_cfgs` (rebuilt with
:func:`decbench.publish.cfg_export.rebuild_cfg`, which preserves the
``is_entrypoint``/``is_exitpoint`` flags GED reads). And it has no in-memory
:class:`DecompilationResult` objects, so :func:`discover_decompilations`
reconstructs them from the stored ``<dec>_<stem>.c`` artifacts (markers ``//
Function: <name> @ 0x<addr>``) plus the sibling ``.toml`` metadata.

Reconstruction limits: the ``.c``/``.toml`` artifacts carry code, addresses and
failure lists but NOT ``VariableInfo`` — so GED and byte_match evaluate fully,
while type_match (which needs recovered variables) reports errors per function.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.results_tree import OPT_LEVELS, compiled_dir, resolve_binary

if TYPE_CHECKING:
    from networkx import DiGraph

logger = logging.getLogger(__name__)

# Same marker the decompile stage writes and rebuild_function_data.py parses.
MARKER = re.compile(r"^// Function: (\S+) @ (0x[0-9a-fA-F]+)\s*$", re.M)


def load_decompilation(
    c_path: Path,
    dec_name: str,
    binary_path: Path,
) -> DecompilationResult:
    """Rebuild a :class:`DecompilationResult` from a stored ``<dec>_<stem>.c``.

    Function bodies come from the marker-delimited ``.c``; version/timing/failed
    functions come from the sibling ``.toml`` when present (leniently parsed).
    """
    text = c_path.read_text(errors="replace")
    functions: dict[str, FunctionDecompilation] = {}
    marks = list(MARKER.finditer(text))
    for i, m in enumerate(marks):
        start = m.end()
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        code = text[start:end].strip()
        name = m.group(1)
        functions[name] = FunctionDecompilation(
            name=name,
            address=int(m.group(2), 16),
            decompiled_code=code,
            line_count=len(code.splitlines()),
        )

    version: str | None = None
    total_time = 0.0
    timeout = False
    failed: list[str] = []
    toml_path = c_path.with_suffix(".toml")
    if toml_path.is_file():
        try:
            import toml

            meta = toml.load(toml_path)
            version = meta.get("version")
            total_time = float(meta.get("total_time", 0.0) or 0.0)
            timeout = bool(meta.get("timeout", False))
            failed = list(meta.get("failed_functions", []) or [])
        except Exception as exc:  # noqa: BLE001 - metadata is best-effort
            logger.warning("Unparseable artifact metadata %s: %s", toml_path, exc)

    return DecompilationResult(
        binary_path=binary_path,
        binary_name=binary_path.stem,
        decompiler=DecompilerMetadata(
            decompiler_name=dec_name,
            decompiler_version=version,
            total_time_seconds=total_time,
            timeout_occurred=timeout,
            failed_functions=failed,
            extra={"via": "materialized-artifact"},
        ),
        functions=functions,
        output_dir=c_path.parent,
    )


def _split_artifact_name(
    filename: str,
    decompilers: list[str] | None,
) -> tuple[str, str] | None:
    """Split ``<dec>_<stem>.c`` -> ``(dec, stem)``.

    Known decompiler names (when given) are matched as prefixes first, so a
    ``dec`` containing ``_`` still resolves; otherwise split on the first ``_``.
    """
    base = filename[:-2]  # strip ".c"
    if decompilers:
        for dec in sorted(decompilers, key=len, reverse=True):
            if base.startswith(dec + "_"):
                return dec, base[len(dec) + 1 :]
        return None
    if "_" not in base:
        return None
    dec, stem = base.split("_", 1)
    return dec, stem


def discover_decompilations(
    output_dir: Path,
    optimization_levels: list,
    project_names: list[str] | None = None,
    decompilers: list[str] | None = None,
) -> dict:
    """Load every stored decompiled artifact under a results tree.

    Returns the same nested shape as ``pipeline.decompile.decompile_projects``:
    ``{project: {opt: {binary_stem: {dec: DecompilationResult}}}}`` — so the
    evaluate stage and the function-data builder consume it unchanged.
    """
    results: dict = {}
    for opt in optimization_levels:
        opt_value = opt.value if hasattr(opt, "value") else str(opt)
        opt_dir = output_dir / opt_value
        if not opt_dir.is_dir():
            continue
        for proj_dir in sorted(p for p in opt_dir.iterdir() if p.is_dir()):
            project = proj_dir.name
            if project_names is not None and project not in project_names:
                continue
            dec_dir = proj_dir / "decompiled"
            if not dec_dir.is_dir():
                continue
            comp_dir = compiled_dir(output_dir, opt_value, project)
            loaded = 0
            for c_path in sorted(dec_dir.glob("*.c")):
                split = _split_artifact_name(c_path.name, decompilers)
                if split is None:
                    continue
                dec, stem = split
                if decompilers is not None and dec not in decompilers:
                    continue
                binary = resolve_binary(comp_dir, stem) or (comp_dir / stem)
                try:
                    dr = load_decompilation(c_path, dec, binary)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to load artifact %s: %s", c_path, exc)
                    continue
                results.setdefault(project, {}).setdefault(opt, {}).setdefault(stem, {})[dec] = dr
                loaded += 1
            if loaded:
                logger.info("Loaded %d artifacts for %s/%s", loaded, project, opt_value)
    return results


def load_source_cfgs(
    tree_root: Path,
    opt: str,
    project: str,
) -> dict[str, dict[str, DiGraph]] | None:
    """Rebuild ``{binary_stem: {function: DiGraph}}`` from published CFG JSONs.

    Reads ``<tree_root>/<opt>/<project>/source_cfgs/<stem>.json`` (written by
    ``decbench-data materialize``). Returns ``None`` when the directory does not
    exist so callers can fall back to ``.i`` extraction.
    """
    import json

    from decbench.publish.cfg_export import rebuild_cfg

    cfg_dir = tree_root / opt / project / "source_cfgs"
    if not cfg_dir.is_dir():
        return None
    by_binary: dict[str, dict[str, DiGraph]] = {}
    for json_path in sorted(cfg_dir.glob("*.json")):
        try:
            data = json.loads(json_path.read_text())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unparseable source-CFG JSON %s: %s", json_path, exc)
            continue
        funcs = data.get("functions", {}) or {}
        by_binary[json_path.stem] = {name: rebuild_cfg(fc) for name, fc in funcs.items()}
    return by_binary or None


def discover_tree_projects(tree_root: Path) -> tuple[list[str], list[str]]:
    """Return ``(project_names, opt_levels)`` present in a materialized tree."""
    opts = [o for o in OPT_LEVELS if (tree_root / o).is_dir()]
    projects: set[str] = set()
    for opt in opts:
        for p in (tree_root / opt).iterdir():
            if p.is_dir() and (p / "compiled").is_dir():
                projects.add(p.name)
    return sorted(projects), opts
