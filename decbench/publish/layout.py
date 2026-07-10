"""Filesystem layout for the published DecBench dataset (contract §1-§4, §6).

This module turns an on-disk results tree into the published dataset layout:
copy the compiled binaries, strip + content-deduplicate the project sources,
reorganize the decompiled ``.c`` artifacts under one folder per decompiler, and
write the per-config manifests, the filtered ``function_results.json`` scores,
the top-level ``dataset.toml`` index, and the LFS ``.gitattributes`` rules.

It anchors on ``function_results.json`` (loaded as
:class:`decbench.models.function_data.FunctionData` and tagged with dataset
presets via :func:`decbench.scoring.datasets.assign_datasets`) and iterates its
``(project, opt, binary-stem)`` groups. Source-CFG generation is a separate,
gated step (:mod:`decbench.publish.cfg_export`); this module only *references*
the CFG JSONs that already exist on disk so a no-``--cfgs`` run fully succeeds.
Everything is idempotent/resumable: file copies are skipped when the destination
already exists with a matching size.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from collections.abc import Callable, Iterable
from pathlib import Path

import toml
from pydantic import BaseModel, Field

from decbench.models.function_data import BinaryGroup, FunctionData
from decbench.scoring.datasets import PRESETS, assign_datasets
from decbench.scoring.subset import SubsetManifest, filter_function_data
from decbench.utils.cfg import strip_system_headers
from decbench.utils.results_tree import (
    OPT_LEVELS,
    compiled_dir,
    decompiled_dir,
    resolve_binary,
)

logger = logging.getLogger(__name__)

# Normative constants from the publishing contract.
DATASET_NAME = "decbench-dataset"
DATASET_REPO_ID = "noelo-lab/decbench-dataset"
DEFAULT_CONFIGS = ["tiny", "hard", "hard-inlined", "unoptimized", "full"]
_FULL = "full"

Logger = Callable[[str], None]


# --------------------------------------------------------------------------- #
# Manifest models (contract §3). Written as plain JSON via ``model_dump``.
# --------------------------------------------------------------------------- #
class ProjectSources(BaseModel):
    """The stripped translation units published for one project."""

    sources: list[str] = Field(default_factory=list, description="repo-relative source paths")


class BinaryManifestEntry(BaseModel):
    """One published binary in a config manifest (contract §3)."""

    project: str
    opt: str
    binary: str = Field(..., description="stem — join key into function_results.json")
    binary_path: str = Field(..., description="repo-relative path to the real file")
    sha256: str
    size: int
    source_cfg_path: str | None = Field(
        default=None, description="repo-relative source-CFG JSON (only when written)"
    )
    results: dict[str, str] = Field(
        default_factory=dict, description="decompiler -> repo-relative decompiled .c (present only)"
    )
    functions: list[str] = Field(
        default_factory=list, description="functions this config selected from this binary"
    )


class ConfigManifest(BaseModel):
    """A per-config download manifest (contract §3)."""

    config: str
    description: str
    dataset_repo: str = DATASET_REPO_ID
    created: str
    decompilers: list[str]
    metrics: list[str]
    function_count: int
    binary_count: int
    scores: str
    projects: dict[str, ProjectSources] = Field(default_factory=dict)
    binaries: list[BinaryManifestEntry] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Internal per-group record produced by the copy walk.
# --------------------------------------------------------------------------- #
class GroupRecord(BaseModel):
    """A processed ``(project, opt, binary-stem)`` group, on disk in the dest."""

    project: str
    opt: str
    binary: str
    binary_path: str
    sha256: str
    size: int
    results: dict[str, str] = Field(default_factory=dict)
    all_functions: list[str] = Field(default_factory=list)
    config_functions: dict[str, list[str]] = Field(default_factory=dict)
    source_cfg_path: str | None = None


class LayoutResult(BaseModel):
    """The outcome of the copy walk plus running byte/section counters."""

    groups: list[GroupRecord] = Field(default_factory=list)
    project_sources: dict[str, list[str]] = Field(default_factory=dict)
    bytes: dict[str, int] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)
    unresolved: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Small filesystem helpers (mirror decbench.dataset patterns).
# --------------------------------------------------------------------------- #
def _sha256_of(path: Path) -> str:
    """SHA-256 of a file's bytes (streamed)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_file(src: Path, dst: Path) -> int:
    """Copy ``src`` -> ``dst`` (hardlink first), skip if same-size dest exists.

    Returns the number of bytes written (0 when skipped).
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    size = src.stat().st_size
    if dst.exists() and dst.stat().st_size == size:
        return 0
    if dst.exists():
        dst.unlink()
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)
    return size


def _relpath(path: Path, dest: Path) -> str:
    """Repo-relative POSIX path of ``path`` under ``dest``."""
    return path.relative_to(dest).as_posix()


# --------------------------------------------------------------------------- #
# Group selection.
# --------------------------------------------------------------------------- #
def load_dataset(results_dir: Path, seed: int | None = None) -> FunctionData:
    """Load ``function_results.json`` and tag every record with dataset presets."""
    fd = FunctionData.from_json(results_dir / "function_results.json")
    assign_datasets(fd, seed=seed)
    return fd


def select_groups(
    fd: FunctionData,
    configs: Iterable[str],
    max_binaries: int | None = None,
) -> list[BinaryGroup]:
    """Groups to process: those with >=1 function tagged by a requested config.

    ``full`` tags every record, so requesting it selects every group. The first
    ``max_binaries`` (in dataset order) are kept for fast, targeted self-tests.
    """
    wanted = set(configs)
    selected: list[BinaryGroup] = []
    for group in fd.groups:
        if any(wanted.intersection(f.datasets) for f in group.functions):
            selected.append(group)
    if max_binaries is not None:
        selected = selected[:max_binaries]
    return selected


# --------------------------------------------------------------------------- #
# Sources: strip system headers, dedup by stripped content, one dir per project.
# --------------------------------------------------------------------------- #
def build_project_sources(
    root: Path,
    dest: Path,
    project: str,
    write: bool = True,
) -> tuple[list[str], int]:
    """Publish (or discover) a project's stripped, deduplicated source TUs.

    Collects the project's ``.i`` files from every opt level's ``compiled/``
    dir, strips inlined system headers, deduplicates by stripped content, and
    writes each unique unit as ``sources/<project>/<tu>.c`` (``<tu>`` = the
    ``.i`` basename). When two units share a basename but differ in content the
    later one is disambiguated with a short content hash so nothing is lost.

    When ``write`` is False the sources are assumed already published and the
    existing ``sources/<project>/*.c`` files are listed instead. Returns
    ``(repo_relative_paths, bytes_written)``.
    """
    out_dir = dest / "sources" / project
    if not write:
        existing = (
            sorted(_relpath(p, dest) for p in out_dir.glob("*.c")) if out_dir.is_dir() else []
        )
        return existing, 0

    content_to_path: dict[str, str] = {}
    used_names: set[str] = set()
    written_bytes = 0
    for opt in OPT_LEVELS:
        comp = compiled_dir(root, opt, project)
        if not comp.is_dir():
            continue
        for i_path in sorted(comp.glob("*.i")):
            stripped = strip_system_headers(i_path.read_text(errors="replace"))
            sha = hashlib.sha256(stripped.encode("utf-8", "replace")).hexdigest()
            if sha in content_to_path:
                continue
            name = f"{i_path.stem}.c"
            if name in used_names:
                name = f"{i_path.stem}.{sha[:8]}.c"
            used_names.add(name)
            target = out_dir / name
            data = stripped.encode("utf-8", "replace")
            if not (target.exists() and target.stat().st_size == len(data)):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                written_bytes += len(data)
            content_to_path[sha] = _relpath(target, dest)

    return sorted(content_to_path.values()), written_bytes


# --------------------------------------------------------------------------- #
# Copy walk: binaries + decompiled results + sources.
# --------------------------------------------------------------------------- #
def copy_artifacts(
    root: Path,
    dest: Path,
    fd: FunctionData,
    groups: list[BinaryGroup],
    configs: Iterable[str],
    *,
    do_binaries: bool = True,
    do_results: bool = True,
    do_sources: bool = True,
    log: Logger = print,
) -> LayoutResult:
    """Copy binaries, decompiled results, and sources for ``groups``.

    Groups whose binary cannot be resolved on disk are skipped (and logged), so
    the resulting index — and every manifest built from it — only ever
    references files that were actually written.
    """
    configs = list(configs)
    result = LayoutResult(
        bytes={"binaries": 0, "results": 0, "sources": 0},
        counts={"binaries": 0, "results": 0, "sources": 0, "unresolved": 0},
    )

    for group in groups:
        opt, project, stem = group.opt_level, group.project, group.binary
        real = resolve_binary(compiled_dir(root, opt, project), stem)
        if real is None:
            result.unresolved.append(f"{project}::{opt}::{stem}")
            result.counts["unresolved"] += 1
            log(f"[skip] unresolved binary {project}/{opt}/{stem}")
            continue

        bin_dst = dest / "binaries" / opt / project / real.name
        if do_binaries:
            result.bytes["binaries"] += _copy_file(real, bin_dst)
        result.counts["binaries"] += 1

        # Decompiled results -> results/<dec>/<opt>/<project>/<stem>.c (+ .toml).
        results_map: dict[str, str] = {}
        dec_dir = decompiled_dir(root, opt, project)
        for dec in fd.decompilers:
            src_c = dec_dir / f"{dec}_{stem}.c"
            dst_c = dest / "results" / dec / opt / project / f"{stem}.c"
            if do_results and src_c.is_file():
                result.bytes["results"] += _copy_file(src_c, dst_c)
                src_toml = dec_dir / f"{dec}_{stem}.toml"
                if src_toml.is_file():
                    dst_toml = dst_c.with_suffix(".toml")
                    result.bytes["results"] += _copy_file(src_toml, dst_toml)
            if dst_c.is_file():
                results_map[dec] = _relpath(dst_c, dest)
        result.counts["results"] += len(results_map)

        all_fns = [f.function for f in group.functions]
        config_fns = {
            cfg: [f.function for f in group.functions if cfg in f.datasets] for cfg in configs
        }
        result.groups.append(
            GroupRecord(
                project=project,
                opt=opt,
                binary=stem,
                binary_path=_relpath(bin_dst, dest),
                sha256=_sha256_of(real),
                size=real.stat().st_size,
                results=results_map,
                all_functions=all_fns,
                config_functions=config_fns,
            )
        )

    # Sources: once per project appearing in the processed index.
    for project in sorted({g.project for g in result.groups}):
        paths, nbytes = build_project_sources(root, dest, project, write=do_sources)
        result.project_sources[project] = paths
        result.bytes["sources"] += nbytes
        result.counts["sources"] += len(paths)

    return result


def attach_source_cfgs(
    dest: Path,
    layout: LayoutResult,
    cfg_paths: dict[tuple[str, str, str], str],
) -> None:
    """Record each group's source-CFG JSON, but only when it exists on disk."""
    for group in layout.groups:
        key = (group.opt, group.project, group.binary)
        rel = cfg_paths.get(key)
        if rel is None:
            rel = _relpath(
                dest
                / "pipeline_data"
                / "source_cfgs"
                / group.opt
                / group.project
                / f"{group.binary}.json",
                dest,
            )
        if (dest / rel).is_file():
            group.source_cfg_path = rel
        else:
            group.source_cfg_path = None


# --------------------------------------------------------------------------- #
# Config manifests + filtered scores (contract §3).
# --------------------------------------------------------------------------- #
def _preset_description(name: str) -> str:
    for preset in PRESETS:
        if preset.name == name:
            return preset.description
    return ""


def write_config_manifest(
    dest: Path,
    fd: FunctionData,
    layout: LayoutResult,
    config: str,
    created: str,
    log: Logger = print,
) -> dict[str, int]:
    """Write ``configs/<config>/manifest.json`` (+ filtered scores) from the index.

    Only groups that carry >=1 function tagged with ``config`` are listed, and
    only files present on disk are referenced. The ``full`` config points at the
    master ``results/function_results.json``; the others get a filtered copy.
    """
    entries: list[BinaryManifestEntry] = []
    projects: dict[str, ProjectSources] = {}
    fn_total = 0
    subset_fns: list[dict] = []

    for group in layout.groups:
        fns = group.config_functions.get(config, [])
        if not fns:
            continue
        entries.append(
            BinaryManifestEntry(
                project=group.project,
                opt=group.opt,
                binary=group.binary,
                binary_path=group.binary_path,
                sha256=group.sha256,
                size=group.size,
                source_cfg_path=group.source_cfg_path,
                results=dict(group.results),
                functions=fns,
            )
        )
        fn_total += len(fns)
        if group.project not in projects:
            projects[group.project] = ProjectSources(
                sources=layout.project_sources.get(group.project, [])
            )
        for fn in fns:
            subset_fns.append(
                {"project": group.project, "opt": group.opt, "binary": group.binary, "function": fn}
            )

    if config == _FULL:
        scores_ref = "results/function_results.json"
    else:
        scores_ref = f"configs/{config}/function_results.json"
        filtered = filter_function_data(
            fd, SubsetManifest(method="preset", k=0.0, threshold=0.0, functions=subset_fns)
        )
        filtered.to_json(dest / "configs" / config / "function_results.json")

    manifest = ConfigManifest(
        config=config,
        description=_preset_description(config),
        created=created,
        decompilers=list(fd.decompilers),
        metrics=list(fd.metrics),
        function_count=fn_total,
        binary_count=len(entries),
        scores=scores_ref,
        projects=projects,
        binaries=entries,
    )
    manifest_path = dest / "configs" / config / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w") as f:
        json.dump(manifest.model_dump(mode="json", exclude_none=True), f, indent=2)
    log(f"[config] {config}: {len(entries)} binaries, {fn_total} functions")
    return {"binaries": len(entries), "functions": fn_total}


def write_master_scores(
    root: Path,
    dest: Path,
    fd: FunctionData,
    layout: LayoutResult,
    partial: bool,
    log: Logger = print,
) -> None:
    """Write the master ``results/function_results.json`` for the ``full`` config.

    A whole-tree run copies the original file verbatim (preserving samples /
    hardest / compile rates); a partial run writes scores filtered to the
    binaries actually processed so the master never over-references disk.
    """
    out = dest / "results" / "function_results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    if not partial:
        _copy_file(root / "function_results.json", out)
    else:
        subset_fns = [
            {"project": g.project, "opt": g.opt, "binary": g.binary, "function": fn}
            for g in layout.groups
            for fn in g.all_functions
        ]
        filtered = filter_function_data(
            fd, SubsetManifest(method="preset", k=0.0, threshold=0.0, functions=subset_fns)
        )
        filtered.to_json(out)
    sb = root / "scoreboard.toml"
    if sb.is_file():
        _copy_file(sb, dest / "results" / "scoreboard.toml")
    log(f"[master] wrote results/function_results.json ({'filtered' if partial else 'verbatim'})")


# --------------------------------------------------------------------------- #
# Top-level index (contract §4).
# --------------------------------------------------------------------------- #
def write_dataset_toml(
    dest: Path,
    fd: FunctionData,
    layout: LayoutResult,
    configs: list[str],
    config_counts: dict[str, dict[str, int]],
    log: Logger = print,
) -> None:
    """Write ``dataset.toml``: dataset metadata + one table per built config."""
    n_projects = len({g.project for g in layout.groups})
    n_binaries = len(layout.groups)
    n_functions = sum(len(g.all_functions) for g in layout.groups)

    data: dict = {
        "dataset": {
            "name": DATASET_NAME,
            "repo_id": DATASET_REPO_ID,
            "opt_levels": list(OPT_LEVELS),
            "decompilers": list(fd.decompilers),
            "metrics": list(fd.metrics),
            "projects": n_projects,
            "binaries": n_binaries,
            "functions": n_functions,
        },
        "configs": {},
    }
    for config in configs:
        counts = config_counts.get(config, {"binaries": 0, "functions": 0})
        scores = (
            "results/function_results.json"
            if config == _FULL
            else f"configs/{config}/function_results.json"
        )
        data["configs"][config] = {
            "description": _preset_description(config),
            "function_count": counts["functions"],
            "binary_count": counts["binaries"],
            "manifest": f"configs/{config}/manifest.json",
            "scores": scores,
        }

    with open(dest / "dataset.toml", "w") as f:
        toml.dump(data, f)
    log(f"[index] dataset.toml: {n_projects} projects, {n_binaries} binaries, {n_functions} funcs")


# --------------------------------------------------------------------------- #
# .gitattributes (contract §6).
# --------------------------------------------------------------------------- #
_GITATTRIBUTES_LINES = [
    "binaries/** filter=lfs diff=lfs merge=lfs -text",
    "results/**/*.c -filter -diff -merge text",
    "results/function_results.json filter=lfs diff=lfs merge=lfs -text",
]


def extend_gitattributes(dest: Path, log: Logger = print) -> None:
    """Append the publisher's LFS/text rules to ``.gitattributes`` idempotently.

    Never rewrites or reorders HF-managed lines already present; only appends the
    rules from :data:`_GITATTRIBUTES_LINES` that are not already there.
    """
    path = dest / ".gitattributes"
    existing = path.read_text().splitlines() if path.is_file() else []
    present = {line.strip() for line in existing}
    to_add = [line for line in _GITATTRIBUTES_LINES if line not in present]
    if not to_add:
        return
    lines = list(existing)
    if lines and lines[-1].strip():
        lines.append("")
    lines.append("# added by decbench.publish")
    lines.extend(to_add)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    log(f"[gitattributes] appended {len(to_add)} rule(s)")


# --------------------------------------------------------------------------- #
# Manifest + index driver (called after the copy walk and optional CFG step).
# --------------------------------------------------------------------------- #
def write_manifests_and_index(
    root: Path,
    dest: Path,
    fd: FunctionData,
    layout: LayoutResult,
    configs: list[str],
    created: str,
    *,
    partial: bool,
    log: Logger = print,
) -> None:
    """Write all config manifests, the master scores, dataset.toml, gitattributes."""
    config_counts: dict[str, dict[str, int]] = {}
    for config in configs:
        if config == _FULL:
            write_master_scores(root, dest, fd, layout, partial=partial, log=log)
        config_counts[config] = write_config_manifest(dest, fd, layout, config, created, log=log)
    write_dataset_toml(dest, fd, layout, configs, config_counts, log=log)
    extend_gitattributes(dest, log=log)
