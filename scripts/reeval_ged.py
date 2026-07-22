"""Recompute ONLY the GED metric over an existing results tree, using the new
header-stripped source CFGs (decbench.utils.cfg.strip_system_headers).

Why: GED's source CFGs were extracted from full preprocessed .i files, which are
80-98% inlined system headers — Joern timed out on the big ones, so a huge share
of functions had NO source CFG and silently dropped out of GED (looked like the
decompilers' fault). Stripping the headers (keeping the compiler's own ifdef/macro
resolution) makes Joern fast and complete, so GED can be measured on far more
functions. This re-scores GED to reflect that.

Two stages, both parallel via the 'spawn' context (fork deadlocks once angr's
threads are live):
  A. source CFGs per project (from the O0 .i — source is identical across opt
     levels), cached to <results>/ged_src/<project>.pkl
  B. per (opt, project, binary, dec): parse the stored decompiled .c, compute GED
     for every function whose source CFG exists -> <results>/ged_new.json mapping
     opt::project::binary::dec::func -> {"value": float, "perfect": bool}.

Usage:  python scripts/reeval_ged.py results/full_run [workers] [only-projects...]
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import pickle
import sys
from pathlib import Path

# Every decompiler whose checkpoints may carry stale inline GED. r2dec/dewolf
# joined the tree after the first reeval; a refresh must cover them too, or the
# scoped update_ged overlay leaves their columns on the inline values forever.
# codex/claude-code (sample-set-only) are included for the same reason — their
# slice is tiny (~250 fns each) so covering them costs nearly nothing.
DECOMPILERS = (
    "angr",
    "phoenix",
    "ghidra",
    "ida",
    "binja",
    "kuna",
    "r2dec",
    "dewolf",
    "codex",
    "claude-code",
)
OPT_LEVELS = ("O0", "O2", "O2-noinline")
SRC_OPT = "O0"  # source CFGs are opt-independent; extract once from here


# ---- Stage A: source CFGs per project -------------------------------------
def src_cfgs_for_i(i_path: str) -> tuple[str, dict]:
    """Worker: extract (stripped) source CFGs for one .i file."""
    from decbench.utils.cfg import extract_cfgs_from_source

    try:
        cfgs = extract_cfgs_from_source(Path(i_path)) or {}
    except Exception:  # noqa: BLE001
        cfgs = {}
    return i_path, cfgs


def build_source_cfgs(root: Path, projects: list[str], workers: int) -> Path:
    """Extract + cache source CFGs per project (one pickle each)."""
    src_dir = root / "ged_src"
    src_dir.mkdir(exist_ok=True)
    # Gather .i files per project that still need a source-CFG cache.
    todo: dict[str, list[str]] = {}
    for proj in projects:
        if (src_dir / f"{proj}.pkl").exists():
            continue
        comp = root / SRC_OPT / proj / "compiled"
        if not comp.is_dir():
            continue
        ifiles = [
            str(f)
            for f in sorted(comp.glob("*.i"))
            if "conftest" not in f.name and not f.name.startswith("a-")
        ]
        if ifiles:
            todo[proj] = ifiles
    if not todo:
        print("[ged/src] all source-CFG caches present", flush=True)
        return src_dir
    # path -> project, for routing results
    owner = {p: proj for proj, paths in todo.items() for p in paths}
    all_paths = list(owner)
    print(
        f"[ged/src] extracting source CFGs: {len(all_paths)} files over "
        f"{len(todo)} projects, {workers} workers",
        flush=True,
    )
    # proj -> {translation-unit stem -> {function name -> CFG}}. Keeping source
    # CFGs PER-TU (not a project-wide name-keyed union) lets stage B pair each
    # binary against its OWN translation unit, so per-program functions
    # (main/usage/static helpers) are scored against the right body instead of an
    # arbitrary same-named function from another binary (the collision bug).
    acc: dict[str, dict] = {proj: {} for proj in todo}
    ctx = mp.get_context("spawn")
    done = 0
    with ctx.Pool(processes=workers) as pool:
        for ipath, cfgs in pool.imap_unordered(src_cfgs_for_i, all_paths):
            acc[owner[ipath]][Path(ipath).stem] = cfgs
            done += 1
            if done % 50 == 0 or done == len(all_paths):
                print(f"[ged/src] {done}/{len(all_paths)} source files", flush=True)
    for proj, per_stem in acc.items():
        (src_dir / f"{proj}.pkl").write_bytes(pickle.dumps(per_stem))
        nfun = sum(len(c) for c in per_stem.values())
        print(f"[ged/src] {proj}: {len(per_stem)} TUs, {nfun} source functions cached", flush=True)
    return src_dir


# ---- Stage B: GED per (opt, project, binary, dec) -------------------------
# Per-worker cache: src_pkl path -> (per_stem_dict, best_source_by_name). A pool
# worker handles many (binary, dec) tasks for the same project, so the cross-TU
# best-by-name fallback is computed once per project pickle, not per task.
_SRC_CACHE: dict[str, tuple[dict, dict]] = {}


def _load_src(src_pkl: str) -> tuple[dict, dict]:
    if src_pkl not in _SRC_CACHE:
        from decbench.utils.cfg import best_source_by_name

        per_stem = pickle.loads(Path(src_pkl).read_bytes())
        _SRC_CACHE[src_pkl] = (per_stem, best_source_by_name(per_stem))
    return _SRC_CACHE[src_pkl]


def eval_one(task: tuple[str, str, str, str, str, str]) -> tuple[str, dict]:
    """Worker: recompute GED for every function of one (binary, dec).

    ``task`` = (opt, project, stem, dec, decompiled_c_path, src_pkl_path).
    Resolves each function's source CFG TU-aware (own TU first, cross-TU fallback)
    and DROPS non-finite (empty-prototype/degenerate source) results so they are
    excluded from GED's denominator instead of counting as failures.
    """
    import math
    import re

    opt, project, stem, dec, c_path, src_pkl = task
    from decbench.metrics.ged import GEDMetric
    from decbench.utils.cfg import extract_cfgs_from_source, resolved_source_for_binary

    per_stem, best_by_name = _load_src(src_pkl)
    src_cfgs = resolved_source_for_binary(stem, per_stem, best_by_name)
    try:
        # sanitize_decompiled=True mirrors the live pipeline: clean decompiler-
        # specific C quirks (array-return types, binja @reg, ida __int128) so
        # Joern parses functions it would otherwise drop from GED coverage.
        dec_cfgs = extract_cfgs_from_source(Path(c_path), sanitize_decompiled=True) or {}
    except Exception:  # noqa: BLE001
        dec_cfgs = {}
    # The decompiler's own claim of which functions this artifact holds. Joern
    # keys CFGs by the parsed BODY name; when that differs from the marker name
    # (e.g. ida marker `_rl_set_screen_size` over a `rl_set_screen_size` body)
    # the entry would land on a universe row this decompiler never owned —
    # misattribution, not a score. Only emit functions the markers declare.
    markers = set(
        re.findall(r"^// Function: (\S+) @ 0x[0-9a-fA-F]+\s*$", Path(c_path).read_text(errors="replace"), re.M)
    )
    metric = GEDMetric()
    perfect_val = metric.perfect_value
    out: dict[str, dict] = {}
    for fn, dcfg in dec_cfgs.items():
        if fn not in markers:
            continue
        scfg = src_cfgs.get(fn)
        if scfg is None:
            continue
        try:
            mv = metric.compute_for_function(None, source_cfg=scfg, decompiled_cfg=dcfg)
        except Exception:  # noqa: BLE001
            continue
        if not math.isfinite(mv.value):
            continue
        out[fn] = {"value": float(mv.value), "perfect": bool(mv.value == perfect_val)}
    key = f"{opt}::{project}::{stem}::{dec}"
    return key, out


def build_tasks(root: Path, src_dir: Path, only: set[str] | None) -> list[tuple]:
    tasks = []
    for opt in OPT_LEVELS:
        odir = root / opt
        if not odir.is_dir():
            continue
        for proj in sorted(p for p in odir.iterdir() if p.is_dir()):
            if only and proj.name not in only:
                continue
            src_pkl = src_dir / f"{proj.name}.pkl"
            dec_dir = proj / "decompiled"
            if not (src_pkl.exists() and dec_dir.is_dir()):
                continue
            for dec in DECOMPILERS:
                for cf in sorted(dec_dir.glob(f"{dec}_*.c")):
                    stem = cf.name[len(dec) + 1 : -2]
                    tasks.append((opt, proj.name, stem, dec, str(cf), str(src_pkl)))
    return tasks


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/full_run")
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    only = {a for a in sys.argv[3:] if not a.lstrip("-").isdigit()} or None

    projects = sorted(p.name for p in (root / SRC_OPT).iterdir() if p.is_dir())
    if only:
        projects = [p for p in projects if p in only]
    src_dir = build_source_cfgs(root, projects, workers)

    ckpt_dir = root / "reeval_ged"
    ckpt_dir.mkdir(exist_ok=True)
    tasks = build_tasks(root, src_dir, only)

    def _pending(t: tuple) -> bool:
        ckpt = ckpt_dir / (f"{t[0]}::{t[1]}::{t[2]}::{t[3]}".replace("::", "__") + ".json")
        if not ckpt.exists():
            return True
        # A checkpoint older than its decompiled artifact was computed against a
        # PREVIOUS decompile of this binary — its entries may reference functions
        # the artifact no longer holds (the kuna/betaflight stale-overlay bug).
        return ckpt.stat().st_mtime < Path(t[4]).stat().st_mtime

    pending = [t for t in tasks if _pending(t)]
    print(f"[ged] {len(tasks)} tasks, {len(pending)} pending, {workers} workers", flush=True)

    ctx = mp.get_context("spawn")
    done = 0
    # maxtasksperchild bounds the per-worker _SRC_CACHE: without recycling, a
    # long-lived worker accumulates every project pickle it ever touches
    # (multi-GB each for the big projects) and 40 workers OOM a 256 GB box.
    with ctx.Pool(processes=workers, maxtasksperchild=8) as pool:
        for key, result in pool.imap_unordered(eval_one, pending):
            (ckpt_dir / (key.replace("::", "__") + ".json")).write_text(json.dumps(result))
            done += 1
            if done % 25 == 0 or done == len(pending):
                print(f"[ged] {done}/{len(pending)} (binary,dec) done", flush=True)

    merged: dict[str, dict] = {}
    for cp in ckpt_dir.glob("*.json"):
        key = cp.stem.replace("__", "::")
        for func, v in json.loads(cp.read_text()).items():
            merged[f"{key}::{func}"] = v
    out_path = root / "ged_new.json"
    out_path.write_text(json.dumps(merged))
    perf = sum(1 for v in merged.values() if v.get("perfect"))
    print(
        f"[ged] wrote {out_path} ({len(merged)} funcs, {perf} perfect "
        f"= {100*perf/max(1,len(merged)):.1f}%)",
        flush=True,
    )


if __name__ == "__main__":
    os.environ.setdefault("PYTHONWARNINGS", "ignore")
    main()
