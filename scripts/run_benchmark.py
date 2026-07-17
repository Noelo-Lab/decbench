#!/usr/bin/env python
"""Resilient full-benchmark driver: decompile + evaluate already-compiled binaries.

Unlike ``decbench run`` (which only persists at the very end), this driver
processes one project at a time and checkpoints decompile + evaluate results
to ``<out>/checkpoints/<project>.pkl`` after each project, so a multi-hour run
over hundreds of binaries survives a crash and resumes where it left off.

Usage:
    run_benchmark.py <out_dir> [-- only project1 project2 ...]

Env:
    GHIDRA_INSTALL_DIR must point at the Ghidra install for the ghidra backend.
    DECBENCH_DECOMPILERS (comma list) overrides the default "angr,ghidra".
    DECBENCH_WORKERS overrides worker count.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import pickle
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path

# Force 'spawn' for ALL pools (including those created inside the decompile /
# evaluate pipeline). 'fork' deadlocks here because the parent imports angr
# (which starts threads) before forking workers — a forked child can wedge on a
# mutex the parent held at fork time. spawn starts clean processes instead.
# Must be set before any pool is created and before angr is imported below.
if multiprocessing.get_start_method(allow_none=True) != "spawn":
    multiprocessing.set_start_method("spawn", force=True)

# Register backends + metrics
import decbench.metrics  # noqa: F401,E402
from decbench.models.decompilation import DecompilationResult, DecompilerMetadata
from decbench.models.project import OptimizationLevel, Project
from decbench.pipeline.evaluate import evaluate_project
from decbench.pipeline.executor import PipelineExecutor, PipelineConfig
from decbench.scoring.aggregator import aggregate_results
from decbench.scoring.function_data_builder import build_function_data
from decbench.scoring.scoreboard import build_scoreboard
from decbench.utils.cfg import extract_cfgs_from_source

# All benchmark project dirs (top-level *.toml only; cps/disabled/ excluded).
# sailr = x86, cps = ARM firmware, malware = ARM/PE. Decompilation runs on the
# host for all of them; byte_match abstains where the matching recompile
# toolchain is absent (ARM/PE), so GED + type_match carry cps/malware.
PROJECT_DIRS = [Path("projects/sailr"), Path("projects/cps"), Path("projects/malware")]


def gather_tomls() -> list[Path]:
    out: list[Path] = []
    for d in PROJECT_DIRS:
        out.extend(sorted(d.glob("*.toml")))
    return sorted(out, key=lambda p: p.stem)


OPT_LEVELS = [
    OptimizationLevel.O0,
    OptimizationLevel.O2,
    OptimizationLevel.O2_NOINLINE,
]
DECOMPILERS = (os.environ.get("DECBENCH_DECOMPILERS") or "angr,ghidra").split(",")
WORKERS = int(os.environ.get("DECBENCH_WORKERS") or "40")
# Hard per-(binary, decompiler) wall-clock budget. angr's decompiler can spin at
# 100% CPU for many minutes on a single binary; without this a few binaries would
# dominate the whole run. Binaries that exceed it are recorded as decompiler
# timeouts (no functions credited) — an honest data point about decompiler speed.
DECOMPILE_TIMEOUT = int(os.environ.get("DECBENCH_DECOMPILE_TIMEOUT") or "300")
# Per-decompiler wall-clock budget (seconds). FAIRNESS PRINCIPLE: every backend
# gets a budget large enough to finish the largest source-function set, so a
# slow-but-working backend is not truncated (and counted as thousands of
# failures) while a faster one finishes. Small binaries finish in seconds, so the
# large defaults only bite the ~10 big binaries (bash, openssh, coreutils, big
# ARM firmware).
#   - angr/phoenix: the angr engine runs ~15-20s/function; a big binary legit
#     needs up to ~1h. angr previously got 3600s only via a one-off scoped rerun;
#     phoenix (same engine) was left at 300s and truncated on 50/806 binaries.
#   - ghidra/binja: fast per function but a few large binaries still overrun 300s.
#   - kuna: a Ghidra port that emits its JSON only at the very end (a kill yields
#     ZERO functions), so it needs a budget above its slowest binary (~450s on
#     bash) — 900s. Its per-FUNCTION hang guard is now --max-fn-seconds (passed by
#     the backend), so a pathological function can't hang the batch; the
#     process-group SIGKILL stays as a belt-and-suspenders leak guard.
DECOMPILER_TIMEOUT = {
    "kuna": int(os.environ.get("DECBENCH_KUNA_TIMEOUT") or "900"),
    "angr": int(os.environ.get("DECBENCH_ANGR_TIMEOUT") or "3600"),
    "phoenix": int(os.environ.get("DECBENCH_PHOENIX_TIMEOUT") or "3600"),
    "ghidra": int(os.environ.get("DECBENCH_GHIDRA_TIMEOUT") or "1800"),
    "binja": int(os.environ.get("DECBENCH_BINJA_TIMEOUT") or "1800"),
}
_HERE = Path(__file__).resolve().parent
_DECOMPILE_ONE = _HERE / "decompile_one.py"


def _kill_process_group(proc: "subprocess.Popen") -> None:
    """SIGKILL the worker's whole process group.

    The worker is spawned with ``start_new_session=True`` so it leads its own
    group (pgid == pid). Killing the GROUP reaps not just the Python worker but
    every tool it launched (kuna, the Ghidra/kuna JVMs, IDA, ...). A plain
    ``proc.kill()`` (what ``subprocess.run(timeout=)`` does) kills only the direct
    child, letting a hung decompiler ORPHAN and spin forever — which is exactly
    how kuna leaked 9 processes burning 100% CPU for 4+ hours.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
    try:
        proc.wait(timeout=15)
    except Exception:  # noqa: BLE001
        pass


def project_source_functions(binary_path: Path, source_stems: set[str]) -> dict[int, str]:
    """Map ``low_pc -> name`` for functions DEFINED in the project's own sources.

    Reads the binary's DWARF and keeps DW_TAG_subprogram entries that have a
    low_pc (i.e. are defined in this binary) AND whose decl_file basename stem
    is one of ``source_stems`` (the project's compiled translation units, e.g.
    grep's ``src/*.c``). This excludes bundled gnulib/system-header functions —
    matching SAILR's "evaluate the project's own code" intent — and shrinks the
    decompile/evaluate workload by ~1-2 orders of magnitude on gnulib-heavy
    binaries. The address (DWARF low_pc, in ELF-file space) is the key so the
    decompile filter + result re-labeling can work on a STRIPPED binary (no
    symbols), where decompilers only know functions by address. Returns an empty
    map if there is no usable DWARF (caller then falls back to all functions).
    """
    if not source_stems:
        return {}
    # binfmt.dwarf_info reads DWARF from ELF *or* PE (the MinGW malware targets),
    # so this filter works for x86/ARM ELF and PE alike.
    try:
        from decbench.utils import binfmt

        dw = binfmt.dwarf_info(binary_path)
    except Exception:  # noqa: BLE001
        return {}
    if dw is None:
        return {}
    addr2name: dict[int, str] = {}
    try:
        for cu in dw.iter_CUs():
            lp = dw.line_program_for_CU(cu)
            # DW_AT_decl_file indexing is 1-based pre-DWARF5 (entry 0 unused) and
            # 0-based in DWARF5 (entry 0 = primary source); prepend a placeholder
            # only for pre-v5 so the index lines up either way.
            version = 4
            if lp is not None:
                version = lp.header.get("version", cu.header.get("version", 4))
            files: list = [] if version >= 5 else [None]
            if lp is not None:
                for fe in lp["file_entry"]:
                    nm = fe.name
                    files.append(nm.decode() if isinstance(nm, bytes) else nm)
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                attrs = die.attributes
                if "DW_AT_low_pc" not in attrs or "DW_AT_name" not in attrs:
                    continue
                fi = attrs.get("DW_AT_decl_file")
                if fi is None or not (0 <= fi.value < len(files)) or files[fi.value] is None:
                    continue
                base = os.path.basename(files[fi.value])
                stem = base[:-2] if base.endswith(".c") else base
                # Match the decl-file stem to a compiled source unit. Exact match
                # for sailr/cps (basename.i <-> basename.c); also accept the
                # object-prefixed naming some targets use (e.g. malware's
                # `mydoom-main.i` <-> decl `main.c`), where the source stem is a
                # `<prefix>-<decl>` / `<prefix>_<decl>` suffix.
                if stem in source_stems or any(
                    s.endswith("-" + stem) or s.endswith("_" + stem) for s in source_stems
                ):
                    nm = attrs["DW_AT_name"].value
                    addr2name[int(attrs["DW_AT_low_pc"].value)] = (
                        nm.decode() if isinstance(nm, bytes) else nm
                    )
    except Exception:  # noqa: BLE001
        return {}
    return addr2name


def extract_source_cfgs(project: Project, opt: OptimizationLevel) -> dict[str, dict]:
    """Extract source CFGs for every preprocessed source, keyed by .i stem.

    Runs once per (project, opt) and is reused for BOTH the decompile filter
    (function names) and the GED metric (the CFGs themselves), so Joern only
    parses each source file once.
    """
    sources = project.preprocessed_sources.get(opt, {})
    out: dict[str, dict] = {}
    if not sources:
        return out
    if len(sources) == 1:
        ((name, i_path),) = sources.items()
        try:
            out[name] = extract_cfgs_from_source(i_path) or {}
        except Exception:  # noqa: BLE001
            out[name] = {}
        return out
    with ProcessPoolExecutor(max_workers=WORKERS) as pool:
        futs = {
            pool.submit(extract_cfgs_from_source, i_path): name for name, i_path in sources.items()
        }
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                out[name] = fut.result() or {}
            except Exception:  # noqa: BLE001
                out[name] = {}
    return out


def _stripped_copy(binary: Path, strip_dir: Path) -> Path:
    """A fully-stripped (no DWARF, no symbol table) copy of ``binary``.

    Decompilers must NEVER see debug info or symbols — that is unwarranted help
    (DWARF types/vars inflate type_match; symbols hand them function boundaries
    and names). We compile with ``-g`` for the evaluation ground truth, but the
    decompiler only ever gets this stripped copy (same filename, so the artifact
    naming/stem is unchanged). Cached by mtime. ``strip --strip-all`` handles ELF
    of any arch and PE (BFD); we fall back through objcopy variants.
    """
    strip_dir.mkdir(parents=True, exist_ok=True)
    out = strip_dir / binary.name
    if out.exists() and out.stat().st_mtime >= binary.stat().st_mtime:
        return out
    shutil.copy2(binary, out)
    for cmd in (
        ["strip", "--strip-all", str(out)],
        ["objcopy", "--strip-all", str(out), str(out)],
        ["objcopy", "--strip-debug", str(out), str(out)],
    ):
        try:
            if subprocess.run(cmd, capture_output=True).returncode == 0:
                break
        except Exception:  # noqa: BLE001
            continue
    return out


def _relabel_to_dwarf(
    result: DecompilationResult, addr2name: dict[int, str], unstripped: Path
) -> None:
    """Re-symbolize a stripped-binary decompilation for evaluation.

    The decompiler analysed the stripped binary, so it named functions by address
    (``FUN_00102530`` / ``sub_...``). Map each back to the DWARF name at its
    address — renaming in BOTH the code (so GED's Joern parse keys by the right
    name) and the function key — and point eval at the UNSTRIPPED (DWARF) binary.
    This is pure bookkeeping so name-based eval/GED line up; the decompiler got no
    help (its analysis ran on the stripped binary).
    """
    from decbench.decompilers.raw import common

    # PE: pre-fix decompiles stored function addresses as bare RVAs (0x1110)
    # because elf_min_vaddr returned 0 for PE; DWARF low_pc is the linked VA
    # (ImageBase + RVA). Adding the ImageBase recovers the DWARF key. For ELF the
    # base is the min PT_LOAD vaddr, which is already folded into fd.address, so
    # ``addr + base`` is just a harmless non-matching candidate.
    base = common.elf_min_vaddr(unstripped)
    new_funcs: dict[str, object] = {}
    for fd in list(result.functions.values()):
        # Resolve the DWARF name, tolerating two address-space mismatches:
        #  - ARM/Thumb: angr/phoenix report a Thumb entry with the LSB set (odd),
        #    while DWARF low_pc is even (0x8008001 vs 0x8008000).
        #  - PE ImageBase: an RVA-based address needs + base to reach the VA.
        addr = int(fd.address)
        dn = (
            addr2name.get(addr)
            or addr2name.get(addr & ~1)
            or addr2name.get(addr + base)
            or addr2name.get((addr + base) & ~1)
        )
        if dn and dn != fd.name:
            fd.decompiled_code = re.sub(r"\b" + re.escape(fd.name) + r"\b", dn, fd.decompiled_code)
            fd.name = dn
        # Keep the larger body if two addresses collapse to one DWARF name
        # (duplicate low_pc), so a real body is not clobbered by a trivial stub.
        prev = new_funcs.get(fd.name)
        if prev is None or len(fd.decompiled_code or "") >= len(getattr(prev, "decompiled_code", "") or ""):
            new_funcs[fd.name] = fd
    result.functions = new_funcs  # type: ignore[assignment]
    result.binary_path = unstripped


def _timed_decompile(
    binary: Path, dec_name: str, out_dir: Path, names_file: str
) -> DecompilationResult:
    """Decompile one binary via a timed, killable subprocess.

    Returns the unpickled DecompilationResult, or a 'timeout'/'error' result if
    the subprocess overran DECOMPILE_TIMEOUT or failed. ``names_file`` is a JSON
    list of source function names to restrict to ("NONE" = all functions).
    """
    pkl = out_dir / f"{dec_name}_{binary.stem}.result.pkl"
    cmd = [
        sys.executable,
        str(_DECOMPILE_ONE),
        str(binary),
        dec_name,
        str(out_dir),
        str(pkl),
        names_file,
    ]
    timeout_s = DECOMPILER_TIMEOUT.get(dec_name, DECOMPILE_TIMEOUT)
    failure = ""
    timed_out = False
    proc = None
    try:
        # start_new_session so the worker leads its own process group and we can
        # kill the WHOLE group (worker + kuna/JVM/IDA/... it spawned) on timeout.
        proc = subprocess.Popen(
            cmd,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            rc = proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            failure = f"timeout>{timeout_s}s"
            timed_out = True
            _kill_process_group(proc)  # reap the worker AND the tool it spawned
            rc = None
        if not timed_out:
            if rc == 0 and pkl.exists():
                try:
                    result = pickle.loads(pkl.read_bytes())
                    pkl.unlink(missing_ok=True)
                    return result
                except Exception as e:  # noqa: BLE001
                    failure = f"unpickle: {e}"
            else:
                failure = f"exit {rc}"
    except Exception as e:  # noqa: BLE001
        failure = f"{type(e).__name__}: {e}"
    finally:
        # Belt-and-suspenders: never leave a tool subprocess (esp. a hung kuna)
        # orphaned and spinning, whatever path we exited on.
        if proc is not None and proc.poll() is None:
            _kill_process_group(proc)

    # On timeout/error, try to recover whatever the worker checkpointed: a
    # partial decompilation (e.g. angr got 12/40 functions before the kill) is
    # far more useful than nothing.
    partial = None
    if pkl.exists():
        try:
            partial = pickle.loads(pkl.read_bytes())
        except Exception:  # noqa: BLE001
            partial = None
    pkl.unlink(missing_ok=True)
    if partial is not None and partial.functions:
        partial.decompiler.extra = {
            **(partial.decompiler.extra or {}),
            "failure": failure,
            "recovered_partial": True,
        }
        return partial

    return DecompilationResult(
        binary_path=binary,
        binary_name=binary.stem,
        decompiler=DecompilerMetadata(
            decompiler_name=dec_name,
            failed_functions=["all"],
            extra={"failure": failure, "timed_out": timed_out},
        ),
    )


def decompile_project_timed(
    project: Project,
    out_dir: Path,
    opt: OptimizationLevel,
    source_fn_map: dict[str, dict[int, str]],
    decompilers: list[str] | None = None,
) -> tuple[dict, dict[str, int]]:
    """Decompile all of a project's binaries at one opt level, with timeouts.

    Concurrency is managed by a thread pool whose threads each block on a
    decompile subprocess (the work happens in the child, so the GIL is free).
    ``source_fn_map`` maps binary stem -> {low_pc: name} for the project's own
    source functions. The decompiler is run on a STRIPPED copy (no debug info /
    symbols) and restricted to those ADDRESSES; results are then re-labeled with
    the DWARF names and pointed back at the unstripped binary for evaluation.
    ``decompilers`` (default: the global set) lets callers run a SUBSET — used
    for incremental runs that add/redo only one or two decompilers.
    Returns (results_dict binary->dec->DecompilationResult, stats).
    """
    decs = decompilers if decompilers is not None else DECOMPILERS
    binaries = project.compiled_binaries.get(opt, [])
    by_stem = {b.stem: b for b in binaries}
    dec_out = out_dir / opt.value / project.name / "decompiled"
    dec_out.mkdir(parents=True, exist_ok=True)
    strip_dir = out_dir / opt.value / project.name / "stripped"

    results: dict[str, dict[str, DecompilationResult]] = {b.stem: {} for b in binaries}
    stats = {"ok": 0, "partial": 0, "timeout": 0, "error": 0, "filtered": 0}
    tasks = [(b, d) for b in binaries for d in decs]
    if not tasks:
        return results, stats

    # Per binary: a stripped copy for the decompiler + a JSON of the target
    # ADDRESSES (the decompiler sees no names, so we filter/match by address).
    names_dir = Path(tempfile.mkdtemp(prefix="decaddrs_"))
    addr_files: dict[str, str] = {}
    stripped: dict[str, Path] = {}
    for b in binaries:
        stripped[b.stem] = _stripped_copy(b, strip_dir)
        amap = source_fn_map.get(b.stem) or {}
        if amap:
            nf = names_dir / f"{b.stem}.json"
            nf.write_text(json.dumps(sorted(amap.keys())))
            addr_files[b.stem] = str(nf)
            stats["filtered"] += 1
        else:
            addr_files[b.stem] = "NONE"

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futs = {
                pool.submit(_timed_decompile, stripped[b.stem], d, dec_out, addr_files[b.stem]): (
                    b.stem,
                    d,
                )
                for b, d in tasks
            }
            for fut in as_completed(futs):
                stem, dec_name = futs[fut]
                res = fut.result()
                # Re-symbolize from the stripped decompile + point eval at the
                # unstripped (DWARF) binary; rewrite the .c artifact to match.
                orig = by_stem.get(stem)
                amap = source_fn_map.get(stem) or {}
                if orig is not None:
                    if amap:
                        _relabel_to_dwarf(res, amap, orig)
                    else:
                        res.binary_path = orig
                    try:
                        res.to_c_file(dec_out / f"{dec_name}_{stem}.c")
                    except Exception:  # noqa: BLE001
                        pass
                results[stem][dec_name] = res
                extra = res.decompiler.extra or {}
                failure = extra.get("failure", "")
                if not failure:
                    stats["ok"] += 1
                elif extra.get("recovered_partial"):
                    stats["partial"] += 1
                elif failure.startswith("timeout"):
                    stats["timeout"] += 1
                else:
                    stats["error"] += 1
    finally:
        shutil.rmtree(names_dir, ignore_errors=True)
    return results, stats


def discover(project: Project, out_dir: Path) -> int:
    """Populate project.compiled_binaries/preprocessed_sources from disk.

    Returns the total number of binaries discovered across opt levels.
    """
    cfg = PipelineConfig(output_dir=out_dir, optimization_levels=OPT_LEVELS)
    ex = PipelineExecutor(cfg)
    ex._discover_existing_binaries([project], out_dir)
    return sum(len(v) for v in project.compiled_binaries.values())


def _present_decompilers(decompile_data: dict) -> set[str]:
    """Set of decompiler ids already present in a checkpoint's decompile dict
    (``{opt: {binary: {dec: result}}}``)."""
    decs: set[str] = set()
    for opt_d in (decompile_data or {}).values():
        for bin_d in (opt_d or {}).values():
            decs.update(bin_d.keys())
    return decs


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        print(
            "Usage: run_benchmark.py [RESULTS_DIR] [-- project ...]\n\n"
            "Decompile + evaluate + report over a compiled results tree.\n"
            "  RESULTS_DIR   output tree (default results/sailr_full)\n"
            "  -- project    limit to the named projects\n\n"
            "Env: DECBENCH_DECOMPILERS, DECBENCH_REDO_DECOMPILERS, DECBENCH_WORKERS,\n"
            "     DECBENCH_DECOMPILE_TIMEOUT, DECBENCH_{KUNA,ANGR,PHOENIX,GHIDRA,BINJA}_TIMEOUT,\n"
            "     DECBENCH_KUNA_MAX_FN_SECONDS, DECBENCH_DECOMPILE_ONLY, GHIDRA_INSTALL_DIR."
        )
        return 0
    out_dir = Path(args[0]) if args else Path("results/sailr_full")
    only = set(args[2:]) if len(args) > 2 and args[1] == "--" else set()

    # Incremental runs: re-run ONLY decompilers missing from a checkpoint, plus
    # any listed in DECBENCH_REDO_DECOMPILERS (force-redo even if present, e.g.
    # after fixing a backend). Existing decompilers' results are kept & merged.
    redo = {d for d in (os.environ.get("DECBENCH_REDO_DECOMPILERS") or "").split(",") if d}

    ckpt_dir = out_dir / "checkpoints"
    ckpt_dir.mkdir(parents=True, exist_ok=True)

    tomls = gather_tomls()
    if only:
        tomls = [t for t in tomls if t.stem in only]

    projects = [Project.from_toml(t) for t in tomls]
    print(
        f"Benchmark: {len(projects)} projects x {len(OPT_LEVELS)} opts, "
        f"decompilers={DECOMPILERS} -> {out_dir}",
        flush=True,
    )

    # Accumulated results across all projects (for final aggregation).
    all_decompile: dict = {}
    all_evaluate: dict = {}

    for project in projects:
        name = project.name
        ckpt = ckpt_dir / f"{name}.pkl"
        existing: dict | None = None
        if ckpt.exists():
            try:
                existing = pickle.loads(ckpt.read_bytes())
            except Exception as e:  # noqa: BLE001
                print(f"[resume] {name}: bad checkpoint ({e}); recomputing", flush=True)
                existing = None

        present = _present_decompilers(existing["decompile"]) if existing else set()
        # Decompilers to (re)run for this project: those requested but absent,
        # plus any force-redo. If the checkpoint already has everything, resume.
        to_run = [d for d in DECOMPILERS if d not in present or d in redo]
        if existing is not None and not to_run:
            all_decompile[name] = existing["decompile"]
            all_evaluate[name] = existing["evaluate"]
            print(f"[resume] {name}: complete ({sorted(present)})", flush=True)
            continue

        nbin = discover(project, out_dir)
        if nbin == 0:
            print(f"[skip] {name}: no compiled binaries discovered", flush=True)
            all_decompile[name] = (existing or {}).get("decompile", {})
            all_evaluate[name] = (existing or {}).get("evaluate", {})
            (ckpt_dir / f"{name}.pkl").write_bytes(
                pickle.dumps({"decompile": all_decompile[name], "evaluate": all_evaluate[name]})
            )
            continue

        t0 = time.time()
        # Start from existing results so prior decompilers are preserved; the
        # per-opt merge below adds/overwrites only the `to_run` decompilers.
        proj_dec: dict = dict(existing["decompile"]) if existing else {}
        proj_eval: dict = dict(existing["evaluate"]) if existing else {}
        print(f"[{name}] running decompilers={to_run} (have={sorted(present)})", flush=True)
        for opt in OPT_LEVELS:
            if opt not in project.compiled_binaries or not project.compiled_binaries[opt]:
                proj_dec[opt] = {}
                proj_eval[opt] = {}
                continue
            # 1) Compute the per-binary decompile filter from DWARF FIRST (cheap
            #    DWARF read) — the project's OWN src functions, not the .i universe.
            #    SKIP binaries whose filter is empty: those have no usable debug
            #    info (e.g. some LTO'd cps firmware), so the only alternative is
            #    decompiling ALL ~10k+ library/RTOS functions, which times out
            #    every decompiler and produces noisy, un-typed results. Skipping
            #    keeps the benchmark to functions we can actually attribute, and
            #    avoids the (very slow) source-CFG extraction for skipped projects.
            ts = time.time()
            source_stems = set(project.preprocessed_sources.get(opt, {}).keys())
            src_fn_names: dict[str, dict[int, str]] = {}
            kept_binaries = []
            for b in project.compiled_binaries[opt]:
                fns = project_source_functions(b, source_stems)
                if fns:
                    src_fn_names[b.stem] = fns
                    kept_binaries.append(b)
            skipped = len(project.compiled_binaries[opt]) - len(kept_binaries)
            if not kept_binaries:
                print(
                    f"[{name}/{opt.value}] SKIP: no binary has a usable DWARF "
                    f"source filter ({skipped} binaries skipped) in "
                    f"{time.time() - ts:.0f}s",
                    flush=True,
                )
                proj_dec.setdefault(opt, {})
                proj_eval.setdefault(opt, {})
                continue
            project.compiled_binaries[opt] = kept_binaries
            n = len(kept_binaries)

            # 2) Extract source CFGs (for GED) only for the kept binaries' project.
            src_cfgs = extract_source_cfgs(project, opt)
            n_filt = sum(len(v) for v in src_fn_names.values())
            print(
                f"[{name}/{opt.value}] {len(src_cfgs)} sources; DWARF source-fn "
                f"filter = {n_filt} funcs across {len(kept_binaries)} binaries "
                f"({skipped} skipped: no DWARF) in {time.time() - ts:.0f}s",
                flush=True,
            )

            # 2) Decompile, restricted to source functions where known. Only the
            #    `to_run` decompilers (incremental); merge into any existing.
            td = time.time()
            print(
                f"[{name}/{opt.value}] decompiling {n} binaries x {to_run} "
                f"(timeout {DECOMPILE_TIMEOUT}s)...",
                flush=True,
            )
            try:
                dec, dstats = decompile_project_timed(
                    project, out_dir, opt, src_fn_names, decompilers=to_run
                )
            except Exception as e:  # noqa: BLE001
                print(f"[{name}/{opt.value}] decompile ERROR: {e}", flush=True)
                dec, dstats = {}, {}
            merged_dec = proj_dec.get(opt, {})
            for b_stem, dmap in dec.items():
                merged_dec.setdefault(b_stem, {}).update(dmap)
            proj_dec[opt] = merged_dec
            print(
                f"[{name}/{opt.value}] decompiled in {time.time() - td:.0f}s "
                f"(ok={dstats.get('ok', 0)} partial={dstats.get('partial', 0)} "
                f"timeout={dstats.get('timeout', 0)} error={dstats.get('error', 0)} "
                f"filtered={dstats.get('filtered', 0)})",
                flush=True,
            )

            # 3) Evaluate, reusing the source CFGs (no re-extraction).
            # DECBENCH_DECOMPILE_ONLY: skip the Joern GED eval here (a downstream
            # reeval_ged pass re-scores every decompiler from the fresh .c anyway, so
            # evaluating here is redundant double-Joern — the load hog). Decompile-only.
            te = time.time()
            if os.environ.get("DECBENCH_DECOMPILE_ONLY") == "1":
                print(f"[{name}/{opt.value}] evaluating... SKIPPED (DECOMPILE_ONLY)", flush=True)
                ev = {}
            else:
                print(f"[{name}/{opt.value}] evaluating...", flush=True)
                try:
                    ev = evaluate_project(
                        project,
                        dec,
                        out_dir,
                        opt,
                        None,
                        parallel=True,
                        workers=WORKERS,
                        precomputed_source_cfgs=src_cfgs,
                    )
                except Exception as e:  # noqa: BLE001
                    print(f"[{name}/{opt.value}] evaluate ERROR: {e}", flush=True)
                    ev = {}
            merged_eval = proj_eval.get(opt, {})
            for b_stem, emap in ev.items():
                merged_eval.setdefault(b_stem, {}).update(emap)
            proj_eval[opt] = merged_eval
            print(f"[{name}/{opt.value}] evaluated in {time.time() - te:.0f}s", flush=True)

        all_decompile[name] = proj_dec
        all_evaluate[name] = proj_eval
        (ckpt_dir / f"{name}.pkl").write_bytes(
            pickle.dumps({"decompile": proj_dec, "evaluate": proj_eval})
        )
        nfuncs = sum(
            r.function_count
            for opt_d in proj_dec.values()
            for bin_d in opt_d.values()
            for r in bin_d.values()
        )
        print(
            f"[done] {name}: {nfuncs} funcs decompiled in {time.time() - t0:.0f}s "
            f"(checkpointed)",
            flush=True,
        )

    # ---- Final aggregation + scoreboard + interactive report ----
    print("\nAggregating + building scoreboard...", flush=True)
    aggregated = aggregate_results(all_evaluate)
    scoreboard = build_scoreboard(
        aggregated,
        projects=[p.name for p in projects],
        optimization_levels=[o.value for o in OPT_LEVELS],
        decompilers=DECOMPILERS,
    )
    fd = build_function_data(all_evaluate, projects, all_decompile)
    # Populate the report's code-carrying extras: dataset tags (unoptimized/optimized/...),
    # side-by-side Compare samples (with source), Hardest functions, and
    # per-decompiler compile rates. Without this the report has no Compare view,
    # no Hardest list, and no dataset selector.
    try:
        from decbench.scoring.report_extras import attach_extras

        attach_extras(
            fd,
            evaluation_results=all_evaluate,
            decompile_results=all_decompile,
            projects=projects,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[warn] attach_extras failed: {e}", flush=True)
    fd_path = out_dir / "function_results.json"
    fd.to_json(fd_path)
    scoreboard.raw_data_path = fd_path
    sb_path = out_dir / "scoreboard.toml"
    scoreboard.to_toml(sb_path)

    from decbench.scoring.scoreboard import render_scoreboard_text
    from decbench.rendering.html import render_html_report

    print(render_scoreboard_text(scoreboard), flush=True)
    report_path = out_dir / "report.html"
    render_html_report(scoreboard, report_path, fd)

    print(f"\nScoreboard:  {sb_path}", flush=True)
    print(f"Func data:   {fd_path}", flush=True)
    print(f"HTML report: {report_path}", flush=True)
    print(
        f"Totals: {aggregated.total_binaries} binary-results, "
        f"{aggregated.total_functions} distinct functions",
        flush=True,
    )
    print("RUN_DRIVER_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
