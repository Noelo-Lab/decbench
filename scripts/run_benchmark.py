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
import shutil
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

PROJECTS_DIR = Path("projects/sailr")
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
_HERE = Path(__file__).resolve().parent
_DECOMPILE_ONE = _HERE / "decompile_one.py"


def project_source_functions(
    binary_path: Path, source_stems: set[str]
) -> set[str]:
    """Names of functions DEFINED in the project's own source files.

    Reads the binary's DWARF and keeps DW_TAG_subprogram entries that have a
    low_pc (i.e. are defined in this binary) AND whose decl_file basename stem
    is one of ``source_stems`` (the project's compiled translation units, e.g.
    grep's ``src/*.c``). This excludes bundled gnulib/system-header functions —
    matching SAILR's "evaluate the project's own code" intent — and shrinks the
    decompile/evaluate workload by ~1-2 orders of magnitude on gnulib-heavy
    binaries. Returns an empty set if there is no usable DWARF (caller then
    falls back to decompiling everything).
    """
    if not source_stems:
        return set()
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:  # noqa: BLE001
        return set()
    names: set[str] = set()
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return set()
            dw = elf.get_dwarf_info()
            for cu in dw.iter_CUs():
                lp = dw.line_program_for_CU(cu)
                files: list = [None]
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
                    if fi is None or fi.value >= len(files) or files[fi.value] is None:
                        continue
                    base = os.path.basename(files[fi.value])
                    stem = base[:-2] if base.endswith(".c") else base
                    if stem in source_stems:
                        nm = attrs["DW_AT_name"].value
                        names.add(nm.decode() if isinstance(nm, bytes) else nm)
    except Exception:  # noqa: BLE001
        return set()
    return names


def extract_source_cfgs(
    project: Project, opt: OptimizationLevel
) -> dict[str, dict]:
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
        (name, i_path), = sources.items()
        try:
            out[name] = extract_cfgs_from_source(i_path) or {}
        except Exception:  # noqa: BLE001
            out[name] = {}
        return out
    with ProcessPoolExecutor(max_workers=WORKERS) as pool:
        futs = {
            pool.submit(extract_cfgs_from_source, i_path): name
            for name, i_path in sources.items()
        }
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                out[name] = fut.result() or {}
            except Exception:  # noqa: BLE001
                out[name] = {}
    return out


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
    failure = ""
    timed_out = False
    try:
        # start_new_session so we can kill the whole group on timeout.
        proc = subprocess.run(
            cmd,
            timeout=DECOMPILE_TIMEOUT,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if proc.returncode == 0 and pkl.exists():
            try:
                result = pickle.loads(pkl.read_bytes())
                pkl.unlink(missing_ok=True)
                return result
            except Exception as e:  # noqa: BLE001
                failure = f"unpickle: {e}"
        else:
            failure = f"exit {proc.returncode}"
    except subprocess.TimeoutExpired:
        failure = f"timeout>{DECOMPILE_TIMEOUT}s"
        timed_out = True
    except Exception as e:  # noqa: BLE001
        failure = f"{type(e).__name__}: {e}"

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
    source_fn_names: dict[str, set[str]],
) -> tuple[dict, dict[str, int]]:
    """Decompile all of a project's binaries at one opt level, with timeouts.

    Concurrency is managed by a thread pool whose threads each block on a
    decompile subprocess (the work happens in the child, so the GIL is free).
    ``source_fn_names`` maps binary stem -> source function names; when a
    binary has a non-empty set, decompilation is restricted to it.
    Returns (results_dict binary->dec->DecompilationResult, stats).
    """
    binaries = project.compiled_binaries.get(opt, [])
    dec_out = out_dir / opt.value / project.name / "decompiled"
    dec_out.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict[str, DecompilationResult]] = {
        b.stem: {} for b in binaries
    }
    stats = {"ok": 0, "partial": 0, "timeout": 0, "error": 0, "filtered": 0}
    tasks = [(b, d) for b in binaries for d in DECOMPILERS]
    if not tasks:
        return results, stats

    # Write per-binary source-function-name files once (shared across decompilers).
    names_dir = Path(tempfile.mkdtemp(prefix="decnames_"))
    names_files: dict[str, str] = {}
    for b in binaries:
        names = source_fn_names.get(b.stem) or set()
        if names:
            nf = names_dir / f"{b.stem}.json"
            nf.write_text(json.dumps(sorted(names)))
            names_files[b.stem] = str(nf)
            stats["filtered"] += 1
        else:
            names_files[b.stem] = "NONE"

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futs = {
                pool.submit(_timed_decompile, b, d, dec_out, names_files[b.stem]):
                    (b.stem, d)
                for b, d in tasks
            }
            for fut in as_completed(futs):
                stem, dec_name = futs[fut]
                res = fut.result()
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


def main() -> int:
    args = sys.argv[1:]
    out_dir = Path(args[0]) if args else Path("results/sailr_full")
    only = set(args[2:]) if len(args) > 2 and args[1] == "--" else set()

    ckpt_dir = out_dir / "checkpoints"
    ckpt_dir.mkdir(parents=True, exist_ok=True)

    tomls = sorted(PROJECTS_DIR.glob("*.toml"))
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
        if ckpt.exists():
            try:
                data = pickle.loads(ckpt.read_bytes())
                all_decompile[name] = data["decompile"]
                all_evaluate[name] = data["evaluate"]
                print(f"[resume] {name}: loaded checkpoint", flush=True)
                continue
            except Exception as e:  # noqa: BLE001
                print(f"[resume] {name}: bad checkpoint ({e}); recomputing", flush=True)

        nbin = discover(project, out_dir)
        if nbin == 0:
            print(f"[skip] {name}: no compiled binaries discovered", flush=True)
            all_decompile[name] = {}
            all_evaluate[name] = {}
            (ckpt_dir / f"{name}.pkl").write_bytes(
                pickle.dumps({"decompile": {}, "evaluate": {}})
            )
            continue

        t0 = time.time()
        proj_dec: dict = {}
        proj_eval: dict = {}
        for opt in OPT_LEVELS:
            if opt not in project.compiled_binaries or not project.compiled_binaries[opt]:
                proj_dec[opt] = {}
                proj_eval[opt] = {}
                continue
            n = len(project.compiled_binaries[opt])

            # 1) Extract source CFGs once (for GED), and compute the per-binary
            #    decompile filter from DWARF (the project's OWN src functions —
            #    NOT the preprocessed .i function universe, which includes every
            #    inlined system/gnulib header and so constrains nothing).
            ts = time.time()
            src_cfgs = extract_source_cfgs(project, opt)
            source_stems = set(project.preprocessed_sources.get(opt, {}).keys())
            src_fn_names: dict[str, set[str]] = {}
            for b in project.compiled_binaries[opt]:
                src_fn_names[b.stem] = project_source_functions(b, source_stems)
            n_filt = sum(len(v) for v in src_fn_names.values())
            print(
                f"[{name}/{opt.value}] {len(src_cfgs)} sources; DWARF source-fn "
                f"filter = {n_filt} funcs across {len(src_fn_names)} binaries "
                f"in {time.time() - ts:.0f}s",
                flush=True,
            )

            # 2) Decompile, restricted to source functions where known.
            td = time.time()
            print(
                f"[{name}/{opt.value}] decompiling {n} binaries x {DECOMPILERS} "
                f"(timeout {DECOMPILE_TIMEOUT}s)...",
                flush=True,
            )
            try:
                dec, dstats = decompile_project_timed(
                    project, out_dir, opt, src_fn_names
                )
            except Exception as e:  # noqa: BLE001
                print(f"[{name}/{opt.value}] decompile ERROR: {e}", flush=True)
                dec, dstats = {}, {}
            proj_dec[opt] = dec
            print(
                f"[{name}/{opt.value}] decompiled in {time.time() - td:.0f}s "
                f"(ok={dstats.get('ok', 0)} partial={dstats.get('partial', 0)} "
                f"timeout={dstats.get('timeout', 0)} error={dstats.get('error', 0)} "
                f"filtered={dstats.get('filtered', 0)})",
                flush=True,
            )

            # 3) Evaluate, reusing the source CFGs (no re-extraction).
            te = time.time()
            print(f"[{name}/{opt.value}] evaluating...", flush=True)
            try:
                ev = evaluate_project(
                    project, dec, out_dir, opt, None, parallel=True,
                    workers=WORKERS, precomputed_source_cfgs=src_cfgs,
                )
            except Exception as e:  # noqa: BLE001
                print(f"[{name}/{opt.value}] evaluate ERROR: {e}", flush=True)
                ev = {}
            proj_eval[opt] = ev
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
