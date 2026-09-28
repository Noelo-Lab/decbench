#!/usr/bin/env python
"""Small-dataset end-to-end driver: validate the v2 features quickly.

Unlike ``run_benchmark.py`` (the full resilient sailr driver), this runs a tiny
slice — a few functions of one or two already-compiled binaries — through the
*new* machinery so the whole stack can be exercised in a couple of minutes:

  * native decompiler backends: ``angr``, ``ghidra@12.0``, ``ghidra@12.1``
  * **multiple versions** of one decompiler as distinct, comparable columns
  * **metric caching** (a 2nd identical run is served from the content cache)
  * the redesigned **report** with the *hardest functions* and *historical*
    line charts (history is built from the two real Ghidra versions)

It never recompiles: it reuses binaries under
``<results>/<opt>/<project>/compiled/`` (so it also demonstrates the
re-run-without-recompiling goal).

Usage:
    python scripts/run_small.py [results_dir] [project] [opts]
Env:
    DECBENCH_SMALL_DECOMPILERS  default "angr,ghidra@12.0,ghidra@12.1"
    DECBENCH_SMALL_MAXFUNCS     default 4 (functions per binary)
    DECBENCH_SMALL_MAXBINS      default 1 (binaries per opt)
    DECBENCH_SMALL_TIMEOUT      default 3600 (seconds per binary)
    GHIDRA_INSTALL_DIR          fallback Ghidra for an unversioned spec
"""

from __future__ import annotations

import contextlib
import json
import os
import pickle
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import decbench.decompilers  # noqa: E402,F401  (register backends)
from decbench.caching import get_cache  # noqa: E402
from decbench.decompilers.limits import (  # noqa: E402
    BINARY_TIMEOUT_SECONDS,
    cleanup_docker_scope,
    kill_resource_scope,
    require_resource_scopes,
    resource_scope_command,
)
from decbench.models.decompilation import DecompilationResult  # noqa: E402
from decbench.models.project import OptimizationLevel, Project, ProjectConfig  # noqa: E402
from decbench.pipeline.evaluate import evaluate_decompilation  # noqa: E402
from decbench.rendering.html import render_html_report  # noqa: E402
from decbench.scoring.aggregator import aggregate_results  # noqa: E402
from decbench.scoring.function_data_builder import build_function_data  # noqa: E402
from decbench.scoring.report_extras import attach_extras  # noqa: E402
from decbench.scoring.scoreboard import build_scoreboard, render_scoreboard_text  # noqa: E402
from decbench.utils.cfg import extract_cfgs_from_source  # noqa: E402
from decbench.utils.langs import preprocessed_by_stem  # noqa: E402


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            if f.read(4) != b"\x7fELF":
                return False
            f.seek(16)
            import struct

            return struct.unpack("<H", f.read(2))[0] in (2, 3)
    except OSError:
        return False


def _discover(compiled: Path) -> tuple[list[Path], dict[str, Path]]:
    binaries = sorted(p for p in compiled.iterdir() if p.is_file() and _is_elf(p))
    sources = preprocessed_by_stem(compiled)
    return binaries, sources


def _decompile_subproc(
    binary: Path, spec: str, out_dir: Path, names: set[str], timeout: int
) -> DecompilationResult | None:
    """Decompile one (binary, spec) in an ISOLATED subprocess via decompile_one.py.

    Isolation is required for correctness here: two Ghidra versions cannot share
    one process (pyghidra binds a single JVM to one install), and idalib/JVM
    global state would otherwise leak between backends.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as nf:
        json.dump(sorted(names), nf)
        names_json = nf.name
    pkl = out_dir / f"{binary.stem}.{spec.replace('@', '_')}.pkl"
    cmd = [
        sys.executable,
        str(REPO / "scripts" / "decompile_one.py"),
        str(binary),
        spec,
        str(out_dir),
        str(pkl),
        names_json,
        str(timeout),
    ]
    cmd, scope_unit = resource_scope_command(cmd, timeout)
    process = None
    cleanup_containers = False
    try:
        process = subprocess.Popen(cmd, cwd=str(REPO), start_new_session=True)
        process.wait(timeout=timeout + 2)
        cleanup_containers = process.returncode != 0
    except subprocess.TimeoutExpired:
        cleanup_containers = True
        print(f"    [{spec}] TIMEOUT after {timeout}s (recovering partial)")
    finally:
        if process is not None and process.poll() is None:
            cleanup_containers = True
            with contextlib.suppress(Exception):
                kill_resource_scope(scope_unit)
            with contextlib.suppress(Exception):
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            with contextlib.suppress(Exception):
                process.wait(timeout=15)
        if cleanup_containers:
            with contextlib.suppress(Exception):
                cleanup_docker_scope(scope_unit)
        Path(names_json).unlink(missing_ok=True)
    if pkl.exists():
        try:
            return pickle.loads(pkl.read_bytes())
        except Exception as e:  # noqa: BLE001
            print(f"    [{spec}] could not load result: {e}")
    return None


def _binary_func_names(binary: Path) -> set[str]:
    """Names of defined functions in the binary's symbol table (STT_FUNC)."""
    names: set[str] = set()
    try:
        from elftools.elf.elffile import ELFFile

        with open(binary, "rb") as f:
            elf = ELFFile(f)
            for secname in (".symtab", ".dynsym"):
                sec = elf.get_section_by_name(secname)
                if sec is None:
                    continue
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] and sym.name:
                        names.add(sym.name)
    except Exception:  # noqa: BLE001
        pass
    return names


def _source_cfgs(sources: dict[str, Path]) -> dict:
    merged: dict = {}
    for name, ipath in sources.items():
        try:
            for fn, cfg in (extract_cfgs_from_source(ipath) or {}).items():
                merged.setdefault(fn, cfg)
        except Exception as e:  # noqa: BLE001
            print(f"    [warn] source CFGs failed for {name}: {e}")
    return merged


def main() -> int:
    try:
        require_resource_scopes()
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    results_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "results" / "sailr_full"
    project_name = sys.argv[2] if len(sys.argv) > 2 else "gzip"
    opts = sys.argv[3].split(",") if len(sys.argv) > 3 else ["O0"]
    specs = os.environ.get("DECBENCH_SMALL_DECOMPILERS", "angr,ghidra@12.0,ghidra@12.1").split(",")
    max_funcs = int(os.environ.get("DECBENCH_SMALL_MAXFUNCS", "4"))
    max_bins = int(os.environ.get("DECBENCH_SMALL_MAXBINS", "1"))
    out_dir = REPO / "results" / "small_validate"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"=== small validation: {project_name} {opts} specs={specs} ===")
    project = Project(config=ProjectConfig(name=project_name, labels=["sailr"]))

    evaluation: dict = {project_name: {}}
    decompiled: dict = {project_name: {}}

    for opt_str in opts:
        opt = OptimizationLevel(opt_str)
        compiled = results_dir / opt_str / project_name / "compiled"
        if not compiled.is_dir():
            print(f"[skip] no compiled dir: {compiled}")
            continue
        binaries, sources = _discover(compiled)
        if not binaries:
            print(f"[skip] no binaries in {compiled}")
            continue
        binaries = binaries[:max_bins]
        print(f"[{opt_str}] {len(binaries)} binary(ies); extracting source CFGs...")
        src_cfgs = _source_cfgs(sources)
        bin_funcs = _binary_func_names(binaries[0])
        common = sorted(set(src_cfgs) & bin_funcs) if bin_funcs else sorted(src_cfgs)
        targets = common[:max_funcs] or sorted(src_cfgs)[:max_funcs]
        names = set(targets)
        print(
            f"[{opt_str}] source CFGs={len(src_cfgs)} binary funcs={len(bin_funcs)}; "
            f"targeting {targets}"
        )

        evaluation[project_name].setdefault(opt, {})
        decompiled[project_name].setdefault(opt, {})

        for binary in binaries:
            stem = binary.stem
            evaluation[project_name][opt].setdefault(stem, {})
            decompiled[project_name][opt].setdefault(stem, {})
            for spec in specs:
                t0 = time.time()
                res = _decompile_subproc(
                    binary,
                    spec,
                    out_dir / opt_str / spec.replace("@", "_"),
                    names,
                    timeout=int(
                        os.environ.get("DECBENCH_SMALL_TIMEOUT", str(BINARY_TIMEOUT_SECONDS))
                    ),
                )
                if res is None:
                    print(f"    [{spec}] decompile produced no result")
                    continue
                dec_id = res.decompiler.decompiler_name
                metric_results = evaluate_decompilation(
                    res,
                    src_cfgs,
                    preprocessed_sources=list(sources.values()),
                )
                evaluation[project_name][opt][stem][dec_id] = metric_results
                decompiled[project_name][opt][stem][dec_id] = res
                got = res.successful_count
                scored = {
                    m: f"{r.mean:.2f}" for m, r in metric_results.items() if r.mean is not None
                }
                dt = time.time() - t0
                print(f"    [{dec_id}] {got} funcs in {dt:.0f}s scored={scored}")

    aggregated = aggregate_results(evaluation)
    scoreboard = build_scoreboard(
        aggregated,
        projects=[project_name],
        optimization_levels=opts,
        decompilers=aggregated.decompilers,
        name="DecBench (small validation)",
    )
    function_data = build_function_data(evaluation, [project], decompiled)

    history_inputs = []
    for dec_id, ds in scoreboard.decompiler_scores.items():
        if "@" not in dec_id:
            continue
        base, version = dec_id.split("@", 1)
        history_inputs.append(
            {
                "decompiler": base,
                "version": version,
                "date": datetime.now().strftime("%Y-%m-%d"),
                "scores": {m: ms.perfect_percentage for m, ms in ds.metric_scores.items()},
                "overall": ds.overall_perfect_percentage,
            }
        )
    function_data.decompiler_versions = {
        dec_id: (dec_id.split("@", 1)[1] if "@" in dec_id else "")
        for dec_id in aggregated.decompilers
    }

    attach_extras(
        function_data,
        evaluation_results=evaluation,
        decompile_results=decompiled,
        projects=[project],
        history_inputs=history_inputs or None,
    )

    function_data.to_json(out_dir / "function_results.json")
    scoreboard.to_toml(out_dir / "scoreboard.toml")
    render_html_report(scoreboard, out_dir / "report.html", function_data)

    print("\n" + render_scoreboard_text(scoreboard))
    print(
        f"\nhardest entries: {len(function_data.hardest)}; "
        f"history points: {len(function_data.history)}"
    )
    cache = get_cache("metric")
    print(f"metric cache stats: {cache.stats()}")
    print(f"report: {out_dir / 'report.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
