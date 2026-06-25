#!/usr/bin/env python
"""Compile every sailr project at every opt level into a persistent dir.

Build-verification driver: runs the real ``compile_project`` code path for
each (project, opt) pair in parallel, persisting binaries under
``<out>/<opt>/<project>/compiled/`` so a later ``--skip-compile`` decompile
+ evaluate run can reuse them. Prints a per-target binary/.i count table and
writes ``compile_report.json`` for the orchestrator.
"""

from __future__ import annotations

import json
import multiprocessing
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from decbench.models.project import OptimizationLevel, Project
from decbench.pipeline.compile import compile_project

# Use 'spawn': fresh worker processes with no inherited lock state. The default
# 'fork' deadlocks when a worker is forked while the parent's pool-management
# thread holds an internal mutex (observed: late workers wedged on futex_wait
# with downloads done but never extracted).
_MP = multiprocessing.get_context("spawn")

PROJECTS_DIR = Path("projects/sailr")
OPT_LEVELS = [
    OptimizationLevel.O0,
    OptimizationLevel.O2,
    OptimizationLevel.O2_NOINLINE,
]


def _count_outputs(out_dir: Path, opt: str, name: str) -> tuple[int, int]:
    """Return (elf_binary_count, i_file_count) in the compiled dir."""
    import struct

    compiled = out_dir / opt / name / "compiled"
    if not compiled.is_dir():
        return (0, 0)
    elfs = 0
    for entry in compiled.iterdir():
        if not entry.is_file() or entry.is_symlink():
            continue
        if entry.suffix in (".i", ".o", ".a", ".s", ".c", ".h"):
            continue
        try:
            with open(entry, "rb") as f:
                if f.read(4) != b"\x7fELF":
                    continue
                f.seek(16)
                if struct.unpack("<H", f.read(2))[0] in (2, 3):
                    elfs += 1
        except (OSError, struct.error):
            continue
    i_files = len(list(compiled.glob("*.i")))
    return (elfs, i_files)


def _build_one(toml_path: str, opt_value: str, out_dir: str) -> dict:
    """Worker: compile one (project, opt) pair. Never raises."""
    name = Path(toml_path).stem
    start = time.time()
    try:
        project = Project.from_toml(Path(toml_path))
        opt = OptimizationLevel(opt_value)
        results = compile_project(project, Path(out_dir), opt, clean=True)
        successes = sum(1 for r in results if getattr(r, "success", False))
        elfs, i_files = _count_outputs(Path(out_dir), opt_value, name)
        errs = [
            (r.error_message or "")[:300]
            for r in results
            if not getattr(r, "success", False) and getattr(r, "error_message", None)
        ]
        return {
            "project": name,
            "opt": opt_value,
            "elf_binaries": elfs,
            "i_files": i_files,
            "compile_results": len(results),
            "successes": successes,
            "errors": errs[:3],
            "seconds": round(time.time() - start, 1),
            "ok": elfs > 0,
        }
    except Exception as e:  # noqa: BLE001 - report, never crash the pool
        return {
            "project": name,
            "opt": opt_value,
            "elf_binaries": 0,
            "i_files": 0,
            "compile_results": 0,
            "successes": 0,
            "errors": [f"{type(e).__name__}: {e}", traceback.format_exc()[-400:]],
            "seconds": round(time.time() - start, 1),
            "ok": False,
        }


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results/sailr_full")
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 78
    only = set(sys.argv[3:])  # optional: restrict to these project stems

    out_dir.mkdir(parents=True, exist_ok=True)
    tomls = sorted(PROJECTS_DIR.glob("*.toml"))
    if only:
        tomls = [t for t in tomls if t.stem in only]

    tasks = [(str(t), opt.value, str(out_dir)) for t in tomls for opt in OPT_LEVELS]
    print(
        f"Compiling {len(tomls)} projects x {len(OPT_LEVELS)} opts "
        f"= {len(tasks)} builds, {workers} workers -> {out_dir}",
        flush=True,
    )

    reports: list[dict] = []
    done = 0
    with ProcessPoolExecutor(max_workers=workers, mp_context=_MP) as ex:
        futs = {ex.submit(_build_one, *t): t for t in tasks}
        for fut in as_completed(futs):
            r = fut.result()
            reports.append(r)
            done += 1
            flag = "OK " if r["ok"] else "FAIL"
            print(
                f"[{done}/{len(tasks)}] {flag} {r['project']:18s} {r['opt']:11s} "
                f"elf={r['elf_binaries']:<4d} i={r['i_files']:<4d} "
                f"{r['seconds']:.0f}s"
                + (f"  ERR: {r['errors'][0][:120]}" if not r["ok"] and r["errors"] else ""),
                flush=True,
            )

    # Per-project summary across opt levels
    by_proj: dict[str, dict[str, int]] = {}
    for r in reports:
        by_proj.setdefault(r["project"], {})[r["opt"]] = r["elf_binaries"]

    print("\n==== PER-PROJECT ELF BINARY COUNTS ====", flush=True)
    print(f"{'project':20s} {'O0':>6s} {'O2':>6s} {'O2-noinline':>12s}", flush=True)
    fully_ok, partial, broken = [], [], []
    for proj in sorted(by_proj):
        c = by_proj[proj]
        o0, o2, on = c.get("O0", 0), c.get("O2", 0), c.get("O2-noinline", 0)
        print(f"{proj:20s} {o0:6d} {o2:6d} {on:12d}", flush=True)
        if o0 and o2 and on:
            fully_ok.append(proj)
        elif o0 or o2 or on:
            partial.append(proj)
        else:
            broken.append(proj)

    print(
        f"\nFully OK ({len(fully_ok)}): {', '.join(fully_ok)}", flush=True
    )
    print(f"Partial ({len(partial)}): {', '.join(partial)}", flush=True)
    print(f"BROKEN ({len(broken)}): {', '.join(broken)}", flush=True)

    report_path = out_dir / "compile_report.json"
    report_path.write_text(json.dumps(reports, indent=2))
    print(f"\nReport written to {report_path}", flush=True)
    print("COMPILE_DRIVER_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
