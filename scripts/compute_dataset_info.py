"""Compute the report's Dataset/About-page info and store it in function_results.json.

Produces:
- total_loc + per-project LOC: line counts of the projects' own source (.c files
  the compile stage kept under compiled/; counted once per project from O0 so opt
  levels aren't triple-counted).
- cfg_frontend: source-parse failure rate — how often Cindergraph fails to
  parse a source file, i.e. how much of the GED pipeline is lost to our own
  tooling rather than the decompilers. Measured on a stratified SAMPLE of real
  source .i files (preprocessed units; conftest/autoconf noise excluded).

Software-type categories (parser/webserver/cryptography/malware/firmware) are
derived client-side from per-binary labels, so they aren't stored here.

Usage:  python scripts/compute_dataset_info.py results/full_run [sample_per_project]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from decbench.models.function_data import FunctionData

OPT_FOR_LOC = "O0"
SKIP_C = ("conftest.c",)


def count_loc(root: Path) -> tuple[int, dict[str, int]]:
    """Total + per-project source LOC (lines of compiled/*.c, deduped per name)."""
    by_project: dict[str, int] = {}
    base = root / OPT_FOR_LOC
    if not base.is_dir():
        return 0, {}
    for proj in sorted(p for p in base.iterdir() if p.is_dir()):
        comp = proj / "compiled"
        if not comp.is_dir():
            continue
        total = 0
        for c in comp.glob("*.c"):
            if c.name in SKIP_C or c.name.startswith("a-conftest"):
                continue
            try:
                total += sum(1 for _ in c.open("rb"))
            except OSError:
                continue
        if total:
            by_project[proj.name] = total
    return sum(by_project.values()), by_project


def sample_i_files(root: Path, per_project: int) -> list[Path]:
    """A stratified sample of real source .i files (exclude autoconf probes)."""
    out: list[Path] = []
    base = root / OPT_FOR_LOC
    for proj in sorted(p for p in base.iterdir() if p.is_dir()):
        comp = proj / "compiled"
        if not comp.is_dir():
            continue
        cand = sorted(
            f for f in comp.glob("*.i") if "conftest" not in f.name and not f.name.startswith("a-")
        )
        if len(cand) > per_project:
            step = len(cand) / per_project
            cand = [cand[int(i * step)] for i in range(per_project)]
        out.extend(cand)
    return out


def _parse_one(ip: Path) -> tuple[bool, int]:
    """Return ``(failed, function count)`` for one Cindergraph extraction."""
    from decbench.utils.cfg import extract_cfgs_from_source

    try:
        cfgs = extract_cfgs_from_source(ip) or {}
    except Exception:  # noqa: BLE001
        return True, 0
    return (not cfgs), len(cfgs)


def cfg_frontend_failures(samples: list[Path], workers: int = 8, deadline_s: int = 420) -> dict:
    """Extract sampled C units concurrently and report failures and deadline misses."""
    import concurrent.futures as cf

    completed = failed = funcs = 0
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_parse_one, ip) for ip in samples]
        try:
            for fut in cf.as_completed(futs, timeout=deadline_s):
                completed += 1
                fail, n = fut.result()
                if fail:
                    failed += 1
                else:
                    funcs += n
        except cf.TimeoutError:
            pass
        for f in futs:
            f.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
    return {
        "files_sampled": completed,
        "files_failed": failed,
        "files_timed_out": len(samples) - completed,
        "file_fail_pct": (100.0 * failed / completed) if completed else 0.0,
        "functions_extracted": funcs,
    }


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/full_run")
    per_project = int(sys.argv[2]) if len(sys.argv) > 2 else 4

    fd = FunctionData.from_json(root / "function_results.json")

    total_loc, loc_by_project = count_loc(root)
    print(f"[dataset] total LOC: {total_loc:,} across {len(loc_by_project)} projects", flush=True)

    samples = sample_i_files(root, per_project)
    print(f"[dataset] Cindergraph sample: {len(samples)} source files...", flush=True)
    frontend = cfg_frontend_failures(samples)
    print(
        f"[dataset] Cindergraph: {frontend['files_failed']}/"
        f"{frontend['files_sampled']} files failed to parse "
        f"({frontend['file_fail_pct']:.1f}%), "
        f"{frontend['functions_extracted']} functions extracted",
        flush=True,
    )

    fd.dataset_info = {
        "total_loc": total_loc,
        "loc_by_project": loc_by_project,
        "cfg_frontend": frontend,
    }
    # This script only ADDS dataset_info, so any coverage regression the guard
    # reports means the file changed under us.
    from decbench.results_store import write_function_data_guarded

    write_function_data_guarded(fd, root)
    print("[dataset] wrote dataset_info into function_results.json", flush=True)
    # Hard-exit so a wedged worker cannot block interpreter shutdown.
    os._exit(0)


if __name__ == "__main__":
    main()
