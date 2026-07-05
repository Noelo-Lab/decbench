"""Render a report from whatever project checkpoints exist RIGHT NOW.

Lets you preview the (fair, stripped) benchmark mid-run without touching the
live run_benchmark outputs: reads results/<root>/checkpoints/*.pkl read-only and
writes function_results.json + scoreboard.toml + report.html into a SEPARATE
output dir (default results/<root>/partial/). byte_match for ARM/PE will be
missing until the Docker recompile step runs.

Usage:  python scripts/partial_render.py [results/full_run] [out_subdir]
"""

from __future__ import annotations

import glob
import pickle
import sys
from pathlib import Path

from decbench.models.project import Project
from decbench.rendering.html import render_html_report
from decbench.scoring.aggregator import aggregate_results
from decbench.scoring.function_data_builder import build_function_data
from decbench.scoring.scoreboard import build_scoreboard, render_scoreboard_text
from scripts.run_benchmark import OPT_LEVELS, gather_tomls


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/full_run")
    out = root / (sys.argv[2] if len(sys.argv) > 2 else "partial")
    out.mkdir(parents=True, exist_ok=True)

    projects = []
    for t in gather_tomls():
        try:
            projects.append(Project.from_toml(t))
        except Exception as e:  # noqa: BLE001
            print(f"[skip project toml] {t.name}: {e}", flush=True)

    all_decompile: dict = {}
    all_evaluate: dict = {}
    for pf in sorted(glob.glob(str(root / "checkpoints" / "*.pkl"))):
        name = Path(pf).stem
        try:
            d = pickle.loads(Path(pf).read_bytes())
        except Exception as e:  # noqa: BLE001 - may be mid-write; just skip
            print(f"[skip checkpoint] {name}: {e}", flush=True)
            continue
        all_decompile[name] = d.get("decompile", {})
        all_evaluate[name] = d.get("evaluate", {})
    print(f"[partial] loaded {len(all_evaluate)} project checkpoints", flush=True)

    # Decompilers actually present in the data (don't trust the env default).
    decs: set[str] = set()
    for opts in all_decompile.values():
        for bins in (opts or {}).values():
            for decmap in (bins or {}).values():
                decs.update(decmap.keys())
    decompilers = sorted(decs)

    aggregated = aggregate_results(all_evaluate)
    sb = build_scoreboard(
        aggregated,
        projects=[p.name for p in projects],
        optimization_levels=[o.value for o in OPT_LEVELS],
        decompilers=decompilers,
    )
    fd = build_function_data(all_evaluate, projects, all_decompile)
    # Fast extras only (leaderboard/metrics/dataset need these): dataset preset
    # tags + compile rates. The Compare/Hardest views need per-function SOURCE
    # extraction (slow) — pass --full to include them, else they're left empty for
    # a quick mid-run preview.
    try:
        from decbench.scoring.datasets import assign_datasets
        from decbench.scoring.report_extras import compute_compile_rates

        assign_datasets(fd)
        fd.compile_rates = compute_compile_rates(all_evaluate)
    except Exception as e:  # noqa: BLE001
        print(f"[partial] fast-extras failed: {e}", flush=True)
    if "--full" in sys.argv:
        try:
            from decbench.scoring.report_extras import attach_extras

            attach_extras(
                fd,
                evaluation_results=all_evaluate,
                decompile_results=all_decompile,
                projects=projects,
            )
        except Exception as e:  # noqa: BLE001
            print(f"[partial] attach_extras (--full) failed: {e}", flush=True)

    fd_path = out / "function_results.json"
    fd.to_json(fd_path)
    sb.raw_data_path = fd_path
    sb.to_toml(out / "scoreboard.toml")
    render_html_report(sb, out / "report.html", fd)
    print(render_scoreboard_text(sb), flush=True)
    print(f"[partial] decompilers={decompilers}", flush=True)
    print(f"PARTIAL_RENDER_DONE -> {out / 'report.html'}", flush=True)


if __name__ == "__main__":
    main()
