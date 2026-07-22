#!/usr/bin/env python3
"""Run the codex/claude-code sample-set redo as N concurrent run_benchmark.py shards.

run_benchmark.py parallelises only WITHIN a (project, opt) group, and most
sample-set groups have a single binary -> the single-process run pins at ~2
concurrent CLIs regardless of DECBENCH_WORKERS. This launcher shards the work by
PROJECT across many concurrent run_benchmark.py instances (disjoint projects ->
disjoint per-project checkpoints, no write races), which is the documented
pattern for the slow BN/LLM backends.

Each shard does decompile+evaluate+checkpoint and writes a PARTIAL
function_results.json (only its projects) -- that intermediate file is ignored;
the caller runs scripts/rebuild_function_data.py once at the end to assemble the
authoritative full function_results.json from every checkpoint + overlays.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TREE = ROOT / "results" / "full_run"
# Overridable so this launcher can drive a scoped retry (a reduced manifest +
# a single decompiler) as well as the full codex+claude redo.
MANIFEST = Path(os.environ.get("SHARD_MANIFEST") or (TREE / "sample_set_manifest.json"))
DECOMPILERS = os.environ.get("SHARD_DECOMPILERS", "codex,claude-code")
TRACE_DIR = ROOT / "llm_traces"
LOG_DIR = ROOT / os.environ.get("SHARD_LOG_DIR", "shard_logs")

# A project that owns many sample-set binaries gets its own shard with more
# workers so its multi-binary groups fan out; everything else is bin-packed.
BIG = {p for p in os.environ.get("SHARD_BIG", "libopencm3").split(",") if p}
BIG_WORKERS = int(os.environ.get("SHARD_BIG_WORKERS", "6"))
N_SMALL_SHARDS = int(os.environ.get("SHARD_N", "9"))
SMALL_WORKERS = int(os.environ.get("SHARD_WORKERS", "3"))


def build_shards() -> list[tuple[list[str], int]]:
    man = json.loads(MANIFEST.read_text())["functions"]
    counts: dict[str, int] = {}
    for f in man:
        counts[f["project"]] = counts.get(f["project"], 0) + 1
    shards: list[tuple[list[str], int]] = []
    big_projects = set()
    for proj in BIG:
        if proj in counts:
            shards.append(([proj], BIG_WORKERS))
            big_projects.add(proj)
    # Greedy longest-processing-time bin-pack of the rest by function count.
    rest = sorted(
        ((p, c) for p, c in counts.items() if p not in big_projects),
        key=lambda kv: -kv[1],
    )
    n_small = min(N_SMALL_SHARDS, max(1, len(rest)))
    bins: list[list[str]] = [[] for _ in range(n_small)]
    loads = [0] * n_small
    for proj, c in rest:
        i = loads.index(min(loads))
        bins[i].append(proj)
        loads[i] += c
    for b in bins:
        if b:
            shards.append((b, SMALL_WORKERS))
    return shards


def main() -> int:
    shards = build_shards()
    LOG_DIR.mkdir(exist_ok=True)
    TRACE_DIR.mkdir(exist_ok=True)
    base_env = dict(os.environ)
    base_env.update(
        {
            "DECBENCH_DECOMPILERS": DECOMPILERS,
            "DECBENCH_REDO_DECOMPILERS": DECOMPILERS,
            "DECBENCH_SAMPLESET_MANIFEST": str(MANIFEST),
            "DECBENCH_LLM_TRACE_DIR": str(TRACE_DIR),
            "DECBENCH_LLM_FN_WORKERS": "1",
            "DECBENCH_LLM_TIMEOUT": "900",
            "GHIDRA_INSTALL_DIR": os.environ.get(
                "GHIDRA_INSTALL_DIR", "/home/mahaloz/bin/ghidra_12.1"
            ),
        }
    )
    procs = []
    for idx, (projects, workers) in enumerate(shards):
        env = dict(base_env)
        env["DECBENCH_WORKERS"] = str(workers)
        log = LOG_DIR / f"shard_{idx:02d}.log"
        cmd = [
            sys.executable,
            str(HERE / "run_benchmark.py"),
            str(TREE),
            "--",
            *projects,
        ]
        fh = open(log, "w")
        p = subprocess.Popen(cmd, cwd=str(ROOT), env=env, stdout=fh, stderr=subprocess.STDOUT)
        procs.append((idx, p, fh, projects, workers, log))
        print(
            f"[shard {idx:02d}] workers={workers} pid={p.pid} "
            f"projects={projects} -> {log.name}",
            flush=True,
        )
    print(f"\nlaunched {len(procs)} shards; waiting...", flush=True)

    results = {}
    remaining = {idx for idx, *_ in procs}
    while remaining:
        for idx, p, fh, projects, workers, log in procs:
            if idx in remaining and p.poll() is not None:
                results[idx] = p.returncode
                fh.close()
                remaining.discard(idx)
                print(
                    f"[shard {idx:02d}] DONE rc={p.returncode} "
                    f"({len(remaining)} left)",
                    flush=True,
                )
        if remaining:
            time.sleep(5)
    ok = sum(1 for rc in results.values() if rc == 0)
    print(f"\nall shards finished: {ok}/{len(procs)} rc=0", flush=True)
    print("SHARD_LAUNCHER_DONE", flush=True)
    return 0 if ok == len(procs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
