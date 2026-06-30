#!/bin/bash
# Re-render full_run after the report-logic changes (decompiled-flag tracking,
# Errors column, normalize toggle, version hover). No re-decompilation:
#   1) full resume -> rebuild function_results.json with the new builder
#      (per-(function,decompiler) decompiled flags + decompiler versions)
#   2) rebuild --add-only -> re-apply the Docker ARM/PE byte_match (byte_match_new.json)
#   3) render the report
set -uo pipefail
cd /home/mahaloz/github/decbench
source /home/mahaloz/.virtualenvs/decbench/bin/activate
export KUNA_BIN=/home/mahaloz/github/kuna/decompiler/target/release/kuna
export GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1
export DECBENCH_DECOMPILERS=angr,phoenix,ghidra,ida,binja,kuna
export DECBENCH_WORKERS=40
export DECBENCH_DECOMPILE_TIMEOUT=300

echo "[rerender] step 1/3: full resume (rebuild function_data w/ decompiled flags)..."
python scripts/run_benchmark.py results/full_run >results/rerender_resume.log 2>&1
echo "[rerender] resume tail: $(grep -E 'Functions:|RUN_DRIVER_DONE' results/rerender_resume.log | tail -2 | tr '\n' ' ')"

echo "[rerender] step 2/3: rebuild --add-only (re-apply Docker ARM/PE byte_match)..."
python scripts/rebuild_function_data.py results/full_run --add-only >results/rerender_rebuild.log 2>&1
grep -E "byte_match:|functions," results/rerender_rebuild.log | tail -8

echo "[rerender] step 3/3: render report..."
python -m decbench.cli report results/full_run/scoreboard.toml -o results/full_run/report.html >results/rerender_render.log 2>&1
echo "[rerender] RERENDER_DONE -> results/full_run/report.html"
