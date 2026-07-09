#!/usr/bin/env bash
# Re-decompile ONLY Binary Ninja across an existing results tree with the
# Loading-race fix (decbench/decompilers/raw/binja_raw.py), then re-score binja's
# GED + type_match and re-render — WITHOUT disturbing the other decompilers' data.
#
# Why a wrapper: run_benchmark.py always rewrites function_results.json at the end
# (from its in-process evals), which would clobber the carefully re-eval'd GED/type
# data. So we snapshot function_results.json/scoreboard.toml, let run_benchmark
# re-decompile binja (DECOMPILE_ONLY skips its Joern eval and updates the
# checkpoints + decompiled/binja_*.c), restore our snapshot, then re-run the
# targeted reeval + rebuild.
#
# This is a MULTI-HOUR job (binja headless analyzes ~800 binaries with
# update_analysis_and_wait). Runs detached-safe; each stage is resumable.
#
# Usage:  bash scripts/rerun_binja.sh results/full_run
set -uo pipefail
ROOT=${1:-results/full_run}
cd "$(dirname "$0")/.."
export PYTHONWARNINGS=ignore
export GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1
VENV=/home/mahaloz/.virtualenvs/decbench/bin/python
BIN=/home/mahaloz/.virtualenvs/decbench/bin/decbench

echo "[binja] snapshotting good metric data..."
cp -f "$ROOT/function_results.json" "$ROOT/function_results.beforebinja.json"
cp -f "$ROOT/scoreboard.toml"        "$ROOT/scoreboard.beforebinja.toml"

echo "[binja] (1/5) re-decompiling binja only (DECOMPILE_ONLY; updates checkpoints + decompiled/)..."
# Modest workers: binja headless is heavy; keep it small to avoid contention.
DECBENCH_DECOMPILERS="angr,phoenix,ghidra,ida,binja,kuna" \
  DECBENCH_REDO_DECOMPILERS="binja" \
  DECBENCH_DECOMPILE_ONLY="1" \
  DECBENCH_WORKERS="8" \
  $VENV scripts/run_benchmark.py "$ROOT"

echo "[binja] restoring the good metric data (run_benchmark clobbers it)..."
mv -f "$ROOT/function_results.beforebinja.json" "$ROOT/function_results.json"
mv -f "$ROOT/scoreboard.beforebinja.toml"        "$ROOT/scoreboard.toml"

echo "[binja] (2/5) re-scoring GED for the fresh binja .c (drop binja ckpts so only binja re-runs)..."
rm -f "$ROOT"/reeval_ged/*__binja.json
$VENV scripts/reeval_ged.py "$ROOT" 12

echo "[binja] (3/5) re-scoring type_match from the updated checkpoints..."
$VENV scripts/reeval_typematch.py "$ROOT" --emit

echo "[binja] (4/5) merging GED + type_match..."
$VENV scripts/rebuild_function_data.py "$ROOT" --ged
$VENV scripts/rebuild_function_data.py "$ROOT" --type-match
# byte_match: reuse the restored values (unchanged); recompute the scoreboard only.
$VENV - "$ROOT" <<'PY'
import sys, json
from pathlib import Path
from decbench.models.function_data import FunctionData
from decbench.models.scoreboard import Scoreboard
from decbench.scoring.scoreboard import build_scoreboard_from_function_data
root = Path(sys.argv[1])
fd = FunctionData.from_json(root / "function_results.json")
old = Scoreboard.from_toml(root / "scoreboard.toml")
build_scoreboard_from_function_data(fd, name=old.name, description=old.description,
                                    version=old.version).to_toml(root / "scoreboard.toml")
print("[binja] scoreboard recomputed")
PY

echo "[binja] (5/5) rendering report..."
$BIN report "$ROOT/scoreboard.toml" -o "$ROOT/report.html"
echo "[binja] DONE — binja GED should jump from ~4.7% toward the ~20-40% band."
