#!/usr/bin/env bash
# Finish the coreutils-restore fix: after rebuild_dataset_from_checkpoints.py has
# rewritten function_results.json from all checkpoints (restoring coreutils), this
# regenerates COMPLETE type_match_new + byte_match_new (the last runs left them
# firmware-scoped), then re-applies the authoritative GED / type / byte reeval
# metrics uniformly for every project and re-renders. ged_new.json is already
# complete (reeval_ged merges all checkpoints), so it is not recomputed here.
set -uo pipefail
ROOT=${1:-results/full_run}
cd "$(dirname "$0")/.."
export PYTHONWARNINGS=ignore PYTHONPATH=.
export GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1
VENV=/home/mahaloz/.virtualenvs/decbench/bin/python
BIN=/home/mahaloz/.virtualenvs/decbench/bin/decbench
LOG="$ROOT/fix_coreutils.log"

echo "[fix] $(date +%H:%M:%S) regenerating COMPLETE type_match_new + byte_match_new (parallel)" | tee -a "$LOG"
# type_match: recomputed from checkpoints (no per-task cache) — unscoped = all projects.
$VENV scripts/reeval_typematch.py "$ROOT" --emit >>"$LOG" 2>&1 &
TM_PID=$!
# byte_match: resumable per (opt,proj,bin,dec); only coreutils is pending (others cached).
$VENV scripts/reeval_bytematch.py "$ROOT" 32 >>"$LOG" 2>&1 &
BM_PID=$!
wait $TM_PID; echo "[fix] $(date +%H:%M:%S) type_match reeval done" | tee -a "$LOG"
wait $BM_PID; echo "[fix] $(date +%H:%M:%S) byte_match reeval done" | tee -a "$LOG"

echo "[fix] $(date +%H:%M:%S) applying GED / type / byte reevals + scoreboard" | tee -a "$LOG"
$VENV scripts/rebuild_function_data.py "$ROOT" --ged        >>"$LOG" 2>&1
$VENV scripts/rebuild_function_data.py "$ROOT" --type-match >>"$LOG" 2>&1
$VENV scripts/rebuild_function_data.py "$ROOT"              >>"$LOG" 2>&1

echo "[fix] $(date +%H:%M:%S) rendering report" | tee -a "$LOG"
$BIN report "$ROOT/scoreboard.toml" -o "$ROOT/report.html" >>"$LOG" 2>&1
echo "[fix] $(date +%H:%M:%S) FIX_COREUTILS_DONE" | tee -a "$LOG"
