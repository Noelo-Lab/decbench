#!/bin/bash
# Wait for reeval_ged to finish, then merge GED + rebuild + render.
set -uo pipefail
cd /home/mahaloz/github/decbench
source /home/mahaloz/.virtualenvs/decbench/bin/activate
echo "[ged-final] waiting for reeval_ged..."
until grep -q "\[ged\] wrote" results/reeval_ged.log 2>/dev/null; do sleep 30; done
echo "[ged-final] reeval done: $(grep '\[ged\] wrote' results/reeval_ged.log | tail -1)"
python scripts/rebuild_function_data.py results/full_run --ged >results/ged_rebuild.log 2>&1
grep -E "merged GED|ged:|functions," results/ged_rebuild.log | tail -8
python -m decbench.cli report results/full_run/scoreboard.toml -o results/full_run/report.html >results/ged_render.log 2>&1
echo "[ged-final] GED_FINALIZE_DONE"
