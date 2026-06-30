#!/bin/bash
# Auto-finalize the full_run benchmark after the cps-debug decompile completes:
#   1) wait for the cps-debug decompile (betaflight/chibios/cleanflight) to finish
#   2) full resume run_benchmark over all 41 projects -> function_results.json +
#      scoreboard (host eval; ARM/PE byte_match abstains)
#   3) Docker reeval byte_match for the ARM/PE projects (cps + PE malware) in the
#      cross-toolchain image so they recompile instead of abstaining
#   4) rebuild --add-only: fold the ARM/PE byte_match in (keep host x86 values)
#   5) render the final report
set -uo pipefail
cd /home/mahaloz/github/decbench
source /home/mahaloz/.virtualenvs/decbench/bin/activate

CPS_LOG="$1"          # path to the cps-debug decompile task output
export KUNA_BIN=/home/mahaloz/github/kuna/decompiler/target/release/kuna
export GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1
export DECBENCH_DECOMPILERS=angr,phoenix,ghidra,ida,binja,kuna
export DECBENCH_DECOMPILE_TIMEOUT=300
export DECBENCH_WORKERS=40

# ARM (cps) + PE (malware) projects whose byte_match abstains on the host.
ARMPE="betaflight chibios cleanflight crazyflie freertos libopencm3 nuttx riot-os u-boot dexter minipig mydoom x0r-usb"

echo "[finalize] waiting for cps-debug decompile to finish ($CPS_LOG)..."
until grep -q "RUN_DRIVER_DONE" "$CPS_LOG" 2>/dev/null; do sleep 20; done
echo "[finalize] cps-debug decompile done."

echo "[finalize] step 2/5: full resume over all 41 projects..."
python scripts/run_benchmark.py results/full_run >results/finalize_resume.log 2>&1
echo "[finalize] resume done."

echo "[finalize] step 3/5: Docker byte_match reeval for ARM/PE projects..."
docker run --rm -v "$(pwd)":/workspace -w /workspace -e PYTHONPATH=/workspace \
  -e HOME=/tmp --user "$(id -u):$(id -g)" decbench-compile bash -lc \
  "pip install --quiet --break-system-packages capstone diff-match-patch >/dev/null 2>&1; \
   python3 scripts/reeval_bytematch.py results/full_run 40 $ARMPE" \
  >results/finalize_reeval.log 2>&1
echo "[finalize] Docker reeval done -> $(tail -1 results/finalize_reeval.log)"

echo "[finalize] step 4/5: rebuild --add-only (merge ARM/PE byte_match)..."
python scripts/rebuild_function_data.py results/full_run --add-only >results/finalize_rebuild.log 2>&1
tail -8 results/finalize_rebuild.log

echo "[finalize] step 5/5: render report..."
python -m decbench.cli report results/full_run/scoreboard.toml -o results/full_run/report.html \
  >results/finalize_render.log 2>&1
echo "[finalize] FINALIZE_DONE -> results/full_run/report.html"
