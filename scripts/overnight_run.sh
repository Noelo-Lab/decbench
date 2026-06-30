#!/bin/bash
# Full overnight re-run with the fairness fixes:
#   - decompilers get a STRIPPED binary (no DWARF, no symbols); eval uses the
#     unstripped DWARF copy (run_benchmark strips + address-filters + relabels).
#   - GED source CFGs use header-stripped .i (decbench.utils.cfg) + union across
#     the project's translation units.
# Steps: fresh re-decompile+eval (resumable) -> Docker byte_match for ARM/PE ->
# merge -> render.
set -uo pipefail
cd /home/mahaloz/github/decbench
source /home/mahaloz/.virtualenvs/decbench/bin/activate
export KUNA_BIN=/home/mahaloz/github/kuna/decompiler/target/release/kuna
export GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1
export DECBENCH_DECOMPILERS=angr,phoenix,ghidra,ida,binja,kuna
export DECBENCH_WORKERS=40
export DECBENCH_DECOMPILE_TIMEOUT=300

ARMPE="betaflight chibios cleanflight crazyflie freertos libopencm3 nuttx riot-os u-boot dexter minipig mydoom x0r-usb"

echo "[overnight] step 1/4: fresh stripped re-decompile + evaluate (all 41 x 6)..."
python scripts/run_benchmark.py results/full_run >results/overnight_run.log 2>&1
echo "[overnight] step 1 tail: $(grep -E 'Functions:|RUN_DRIVER_DONE' results/overnight_run.log | tail -2 | tr '\n' ' ')"

echo "[overnight] step 2/4: Docker byte_match for ARM/PE..."
docker run --rm -v "$(pwd)":/workspace -w /workspace -e PYTHONPATH=/workspace \
  -e HOME=/tmp --user "$(id -u):$(id -g)" decbench-compile bash -lc \
  "pip install --quiet --break-system-packages capstone diff-match-patch >/dev/null 2>&1; \
   python3 scripts/reeval_bytematch.py results/full_run 40 $ARMPE" \
  >results/overnight_reeval.log 2>&1
echo "[overnight] step 2 tail: $(tail -1 results/overnight_reeval.log)"

echo "[overnight] step 3/4: rebuild --add-only (merge ARM/PE byte_match)..."
python scripts/rebuild_function_data.py results/full_run --add-only >results/overnight_rebuild.log 2>&1
grep -E "functions,|byte_match:" results/overnight_rebuild.log | tail -8

echo "[overnight] step 4/4: render report..."
python -m decbench.cli report results/full_run/scoreboard.toml -o results/full_run/report.html >results/overnight_render.log 2>&1
echo "[overnight] OVERNIGHT_DONE -> results/full_run/report.html"
