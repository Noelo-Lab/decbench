# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DecBench is a benchmarking suite for evaluating decompiler performance. It implements a three-stage pipeline (compile → decompile → evaluate) with pluggable decompilers and three core metrics.

## Environment

- Use the `decbench` virtualenv at `/home/mahaloz/.virtualenvs/decbench`
  (Python 3.10; decbench installed editable). Activate with
  `source /home/mahaloz/.virtualenvs/decbench/bin/activate`.
- Decompiler backends **available and working** on this machine (verified via
  the raw, declib-free interfaces — see Architecture): **angr** (pip),
  **phoenix** (angr driven with the Phoenix structurer — a distinct decompiler;
  plain `angr` uses angr's default SAILR structurer), **Ghidra 12.1** AND
  **Ghidra 12.0** (`/home/mahaloz/bin/ghidra_12.{1,0}`, via pyghidra; export
  `GHIDRA_INSTALL_DIR` for the unversioned default), **IDA Pro 9.2 idalib** (at
  `/home/mahaloz/ctf/tools/idapro_9.2`), **Binary Ninja 3.1** (install at
  `/home/mahaloz/ctf/tools/binja/binaryninja`; added to the venv via a
  `binaryninja.pth` in site-packages; needs a license at
  `~/.binaryninja/license.dat` — a Commercial/Ultimate license is required for
  headless use, and it must cover v3.1), **r2dec** (radare2; the benchmark path
  is the REAL r2dec plugin via the `decbench/r2dec` Docker image — native `pdc`
  is a fallback whose asm-like output yields no Joern CFG, so `pdd` is required
  for GED), and **dewolf** (fkie-cad/dewolf, a Binary-Ninja research decompiler
  run OUT OF PROCESS in its own py3.10 venv at
  `/home/mahaloz/.virtualenvs/dewolf` with the repo at
  `/home/mahaloz/ctf/tools/dewolf`; see `raw/dewolf_raw.py` +
  `raw/dewolf_driver.py`, configured under `[dewolf.versions.default]`).
  **RetDec/Reko** are Dockerized (`docker/`).
  `decbench list-decompilers` shows availability. The core benchmark set is
  **angr, phoenix, ghidra, ida, binja** (+ kuna in the full run); **r2dec** and
  **dewolf** are the newest additions. NOTE: **phoenix is hidden from the
  published site** (`content/site.toml` `[decompilers] hidden`) but kept in
  `function_results.json`.
- **Phoenix** = `decbench/decompilers/raw/angr_raw.py::RawAngrPhoenixDecompiler`
  (`structurer = "Phoenix"`). The base `RawAngrDecompiler` has a `structurer`
  attr (None = SAILR default); set it via angr's `get_structurer_option()`
  ("SAILR"/"Phoenix"/"DREAM").
- **Five Ghidra versions** are configured for multi-version (historical)
  benchmarking in `~/.config/decbench/decompilers.toml`: `ghidra@12.1`,
  `ghidra@12.0` (in `/home/mahaloz/bin/ghidra_12.{1,0}`), plus the historical
  `ghidra@11.4` (11.4.3), `ghidra@11.0` (11.0.3), `ghidra@10.4` (unzipped under
  `/home/mahaloz/bin/ghidra_*_PUBLIC`). Run as distinct specs (`-d ghidra@11.0
  ...`). They MUST run in separate processes (one JVM per install per process) —
  the run drivers already use per-task subprocesses. Launch dispatch is
  version-aware (`raw/ghidra_raw.py`): pip `pyghidra` (>=12.0), the install's
  OWN bundled PyGhidra (11.2–11.x), or the predecessor `pyhidra` (<11.2); each
  version's JDK comes from a per-version `java_home` in the config (<=11.1 → JDK
  17, >=11.2 → JDK 21). `scripts/ingest_history.py <versioned-run> <target-tree>`
  merges a versioned run into a tree's history points (stored in
  `function_results.json`, unshipped since the Historical view was removed
  2026-07-22).
- Docker **works** here (no sudo needed); used for the RetDec/Reko backends.
- `declib` (4.0.1, PyPI) is still installed and the `*-declib` backends still
  use it, but the **canonical** `angr`/`ghidra`/`ida`/`binja` backends are now
  native (declib-free) implementations under `decbench/decompilers/raw/`.
- `pyjoern` bundles a ~1.9 GB Joern under site-packages and powers the GED metric.
  Gotcha: the wheel can ship a MISMATCHED joern-cli bundle (1.2.18 jars under a
  4.x wrapper) which silently breaks `parse_source` → GED scores nothing. Fix:
  drop the matching Joern **v4.0.150** `joern-cli` into
  `site-packages/pyjoern/bin/joern-cli/` (its zip SHA-512 must equal
  `pyjoern.__init__.JOERN_ZIP_HASH`). Re-apply after any pyjoern reinstall.
- `pygraphviz` builds against the system `libgraphviz-dev` (installed).

## Common Commands

```bash
# Install for development
pip install -e ".[dev]"

# Run tests
pytest                              # All tests with coverage
pytest tests/test_models.py         # Single test file
pytest tests/test_decompilers.py    # Real decompiler smoke tests (auto-skip if unavailable)

# Code quality
ruff check .                        # Linting
black .                             # Formatting
mypy decbench                       # Type checking

# CLI usage
decbench run project.toml -O O0 -O O2 -O O2-noinline -d angr -d ghidra  # Full pipeline
decbench run project.toml -d ghidra@12.0 -d ghidra@12.1  # multiple versions
decbench list-decompilers           # Show available decompilers (angr/ghidra/ida/r2dec/...)
decbench list-metrics               # Show available metrics
decbench evaluate binary.elf        # Evaluate single binary
decbench report scoreboard.toml     # Generate HTML report (interactive if
                                    # function_results.json sits next to the scoreboard)
# v2 helpers:
decbench dataset save results/sailr_full sailr   # snapshot compiled binaries (no recompile later)
decbench dataset materialize sailr results/reuse # lay back out, then: decbench run --skip-compile
decbench subset results/sailr_full/function_results.json  # large-function subset manifest
# Find per-function improvement targets: functions where a BASE decompiler beats
# a TARGET on a metric (respects each metric's direction; --perfect-only = base is
# a perfect match, e.g. GED 0). Reads a results tree's function_results.json and
# resolves each case to its binary path + function symbol/address on disk.
decbench improvements results/full_run -b angr -t kuna -m ged --perfect-only
decbench decompiler-build retdec    # build a dockerized decompiler image
# Caching is automatic (content-addressed); DECBENCH_NO_CACHE=1 disables it.
# Quick end-to-end smoke (raw backends + 2 Ghidra versions + caching + report):
DECBENCH_SMALL_DECOMPILERS="angr,ida,ghidra@12.0,ghidra@12.1" python scripts/run_small.py

# Benchmark targets: 26 sailr-eval Debian packages live in projects/sailr/*.toml
# (each builds at O0 / O2 / O2-noinline, labeled by kind + domain).
# Plus 9 active CPS/drone/RTOS firmware targets in projects/cps/*.toml, each
# CROSS-COMPILED for specific embedded hardware (Cortex-M/-A): libopencm3,
# FreeRTOS, ChibiOS, NuttX, RIOT-OS, Betaflight, Cleanflight, Crazyflie, U-Boot.
# All are C. They set c_compiler=arm-none-eabi-gcc (bare metal) or
# arm-linux-gnueabihf-gcc (embedded Linux) and target_arch="arm" so only the
# hardware binaries are collected (not incidental x86 host tools). The Docker
# image ships both cross toolchains + their build deps; verify a build with
# scripts/cps_compile_smoke.py inside the image. angr/Ghidra decompile ARM;
# byte_match abstains for ARM on hosts without the arm-none-eabi toolchain —
# GED/type_match carry these targets.
# The two C++ autopilots (ArduPilot, PX4) are DISABLED in projects/cps/disabled/
# (decbench has no C++ support yet — pyjoern/GED is C-only); their recipes are
# verified-working and re-enable by moving the TOML back up to projects/cps/.
#
# Plus REAL MALWARE targets in projects/malware/*.toml (C, from theZoo): mirai,
# mirai-win (ELF/gcc), mydoom, x0r-usb, minipig, dexter (PE/MinGW). These are
# COMPILED, NEVER EXECUTED, and ONLY inside the container: each sets
# is_malware=true and compile_project REFUSES to build them on a bare host
# (needs /.dockerenv or DECBENCH_ALLOW_MALWARE=1). download_cmd fetches+extracts
# (password 'infected') just the one theZoo zip; make_cmd is a DIRECT gcc/mingw
# compile (not the malware's Makefile). PE binaries are collected like ELF
# (compilers/gcc.py PE detection). All three metrics work on PE via
# utils/binfmt.py (byte_match needs the MinGW toolchain, else it abstains). See
# projects/malware/README.md (DO NOT EXECUTE). Binaries never leave results/.

# Large multi-target runs: prefer the resilient drivers in scripts/ over a single
# `decbench run` — they use the 'spawn' multiprocessing context (the default
# 'fork' DEADLOCKS when workers are forked after angr's threads start) and
# checkpoint per project so a multi-hour run survives crashes:
GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1 \
  python scripts/compile_all.py results/sailr_full 16   # compile all (16 workers)
DECBENCH_WORKERS=40 GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1 \
  python scripts/run_benchmark.py results/sailr_full     # decompile+evaluate+report
#   run_benchmark.py knobs (env): DECBENCH_DECOMPILERS (default angr,ghidra),
#   DECBENCH_DECOMPILE_TIMEOUT (s, default 300), DECBENCH_GED_MAX_NODES (60; read
#   in metrics/ged.py, takes effect during runs), DECBENCH_OPT_LEVELS (comma list,
#   e.g. "O0" to narrow the run), DECBENCH_METRICS (comma list, e.g. "ged" for a
#   GED-only run). Resume MERGES per project AND per
#   decompiler: `DECBENCH_DECOMPILERS=r2dec python scripts/run_benchmark.py
#   results/full_run` ADDS r2dec (or dewolf) to every project's checkpoint without
#   re-running the others, then regenerates function_results.json with the new
#   column. Restart resumes from per-project checkpoints; `... results/sailr_full
#   -- grep` limits to named projects. Single project: scripts/decompile_one.py.
#   Multi-version Ghidra example (GED-only over O0, five versions):
#     DECBENCH_DECOMPILERS=ghidra@12.1,ghidra@12.0,ghidra@11.4,ghidra@11.0,ghidra@10.4 \
#     DECBENCH_OPT_LEVELS=O0 DECBENCH_METRICS=ged \
#     python scripts/run_benchmark.py results/ghidra_history -- <sailr stems>
#   then: python scripts/ingest_history.py results/ghidra_history results/full_run
#   (history points into function_results.json — unshipped; see Environment note)

# FULL run = EVERY project AND EVERY supported decompiler. A "full run" always
# means all projects we support — projects/{sailr,cps,malware}/*.toml — decompiled
# by all backends available on this machine: angr, phoenix, ghidra, ida, binja,
# kuna, r2dec, and dewolf (phoenix is kept in the data but hidden from the site).
# If a new project or decompiler is added, "full run" includes it too; scope down
# only for a deliberate partial pass. (sailr x86 + cps ARM + malware ARM/PE.) Both
# drivers gather projects/{sailr,cps,malware}/*.toml (gather_tomls(); cps/disabled/
# excluded). sailr compiles on the host; cps/malware need the cross/mingw
# toolchains so they compile INSIDE the slim `decbench-compile` image
# (docker/compile.Dockerfile — ARM + mingw + decbench's light compile deps; the
# host has no cross/mingw gcc). Decompilation runs on the HOST for all of them (the raw
# backends + executor discover ELF *and* PE; PE malware decompiles via
# ghidra/ida/binja/angr). Steps:
#   1) host-compile sailr:  python scripts/compile_all.py results/full_run 20
#   2) docker build -f docker/compile.Dockerfile -t decbench-compile .   (one-time)
#   3) docker-compile cps+malware INTO the same tree (run as host user, /.dockerenv
#      satisfies the is_malware guard):
#      docker run --rm -v "$PWD":/workspace -w /workspace -e PYTHONPATH=/workspace \
#        -e HOME=/tmp --user "$(id -u):$(id -g)" decbench-compile \
#        python3 scripts/compile_all.py results/full_run 8 <cps+malware stems...>
#   4) one decompile+evaluate+report pass over everything (resumes per-project):
#      DECBENCH_WORKERS=40 \
#        DECBENCH_DECOMPILERS=angr,phoenix,ghidra,ida,binja,kuna,r2dec,dewolf \
#        GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1 \
#        python scripts/run_benchmark.py results/full_run
#      (dewolf is slow + BN-based; for it, prefer several concurrent instances on
#      disjoint project groups + DECBENCH_DEWOLF_SHARDS to saturate cores — see the
#      dewolf backend notes. r2dec runs via its Docker image. Resume is per-project
#      AND per-decompiler, so a full run can be assembled decompiler-by-decompiler.)
#   byte_match ABSTAINS (no result, not 0) for ARM/PE on the host (no cross/mingw
#   recompiler) — GED + type_match carry cps/malware. The summary column is Union
#   (perfect on ≥1 measurable metric, over functions with ≥1 measurable metric),
#   so abstained byte_match isn't a failure and ARM/PE still count via GED/types.

# Recompute ONLY byte_match over an existing results tree WITHOUT re-decompiling
# (uses the stored decompiled/*.c + compiled binaries), then rebuild the report
# data (merge new byte_match, build view samples + hardest w/ source, compile
# rates, recompute scoreboard). Used to refresh after a byte_match metric change:
python scripts/reeval_bytematch.py results/sailr_full 40   # parallel, resumable -> byte_match_new.json
python scripts/rebuild_function_data.py results/sailr_full # -> function_results.json + scoreboard.toml
python scripts/compute_dataset_info.py results/sailr_full  # FunctionData.dataset_info (sole writer:
#   About-page corpus LOC + Joern parse-health stats); run over a results tree after
#   (re)building function_results.json — rebuild_function_data.py does NOT repopulate it.
#   NOTE: the on-disk results tree may be a PARTIAL snapshot (some projects have
#   no decompiled .c); rebuild DROPS byte_match for functions whose artifact is
#   gone so the column is uniformly the new metric (per-metric denominators
#   already differ). Re-render: decbench report results/sailr_full/scoreboard.toml
```

**Why the run driver isn't just `decbench run`** (key scaling facts): angr's
decompiler is ~15-20 s/function (Ghidra ~0.5 s/func) and decbench decompiles
*all* `.text` functions, ~99% of which are bundled gnulib in some binaries. So
the driver (a) filters decompilation to the project's own source functions via
DWARF `decl_file` (`project_source_functions`), (b) imposes a hard per-binary
timeout via killable subprocess, (c) recovers partial results on timeout
(`decompile_binary(progress_path=...)` pickles after each function), and (d)
caps exact GED to CFGs ≤ `DECBENCH_GED_MAX_NODES` nodes (super-polynomial; a few
huge optimized CFGs otherwise dominate). These make angr tractable and bound the
run; default in-process `decbench run` does none of them.

## Architecture

**Three-Stage Pipeline** (`decbench/pipeline/`):
1. `compile.py` - Compile C projects at various optimization levels using GCC
2. `decompile.py` - Run registered decompilers on binaries (fresh process per task via
   `max_tasks_per_child=1` to isolate JVM/idalib state)
3. `evaluate.py` - Compute metrics comparing decompiled output to source
4. `executor.py` - Orchestrates the full pipeline via `PipelineExecutor`; also writes
   `function_results.json` (per-function results + labels) next to `scoreboard.toml`

**Decompilers** (`decbench/decompilers/`): backends subclass the
`Decompiler` ABC (`base.py`) and register via `@register_decompiler`. There are
three families:
- **Raw / native** (`decompilers/raw/`, the canonical `angr`/`ghidra`/`ida`/
  `binja`): drive the tools' own APIs directly, **no declib**. `raw/common.py`
  centralises the ELF bookkeeping (`elf_min_vaddr`, `.text` range,
  CRT/PLT/thunk skip sets, `narrow_to_source` function filter, atomic
  `dump_progress` checkpoint, line-mapping helpers). This is the path benchmark
  runs use now.
- **declib** (`declib_dec.py`, registered as `angr-declib`/`ghidra-declib`/…):
  the original declib-driven backends, kept for comparison.
- **Dockerized** (`dockerized.py`: `reko`/`retdec`/`r2dec`): run a tool in a
  container (or natively for r2dec) and split whole-program C into per-function
  results. Build images with `decbench decompiler-build <name>`; Dockerfiles in
  `docker/`.
- **LLM / coding-agent** (`llm_dec.py`: `codex`, `claude-code`, `kimi-code`):
  drive a coding agent CLI (OpenAI `codex` / Anthropic `claude` / Moonshot
  `kimi`) as a decompiler, one agentic
  call per function. **Cost is controlled by only ever running on the
  `sample-set` slice**: freeze it with `scripts/export_sample_set.py`
  (→ `sample_set_manifest.json`), then `DECBENCH_SAMPLESET_MANIFEST=<manifest>
  DECBENCH_DECOMPILERS=codex,claude-code python scripts/run_benchmark.py
  results/full_run`; `DECBENCH_LLM_FN_WORKERS` decompiles a binary's sampled
  functions concurrently. On the SITE they are **sample-set-only** decompilers
  (`[decompilers] sample_set_only` in site.toml + `visibleDecs()` in app.js).
  Default models: codex `gpt-5.6-sol`, claude-code `claude-opus-4-8`, kimi-code
  `kimi-code/k3`. NOTE: a
  nested `claude` (launched from inside a Claude Code session) needs an isolated
  `CLAUDE_CONFIG_DIR` + a per-call OAuth credential RE-SYNC (a one-time copy goes
  stale) — the backend does both automatically. Full guide: `docs/LLM_DECOMPILERS.md`.

Key conventions (all families):
- Addresses are stored in **ELF-file-space** (`lifted + min PT_LOAD vaddr`) so
  they match DWARF; raw backends normalise per-tool load bases (angr `0x400000`,
  Ghidra `0x100000`, IDA `0x0`) for PIE binaries.
- Functions outside `.text` (PLT/thunks) and CRT helpers are skipped.
- `FunctionDecompilation.variables` (`VariableInfo`) carries stack vars/args for
  the type metric; line maps are best-effort (angr/Ghidra populate them).
- **Decompiler identity is `name` or `name@version`** (`spec.py`): the registry
  resolves `ghidra@12.1` to a versioned instance whose `.id` flows through
  results/scoreboard/report as a distinct column. Per-version settings (e.g.
  which Ghidra install) come from `~/.config/decbench/decompilers.toml`. See
  `docs/ADDING_A_DECOMPILER.md` for the full plugin contract.

**Caching** (`decbench/caching.py`): a content-addressed on-disk cache. Each
metric's `compute_for_function` keys on a `stable_hash` of its determining
inputs (GED: both CFG structures; type_match: vars + DWARF ground truth +
calibration shift; byte_match: code + original function bytes), so re-runs over
seen (decompiled, source) pairs skip recomputation. Disable with
`DECBENCH_NO_CACHE`; root `DECBENCH_CACHE_DIR`.

**Binary datasets & subsets** (`decbench/dataset.py`, `decbench/scoring/subset.py`):
`dataset.py` content-addresses compiled binaries + `.i` sources into a reusable
store so a benchmark can re-run **without recompiling** (`decbench dataset
save/list/materialize`, then `run --skip-compile`). `subset.py` finds the
**large-function** upper tail of the size bell curve (`mean + k·std` or a
percentile) and emits a manifest to evaluate/report on just the hard, large
functions — no binary copying (`decbench subset function_results.json`).

**Three Metrics** (`decbench/metrics/`):
- `ged.py` - Structural Correctness: CFG Graph Edit Distance between source and decompiled code
- `type_match.py` - Type Correctness vs DWARF ground truth. Works at **all opt
  levels**: ground truth keeps every variable with ANY DWARF location (register
  loclists included; only fully optimized-out vars are dropped). Unified 3-pass
  matching against `FunctionDecompilation.variables`: ① arguments by ABI position
  (DWARF formal-parameter order ↔ `VariableInfo.arg_index` — name-independent, so
  angr's `a0`/`a1` get fair credit), ② stack vars by auto-calibrated offset shift,
  ③ rest by exact name. Regex text parsing is the last-resort fallback. At `-O2`,
  register locals that decompilers fold into expressions count as misses for
  everyone uniformly.
- `byte_match.py` - Recompilation Bytematch: assembly similarity after recompiling
  the decompiled C **the same way the source was compiled** — the toolchain and
  `-m*/-O*` flags matching the original binary's own format+arch (PE→MinGW,
  ARM→arm-none-eabi, x86→gcc; flags read from the DWARF producer), via
  `decbench/utils/binfmt.py`. Returns a non-scoring result if that toolchain
  isn't installed (don't fake a wrong-arch recompile). Works on ELF and PE.
  **Two fairness passes (v5, `cache_version="5"`) — investigate before changing,
  and bump `cache_version` if you do:** (1) a **compilability fixup**
  (`decbench/metrics/fixup.py` — full details in its docstrings) so decompiler
  output actually builds instead of auto-scoring 0: token sanitization plus a
  **gcc-diagnostic-driven self-repair loop** that injects ONLY what the compiler
  reports missing (pseudo-type typedefs, IDA/Ghidra helper macros, libc + the
  decompiler's OWN sibling prototypes via `derive_context_decls`, synthesized
  structs, width-typed globals, positional edits) and never redefines what the
  decompiler declared. This *maximizes compilation* uniformly (sailr O0 compile
  rate ~20-79%→~83-95% per decompiler). (2) **operand normalization** in
  `_disassemble_bytes` (byte_match.py) blanks link-time-dependent operands
  (direct branch/call targets, rip/pc-relative memory INCLUDING the unlinked
  object's bare `[rip]` form) and drops x86-64 varargs AL-zeroing from both
  listings. `binfmt.producer_flags` also carries codegen `-f` flags from the
  DWARF producer — dropping them made whole projects unwinnable. The metric
  still records `compilable` per function (report's per-decompiler **compile
  rate**). Known accepted limit: a normalized bare `[rip]` does not compare
  symbol identity, so reads of *different* globals can both reach 1.0. Type
  recovery is measured separately by `type_match`, so fixing types to compile
  is fair.

`decbench/utils/binfmt.py` is the shared binary-format helper: detect ELF/PE +
arch, pick the matching recompiler + capstone arch, read DWARF from ELF *or* PE
(PE: `.debug_*` sections via objdump file offsets -> pyelftools, since LIEF's
community build has no DWARF reader and PE COFF truncates section names), and
extract function bytes from a final ELF/PE or a recompiled ELF/COFF object. Both
type_match and byte_match use it, so they work on the PE (MinGW) malware targets.

**Scoring** (`decbench/scoring/`):
- `aggregator.py` - Aggregates per-function results (function key:
  `project::opt::binary::function`)
- `scoreboard.py` - Builds Scoreboard with per-metric rankings and Union (perfect on ≥1
  metric; stored in the legacy `overall_*` fields / `overall` JSON keys)
- `labels.py` - Label derivation: auto opt-level labels (`O0`/`O2` +
  `optimized`/`unoptimized`), project labels from `ProjectConfig.labels` /
  `binary_labels` (TOML), per-function auto labels (`large` ≥ 100 decompiled lines)
- `function_data_builder.py` - Builds the per-function `FunctionData` dataset persisted
  as `function_results.json`

**Results Rendering** (`decbench/rendering/`): themed after mahaloz.re (terminal
aesthetic: black bg, Source Code Pro mono, dashed rules, ASCII bars). `html.py` is
**skeleton assembly only** — it holds NO CSS, NO JS, NO prose. Layout:
- `content/` - **ALL maintainer-editable text.** `<view>.md` per view
  (leaderboard, distance, **view**, insights, changelog, **about**) + `site.toml`
  (brand/footer/banners/sidebar/side_stats, and `[decompilers] hidden` = the
  site-hidden decompilers) `views.toml` (view registry: id, nav label,
  `requires_function_data`, which is `default`), `metrics.toml` (display
  name/short name/order/perfect definition — the ONE source of truth),
  `datasets.toml` (the 5 presets' label+description+`default`), `categories.toml`
  (software-type taxonomy). Loaded by `content.py` (`load_content()`) into frozen
  dataclasses. NOTE the view set was consolidated: the old `metrics` + `dataset`
  views merged into **about** (which now carries the metric goal cards with
  collapsible SVG visualizations AND the dataset tables), and `compare` +
  `hardest` merged into **view** (source vs one decompiler across easy/medium/hard
  difficulty tiers — `scoring/view_samples.py`; ~100 samples/tier in
  `samples.json`, and `hardest.json` is no longer shipped). The 5 presets are
  now `unoptimized` (default) / `optimized` (O2-noinline) / `inlined` (O2) /
  `large` / `sample-set` (250 fns; `scoring/datasets.py`). The Compiles rate
  renders on the **distance** page; the old Historical view was removed
  2026-07-22 (HistoryPoint data + `ingest_history.py` remain, just unshipped).
  A view's `id` MUST have a matching `<id>.md`; exactly one view and one preset
  must set `default = true` (`tests/test_content.py` enforces both).
  PLUS `decompilers.toml` — the decompiler registry (id → official
  display_name/url/version_overrides, e.g. ida→"Hex-Rays" + "920"→"9.2"); shipped
  into `aggregates.json` as `decompiler_registry` (hidden decompilers gated out),
  rendered as linked names + versions everywhere `app.js` names a decompiler.
  **Raw-HTML islands**: `<details class="metric-viz">...</details>` blocks pass
  through markdown VERBATIM (`content.py _render_with_islands` — mistune would
  otherwise wrap SVG children in `<p>` inside `<svg>`, which browsers refuse to
  draw, silently breaking the about page). No line inside an
  island may start with `# `/`## `; blank lines are fine.
- `assets/` - `app.css`, `app.js`, and a **vendored** Source Code Pro woff2 (no
  Google Fonts CDN — the report must render offline). The scaffold's element ids
  (`leaderboard-table`, `view-<id>`, ...) are the contract with `app.js`;
  renaming one silently blanks a view. `app.js` also carries a self-contained
  C/asm syntax highlighter (`hlC`/`hlAsm`/`applyStaticHighlights`; token classes
  `tok-*` in app.css) — every `<pre data-lang="c|asm">` in static content and the
  view page's code panels are highlighted with it; NO third-party highlighter.
- `aggregate.py` - **precomputes every aggregate at BUILD time.** Every view is a
  pure function of exactly 2 selectors (dataset preset x normalize-failures
  toggle) = 5x2 = **10 combos**, keyed `"<preset>|<0|1>"`. Semantics are ported
  *verbatim* from the old client-side `recompute()`/`buildDistance()`/
  `buildDataset()` — they are the **fairness contract** (shared denominators),
  and JS quirks are reproduced on purpose (marked `JS parity`, e.g. global
  `isFinite(null) === true`). A "fix" here silently moves published numbers.
- `site.py` - the split Pages tree (`build_site`); its only writer.
- Two delivery modes share ONE skeleton (`build_page`) — the only difference is
  the `PageAssets` passed in: **inline** (`decbench report`, everything embedded
  because `file://` CORS-blocks `fetch()`) vs **split** (`decbench site build`,
  linked assets + lazy payloads).

Preset membership is tagged server-side by `scoring/datasets.py`
(`assign_datasets`; "large" = upper tail of the size bell curve). The
code-carrying extras (`samples`, `hardest`, `compile_rates`) are built by
`scoring/report_extras.py` (`build_samples`/`build_hardest`/`compute_compile_rates`,
wired in `attach_extras` AFTER datasets are assigned). Models in
`models/function_data.py` (`SampleEntry`, `compile_rates`).

**Why precompute**: the old report embedded every `FunctionRecord` — ~98.5 MB of
JSON the browser re-scanned on every click — and a fresh single-file report
exceeded GitHub's **100 MiB** per-file push limit, so it could not be committed
at all. Precomputing the 10 combos shrinks `aggregates.json` to tens of KiB.
Only `samples.json` and `dataset.json` are fetched lazily, when their view opens.

**Site build + deploy**: `decbench site build <results-tree> -o site/` (CLI in
`cli.py`; takes a RESULTS TREE, not a scoreboard — `scoreboard.toml` is also
accepted and resolved to its parent — and REQUIRES `function_results.json`, since
the site is entirely data-driven; `decbench report` can still fall back to
scoreboard-only tables). `data/` and `fonts/` are wiped per build: stale JSON on a
live site is worse than missing JSON, because nothing reports it. Emits
`.nojekyll` (Jekyll silently drops `_`-prefixed paths). Contract:
`docs/SITE_DATA_SCHEMA.md`. **Linkable URLs**: the build also writes a
`site/<view>/index.html` per visible view (`<base href="../">` +
`window.__DECBENCH_ROOT__`; stale view dirs pruned only when their index.html
carries `SITE_PAGE_MARKER`), so `/leaderboard/` etc. deep-link; client state
lives in query params (`?dataset=<preset>&norm=1`, and on the view page
`?tier=&dec=&metric=&fn=<proj>/<opt>/<bin>::<func>`); legacy `#<view>` hashes
still route. Payload writers use `json.dumps(..., allow_nan=False)` — browsers
parse JSON strictly, and `function_results.json` CAN contain `ged: Infinity`
(non-finite sample values are dropped by `aggregate._finite_sample`; anything
else non-finite fails the build loudly instead of shipping a payload
`JSON.parse` rejects). **`.github/workflows/pages.yml` is deploy-ONLY** — CI
CANNOT generate the site (needs the decompilers + ~1.9 GB Joern + ~15 GB of
binaries); the maintainer builds locally and commits `site/` (no longer gitignored),
and the workflow only uploads it, failing if `site/index.html` or
`site/data/aggregates.json` is missing.

**Data Models** (`decbench/models/`):
- Pydantic-based models for projects, decompilation results, metrics, scoreboards, and
  per-function data (`function_data.py`)
- Configuration via TOML files; projects support `labels` and `binary_labels` fields

**Data Flow**:
Project TOML → `Project` → compile → binaries + .i files → decompile → `DecompilationResult` (incl. per-function `variables`) → compute metrics (GED needs CFGs via pyjoern, type_match needs DWARF via pyelftools, byte_match recompiles with gcc) → `MetricResult` → aggregate → `Scoreboard` + `FunctionData` → HTML report

## Key Files

- `decbench/cli.py` - Click-based CLI entry point
- `tests/example_project/` - Example C project with Makefile for testing (Makefile uses
  `CFLAGS ?=` so the pipeline's env CFLAGS — which carry the opt level — take effect)

## Optimization levels

`OptimizationLevel` (`decbench/models/project.py`) maps each level to GCC flags via
`opt_gcc_flags()` — use that, never `f"-{opt}"`. Levels: `O0`/`O1`/`O2`/`O3`/`Os`/`Oz`
plus **`O2-noinline`** (= `-O2 -fno-inline`), an optimized build with inlining (an
outlier optimization that destroys function boundaries) specifically disabled. Plain
`O2` is now a *genuine* O2: `-fno-inline` was removed from the default `base_flags`,
so inlining is controlled solely by the level. `opt_level_labels` adds a `noinline`
label for the noinline variants.

## Gotchas

- **The published metric numbers are the reeval OVERLAYS, not the checkpoint
  inline values.** `results/<tree>/{ged,type_match,byte_match}_new.json` (from
  `scripts/reeval_{ged,typematch}.py` / `reeval_bytematch.py`) carry the
  corrected values (sanitized decompiled parses, per-TU source matching,
  non-finite dropped, compilability fixup); the per-project checkpoints still
  hold the ORIGINAL inline values from each decompiler's first evaluation.
  `run_benchmark.py`'s finalize now re-applies all three overlays (scoped: a
  decompiler with no overlay entries — freshly added r2dec/dewolf — keeps its
  inline values). Before that fix, any additive resume silently reverted every
  metric column to the stale inline set — a silent leaderboard-wide regression.
  After adding a decompiler, refresh the overlays (the reeval
  scripts' DECOMPILERS now include r2dec/dewolf) and re-run
  `rebuild_function_data.py` before publishing.
- **An additive resume leaves a SCOPED `scoreboard.toml`.**
  `DECBENCH_DECOMPILERS=<one> scripts/run_benchmark.py <tree>` merges that
  decompiler into every checkpoint and `function_results.json`, but the
  `scoreboard.toml` it writes lists ONLY that run's decompilers.
  The site renderer now takes its sidebar counts from
  `function_results.json`, but anything else reading `scoreboard.decompilers`
  after a resume sees a partial list until the next full rebuild
  (`scripts/rebuild_function_data.py`).
- **Sample source extraction needs `.c`/`.i` next to the binary.** Compile now
  `rglob`s `.c` sources; older trees' samples used the preprocessed `.i` fallback
  (`SampleEntry.source_status` `"preprocessed"`). A rebuild via
  `scripts/rebuild_function_data.py` re-extracts sample sources.
- **Multiprocessing must use `spawn`/`forkserver`, not `fork`, for large parallel
  runs.** The main process imports angr (which starts threads); forking workers
  afterward deadlocks them on a mutex held at fork time (symptom: workers wedged in
  `futex_wait`, downloads done but never extracted). `scripts/*.py` set `spawn`;
  any new parallel driver must too. Also avoid 70+ simultaneous autotools builds —
  the `configure` storm contends badly; ~16 workers is plenty.
- Local (`remote_type = "local"`) projects build **in-place**; use `pre_make_cmds =
  ["make clean"]` and avoid compiling multiple opt levels in parallel for the same
  local project (`-j 1`), or stale/raced artifacts result.
- Project source URLs: prefer release tarballs over git+bootstrap; `ftp.gnu.org` is
  flaky here, so GNU packages use the `mirrors.kernel.org/gnu/` mirror. Makefiles
  that hardcode CFLAGS need `make_cmd = 'make CFLAGS="$CFLAGS" CC="$CC"'`.
- angr vendors ailment as `angr.ailment`; the standalone `ailment` package is a
  different module — `isinstance` checks against the wrong one silently fail (this
  bit declib's line mapping once; fixed in ~/github/declib).
- `DecompilerConfig.function_timeout_seconds` is advisory: declib exposes no
  per-function decompile timeout.
- **Multi-version Ghidra needs separate processes.** pyghidra binds a single JVM
  to one install per process, so `ghidra@12.0` and `ghidra@12.1` cannot both run
  in one process — the run drivers (`decompile_one.py` subprocess per task)
  already isolate them. `scripts/run_small.py` validates this end-to-end.
- **Canonical decompiler names are now the raw (declib-free) backends**; the
  declib ones moved to `*-declib`. `scripts/decompile_one.py` must
  `import decbench.decompilers` (the whole package) to register raw+declib+
  dockerized — importing just `declib_dec` would miss the canonical names.
- **Metric caching is deterministic by content.** If you change a metric's
  algorithm, bump its `cache_version` class attr (else stale values are served);
  or run with `DECBENCH_NO_CACHE=1`. Cache root: `DECBENCH_CACHE_DIR`.
- **The site's prose is NOT in `html.py`** — it is in `decbench/rendering/content/`
  (`<view>.md` + `site/views/metrics/datasets/categories.toml`), the CSS/JS in
  `decbench/rendering/assets/`. `html.py` is skeleton assembly only; grepping it
  for user-visible text finds nothing. Editing `datasets.toml`/`metrics.toml`
  (preset labels + descriptions, metric names, perfect definitions) takes effect
  on **re-render alone — no benchmark re-run**: preset *text* is content, while
  preset *membership* is scoring (`scoring/datasets.py`), joined at render time.
  Adding a new client-side **filter dimension** is the exception — aggregates are
  precomputed per (preset x normalize) combo, so that needs a re-render
  (`decbench site build`), not just a page reload.
- A second compiled-binary snapshot can be reused without recompiling via
  `decbench dataset save/materialize` then `run --skip-compile`.

## Coding Standards

- Type hints required on all functions
- pytest for testing (fixtures in `tests/conftest.py`)
- PEP 8 with 100 character lines
