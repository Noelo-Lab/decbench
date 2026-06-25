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
  **Ghidra 12.1** AND **Ghidra 12.0** (`/home/mahaloz/bin/ghidra_12.{1,0}`, via
  pyghidra; export `GHIDRA_INSTALL_DIR` for the unversioned default),
  **IDA Pro 9.2 idalib** (at `/home/mahaloz/ctf/tools/idapro_9.2`, license
  present — it works; the older note that only an unusable IDA 8.0 exists is
  obsolete), and **r2dec** (native radare2 at `/usr/bin`, using the built-in
  `pdc` pseudo-decompiler since the r2dec plugin can't build without dev
  headers/sudo). **Binary Ninja is NOT installed** (`binja` coded but
  unavailable). **RetDec/Reko** are Dockerized (`docker/`, images not pre-built).
  `decbench list-decompilers` shows availability.
- **Two Ghidra versions** are configured for multi-version benchmarking in
  `~/.config/decbench/decompilers.toml` (`ghidra@12.0` → ghidra_12.0,
  `ghidra@12.1` → ghidra_12.1). Run them as distinct specs: `-d ghidra@12.0 -d
  ghidra@12.1`. They MUST run in separate processes (pyghidra binds one JVM to
  one install per process) — the run drivers already use per-task subprocesses.
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
- See PROGRESS.md "Environment setup" / "Target expansion" for full rebuild notes.

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
decbench run project.toml -d ghidra@12.0 -d ghidra@12.1  # multiple versions (historical view)
decbench list-decompilers           # Show available decompilers (angr/ghidra/ida/r2dec/...)
decbench list-metrics               # Show available metrics
decbench evaluate binary.elf        # Evaluate single binary
decbench report scoreboard.toml     # Generate HTML report (interactive if
                                    # function_results.json sits next to the scoreboard)
# v2 helpers:
decbench dataset save results/sailr_full sailr   # snapshot compiled binaries (no recompile later)
decbench dataset materialize sailr results/reuse # lay back out, then: decbench run --skip-compile
decbench subset results/sailr_full/function_results.json  # large-function subset manifest
decbench decompiler-build retdec    # build a dockerized decompiler image
# Caching is automatic (content-addressed); DECBENCH_NO_CACHE=1 disables it.
# Quick end-to-end smoke (raw backends + 2 Ghidra versions + caching + report):
DECBENCH_SMALL_DECOMPILERS="angr,ida,ghidra@12.0,ghidra@12.1" python scripts/run_small.py

# Benchmark targets: 26 sailr-eval Debian packages live in projects/sailr/*.toml
# (each builds at O0 / O2 / O2-noinline, labeled by kind + domain).

# Large multi-target runs: prefer the resilient drivers in scripts/ over a single
# `decbench run` — they use the 'spawn' multiprocessing context (the default
# 'fork' DEADLOCKS when workers are forked after angr's threads start) and
# checkpoint per project so a multi-hour run survives crashes:
GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1 \
  python scripts/compile_all.py results/sailr_full 16   # compile all (16 workers)
DECBENCH_WORKERS=40 GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1 \
  python scripts/run_benchmark.py results/sailr_full     # decompile+evaluate+report
#   run_benchmark.py knobs (env): DECBENCH_DECOMPILERS (default angr,ghidra),
#   DECBENCH_DECOMPILE_TIMEOUT (s, default 300), DECBENCH_GED_MAX_NODES (60).
#   Restart resumes from per-project checkpoints; `... results/sailr_full -- grep`
#   limits to named projects. Single project: scripts/decompile_one.py.
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
- `byte_match.py` - Recompilation Bytematch: Assembly similarity after recompiling decompiled code

**Scoring** (`decbench/scoring/`):
- `aggregator.py` - Aggregates per-function results (function key:
  `project::opt::binary::function`)
- `scoreboard.py` - Builds Scoreboard with per-metric rankings and Overall (perfect on all 3 metrics)
- `labels.py` - Label derivation: auto opt-level labels (`O0`/`O2` +
  `optimized`/`unoptimized`), project labels from `ProjectConfig.labels` /
  `binary_labels` (TOML), per-function auto labels (`large` ≥ 100 decompiled lines)
- `function_data_builder.py` - Builds the per-function `FunctionData` dataset persisted
  as `function_results.json`

**Results Rendering** (`decbench/rendering/`):
- `html.py` - Self-contained HTML report, themed after mahaloz.re (terminal
  aesthetic: black bg, Source Code Pro mono, dashed rules, Unix-path nav, ASCII
  bars). With function data it embeds JSON + vanilla JS: label/binary toggles
  that live-recompute all scores, a comparison matrix, and a per-binary
  breakdown. Two extra views (built by `scoring/report_extras.py`): **Hardest
  Functions** (a "hall of shame" of the worst-scoring functions with their
  decompiled code) and **Historical** (pure-SVG line charts, one per metric,
  of each decompiler's score across versions/time — driven by multi-version
  data, e.g. `ghidra@12.0` vs `ghidra@12.1`).

**Data Models** (`decbench/models/`):
- Pydantic-based models for projects, decompilation results, metrics, scoreboards, and
  per-function data (`function_data.py`)
- Configuration via TOML files; projects support `labels` and `binary_labels` fields

**Data Flow**:
Project TOML → `Project` → compile → binaries + .i files → decompile → `DecompilationResult` (incl. per-function `variables`) → compute metrics (GED needs CFGs via pyjoern, type_match needs DWARF via pyelftools, byte_match recompiles with gcc) → `MetricResult` → aggregate → `Scoreboard` + `FunctionData` → HTML report

## Key Files

- `decbench/cli.py` - Click-based CLI entry point
- `decbench/config.py` - Global configuration (searches decbench.toml, ~/.config/decbench/config.toml)
- `tests/example_project/` - Example C project with Makefile for testing (Makefile uses
  `CFLAGS ?=` so the pipeline's env CFLAGS — which carry the opt level — take effect)
- `e2e_test_3metrics.py` - End-to-end test with all 3 metrics on coreutils
- `PROGRESS.md` - Work log: environment setup details, declib integration notes, results

## Optimization levels

`OptimizationLevel` (`decbench/models/project.py`) maps each level to GCC flags via
`opt_gcc_flags()` — use that, never `f"-{opt}"`. Levels: `O0`/`O1`/`O2`/`O3`/`Os`/`Oz`
plus **`O2-noinline`** (= `-O2 -fno-inline`), an optimized build with inlining (an
outlier optimization that destroys function boundaries) specifically disabled. Plain
`O2` is now a *genuine* O2: `-fno-inline` was removed from the default `base_flags`,
so inlining is controlled solely by the level. `opt_level_labels` adds a `noinline`
label for the noinline variants.

## Gotchas

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
- A second compiled-binary snapshot can be reused without recompiling via
  `decbench dataset save/materialize` then `run --skip-compile`.

## Coding Standards

- Type hints required on all functions
- pytest for testing (fixtures in `tests/conftest.py`)
- PEP 8 with 100 character lines
