# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DecBench is a benchmarking suite for evaluating decompiler performance. It implements a three-stage pipeline (compile → decompile → evaluate) with pluggable decompilers and three core metrics.

## Environment

- Use the `decbench` virtualenv: `source /home/mahaloz/.virtualenvs/decbench/bin/activate`
  (Python 3.12; decbench is installed editable there).
- Decompiler backends on this machine: IDA Pro 9.2 (`/home/mahaloz/bin/idapro_92`,
  idalib importable as `idapro`), Ghidra 12.1 (needs `GHIDRA_INSTALL_DIR`, set to
  `/home/mahaloz/bin/ghidra_12.1`), angr (pip). Binary Ninja is supported but not installed.
- `declib` (the unified decompiler interface library) is installed editable from
  `~/github/declib`. Decompiler bugs sometimes need fixing THERE, not in decbench.
- `pyjoern` bundles a ~1.9 GB Joern under site-packages (auto-downloaded on first import).
  `pygraphviz` was built against headers extracted to `~/.local/graphviz-dev` (no sudo
  needed — see PROGRESS.md "Environment setup" if it ever needs reinstalling).

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
decbench run project.toml -O O0 -O O2 -d angr -d ida -d ghidra   # Full pipeline
decbench list-decompilers           # Show available decompilers
decbench list-metrics               # Show available metrics
decbench evaluate binary.elf        # Evaluate single binary
decbench report scoreboard.toml     # Generate HTML report (interactive if
                                    # function_results.json sits next to the scoreboard)
```

## Architecture

**Three-Stage Pipeline** (`decbench/pipeline/`):
1. `compile.py` - Compile C projects at various optimization levels using GCC
2. `decompile.py` - Run registered decompilers on binaries (fresh process per task via
   `max_tasks_per_child=1` to isolate JVM/idalib state)
3. `evaluate.py` - Compute metrics comparing decompiled output to source
4. `executor.py` - Orchestrates the full pipeline via `PipelineExecutor`; also writes
   `function_results.json` (per-function results + labels) next to `scoreboard.toml`

**Decompilers** (`decbench/decompilers/`): all four backends — `angr`, `ida`, `ghidra`,
`binja` — are thin subclasses of `DeclibDecompiler` in `declib_dec.py`, driving declib's
`DecompilerInterface.discover(force_decompiler=..., headless=True, binary_path=...)`.
Key conventions:
- declib returns *lifted* (0-based) addresses; decbench stores ELF-file-space addresses
  (`lifted + min PT_LOAD vaddr`) so they match DWARF.
- Functions outside the ELF `.text` section (PLT stubs/thunks) and CRT helpers are skipped.
- `FunctionDecompilation.variables` (list of `VariableInfo`) carries recovered stack
  variables/args (name, type, declib-lifted stack offset, size) for the type metric.
- Ghidra forbids dot-prefixed path elements; per-binary project dirs are
  `declib_<name>_projects/<binary>/` under the output dir.

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
- `html.py` - Self-contained HTML report. With function data it embeds JSON + vanilla JS:
  label/binary disable toggles that live-recompute all scores, a decompiler comparison
  matrix, and a per-binary breakdown. Without it, a static report with a notice banner.

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

## Gotchas

- Local (`remote_type = "local"`) projects build **in-place**; use `pre_make_cmds =
  ["make clean"]` and avoid compiling multiple opt levels in parallel for the same
  local project (`-j 1`), or stale/raced artifacts result.
- angr vendors ailment as `angr.ailment`; the standalone `ailment` package is a
  different module — `isinstance` checks against the wrong one silently fail (this
  bit declib's line mapping once; fixed in ~/github/declib).
- `DecompilerConfig.function_timeout_seconds` is advisory: declib exposes no
  per-function decompile timeout.

## Coding Standards

- Type hints required on all functions
- pytest for testing (fixtures in `tests/conftest.py`)
- PEP 8 with 100 character lines
