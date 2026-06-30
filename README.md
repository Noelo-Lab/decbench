# DecBench

A benchmarking suite for evaluating decompiler performance across three dimensions of correctness.

## Metrics

DecBench evaluates decompilers using three core metrics:

| Metric | What it measures | How it works |
|--------|-----------------|--------------|
| **Structural Correctness (GED)** | Control flow recovery | Graph Edit Distance between source and decompiled CFGs using [cfgutils](https://github.com/angr/cfgutils) |
| **Type Correctness** | Variable type recovery | Compares decompiled variable types against DWARF debug info ground truth |
| **Recompilation Bytematch** | Recompilable, semantically-equivalent code | Recompiles each decompiled function with the **original toolchain** (matching its format/arch/opt flags) after a compilability **fixup** pass, then diffs the assembly via Jaccard similarity with linker-dependent operands normalized away |

An **Overall** score tracks the percentage of functions where a decompiler achieves a perfect match on *all three* metrics simultaneously — i.e. the source was precisely recovered.

### Byte-match fairness (fixup + normalization)

Raw decompiler output rarely recompiles as-is (Ghidra emits pseudo-types like
`undefined4`/`code`; angr emits illegal `GLIBC_2.2.5::stderr` tokens), so naive
recompilation scores almost everything 0. To measure *logic* recovery fairly,
the byte-match metric applies the same two passes to every decompiler:

- **Compilability fixup** (`decbench/metrics/fixup.py`) — a deterministic,
  algorithmic (no LLM) gcc-diagnostic-driven self-repair loop: it strips illegal
  tokens, then injects *only* what the compiler reports missing (typedefs for
  pseudo-types, stubs for undeclared symbols), never redefining what the
  decompiler already declared. Raised the compile rate from ~16–39% to ~44–46%.
- **Operand normalization** — branch/call targets and PC-relative (`[rip±x]`,
  AArch64 `adrp`) displacements are link-time-dependent, so they're blanked
  before diffing; otherwise an unlinked `call` displacement counts as a mismatch.

Type recovery is scored separately (Type Correctness), so fixing types just to
compile does not inflate this metric. Each function also records whether it
recompiled at all, surfaced as the report's per-decompiler **compile rate**.

## Pipeline

DecBench runs a three-stage pipeline:

```
Source Code (TOML config)
    --> Compile (gcc, multiple -O levels)
    --> Decompile (angr, Ghidra, IDA)
    --> Evaluate (GED + Type Match + Byte Match)
    --> Scoreboard + HTML Report
```

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run full pipeline on a project
decbench run projects/sailr/coreutils.toml

# Run with specific decompilers and metrics
decbench run project.toml -d angr -d ghidra -m ged -m type_match -m byte_match

# Evaluate a single binary
decbench evaluate binary.elf -s source.c

# Generate HTML report from results
decbench report results/scoreboard.toml -o report.html

# List available decompilers and metrics
decbench list-decompilers
decbench list-metrics
```

## Generating results

`decbench run` works for a single project, but real benchmark runs use the
resilient drivers in `scripts/` — they checkpoint per project (so a multi-hour
run survives crashes) and use the `spawn` multiprocessing context (the default
`fork` deadlocks workers once angr's threads are live).

```bash
# 1. Compile every project at every opt level into a results tree.
GHIDRA_INSTALL_DIR=/path/to/ghidra \
  python scripts/compile_all.py results/sailr_full 16        # 16 workers

# 2. Decompile + evaluate + write the scoreboard, function data, and report.
DECBENCH_WORKERS=40 DECBENCH_DECOMPILERS=angr,ghidra \
  GHIDRA_INSTALL_DIR=/path/to/ghidra \
  python scripts/run_benchmark.py results/sailr_full
#   Restart resumes from per-project checkpoints.
#   `... results/sailr_full -- grep` limits to named projects.
```

This produces, under `results/sailr_full/`:

- `scoreboard.toml` — machine-readable per-metric + overall scores
- `function_results.json` — the per-function dataset the HTML report embeds
  (values, perfect flags, dataset tags, side-by-side **samples** with source,
  **hardest** functions, per-decompiler **compile rates**)
- `<opt>/<project>/{compiled,decompiled,evaluated}/` — intermediate artifacts

### Re-scoring byte-match without re-decompiling

Decompilation is the slow part. To re-score **only** byte-match over an existing
results tree (e.g. after a metric change) — reusing the stored `decompiled/*.c`
and `compiled/` binaries — run the two offline scripts, then re-render:

```bash
python scripts/reeval_bytematch.py results/sailr_full 40      # -> byte_match_new.json (parallel, resumable)
python scripts/rebuild_function_data.py results/sailr_full    # -> refreshed function_results.json + scoreboard.toml
decbench report results/sailr_full/scoreboard.toml -o results/sailr_full/report.html
```

## Rendering the site

```bash
# Render the interactive HTML report next to a scoreboard. If a sibling
# function_results.json exists, the report is fully interactive.
decbench report results/sailr_full/scoreboard.toml -o results/sailr_full/report.html
```

The report is a **self-contained single-page app** (no server, no external
assets beyond a web font) themed in a terminal aesthetic. A left **sidebar**
switches between views and holds a **dataset selector** (`full` / `hard` /
`hard-inlined` / `tiny`) that live-recomputes every score client-side:

| View | What it shows |
|------|---------------|
| **Leaderboard** | swebench-style ranked table — one row per decompiler, columns for Overall + each metric's perfect % + compile rate; sortable by any column |
| **Metrics** | the three decompilation goals, the metric for each, and per-decompiler perfect/compile rates |
| **Compare** | original source side-by-side with each decompiler's output for a curated set of functions, with per-metric scores |
| **Hardest** | the worst-scoring functions, with decompiled code and source |
| **Historical** | per-metric perfect % across decompiler versions (e.g. `ghidra@12.0` vs `ghidra@12.1`) |

## Project Configuration

Projects are defined via TOML files:

```toml
name = "coreutils"
version = "9.4"
source_remote = "https://ftp.gnu.org/gnu/coreutils/coreutils-9.4.tar.xz"
remote_type = "tar"
source_dir = "src"
make_cmd = "make"
pre_make_cmds = ["./configure --quiet"]

[compilation]
optimization_levels = ["O0", "O2"]
base_flags = ["-g", "-fno-inline", "-fno-builtin"]
```

## Supported Decompilers

- **angr** - Open-source binary analysis framework (multiple structuring algorithms)
- **Ghidra** - NSA's open-source reverse engineering tool (via pyghidra)
- **IDA Pro** - Commercial decompiler (via idalib, IDA 9+)

## Results

After running the pipeline, DecBench generates:

- **Scoreboard** (`scoreboard.toml`) — machine-readable per-metric + overall scores
- **Function data** (`function_results.json`) — per-function dataset embedded by the report
- **HTML Report** — the interactive single-page site described in [Rendering the site](#rendering-the-site)
- **Per-binary TOML files** — detailed per-function metric values

`decbench run` also prints a text scoreboard to the terminal, e.g.:
```
============================================================
  DecBench Scoreboard
  Functions: 2,309 | Binaries: 2
============================================================

GED:
  > angr                       48.8%

BYTE_MATCH:
  > angr                        1.7%

TYPE_MATCH:
  > angr                        0.0%

OVERALL (perfect on all metrics):
  > angr                        0.0%
============================================================
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Linting and formatting
ruff check .
black .
mypy decbench
```

## Architecture

```
decbench/
  pipeline/         # compile -> decompile -> evaluate orchestration
  metrics/          # ged.py, type_match.py, byte_match.py, fixup.py
  decompilers/      # angr, ghidra, ida plugins
  compilers/        # gcc plugin
  models/           # Pydantic data models
  scoring/          # aggregation, scoreboard, datasets, report extras
  rendering/        # html.py — interactive single-page report
  utils/            # binfmt.py, source_extract.py, cfg.py
  cli.py            # Click-based CLI
scripts/            # scalable run drivers + offline byte-match re-eval/rebuild
```

## Dependencies

- Python 3.10+
- [angr](https://angr.io/) - Binary analysis and decompilation
- [pyjoern](https://github.com/angr/pyjoern) - Source CFG extraction
- [cfgutils](https://github.com/angr/cfgutils) - Graph Edit Distance
- [pyelftools](https://github.com/eliben/pyelftools) - ELF/DWARF parsing
- [capstone](https://www.capstone-engine.org/) - Disassembly for byte matching
- [diff-match-patch](https://github.com/google/diff-match-patch) - Assembly diffing

## License

MIT
