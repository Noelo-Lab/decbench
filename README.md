# DecBench

A benchmarking suite for evaluating decompiler performance across three dimensions of correctness.

## Metrics

DecBench evaluates decompilers using three core metrics:

| Metric | What it measures | How it works |
|--------|-----------------|--------------|
| **Structural Correctness (GED)** | Control flow recovery | Graph Edit Distance between source and decompiled CFGs using [cfgutils](https://github.com/angr/cfgutils) |
| **Type Correctness** | Variable type recovery | Compares decompiled variable types against DWARF debug info ground truth |
| **Recompilation Bytematch** | Semantic equivalence | Recompiles decompiled code with gcc, compares assembly via Jaccard similarity |

An **Overall** score tracks the percentage of functions where a decompiler achieves a perfect match on *all three* metrics simultaneously.

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

- **Scoreboard** (`scoreboard.toml`) - Machine-readable results
- **HTML Report** - Self-contained dark-themed page with rankings per metric and overall
- **Per-binary TOML files** - Detailed per-function metric values

Example output:
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
  metrics/          # ged.py, type_match.py, byte_match.py
  decompilers/      # angr, ghidra, ida plugins
  compilers/        # gcc plugin
  models/           # Pydantic data models
  scoring/          # aggregation and scoreboard generation
  rendering/        # HTML report renderer
  cli.py            # Click-based CLI
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
