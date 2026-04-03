# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DecBench is a benchmarking suite for evaluating decompiler performance. It implements a three-stage pipeline (compile → decompile → evaluate) with pluggable decompilers and three core metrics.

## Common Commands

```bash
# Install for development
pip install -e ".[dev]"

# Run tests
pytest                              # All tests with coverage
pytest tests/test_models.py         # Single test file

# Code quality
ruff check .                        # Linting
black .                             # Formatting
mypy decbench                       # Type checking

# CLI usage
decbench run project.toml           # Run full pipeline
decbench list-decompilers           # Show available decompilers
decbench list-metrics               # Show available metrics
decbench evaluate binary.elf        # Evaluate single binary
decbench report scoreboard.toml     # Generate HTML report
```

## Architecture

**Three-Stage Pipeline** (`decbench/pipeline/`):
1. `compile.py` - Compile C projects at various optimization levels using GCC
2. `decompile.py` - Run registered decompilers on binaries
3. `evaluate.py` - Compute metrics comparing decompiled output to source
4. `executor.py` - Orchestrates the full pipeline via `PipelineExecutor`

**Plugin Systems** (registry pattern):
- `decompilers/registry.py` - Decompiler plugins (angr, Ghidra, IDA)
- `metrics/registry.py` - Metric plugins with `@register_metric` decorator
- `compilers/` - Compiler plugins (GCC)

**Three Metrics** (`decbench/metrics/`):
- `ged.py` - Structural Correctness: CFG Graph Edit Distance between source and decompiled code
- `type_match.py` - Type Correctness: Variable type recovery accuracy vs DWARF ground truth
- `byte_match.py` - Recompilation Bytematch: Assembly similarity after recompiling decompiled code

**Scoring** (`decbench/scoring/`):
- `aggregator.py` - Aggregates per-function results across binaries, tracks per-function perfects for Overall
- `scoreboard.py` - Builds Scoreboard with per-metric rankings and Overall (perfect on all 3 metrics)

**Results Rendering** (`decbench/rendering/`):
- `html.py` - Self-contained HTML report with sections for each metric and Overall

**Data Models** (`decbench/models/`):
- Pydantic-based models for projects, decompilation results, metrics, and scoreboards
- Configuration via TOML files
- No category-based organization - flat metric system

**Data Flow**:
Project TOML → `Project` → compile → binaries + .i files → decompile → `DecompilationResult` → compute metrics (GED needs CFGs via pyjoern, type_match needs DWARF via pyelftools, byte_match recompiles with gcc) → `MetricResult` → aggregate → `Scoreboard` → HTML report

## Key Files

- `decbench/cli.py` - Click-based CLI entry point
- `decbench/config.py` - Global configuration (searches decbench.toml, ~/.config/decbench/config.toml)
- `tests/example_project/` - Example C project with Makefile for testing
- `e2e_test_3metrics.py` - End-to-end test with all 3 metrics on coreutils

## Coding Standards

- Type hints required on all functions
- pytest for testing (fixtures in `tests/conftest.py`)
- PEP 8 with 100 character lines
