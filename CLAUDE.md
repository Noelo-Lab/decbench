# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DecBench is a benchmarking suite for evaluating decompiler performance. It implements a three-stage pipeline (compile → decompile → evaluate) with pluggable decompilers and metrics.

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

**Metric Categories** (`decbench/metrics/`):
- `faithful/` - CFG-based metrics (Graph Edit Distance)
- `simple/` - Structural metrics (LOC similarity)
- `correct/` - Correctness metrics (byte matching)

**Data Models** (`decbench/models/`):
- Pydantic-based models for projects, decompilation results, metrics, and scoreboards
- Configuration via TOML files

**Data Flow**:
Project TOML → `Project` → compile → `CompileResult` (binaries + .i files) → decompile → `DecompilationResult` → extract CFGs with pyjoern → compute metrics → `MetricResult` → aggregate → `Scoreboard`

## Key Files

- `decbench/cli.py` - Click-based CLI entry point
- `decbench/config.py` - Global configuration (searches decbench.toml, ~/.config/decbench/config.toml)
- `tests/example_project/` - Example C project with Makefile for testing

## Coding Standards

- Type hints required on all functions
- pytest for testing (fixtures in `tests/conftest.py`)
- PEP 8 with 100 character lines
