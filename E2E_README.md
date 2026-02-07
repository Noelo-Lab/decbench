# End-to-End Evaluation Guide for DecBench

This document provides instructions for running end-to-end evaluations on coreutils with angr and Ghidra decompilers using the faithful (GED) metric.

## Prerequisites

### System Requirements
- x86_64 Linux machine
- Python 3.10+
- GCC 9+ (for compilation)
- Java Runtime Environment (for Ghidra)
- At least 16GB RAM recommended
- ~50GB disk space for coreutils evaluation

### Environment Setup

1. **Virtual Environment**: Use the `decbench` virtualenv:
   ```bash
   # If using virtualenvwrapper
   workon decbench

   # Or activate directly
   source ~/.virtualenvs/decbench/bin/activate
   ```

2. **Environment Variables**:
   ```bash
   export GHIDRA_INSTALL_DIR="/home/mahaloz/bin/ghidra_12"
   ```

### Installed Dependencies

The following dependencies are required and should be installed in the `decbench` environment:

```
angr>=9.2.197
cfgutils>=1.16.0
pyjoern>=4.0.150
networkx>=3.6.1
pyelftools>=0.32
pydantic>=2.0
toml>=0.10
tqdm>=4.0
click>=8.0
rich>=13.0
```

Install missing dependencies:
```bash
pip install angr cfgutils pyjoern networkx pyelftools
```

## Quick Start

### Test Installation

1. **Verify Setup**:
   ```bash
   python test_single_binary.py
   ```

   This will check that angr and Ghidra are available and properly configured.

2. **Test with Simple Binary**:
   ```bash
   python test_full_pipeline.py
   ```

   This tests the full pipeline with a simple test program.

### Run Coreutils Evaluation

#### Full Evaluation (All Binaries)

Run the complete coreutils evaluation with angr and Ghidra:

```bash
python e2e_coreutils_eval.py \
    --project projects/sailr/coreutils.toml \
    --output results_coreutils \
    --opt-levels O2 \
    --decompilers angr ghidra \
    --metrics ged \
    --workers 4
```

#### Options Explained

- `--project`: Path to project TOML configuration (default: projects/sailr/coreutils.toml)
- `--output`, `-o`: Output directory for results (default: results_e2e_coreutils)
- `--opt-levels`, `-O`: Optimization levels to use (choices: O0, O1, O2, O3, Os)
- `--decompilers`, `-d`: Decompilers to use (choices: angr, angr_phoenix, angr_dream, ghidra)
- `--metrics`, `-m`: Metrics to evaluate (default: ged)
- `--workers`, `-j`: Number of parallel workers (default: 4)
- `--skip-compile`: Skip compilation step (use existing binaries)
- `--skip-decompile`: Skip decompilation step (use existing decompilations)
- `--skip-evaluate`: Skip evaluation step

#### Incremental Runs

If you want to run evaluation in stages:

1. **Compile Only**:
   ```bash
   python e2e_coreutils_eval.py --skip-decompile --skip-evaluate
   ```

2. **Decompile Only** (after compilation):
   ```bash
   python e2e_coreutils_eval.py --skip-compile --skip-evaluate
   ```

3. **Evaluate Only** (after decompilation):
   ```bash
   python e2e_coreutils_eval.py --skip-compile --skip-decompile
   ```

## Output Structure

After running the evaluation, the output directory will contain:

```
results_coreutils/
├── scoreboard.toml              # Overall decompiler rankings
├── ged_statistics.json          # Detailed GED statistics (mean, median, stddev)
├── evaluation_results.json      # Raw evaluation results
└── O2/                          # Results per optimization level
    └── coreutils/
        ├── compiled/            # Compiled binaries and preprocessed sources
        ├── decompiled/          # Decompilation outputs
        │   ├── angr_*.c        # angr decompilations
        │   ├── angr_*.toml     # angr metadata
        │   ├── ghidra_*.c      # Ghidra decompilations
        │   └── ghidra_*.toml   # Ghidra metadata
        └── evaluated/           # Evaluation results per binary
```

### Key Output Files

1. **scoreboard.toml**: Overall rankings and aggregate scores
2. **ged_statistics.json**: Important statistics including:
   - `mean`: Average GED across all functions
   - `median`: Median GED
   - `stddev`: Standard deviation
   - `min`/`max`: Range of GED values
   - `perfect_matches`: Number of functions with GED=0
   - `count`: Total functions evaluated

3. **evaluation_results.json**: Detailed per-function metrics

## Expected Results

For coreutils O2 with angr and Ghidra:

- **Total binaries**: ~100 (coreutils utilities)
- **Total functions**: ~2000-3000 functions
- **Runtime**: 2-4 hours (depending on hardware and parallelism)
- **Disk usage**: ~10-20GB

### GED Metric Interpretation

- **GED = 0**: Perfect structural match between source and decompiled CFG
- **Lower is better**: Smaller GED indicates closer match to source
- **Perfect matches**: Higher percentage indicates better decompilation quality

## Troubleshooting

### angr Issues

1. **Unicorn warnings**: Safe to ignore - angr will use fallback engine
2. **CFG warnings**: Common for complex binaries, usually non-fatal
3. **Memory issues**: Reduce `--workers` count or increase system RAM

### Ghidra Issues

1. **Java not found**: Install Java Runtime Environment
   ```bash
   sudo apt-get install default-jre
   ```

2. **Ghidra timeout**: Increase timeout in decompiler config
3. **Script errors**: Check Ghidra logs in output directory

### pyjoern Issues

1. **First run**: pyjoern downloads Joern binaries (~1.8GB) on first use
2. **CFG extraction fails**: Check that source files are valid C code
3. **Java memory**: Increase Java heap size if needed

### General Issues

1. **Permission errors**: Ensure write access to output directory
2. **Disk space**: Check available disk space before running
3. **Python packages**: Verify all dependencies are installed:
   ```bash
   pip list | grep -E "(angr|cfgutils|pyjoern)"
   ```

## Docker Deployment

For reproducible environments, use the provided Dockerfile:

```bash
# Build image
docker build -t decbench:latest .

# Run evaluation
docker run -v $(pwd)/results:/workspace/results decbench:latest \
    python e2e_coreutils_eval.py --output /workspace/results
```

### Docker Configuration

The Dockerfile includes:
- Ubuntu 22.04 base
- GCC 9
- Python 3.12
- Ghidra 12.0
- All required Python dependencies
- Pre-configured GHIDRA_INSTALL_DIR

## Performance Tuning

### Parallelism

Adjust `--workers` based on your system:
- **4-8 workers**: Typical for 16GB RAM systems
- **8-16 workers**: For 32GB+ RAM systems
- **1-2 workers**: For memory-constrained systems

### Optimization Levels

- **O0**: Largest binaries, most functions, longest runtime
- **O2**: Good balance (recommended for initial runs)
- **O3**: Aggressive optimization, fewer functions

### Metrics

- **GED only**: Fastest, most relevant for structural comparison
- **All metrics**: Complete evaluation but longer runtime

## Verification

The E2E script includes automatic verification:

```python
if results.total_functions > 0:
    print("✓ Verification: Output is greater than 0")
else:
    print("✗ Verification failed: No functions were processed")
```

Successful runs will show:
- Total functions > 0
- GED statistics with valid mean/median/stddev
- Scoreboard with decompiler rankings

## Notes

- **First run**: May take longer due to pyjoern downloading Joern binaries
- **Incremental**: Use `--skip-*` flags to resume from previous stages
- **Debugging**: Check individual binary results in evaluation_results.json
- **Reproducibility**: Use Docker for consistent cross-machine results

## Support

For issues or questions:
1. Check this README first
2. Review error messages in output
3. Verify environment setup with `test_single_binary.py`
4. Check decbench logs in output directory
