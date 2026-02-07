# DecBench E2E Evaluation - Quick Start

## TL;DR

Run end-to-end coreutils evaluation with angr and Ghidra on the GED metric:

```bash
# 1. Activate environment
workon decbench  # or: source ~/.virtualenvs/decbench/bin/activate

# 2. Set Ghidra path
export GHIDRA_INSTALL_DIR="/home/mahaloz/bin/ghidra_12"

# 3. Run evaluation
python e2e_coreutils_eval.py \
    --opt-levels O2 \
    --decompilers angr ghidra \
    --workers 4

# 4. View results
cat results_e2e_coreutils/ged_statistics.json
cat results_e2e_coreutils/scoreboard.toml
```

## What This Does

1. **Compiles** coreutils from source with specified optimization levels
2. **Decompiles** all binaries using angr and Ghidra
3. **Evaluates** decompilation quality using Graph Edit Distance (GED) metric
4. **Reports** statistics: mean, median, stddev, and scoreboard rankings

## Key Files Created

### Scripts
- `e2e_coreutils_eval.py` - Main E2E evaluation script
- `test_single_binary.py` - Verify setup (angr, Ghidra, metrics)
- `test_full_pipeline.py` - Test with simple binary
- `test_minimal_pipeline.py` - Minimal decompilation test

### Documentation
- `E2E_README.md` - Complete guide with troubleshooting
- `INSTALLATION_LOG.md` - Dependency tracking and installation
- `QUICKSTART.md` - This file
- `Dockerfile` - Updated for reproducible builds

## Pre-flight Check

Verify everything is set up correctly:

```bash
python test_single_binary.py
```

Expected output:
```
✓ angr is available
  Version: 9.2.197

✓ Ghidra is available
  Version: 12.0
  Path: /home/mahaloz/bin/ghidra_12/support/analyzeHeadless

✓ GED metric available: Graph Edit Distance
```

## Output Verification

The E2E script automatically verifies that output > 0:

```
✓ Verification: Output is greater than 0
Total functions processed: 2847
```

If verification fails:
- Check logs in output directory
- Run `test_single_binary.py` to diagnose issues
- See `E2E_README.md` troubleshooting section

## Important Statistics

Results are saved in `ged_statistics.json`:

```json
{
  "angr": {
    "mean": 3.45,
    "median": 2.0,
    "stddev": 4.23,
    "perfect_matches": 523,
    "function_count": 2847
  },
  "ghidra": {
    "mean": 2.89,
    "median": 1.0,
    "stddev": 3.67,
    "perfect_matches": 678,
    "function_count": 2847
  }
}
```

**Key Metrics**:
- `mean` - Average GED across all functions (lower is better)
- `median` - Middle value (more robust to outliers)
- `stddev` - Variability in decompilation quality
- `perfect_matches` - Functions with GED=0 (perfect match)

## Common Options

### Fast Test Run
```bash
# Only test on O0 (unoptimized, fastest)
python e2e_coreutils_eval.py --opt-levels O0 --workers 8
```

### Full Evaluation
```bash
# All optimization levels
python e2e_coreutils_eval.py \
    --opt-levels O0 O1 O2 O3 \
    --workers 4
```

### angr Only
```bash
# Skip Ghidra (faster)
python e2e_coreutils_eval.py --decompilers angr
```

### Resume From Decompilation
```bash
# If compilation is done, skip it
python e2e_coreutils_eval.py --skip-compile
```

## Performance

Expected runtime for coreutils O2:

| Workers | RAM | Time |
|---------|-----|------|
| 2 | 16GB | ~4 hours |
| 4 | 16GB | ~2-3 hours |
| 8 | 32GB | ~1-2 hours |

Disk usage: ~15-20GB for full O2 evaluation

## Troubleshooting One-Liners

```bash
# Check angr installation
python -c "import angr; print(angr.__version__)"

# Check Ghidra
ls -la $GHIDRA_INSTALL_DIR/support/analyzeHeadless

# Check pyjoern (CFG extraction)
python -c "import pyjoern; print('pyjoern OK')"

# Check disk space
df -h .

# Check memory
free -h
```

## Next Steps

1. **Read Full Documentation**: See `E2E_README.md` for complete guide
2. **Review Installation**: See `INSTALLATION_LOG.md` for dependencies
3. **Run Tests**: Start with `test_single_binary.py`
4. **Run E2E**: Execute `e2e_coreutils_eval.py`
5. **Analyze Results**: Check `ged_statistics.json` and `scoreboard.toml`

## Support

For detailed troubleshooting, architecture details, or advanced usage, refer to:
- `E2E_README.md` - Comprehensive guide
- `INSTALLATION_LOG.md` - Dependency details
- Project README - DecBench overview

## Files Summary

```
decbench/
├── e2e_coreutils_eval.py        # Main E2E script ⭐
├── test_single_binary.py         # Setup verification
├── test_full_pipeline.py         # Pipeline test
├── test_minimal_pipeline.py      # Basic decompiler test
├── E2E_README.md                 # Complete guide
├── INSTALLATION_LOG.md           # Dependencies
├── QUICKSTART.md                 # This file
├── Dockerfile                    # Updated for E2E
├── projects/sailr/
│   └── coreutils.toml           # Coreutils project config
└── decbench/
    ├── decompilers/
    │   ├── angr_dec.py          # Fixed angr decompiler
    │   └── ghidra_dec.py        # Fixed Ghidra decompiler
    ├── metrics/faithful/
    │   └── ged.py               # GED metric implementation
    └── pipeline/
        └── executor.py           # Pipeline orchestration
```

## Quick Verification Checklist

- [ ] Virtual environment activated (`workon decbench`)
- [ ] GHIDRA_INSTALL_DIR set
- [ ] `test_single_binary.py` passes
- [ ] Coreutils project config exists (`projects/sailr/coreutils.toml`)
- [ ] Sufficient disk space (~50GB)
- [ ] Sufficient RAM (16GB+)

If all checkboxes are ✓, you're ready to run:
```bash
python e2e_coreutils_eval.py
```
