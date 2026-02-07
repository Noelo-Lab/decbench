# Docker-Based Evaluation Guide

This guide explains how to run DecBench evaluations using Docker with source code mounting for easy development.

## Quick Start

### 1. Rebuild Docker Image (After Dependency Changes)

Only needed when you modify the Dockerfile or need to update system dependencies:

```bash
./rebuild_docker.sh
```

### 2. Run Quick Test

Test the pipeline with a small evaluation:

```bash
./run_eval_quick.sh
```

This will:
- Mount your source code into the container
- Install DecBench in editable mode
- Run evaluation on coreutils with O2 optimization
- Output results to `./results/`
- Verify that GED statistics are generated with non-zero values

### 3. Run Full Evaluation

```bash
./run_eval.sh
```

## What's Fixed

The previous issues have been resolved:

1. **Missing `autopoint`**: Removed duplicate package entry (it comes with `gettext`)
2. **Missing `help2man`**: Added to Dockerfile dependencies
3. **Source code mounting**: Docker now mounts your local code instead of copying at build time
4. **No rebuild needed**: You can modify Python code without rebuilding the Docker image

## Docker Architecture

The Dockerfile now contains:
- Ubuntu 24.04 base
- System dependencies (gcc, autoconf, rsync, etc.)
- Ghidra 12
- Python 3.12 and base packages
- **No source code** (mounted at runtime)

## Manual Docker Commands

If you prefer to run commands manually:

### Build the image:
```bash
docker build -t decbench:latest .
```

### Run evaluation:
```bash
docker run --rm \
    -v "$(pwd):/workspace/decbench" \
    -v "$(pwd)/results:/workspace/results" \
    -w /workspace/decbench \
    -e PYTHONPATH=/workspace/decbench \
    decbench:latest \
    bash -c "python3.12 -m pip install --break-system-packages -e . && \
             python3.12 e2e_coreutils_eval.py --output /workspace/results"
```

### Interactive shell:
```bash
docker run --rm -it \
    -v "$(pwd):/workspace/decbench" \
    -w /workspace/decbench \
    -e PYTHONPATH=/workspace/decbench \
    decbench:latest \
    bash
```

## Output Files

Results are saved to `./results/`:

- **ged_statistics.json**: Summary statistics (mean, median, stddev, perfect matches)
- **evaluation_results.json**: Detailed per-binary, per-function results
- **scoreboard.toml**: Overall decompiler rankings

## Verification

The evaluation is successful if:
1. `ged_statistics.json` is created
2. Statistics contain non-zero mean/median values
3. At least some functions were evaluated
4. Perfect matches (GED=0) are reported

Example successful output:
```json
{
  "angr": {
    "mean": 15.23,
    "median": 12.0,
    "perfect_matches": 42,
    "function_count": 150
  },
  "ghidra": {
    "mean": 18.45,
    "median": 15.0,
    "perfect_matches": 38,
    "function_count": 150
  }
}
```

## Troubleshooting

### Docker daemon not running
```bash
sudo systemctl start docker
# Or on your system:
sudo service docker start
```

### Permission denied on Docker socket
```bash
sudo usermod -aG docker $USER
# Then log out and back in
```

### Out of disk space
```bash
# Clean up old Docker images
docker system prune -a
```

### Evaluation hangs or takes too long
- Reduce `--workers` to 1 or 2
- Use `--skip-compile` if you've already compiled
- Use `--skip-decompile` if you've already decompiled

## Development Workflow

1. Modify Python code in your editor
2. Run `./run_eval_quick.sh` to test changes
3. No Docker rebuild needed!
4. Results appear immediately in `./results/`

## Advanced Options

See help for all options:
```bash
docker run --rm \
    -v "$(pwd):/workspace/decbench" \
    decbench:latest \
    python3.12 /workspace/decbench/e2e_coreutils_eval.py --help
```

Key options:
- `--opt-levels O0 O2 O3`: Choose optimization levels
- `--decompilers angr ghidra`: Select decompilers
- `--workers 8`: Parallel worker count
- `--skip-compile`: Use existing binaries
- `--skip-decompile`: Use existing decompilations
