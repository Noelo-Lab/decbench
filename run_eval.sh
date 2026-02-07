#!/bin/bash
# Run DecBench evaluation with source code mounted

set -e

# Unset DOCKER_HOST to avoid socket issues
unset DOCKER_HOST

# Create results directory if it doesn't exist
mkdir -p results

echo "Running DecBench evaluation with mounted source code..."
docker run --rm \
    -v "$(pwd):/workspace/decbench" \
    -v "$(pwd)/results:/workspace/results" \
    -w /workspace/decbench \
    -e PYTHONPATH=/workspace/decbench \
    decbench:latest \
    bash -c "python3.12 -m pip install --break-system-packages -e . && python3.12 e2e_coreutils_eval.py --output /workspace/results --opt-levels O2 --workers 4"

echo ""
echo "Evaluation complete! Check results in ./results/"
echo "Key files:"
echo "  - results/ged_statistics.json"
echo "  - results/evaluation_results.json"
echo "  - results/scoreboard.toml"
