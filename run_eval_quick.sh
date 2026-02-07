#!/bin/bash
# Quick test with minimal coreutils binaries

set -e

mkdir -p results

echo "Running quick DecBench test (limited binaries)..."
docker run --rm \
    -v "$(pwd):/workspace/decbench" \
    -v "$(pwd)/results:/workspace/results" \
    -w /workspace/decbench \
    -e PYTHONPATH=/workspace/decbench \
    decbench:latest \
    bash -c "python3.12 -m pip install --break-system-packages -q -e . && python3.12 e2e_coreutils_eval.py --output /workspace/results --opt-levels O2 --workers 2"

echo ""
echo "Test complete! Checking results..."

# Check if results exist and have non-zero content
if [ -f results/ged_statistics.json ]; then
    echo "✓ GED statistics file created"

    # Check for non-zero faithful component
    if grep -q "mean" results/ged_statistics.json; then
        echo "✓ Statistics contain data"

        # Display the statistics
        echo ""
        echo "=== GED Statistics ==="
        cat results/ged_statistics.json | python3 -m json.tool
    else
        echo "✗ Statistics file is empty or invalid"
        exit 1
    fi
else
    echo "✗ GED statistics file not found"
    exit 1
fi
