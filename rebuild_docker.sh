#!/bin/bash
# Rebuild the DecBench Docker container

set -e

# Unset DOCKER_HOST to avoid socket issues
unset DOCKER_HOST

echo "Building DecBench Docker image..."
docker build -t decbench:latest .

echo "Docker image built successfully!"
echo "You can now run evaluation with: ./run_eval.sh"
