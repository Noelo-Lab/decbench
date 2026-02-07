#!/bin/bash
# Installation script for DecBench end-to-end evaluation

set -e  # Exit on error

echo "╔══════════════════════════════════════════════╗"
echo "║  DecBench Installation Script                ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Check Python version
echo "[1/5] Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo "❌ Python 3.10 or higher required. Found: $PYTHON_VERSION"
    exit 1
fi
echo "✓ Python $PYTHON_VERSION found"

# Check for required system tools
echo ""
echo "[2/5] Checking system dependencies..."
MISSING_DEPS=""

for cmd in gcc g++ git java; do
    if ! command -v $cmd &> /dev/null; then
        MISSING_DEPS="$MISSING_DEPS $cmd"
    fi
done

if [ -n "$MISSING_DEPS" ]; then
    echo "⚠ Missing system dependencies:$MISSING_DEPS"
    echo "Please install them with:"
    echo "  sudo apt-get install build-essential git default-jre"
    exit 1
fi
echo "✓ System dependencies found"

# Check Ghidra
echo ""
echo "[3/5] Checking Ghidra installation..."
GHIDRA_DIR="${GHIDRA_INSTALL_DIR:-/home/$USER/bin/ghidra_12}"

if [ ! -d "$GHIDRA_DIR" ]; then
    echo "⚠ Ghidra not found at: $GHIDRA_DIR"
    echo "Please set GHIDRA_INSTALL_DIR environment variable or install Ghidra"
    echo "Example: export GHIDRA_INSTALL_DIR=/path/to/ghidra"
    exit 1
fi

if [ ! -f "$GHIDRA_DIR/support/analyzeHeadless" ]; then
    echo "❌ analyzeHeadless not found in $GHIDRA_DIR/support/"
    exit 1
fi
echo "✓ Ghidra found at: $GHIDRA_DIR"

# Create virtual environment
echo ""
echo "[4/5] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "⚠ Virtual environment already exists. Skipping creation."
else
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi

# Install Python packages
echo ""
echo "[5/5] Installing Python packages..."
source venv/bin/activate

pip install --upgrade pip > /dev/null 2>&1
pip install -e . > /dev/null
echo "✓ Installed decbench"

pip install angr > /dev/null
echo "✓ Installed angr"

# Export environment variable
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Installation Complete!                      ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To set Ghidra path for your session:"
echo "  export GHIDRA_INSTALL_DIR=\"$GHIDRA_DIR\""
echo ""
echo "To add to your .bashrc (persistent):"
echo "  echo 'export GHIDRA_INSTALL_DIR=\"$GHIDRA_DIR\"' >> ~/.bashrc"
echo ""
echo "Test your setup with:"
echo "  python test_single_binary.py"
echo ""
echo "Run full evaluation with:"
echo "  python e2e_coreutils_eval.py"
echo ""
