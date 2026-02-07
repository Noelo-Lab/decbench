# DecBench Installation Log

This document tracks all dependencies and system requirements for running DecBench end-to-end evaluations.

## System Information

- **Date**: 2026-02-05
- **Platform**: x86_64 Linux
- **OS**: Linux 6.14.0-37-generic
- **Python**: 3.12

## Python Environment

**Environment Name**: `decbench`
**Location**: `~/.virtualenvs/decbench/`

### Core Dependencies

Installed via `pyproject.toml`:

```toml
[project]
dependencies = [
    "pydantic>=2.0",
    "toml>=0.10",
    "tqdm>=4.0",
    "networkx>=3.0",
    "pyelftools>=0.29",
    "cfgutils>=1.10.2",
    "pyjoern>=1.2.18",
    "click>=8.0",
    "rich>=13.0",
    "angr"
]
```

### Installed Package Versions

| Package | Version | Purpose |
|---------|---------|---------|
| angr | 9.2.197 | Binary decompilation |
| cfgutils | 1.16.0 | CFG similarity/GED computation |
| pyjoern | 4.0.150.4 | CFG extraction from C source |
| networkx | 3.6.1 | Graph operations |
| pyelftools | 0.32 | ELF binary parsing |
| pydantic | 2.10.6 | Data validation |
| toml | 0.10.2 | Config file parsing |
| tqdm | 4.67.1 | Progress bars |
| click | 8.1.8 | CLI framework |
| rich | 13.9.4 | Terminal formatting |

### Additional Dependencies

These are automatically installed as transitive dependencies:

- `ailment` - angr IL
- `archinfo` - Architecture definitions
- `pyvex` - VEX IR translation
- `cle` - Binary loader for angr
- `claripy` - Constraint solving
- `capstone` - Disassembly
- `unicorn` - CPU emulation (optional)
- `pygments` - Syntax highlighting
- `z3-solver` - SMT solver

## External Tools

### Ghidra 12.0

**Installation Location**: `/home/mahaloz/bin/ghidra_12/`
**Environment Variable**: `GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12`

**Components**:
- Ghidra Framework
- Decompiler (C/C++)
- analyzeHeadless (headless analysis tool)

**Version**: 12.0 (PUBLIC)
**Java Requirement**: JRE 17+

### GCC Compiler

**Version**: GCC 9+
**Purpose**: Compiling test projects (coreutils)

**Required Flags**:
```bash
-g                  # Debug symbols
-fno-inline         # Disable inlining
-fno-builtin        # Disable builtin functions
-save-temps=obj     # Save preprocessed files (.i)
-O2                 # Optimization level
```

### Joern (via pyjoern)

**Version**: Automatically downloaded by pyjoern (v2.x)
**Size**: ~1.8GB
**Location**: Managed by pyjoern (typically `~/.local/share/pyjoern/`)

**Purpose**: CFG extraction from C source code for GED metric

**First Run Note**: On first use, pyjoern will automatically download Joern binaries. This is a one-time operation that may take several minutes depending on network speed.

## System Packages

Required system packages (Ubuntu/Debian):

```bash
sudo apt-get install -y \
    build-essential \
    git \
    python3-dev \
    default-jre \
    graphviz \
    graphviz-dev \
    libgraphviz-dev \
    pkg-config
```

## Installation Steps

### 1. Create Virtual Environment

Using virtualenvwrapper:
```bash
mkvirtualenv decbench -p python3.12
workon decbench
```

Or using venv:
```bash
python3.12 -m venv ~/.virtualenvs/decbench
source ~/.virtualenvs/decbench/bin/activate
```

### 2. Install DecBench

```bash
cd /home/mahaloz/github/decbench
pip install -e .
```

This installs decbench in editable mode along with all dependencies listed in `pyproject.toml`.

### 3. Install Additional Dependencies

If not already installed:
```bash
pip install angr cfgutils pyjoern
```

### 4. Set Environment Variables

Add to `~/.bashrc` or `~/.zshrc`:
```bash
export GHIDRA_INSTALL_DIR="/home/mahaloz/bin/ghidra_12"
```

### 5. Verify Installation

```bash
python test_single_binary.py
```

Expected output:
- ✓ angr is available (version 9.2.197)
- ✓ Ghidra is available (version 12.0)
- ✓ GED metric available

## Docker Installation

For reproducible environments, use the provided Dockerfile:

### Build Image

```bash
docker build -t decbench:latest .
```

### Dockerfile Contents

- **Base**: Ubuntu 22.04
- **Python**: 3.12
- **GCC**: 9
- **Ghidra**: 12.0 (installed to `/opt/ghidra_12`)
- **Dependencies**: All Python packages pre-installed

### Run Container

```bash
docker run -it -v $(pwd)/results:/workspace/results decbench:latest
```

## Known Issues and Workarounds

### 1. Unicorn Warning

**Issue**:
```
ERROR | angr.state_plugins.unicorn_engine | failed loading "unicornlib.so"
```

**Impact**: Low - angr uses fallback engine
**Workaround**: Safe to ignore, or reinstall unicorn-engine

### 2. pyjoern First Run

**Issue**: Long delay on first run while downloading Joern

**Workaround**:
- Pre-download by running: `python -c "import pyjoern; pyjoern.get_joern()"`
- Or wait ~5-10 minutes for automatic download

### 3. Ghidra Script Execution

**Issue**: Ghidra scripts require proper argument passing

**Fix Applied**: Updated `ghidra_dec.py` to use `getScriptArgs()` instead of interactive `askString()`

### 4. angr Decompilation Options

**Issue**: `REMOVE_DEAD_MEMDEFS` option not available in angr 9.2.197

**Fix Applied**: Removed unsupported option from decompiler configuration

## Verification

Run the test suite to verify installation:

```bash
# Test basic setup
python test_single_binary.py

# Test decompilation pipeline
python test_full_pipeline.py

# Test GED statistics collection
python e2e_coreutils_eval.py --help
```

## Troubleshooting

### Import Errors

If you encounter import errors:
```bash
pip install --upgrade pip
pip install -e . --force-reinstall --no-cache-dir
```

### Memory Issues

For large projects like coreutils:
- Reduce `--workers` parameter
- Use incremental processing with `--skip-*` flags
- Increase system swap space

### Ghidra Issues

If Ghidra fails to start:
```bash
# Check Java installation
java -version

# Check Ghidra path
ls -la $GHIDRA_INSTALL_DIR/support/analyzeHeadless

# Test Ghidra manually
$GHIDRA_INSTALL_DIR/support/analyzeHeadless
```

## Maintenance

### Update Dependencies

```bash
pip install --upgrade angr cfgutils pyjoern
```

### Update Ghidra

1. Download new version
2. Extract to `/home/mahaloz/bin/ghidra_XX`
3. Update `GHIDRA_INSTALL_DIR` environment variable
4. Update Dockerfile if needed

### Clean Environment

```bash
# Remove cached files
rm -rf ~/.cache/pyjoern
rm -rf /tmp/ghidra_*

# Reinstall decbench
pip uninstall decbench
pip install -e .
```

## Performance Notes

### Hardware Recommendations

- **CPU**: 8+ cores for parallel processing
- **RAM**: 16GB minimum, 32GB recommended
- **Disk**: 50GB+ for coreutils evaluation
- **Network**: Fast connection for initial pyjoern download

### Optimization

- **Parallelism**: Use `--workers N` where N = CPU cores / 2
- **Compilation**: Use `-O2` for balanced binary size vs. decompilation accuracy
- **Incremental**: Use `--skip-*` flags to resume interrupted runs

## References

- **angr Documentation**: https://docs.angr.io/
- **Ghidra Documentation**: https://ghidra-sre.org/
- **pyjoern Repository**: https://github.com/fabsx00/pyjoern
- **cfgutils Repository**: https://github.com/mahaloz/cfgutils
- **DecBench**: This repository

## Change Log

### 2026-02-05
- Initial installation on x86_64 Linux system
- Installed angr 9.2.197, cfgutils 1.16.0, pyjoern 4.0.150
- Configured Ghidra 12.0
- Fixed angr decompilation options compatibility
- Fixed Ghidra script argument passing
- Created E2E evaluation script for coreutils
- All core functionality verified working

