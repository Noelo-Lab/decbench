#!/usr/bin/env python3
"""
Minimal test of the pipeline with a simple binary.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add decbench to path
sys.path.insert(0, str(Path(__file__).parent))

# Set up environment
os.environ["GHIDRA_INSTALL_DIR"] = "/home/mahaloz/bin/ghidra_12"

# Import after setting environment
from decbench.decompilers.registry import DecompilerRegistry
from decbench.decompilers.base import DecompilerConfig

# Register decompilers
import decbench.decompilers.angr_dec
import decbench.decompilers.ghidra_dec

from rich.console import Console
import shutil

console = Console()


def main():
    console.print("\n[bold cyan]Testing Minimal Pipeline[/bold cyan]\n")

    # Find a simple binary
    test_binary = shutil.which("ls")
    if not test_binary:
        console.print("[red]Could not find ls binary[/red]")
        return 1

    console.print(f"[green]Testing with binary: {test_binary}[/green]")

    # Create temp output directory
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir)
        console.print(f"Output directory: {output_dir}")

        # Test angr
        console.print("\n[bold]Testing angr decompilation:[/bold]")
        try:
            angr_dec = DecompilerRegistry.get("angr")
            config = DecompilerConfig(
                binary_timeout_seconds=60,
                function_timeout_seconds=30
            )
            angr_dec.config = config

            result = angr_dec.decompile_binary(
                Path(test_binary),
                output_dir=output_dir / "angr"
            )

            console.print(f"[green]✓[/green] angr decompiled {len(result.functions)} functions")
            console.print(f"  Failed functions: {len(result.decompiler.failed_functions)}")
            console.print(f"  Total time: {result.decompiler.total_time_seconds:.2f}s")

        except Exception as e:
            console.print(f"[red]✗ angr decompilation failed: {e}[/red]")
            import traceback
            traceback.print_exc()

        # Test Ghidra
        console.print("\n[bold]Testing Ghidra decompilation:[/bold]")
        try:
            ghidra_dec = DecompilerRegistry.get("ghidra")
            config = DecompilerConfig(
                binary_timeout_seconds=120,
                function_timeout_seconds=30
            )
            ghidra_dec.config = config

            result = ghidra_dec.decompile_binary(
                Path(test_binary),
                output_dir=output_dir / "ghidra"
            )

            console.print(f"[green]✓[/green] Ghidra decompiled {len(result.functions)} functions")
            console.print(f"  Failed functions: {len(result.decompiler.failed_functions)}")
            console.print(f"  Total time: {result.decompiler.total_time_seconds:.2f}s")

            # Check output files
            output_files = list((output_dir / "ghidra").glob("*"))
            console.print(f"  Output files: {len(output_files)}")
            for f in output_files[:3]:
                console.print(f"    - {f.name}")

        except Exception as e:
            console.print(f"[red]✗ Ghidra decompilation failed: {e}[/red]")
            import traceback
            traceback.print_exc()

    console.print("\n[bold green]Minimal pipeline test complete![/bold green]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
