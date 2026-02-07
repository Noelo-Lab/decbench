#!/usr/bin/env python3
"""
Test the full pipeline with a simple binary and source.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add decbench to path
sys.path.insert(0, str(Path(__file__).parent))

# Set up environment
os.environ["GHIDRA_INSTALL_DIR"] = "/home/mahaloz/bin/ghidra_12"

from decbench.decompilers.registry import DecompilerRegistry
from decbench.metrics.registry import MetricRegistry
from decbench.utils.cfg import extract_cfgs_from_source
from decbench.pipeline.evaluate import evaluate_decompilation

# Register modules
import decbench.decompilers.angr_dec
import decbench.decompilers.ghidra_dec
import decbench.metrics.faithful

from rich.console import Console
import json

console = Console()


def main():
    console.print("\n[bold cyan]Testing Full Pipeline with GED Metric[/bold cyan]\n")

    # Use test binary
    test_binary = Path("/tmp/test_program")
    test_source = Path("/tmp/test_program.i")  # preprocessed source

    if not test_binary.exists():
        console.print("[red]Test binary not found[/red]")
        return 1

    if not test_source.exists():
        console.print("[yellow]Preprocessed source not found, using .c[/yellow]")
        test_source = Path("/tmp/test_program.c")

    console.print(f"Binary: {test_binary}")
    console.print(f"Source: {test_source}")

    # Extract source CFGs
    console.print("\n[bold]Extracting source CFGs...[/bold]")
    try:
        source_cfgs = extract_cfgs_from_source(test_source)
        console.print(f"[green]✓[/green] Extracted {len(source_cfgs)} function CFGs")
        for func_name in list(source_cfgs.keys())[:5]:
            cfg = source_cfgs[func_name]
            console.print(f"  - {func_name}: {cfg.number_of_nodes()} nodes, {cfg.number_of_edges()} edges")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not extract source CFGs: {e}[/yellow]")
        source_cfgs = {}

    # Create temp output directory
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir)

        # Test angr
        console.print("\n[bold]Testing angr decompilation:[/bold]")
        try:
            angr_dec = DecompilerRegistry.get("angr")
            angr_result = angr_dec.decompile_binary(
                test_binary,
                output_dir=output_dir / "angr"
            )

            console.print(f"[green]✓[/green] angr decompiled {len(angr_result.functions)} functions")
            for func_name in list(angr_result.functions.keys())[:3]:
                console.print(f"  - {func_name}")

            # Evaluate with GED metric if we have source CFGs
            if source_cfgs and len(angr_result.functions) > 0:
                console.print("\n[bold]Evaluating angr with GED metric...[/bold]")
                try:
                    eval_result = evaluate_decompilation(
                        angr_result,
                        source_cfgs,
                        metrics=["ged"]
                    )

                    if "ged" in eval_result:
                        ged_result = eval_result["ged"]
                        console.print(f"[green]✓[/green] GED evaluation complete")
                        console.print(f"  Mean: {ged_result.mean}")
                        console.print(f"  Median: {ged_result.median}")
                        console.print(f"  Std Dev: {ged_result.stddev}")
                except Exception as e:
                    console.print(f"[yellow]Warning: GED evaluation failed: {e}[/yellow]")
                    import traceback
                    traceback.print_exc()

        except Exception as e:
            console.print(f"[red]✗ angr failed: {e}[/red]")
            import traceback
            traceback.print_exc()

        # Test Ghidra
        console.print("\n[bold]Testing Ghidra decompilation:[/bold]")
        try:
            ghidra_dec = DecompilerRegistry.get("ghidra")
            ghidra_result = ghidra_dec.decompile_binary(
                test_binary,
                output_dir=output_dir / "ghidra"
            )

            console.print(f"[green]✓[/green] Ghidra decompiled {len(ghidra_result.functions)} functions")
            for func_name in list(ghidra_result.functions.keys())[:3]:
                console.print(f"  - {func_name}")

            # Evaluate with GED metric if we have source CFGs
            if source_cfgs and len(ghidra_result.functions) > 0:
                console.print("\n[bold]Evaluating Ghidra with GED metric...[/bold]")
                try:
                    eval_result = evaluate_decompilation(
                        ghidra_result,
                        source_cfgs,
                        metrics=["ged"]
                    )

                    if "ged" in eval_result:
                        ged_result = eval_result["ged"]
                        console.print(f"[green]✓[/green] GED evaluation complete")
                        console.print(f"  Mean: {ged_result.mean}")
                        console.print(f"  Median: {ged_result.median}")
                        console.print(f"  Std Dev: {ged_result.stddev}")
                except Exception as e:
                    console.print(f"[yellow]Warning: GED evaluation failed: {e}[/yellow]")
                    import traceback
                    traceback.print_exc()

        except Exception as e:
            console.print(f"[red]✗ Ghidra failed: {e}[/red]")
            import traceback
            traceback.print_exc()

    console.print("\n[bold green]Full pipeline test complete![/bold green]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
