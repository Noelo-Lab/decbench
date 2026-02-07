#!/usr/bin/env python3
"""
Test script for a single binary to verify the pipeline works.
"""

import os
import sys
from pathlib import Path

# Add decbench to path
sys.path.insert(0, str(Path(__file__).parent))

# Set up environment
os.environ["GHIDRA_INSTALL_DIR"] = "/home/mahaloz/bin/ghidra_12"

# Import after setting environment
from decbench.decompilers.registry import DecompilerRegistry
from decbench.metrics.registry import MetricRegistry

# Register decompilers
import decbench.decompilers.angr_dec
import decbench.decompilers.ghidra_dec

# Register metrics
import decbench.metrics.faithful
import decbench.metrics.simple

from rich.console import Console
from rich.table import Table

console = Console()


def main():
    console.print("\n[bold cyan]Testing DecBench Setup[/bold cyan]\n")

    # Test decompiler availability
    console.print("[bold]Checking Decompilers:[/bold]")
    table = Table()
    table.add_column("Decompiler", style="cyan")
    table.add_column("Available", style="green")
    table.add_column("Version")

    for name in DecompilerRegistry.list_registered():
        try:
            dec = DecompilerRegistry.get(name)
            available = "✓" if dec.is_available() else "✗"
            version = dec.get_version() or "-"
            table.add_row(name, available, version)
        except Exception as e:
            table.add_row(name, "✗", f"Error: {e}")

    console.print(table)

    # Test metric availability
    console.print("\n[bold]Checking Metrics:[/bold]")
    metric_table = Table()
    metric_table.add_column("Metric", style="cyan")
    metric_table.add_column("Category", style="yellow")

    for name in MetricRegistry.list_registered():
        try:
            metric = MetricRegistry.get(name)
            metric_table.add_row(name, metric.category.value)
        except Exception as e:
            metric_table.add_row(name, f"Error: {e}")

    console.print(metric_table)

    # Test angr specifically
    console.print("\n[bold]Testing angr decompiler:[/bold]")
    try:
        angr_dec = DecompilerRegistry.get("angr")
        if angr_dec.is_available():
            console.print("[green]✓[/green] angr is available")
            console.print(f"  Version: {angr_dec.get_version()}")
        else:
            console.print("[red]✗[/red] angr is not available")
    except Exception as e:
        console.print(f"[red]✗[/red] Error with angr: {e}")

    # Test ghidra specifically
    console.print("\n[bold]Testing Ghidra decompiler:[/bold]")
    try:
        ghidra_dec = DecompilerRegistry.get("ghidra")
        if ghidra_dec.is_available():
            console.print("[green]✓[/green] Ghidra is available")
            console.print(f"  Version: {ghidra_dec.get_version()}")
            console.print(f"  Path: {ghidra_dec._ghidra_path}")
        else:
            console.print("[red]✗[/red] Ghidra is not available")
    except Exception as e:
        console.print(f"[red]✗[/red] Error with Ghidra: {e}")

    # Test GED metric
    console.print("\n[bold]Testing GED metric:[/bold]")
    try:
        ged_metric = MetricRegistry.get("ged")
        console.print(f"[green]✓[/green] GED metric available: {ged_metric.display_name}")
    except Exception as e:
        console.print(f"[red]✗[/red] Error with GED metric: {e}")

    console.print("\n[bold green]Setup test complete![/bold green]\n")


if __name__ == "__main__":
    main()
