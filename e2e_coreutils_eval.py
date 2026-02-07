#!/usr/bin/env python3
"""
End-to-end evaluation script for Coreutils with angr and Ghidra decompilers.
This script runs the full pipeline: compile, decompile, evaluate on the faithful (GED) metric.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List

# Add decbench to path
sys.path.insert(0, str(Path(__file__).parent))

from decbench.models.project import Project, OptimizationLevel
from decbench.pipeline.executor import PipelineConfig, PipelineExecutor
from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()


def setup_environment():
    """Setup required environment variables."""
    # Set GHIDRA_INSTALL_DIR if not already set
    if "GHIDRA_INSTALL_DIR" not in os.environ:
        ghidra_path = "/home/mahaloz/bin/ghidra_12"
        if Path(ghidra_path).exists():
            os.environ["GHIDRA_INSTALL_DIR"] = ghidra_path
            console.print(f"[yellow]Set GHIDRA_INSTALL_DIR to: {ghidra_path}[/yellow]")

    # Verify Ghidra is available
    ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_install:
        console.print(f"[green]GHIDRA_INSTALL_DIR: {ghidra_install}[/green]")
    else:
        console.print("[yellow]Warning: GHIDRA_INSTALL_DIR not set[/yellow]")


def collect_ged_statistics(results) -> Dict:
    """
    Collect GED statistics from evaluation results.

    Returns:
        Dictionary with mean, median, stddev for each decompiler
    """
    import statistics

    stats = {}

    # Iterate through evaluation results
    for binary_name, decompiler_results in results.evaluate_results.items():
        for dec_name, metrics in decompiler_results.items():
            if dec_name not in stats:
                stats[dec_name] = {
                    "ged_values": [],
                    "binary_count": 0,
                    "function_count": 0
                }

            # Look for GED metric
            if "ged" in metrics:
                ged_metric = metrics["ged"]
                # Collect all function-level GED values
                if hasattr(ged_metric, "per_function") and ged_metric.per_function:
                    for func_name, func_value in ged_metric.per_function.items():
                        if isinstance(func_value, (int, float)) and func_value != float('inf'):
                            stats[dec_name]["ged_values"].append(func_value)
                            stats[dec_name]["function_count"] += 1
                elif hasattr(ged_metric, "value") and ged_metric.value != float('inf'):
                    stats[dec_name]["ged_values"].append(ged_metric.value)
                    stats[dec_name]["function_count"] += 1

                stats[dec_name]["binary_count"] += 1

    # Calculate statistics
    summary = {}
    for dec_name, data in stats.items():
        values = data["ged_values"]
        if values:
            summary[dec_name] = {
                "mean": statistics.mean(values),
                "median": statistics.median(values),
                "stddev": statistics.stdev(values) if len(values) > 1 else 0.0,
                "min": min(values),
                "max": max(values),
                "count": len(values),
                "perfect_matches": sum(1 for v in values if v == 0),
                "binary_count": data["binary_count"],
                "function_count": data["function_count"]
            }
        else:
            summary[dec_name] = {
                "mean": None,
                "median": None,
                "stddev": None,
                "min": None,
                "max": None,
                "count": 0,
                "perfect_matches": 0,
                "binary_count": data["binary_count"],
                "function_count": data["function_count"]
            }

    return summary


def display_ged_statistics(stats: Dict):
    """Display GED statistics in a formatted table."""
    if not stats:
        console.print("[yellow]No GED statistics available[/yellow]")
        return

    console.print("\n[bold cyan]GED Statistics Summary[/bold cyan]\n")

    table = Table(title="Graph Edit Distance (GED) Metrics")
    table.add_column("Decompiler", style="cyan")
    table.add_column("Mean", justify="right", style="green")
    table.add_column("Median", justify="right", style="green")
    table.add_column("StdDev", justify="right", style="yellow")
    table.add_column("Min", justify="right")
    table.add_column("Max", justify="right")
    table.add_column("Perfect (GED=0)", justify="right", style="blue")
    table.add_column("Functions", justify="right")

    for dec_name, data in sorted(stats.items()):
        if data["mean"] is not None:
            perfect_pct = (data["perfect_matches"] / data["count"] * 100) if data["count"] > 0 else 0
            table.add_row(
                dec_name,
                f"{data['mean']:.2f}",
                f"{data['median']:.2f}",
                f"{data['stddev']:.2f}",
                f"{data['min']:.2f}",
                f"{data['max']:.2f}",
                f"{data['perfect_matches']} ({perfect_pct:.1f}%)",
                str(data["count"])
            )
        else:
            table.add_row(dec_name, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "0")

    console.print(table)


def save_results(results, output_dir: Path, stats: Dict):
    """Save evaluation results and statistics to disk."""
    # Save GED statistics as JSON
    stats_file = output_dir / "ged_statistics.json"
    with open(stats_file, "w") as f:
        json.dump(stats, f, indent=2)
    console.print(f"\n[green]GED statistics saved to: {stats_file}[/green]")

    # Save raw evaluation results
    eval_results_file = output_dir / "evaluation_results.json"
    try:
        # Convert results to serializable format
        eval_data = {}
        for binary_name, dec_results in results.evaluate_results.items():
            eval_data[binary_name] = {}
            for dec_name, metrics in dec_results.items():
                eval_data[binary_name][dec_name] = {}
                for metric_name, metric_result in metrics.items():
                    if hasattr(metric_result, "to_dict"):
                        eval_data[binary_name][dec_name][metric_name] = metric_result.to_dict()
                    else:
                        eval_data[binary_name][dec_name][metric_name] = str(metric_result)

        with open(eval_results_file, "w") as f:
            json.dump(eval_data, f, indent=2)
        console.print(f"[green]Evaluation results saved to: {eval_results_file}[/green]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not save evaluation results: {e}[/yellow]")

    # Scoreboard is already saved by the executor
    console.print(f"[green]Scoreboard saved to: {output_dir / 'scoreboard.toml'}[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="End-to-end evaluation of Coreutils with angr and Ghidra on the faithful (GED) metric"
    )
    parser.add_argument(
        "--project",
        type=Path,
        default=Path("projects/sailr/coreutils.toml"),
        help="Path to coreutils project TOML (default: projects/sailr/coreutils.toml)"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("results_e2e_coreutils"),
        help="Output directory for results (default: results_e2e_coreutils)"
    )
    parser.add_argument(
        "--opt-levels",
        "-O",
        nargs="+",
        choices=["O0", "O1", "O2", "O3", "Os"],
        default=["O2"],
        help="Optimization levels to use (default: O2)"
    )
    parser.add_argument(
        "--decompilers",
        "-d",
        nargs="+",
        choices=["angr", "angr_phoenix", "angr_dream", "ghidra"],
        default=["angr", "ghidra"],
        help="Decompilers to use (default: angr ghidra)"
    )
    parser.add_argument(
        "--metrics",
        "-m",
        nargs="+",
        default=["ged"],
        help="Metrics to evaluate (default: ged)"
    )
    parser.add_argument(
        "--workers",
        "-j",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4)"
    )
    parser.add_argument(
        "--skip-compile",
        action="store_true",
        help="Skip compilation step (use existing binaries)"
    )
    parser.add_argument(
        "--skip-decompile",
        action="store_true",
        help="Skip decompilation step (use existing decompilations)"
    )
    parser.add_argument(
        "--skip-evaluate",
        action="store_true",
        help="Skip evaluation step"
    )

    args = parser.parse_args()

    # Setup environment
    setup_environment()

    # Load project
    console.print(f"\n[bold]Loading project from: {args.project}[/bold]")
    try:
        project = Project.from_toml(args.project)
        console.print(f"[green]✓[/green] Loaded project: [bold]{project.name}[/bold]")
    except Exception as e:
        console.print(f"[red]✗ Failed to load project: {e}[/red]")
        return 1

    # Configure pipeline
    config = PipelineConfig(
        output_dir=args.output,
        optimization_levels=[OptimizationLevel(o) for o in args.opt_levels],
        decompilers=args.decompilers,
        metrics=args.metrics,
        workers=args.workers,
        skip_compile=args.skip_compile,
        skip_decompile=args.skip_decompile,
        skip_evaluate=args.skip_evaluate,
    )

    # Display configuration
    console.print("\n[bold]Configuration:[/bold]")
    console.print(f"  Output directory: {args.output}")
    console.print(f"  Optimization levels: {', '.join(args.opt_levels)}")
    console.print(f"  Decompilers: {', '.join(args.decompilers)}")
    console.print(f"  Metrics: {', '.join(args.metrics)}")
    console.print(f"  Workers: {args.workers}")

    # Run pipeline
    console.print("\n[bold cyan]Starting DecBench E2E Pipeline...[/bold cyan]\n")

    executor = PipelineExecutor(config)

    try:
        results = executor.run([project])

        # Collect and display GED statistics
        console.print("\n[bold cyan]Collecting GED Statistics...[/bold cyan]")
        ged_stats = collect_ged_statistics(results)
        display_ged_statistics(ged_stats)

        # Save all results
        console.print("\n[bold cyan]Saving Results...[/bold cyan]")
        save_results(results, args.output, ged_stats)

        # Display summary
        console.print("\n[bold green]═══════════════════════════════════════════[/bold green]")
        console.print("[bold green]Pipeline Complete![/bold green]")
        console.print(f"[bold green]═══════════════════════════════════════════[/bold green]\n")

        if results.scoreboard:
            from decbench.scoring.scoreboard import render_scoreboard_text
            console.print(render_scoreboard_text(results.scoreboard))

        console.print(f"\n[cyan]Total binaries processed: {results.total_binaries}[/cyan]")
        console.print(f"[cyan]Total functions processed: {results.total_functions}[/cyan]")
        console.print(f"[cyan]Total time: {results.total_time_seconds:.1f}s ({results.total_time_seconds/60:.1f}m)[/cyan]")
        console.print(f"\n[green]Results saved to: {args.output}/[/green]")

        # Verify output is greater than 0
        if results.total_functions > 0:
            console.print("\n[bold green]✓ Verification: Output is greater than 0[/bold green]")
            return 0
        else:
            console.print("\n[bold red]✗ Verification failed: No functions were processed[/bold red]")
            return 1

    except Exception as e:
        console.print(f"\n[bold red]Pipeline failed: {e}[/bold red]")
        import traceback
        console.print(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())
