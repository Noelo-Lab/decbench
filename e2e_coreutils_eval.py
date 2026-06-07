#!/usr/bin/env python3
"""
End-to-end evaluation script for Coreutils with angr and Ghidra decompilers.
This script runs the full pipeline: compile, decompile, evaluate on the faithful (GED) metric.
"""

import argparse
import json
import logging
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
        # Check common install locations
        for ghidra_path in ["/opt/ghidra_12", "/home/mahaloz/bin/ghidra_12"]:
            if Path(ghidra_path).exists():
                os.environ["GHIDRA_INSTALL_DIR"] = ghidra_path
                console.print(f"[yellow]Set GHIDRA_INSTALL_DIR to: {ghidra_path}[/yellow]")
                break

    # Verify Ghidra is available
    ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_install:
        console.print(f"[green]GHIDRA_INSTALL_DIR: {ghidra_install}[/green]")
    else:
        console.print("[yellow]Warning: GHIDRA_INSTALL_DIR not set[/yellow]")


def collect_ged_statistics(results, normalize: bool = True) -> Dict:
    """
    Collect GED statistics from evaluation results.

    Args:
        results: PipelineResults object
        normalize: If True, only include functions that ALL decompilers
                   successfully computed GED for (intersection). This makes
                   cross-decompiler comparison fair.

    Returns:
        Dictionary keyed by opt_level with mean, median, stddev for each decompiler
    """
    import statistics

    # Structure: project -> opt_level -> binary -> decompiler -> metric -> result
    # Pass 1: collect per-function GED values keyed by (binary, func_name, decompiler)
    # raw_values[opt_key][binary_name][dec_name][func_name] = ged_value
    raw_values: Dict[str, Dict[str, Dict[str, Dict[str, float]]]] = {}

    for project_name, opt_results in results.evaluate_results.items():
        for opt_level, binary_results in opt_results.items():
            opt_key = opt_level.value if hasattr(opt_level, "value") else str(opt_level)
            if opt_key not in raw_values:
                raw_values[opt_key] = {}

            for binary_name, decompiler_results in binary_results.items():
                if binary_name not in raw_values[opt_key]:
                    raw_values[opt_key][binary_name] = {}

                for dec_name, metrics in decompiler_results.items():
                    if dec_name not in raw_values[opt_key][binary_name]:
                        raw_values[opt_key][binary_name][dec_name] = {}

                    if "ged" in metrics:
                        ged_metric = metrics["ged"]
                        if hasattr(ged_metric, "function_results") and ged_metric.function_results:
                            for func_name, func_result in ged_metric.function_results.items():
                                value = func_result.value if hasattr(func_result, "value") else func_result
                                if isinstance(value, (int, float)) and value != float('inf'):
                                    raw_values[opt_key][binary_name][dec_name][func_name] = value

    # Pass 2: compute allowed function sets (intersection across decompilers per binary)
    allowed_funcs: Dict[str, Dict[str, set]] = {}  # opt_key -> binary -> set of func names
    for opt_key, binaries in raw_values.items():
        allowed_funcs[opt_key] = {}
        for binary_name, dec_data in binaries.items():
            if normalize and len(dec_data) > 1:
                # Intersection of function names across all decompilers
                func_sets = [set(funcs.keys()) for funcs in dec_data.values()]
                allowed_funcs[opt_key][binary_name] = set.intersection(*func_sets)
            else:
                # No normalization or single decompiler: allow all functions
                allowed_funcs[opt_key][binary_name] = set().union(
                    *(set(funcs.keys()) for funcs in dec_data.values())
                )

    # Pass 3: aggregate stats using only allowed functions
    summary: Dict = {}
    for opt_key, binaries in raw_values.items():
        summary[opt_key] = {}
        all_stats: Dict[str, Dict] = {}

        for binary_name, dec_data in binaries.items():
            allowed = allowed_funcs[opt_key][binary_name]
            for dec_name, func_values in dec_data.items():
                if dec_name not in all_stats:
                    all_stats[dec_name] = {"ged_values": [], "binary_count": 0, "function_count": 0}

                filtered = [v for fn, v in func_values.items() if fn in allowed]
                if filtered:
                    all_stats[dec_name]["ged_values"].extend(filtered)
                    all_stats[dec_name]["function_count"] += len(filtered)
                    all_stats[dec_name]["binary_count"] += 1

        for dec_name, data in all_stats.items():
            values = data["ged_values"]
            if values:
                summary[opt_key][dec_name] = {
                    "mean": statistics.mean(values),
                    "median": statistics.median(values),
                    "stddev": statistics.stdev(values) if len(values) > 1 else 0.0,
                    "min": min(values),
                    "max": max(values),
                    "count": len(values),
                    "perfect_matches": sum(1 for v in values if v == 0),
                    "binary_count": data["binary_count"],
                    "function_count": data["function_count"],
                }
            else:
                summary[opt_key][dec_name] = {
                    "mean": None, "median": None, "stddev": None,
                    "min": None, "max": None, "count": 0,
                    "perfect_matches": 0,
                    "binary_count": data["binary_count"],
                    "function_count": data["function_count"],
                }

    return summary


def display_ged_statistics(stats: Dict, normalized: bool = True):
    """Display GED statistics in a formatted table."""
    if not stats:
        console.print("[yellow]No GED statistics available[/yellow]")
        return

    mode = "normalized" if normalized else "raw"
    console.print(f"\n[bold cyan]GED Statistics Summary ({mode})[/bold cyan]\n")

    for opt_key, dec_stats in sorted(stats.items()):
        table = Table(title=f"Graph Edit Distance (GED) Metrics - {opt_key} ({mode})")
        table.add_column("Decompiler", style="cyan")
        table.add_column("Mean", justify="right", style="green")
        table.add_column("Median", justify="right", style="green")
        table.add_column("StdDev", justify="right", style="yellow")
        table.add_column("Min", justify="right")
        table.add_column("Max", justify="right")
        table.add_column("Perfect (GED=0)", justify="right", style="blue")
        table.add_column("Functions", justify="right")

        for dec_name, data in sorted(dec_stats.items()):
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
        # Structure: project -> opt_level -> binary -> decompiler -> metric -> result
        eval_data = {}
        for project_name, opt_results in results.evaluate_results.items():
            eval_data[project_name] = {}
            for opt_level, binary_results in opt_results.items():
                opt_key = opt_level.value if hasattr(opt_level, "value") else str(opt_level)
                eval_data[project_name][opt_key] = {}
                for binary_name, dec_results in binary_results.items():
                    eval_data[project_name][opt_key][binary_name] = {}
                    for dec_name, metrics in dec_results.items():
                        eval_data[project_name][opt_key][binary_name][dec_name] = {}
                        for metric_name, metric_result in metrics.items():
                            if hasattr(metric_result, "model_dump"):
                                eval_data[project_name][opt_key][binary_name][dec_name][metric_name] = metric_result.model_dump(mode="json")
                            elif hasattr(metric_result, "to_dict"):
                                eval_data[project_name][opt_key][binary_name][dec_name][metric_name] = metric_result.to_dict()
                            else:
                                eval_data[project_name][opt_key][binary_name][dec_name][metric_name] = str(metric_result)

        with open(eval_results_file, "w") as f:
            json.dump(eval_data, f, indent=2)
        console.print(f"[green]Evaluation results saved to: {eval_results_file}[/green]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not save evaluation results: {e}[/yellow]")

    # Scoreboard is already saved by the executor
    console.print(f"[green]Scoreboard saved to: {output_dir / 'scoreboard.toml'}[/green]")


def validate_results(results, expected_decompilers: List[str]) -> bool:
    """Validate that pipeline results are non-empty and meaningful.

    Returns True if validation passes, False otherwise.
    """
    passed = True

    # Check total functions
    if results.total_functions == 0:
        console.print("[red]FAIL: No functions were processed[/red]")
        passed = False
    else:
        console.print(f"[green]PASS: {results.total_functions} functions processed[/green]")

    # Check each decompiler produced output
    # decompile_results structure: project -> opt_level -> binary -> decompiler -> DecompilationResult
    decompiler_func_counts: Dict[str, int] = {d: 0 for d in expected_decompilers}

    for project_results in results.decompile_results.values():
        for opt_results in project_results.values():
            for binary_results in opt_results.values():
                for dec_name, dec_result in binary_results.items():
                    if dec_name in decompiler_func_counts:
                        decompiler_func_counts[dec_name] += dec_result.function_count

    for dec_name in expected_decompilers:
        count = decompiler_func_counts.get(dec_name, 0)
        if count > 0:
            console.print(f"[green]PASS: {dec_name} decompiled {count} functions[/green]")
        else:
            console.print(f"[red]FAIL: {dec_name} produced 0 functions[/red]")
            passed = False

    # Check evaluation results are non-empty
    # evaluate_results structure: project -> opt_level -> binary -> decompiler -> metric -> MetricResult
    total_metric_results = 0
    non_empty_metric_results = 0

    for project_results in results.evaluate_results.values():
        for opt_results in project_results.values():
            for binary_results in opt_results.values():
                for dec_name, metrics in binary_results.items():
                    for metric_name, metric_result in metrics.items():
                        total_metric_results += 1
                        if hasattr(metric_result, "function_results") and metric_result.function_results:
                            non_empty_metric_results += 1
                        elif hasattr(metric_result, "mean") and metric_result.mean is not None:
                            non_empty_metric_results += 1

    if total_metric_results > 0:
        console.print(f"[green]PASS: {total_metric_results} metric results ({non_empty_metric_results} with values)[/green]")
    else:
        console.print("[red]FAIL: No metric results produced[/red]")
        passed = False

    if total_metric_results > 0 and non_empty_metric_results == 0:
        console.print("[yellow]WARN: All metric results are empty (no function-level values)[/yellow]")

    return passed


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
        choices=["angr", "ghidra", "ida", "binja"],
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
        "--limit",
        "-l",
        type=int,
        default=None,
        help="Limit number of binaries to process (default: all)"
    )
    parser.add_argument(
        "--sample",
        "-s",
        type=int,
        default=None,
        help="Deterministically sample N binaries to process (default: all)"
    )
    parser.add_argument(
        "--no-normalize",
        action="store_true",
        help="Disable normalization (show all functions per decompiler, not just shared ones)"
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

    # Configure logging so warnings from cfg.py/evaluate.py are visible
    logging.basicConfig(
        level=logging.WARNING,
        format="%(name)s: %(levelname)s: %(message)s",
    )

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
        binary_limit=args.limit,
        binary_sample=args.sample,
    )

    # Display configuration
    console.print("\n[bold]Configuration:[/bold]")
    console.print(f"  Output directory: {args.output}")
    console.print(f"  Optimization levels: {', '.join(args.opt_levels)}")
    console.print(f"  Decompilers: {', '.join(args.decompilers)}")
    console.print(f"  Metrics: {', '.join(args.metrics)}")
    console.print(f"  Workers: {args.workers}")
    if args.limit:
        console.print(f"  Binary limit: {args.limit}")
    if args.sample:
        console.print(f"  Binary sample: {args.sample}")
    console.print(f"  Normalize: {not args.no_normalize}")

    # Run pipeline
    console.print("\n[bold cyan]Starting DecBench E2E Pipeline...[/bold cyan]\n")

    executor = PipelineExecutor(config)

    try:
        results = executor.run([project])

        # Collect and display GED statistics
        normalize = not args.no_normalize
        console.print("\n[bold cyan]Collecting GED Statistics...[/bold cyan]")
        ged_stats = collect_ged_statistics(results, normalize=normalize)
        display_ged_statistics(ged_stats, normalized=normalize)

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

        # Validate results
        console.print("\n[bold cyan]Validating Results...[/bold cyan]")
        if validate_results(results, args.decompilers):
            console.print("\n[bold green]✓ All validation checks passed[/bold green]")
            return 0
        else:
            console.print("\n[bold red]✗ Some validation checks failed[/bold red]")
            return 1

    except Exception as e:
        console.print(f"\n[bold red]Pipeline failed: {e}[/bold red]")
        import traceback
        console.print(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())
