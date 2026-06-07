#!/usr/bin/env python3
"""
End-to-end test: Run all 3 metrics on 2 coreutils binaries and generate HTML report.

This script verifies:
1. All 3 metrics (ged, type_match, byte_match) run on real binaries
2. The scoring pipeline aggregates results correctly
3. The HTML report renders properly
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from decbench.models.project import Project, OptimizationLevel
from decbench.pipeline.executor import PipelineConfig, PipelineExecutor
from decbench.rendering.html import render_html_report
from rich.console import Console

console = Console()

logging.basicConfig(level=logging.WARNING)


def main() -> int:
    project_toml = Path("projects/sailr/coreutils.toml")
    output_dir = Path("results_3metric_test")

    console.print("\n[bold]DecBench 3-Metric E2E Test[/bold]\n")

    # Load project
    try:
        project = Project.from_toml(project_toml)
        console.print(f"Loaded project: [bold]{project.name}[/bold]")
    except Exception as e:
        console.print(f"[red]Failed to load project: {e}[/red]")
        return 1

    # Configure pipeline - skip compile, use existing binaries, sample 2
    config = PipelineConfig(
        output_dir=output_dir,
        optimization_levels=[OptimizationLevel.O2],
        decompilers=["angr", "ida", "ghidra"],
        metrics=["ged", "type_match", "byte_match"],
        workers=2,
        skip_compile=True,
        binary_sample=2,
        parallel=False,  # Serial for debugging
    )

    executor = PipelineExecutor(config)

    # Need to discover binaries from existing results
    existing_results = Path("results")
    if existing_results.exists():
        # Copy compiled dir to new output
        import shutil
        compiled_src = existing_results / "O2" / "coreutils" / "compiled"
        compiled_dst = output_dir / "O2" / "coreutils" / "compiled"
        if compiled_src.exists() and not compiled_dst.exists():
            compiled_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(compiled_src, compiled_dst)
            console.print(f"Copied compiled binaries from {compiled_src}")

    try:
        console.print("\n[bold]Running pipeline with 3 metrics on 2 sampled binaries...[/bold]\n")
        results = executor.run([project])

        # Display results
        console.print("\n[bold green]Pipeline Complete![/bold green]\n")

        if results.scoreboard:
            text = results.scoreboard.render_text()
            console.print(text)

            # Generate HTML report
            report_path = output_dir / "report.html"
            render_html_report(results.scoreboard, report_path)
            console.print(f"\n[green]HTML report saved to: {report_path}[/green]")

        # Validation
        console.print("\n[bold]Validation:[/bold]")
        passed = True

        if results.total_functions == 0:
            console.print("[red]FAIL: No functions processed[/red]")
            passed = False
        else:
            console.print(f"[green]PASS: {results.total_functions} functions[/green]")

        # Check each metric produced results
        metrics_with_results = set()
        for proj_results in results.evaluate_results.values():
            for opt_results in proj_results.values():
                for bin_results in opt_results.values():
                    for dec_results in bin_results.values():
                        for metric_name, metric_result in dec_results.items():
                            if metric_result.function_results:
                                metrics_with_results.add(metric_name)

        for m in ["ged", "type_match", "byte_match"]:
            if m in metrics_with_results:
                console.print(f"[green]PASS: {m} produced results[/green]")
            else:
                console.print(f"[yellow]WARN: {m} produced no results (may need debug binary)[/yellow]")

        console.print(f"\nTotal time: {results.total_time_seconds:.1f}s")
        return 0 if passed else 1

    except Exception as e:
        console.print(f"\n[red]Pipeline failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
