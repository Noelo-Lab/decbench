"""Command-line interface for DecBench."""

from __future__ import annotations

from pathlib import Path

import click

from decbench.models.project import OptimizationLevel, Project


@click.group()
@click.version_option()
def main() -> None:
    """DecBench - Decompiler Benchmarking Suite."""
    pass


@main.command()
@click.argument("projects", nargs=-1, type=click.Path(exists=True))
@click.option(
    "-o", "--output",
    type=click.Path(),
    default="results",
    help="Output directory for results",
)
@click.option(
    "--opt-level",
    "-O",
    multiple=True,
    type=click.Choice(["O0", "O1", "O2", "O3", "Os"]),
    default=["O2"],
    help="Optimization levels to compile with",
)
@click.option(
    "--decompiler",
    "-d",
    multiple=True,
    help="Decompilers to use (default: all available)",
)
@click.option(
    "--metric",
    "-m",
    multiple=True,
    help="Metrics to compute (default: all)",
)
@click.option(
    "--workers",
    "-j",
    type=int,
    default=None,
    help="Number of parallel workers",
)
@click.option(
    "--skip-compile",
    is_flag=True,
    help="Skip compilation step",
)
@click.option(
    "--skip-decompile",
    is_flag=True,
    help="Skip decompilation step",
)
@click.option(
    "--skip-evaluate",
    is_flag=True,
    help="Skip evaluation step",
)
def run(
    projects,
    output,
    opt_level,
    decompiler,
    metric,
    workers,
    skip_compile,
    skip_decompile,
    skip_evaluate,
) -> None:
    """Run the full benchmark pipeline on project(s)."""
    from rich.console import Console

    from decbench.pipeline.executor import PipelineConfig, PipelineExecutor

    console = Console()

    project_list = []
    for project_path in projects:
        try:
            project = Project.from_toml(Path(project_path))
            project_list.append(project)
            console.print(f"Loaded project: [bold]{project.name}[/bold]")
        except Exception as e:
            console.print(f"[red]Error loading {project_path}: {e}[/red]")
            return

    if not project_list:
        console.print("[yellow]No projects specified. Use --help for usage.[/yellow]")
        return

    config = PipelineConfig(
        output_dir=Path(output),
        optimization_levels=[OptimizationLevel(o) for o in opt_level],
        decompilers=list(decompiler) if decompiler else None,
        metrics=list(metric) if metric else None,
        workers=workers,
        skip_compile=skip_compile,
        skip_decompile=skip_decompile,
        skip_evaluate=skip_evaluate,
    )

    executor = PipelineExecutor(config)

    console.print("\n[bold]Running DecBench pipeline...[/bold]\n")

    try:
        results = executor.run(project_list)

        console.print("\n[bold green]Pipeline complete![/bold green]\n")

        if results.scoreboard:
            from decbench.scoring.scoreboard import render_scoreboard_text
            console.print(render_scoreboard_text(results.scoreboard))

        console.print(f"\nTotal time: {results.total_time_seconds:.1f}s")
        console.print(f"Results saved to: {output}/")

    except Exception as e:
        console.print(f"[red]Pipeline failed: {e}[/red]")
        raise


@main.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "-s", "--source",
    type=click.Path(exists=True),
    help="Path to source/preprocessed file for comparison",
)
@click.option(
    "-o", "--output",
    type=click.Path(),
    default="results",
    help="Output directory",
)
@click.option(
    "--decompiler",
    "-d",
    multiple=True,
    help="Decompilers to use",
)
def evaluate(binary, source, output, decompiler) -> None:
    """Evaluate a single binary with available decompilers."""
    from rich.console import Console

    from decbench.pipeline.executor import PipelineConfig, PipelineExecutor

    console = Console()

    config = PipelineConfig(
        output_dir=Path(output),
        decompilers=list(decompiler) if decompiler else None,
    )

    executor = PipelineExecutor(config)

    console.print(f"Evaluating: [bold]{binary}[/bold]")

    try:
        results = executor.run_single_binary(
            Path(binary),
            Path(source) if source else None,
        )

        for binary_name, dec_results in results.evaluate_results.items():
            console.print(f"\n[bold]{binary_name}[/bold]")

            for dec_name, metrics in dec_results.items():
                console.print(f"  {dec_name}:")
                for metric_name, result in metrics.items():
                    if result.mean is not None:
                        console.print(f"    {metric_name}: {result.mean:.2f} (mean)")

    except Exception as e:
        console.print(f"[red]Evaluation failed: {e}[/red]")
        raise


@main.command()
def list_decompilers() -> None:
    """List available decompilers."""
    from rich.console import Console
    from rich.table import Table

    from decbench.decompilers.registry import DecompilerRegistry

    import decbench.decompilers.declib_dec  # noqa: F401

    console = Console()
    table = Table(title="Available Decompilers")
    table.add_column("Name", style="cyan")
    table.add_column("Available", style="green")
    table.add_column("Version")

    for name in DecompilerRegistry.list_registered():
        try:
            dec = DecompilerRegistry.get(name)
            available = "Y" if dec.is_available() else "N"
            version = dec.get_version() or "-"
            table.add_row(name, available, version)
        except Exception:
            table.add_row(name, "N", "-")

    console.print(table)


@main.command()
def list_metrics() -> None:
    """List available metrics."""
    from rich.console import Console
    from rich.table import Table

    from decbench.metrics.registry import MetricRegistry

    # Import to register
    import decbench.metrics  # noqa: F401

    console = Console()
    table = Table(title="Available Metrics")
    table.add_column("Name", style="cyan")
    table.add_column("Description")

    for name in MetricRegistry.list_registered():
        try:
            metric = MetricRegistry.get(name)
            table.add_row(name, metric.description)
        except Exception:
            table.add_row(name, "-")

    console.print(table)


@main.command()
@click.argument("scoreboard_path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["text", "markdown", "json"]),
    default="text",
    help="Output format",
)
def show(scoreboard_path, format) -> None:
    """Display a saved scoreboard."""
    from rich.console import Console

    from decbench.models.scoreboard import Scoreboard
    from decbench.scoring.scoreboard import (
        render_scoreboard_markdown,
        render_scoreboard_text,
    )

    console = Console()

    scoreboard = Scoreboard.from_toml(Path(scoreboard_path))

    if format == "text":
        console.print(render_scoreboard_text(scoreboard))
    elif format == "markdown":
        console.print(render_scoreboard_markdown(scoreboard))
    elif format == "json":
        import json
        console.print(json.dumps(scoreboard.to_display_dict(), indent=2))


@main.command()
@click.argument("scoreboard_path", type=click.Path(exists=True))
@click.option(
    "-o", "--output",
    type=click.Path(),
    default="results/report.html",
    help="Output HTML file path",
)
@click.option(
    "--function-data",
    type=click.Path(),
    default=None,
    help="Path to function_results.json for interactive report "
    "(default: sibling of scoreboard)",
)
def report(scoreboard_path, output, function_data) -> None:
    """Generate an HTML report from a scoreboard."""
    from rich.console import Console

    from decbench.models.function_data import FunctionData
    from decbench.models.scoreboard import Scoreboard
    from decbench.rendering.html import render_html_report

    console = Console()

    scoreboard = Scoreboard.from_toml(Path(scoreboard_path))

    # Resolve the function data path: explicit -> sibling -> None.
    if function_data is not None:
        fd_path: Path | None = Path(function_data)
    else:
        sibling = Path(scoreboard_path).parent / "function_results.json"
        fd_path = sibling if sibling.exists() else None

    fd: FunctionData | None = None
    if fd_path is not None:
        try:
            fd = FunctionData.from_json(fd_path)
        except Exception as e:
            console.print(
                f"[yellow]Could not load function data from {fd_path}: {e}. "
                "Generating static report.[/yellow]"
            )
            fd = None
    else:
        console.print(
            "[yellow]No function data found; generating static report.[/yellow]"
        )

    render_html_report(scoreboard, Path(output), fd)

    console.print(f"Report generated: [bold]{output}[/bold]")


@main.command()
@click.argument("name")
@click.option(
    "-o", "--output",
    type=click.Path(),
    default=".",
    help="Output directory for project file",
)
def init_project(name, output) -> None:
    """Initialize a new project configuration file."""
    from rich.console import Console

    from decbench.models.project import Project, ProjectConfig, CompilationConfig

    console = Console()

    project = Project(
        config=ProjectConfig(
            name=name,
            source_dir="src",
        ),
        compilation=CompilationConfig(),
    )

    output_path = Path(output) / f"{name}.toml"
    project.to_toml(output_path)

    console.print(f"Created project configuration: [bold]{output_path}[/bold]")
    console.print("Edit this file to configure your project.")


if __name__ == "__main__":
    main()
