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
    "-o",
    "--output",
    type=click.Path(),
    default="results",
    help="Output directory for results",
)
@click.option(
    "--opt-level",
    "-O",
    multiple=True,
    type=click.Choice([o.value for o in OptimizationLevel]),
    default=["O2"],
    help="Optimization levels to compile with "
    "(O2-noinline is O2 with function inlining disabled)",
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
@click.option(
    "--binary-limit",
    type=int,
    default=None,
    help="Process at most N binaries per project/opt-level",
)
@click.option(
    "--binary-sample",
    type=int,
    default=None,
    help="Deterministically sample N binaries per project/opt-level",
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
    binary_limit,
    binary_sample,
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
        binary_limit=binary_limit,
        binary_sample=binary_sample,
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
    "-s",
    "--source",
    type=click.Path(exists=True),
    help="Path to source/preprocessed file for comparison",
)
@click.option(
    "-o",
    "--output",
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

    import decbench.decompilers.declib_dec  # noqa: F401
    from decbench.decompilers.registry import DecompilerRegistry

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

    # Import to register
    import decbench.metrics  # noqa: F401
    from decbench.metrics.registry import MetricRegistry

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
    "-o",
    "--output",
    type=click.Path(),
    default="results/report.html",
    help="Output HTML file path",
)
@click.option(
    "--function-data",
    type=click.Path(),
    default=None,
    help="Path to function_results.json for interactive report " "(default: sibling of scoreboard)",
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
        console.print("[yellow]No function data found; generating static report.[/yellow]")

    # Ensure the dataset presets (full/hard/hard-inlined/tiny) are tagged so the
    # report's dataset selector works even when re-rendering older data.
    if fd is not None and not fd.dataset_presets:
        try:
            from decbench.scoring.datasets import assign_datasets

            assign_datasets(fd)
        except Exception:
            pass

    render_html_report(scoreboard, Path(output), fd)

    console.print(f"Report generated: [bold]{output}[/bold]")


@main.command()
@click.argument("name")
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    default=".",
    help="Output directory for project file",
)
def init_project(name, output) -> None:
    """Initialize a new project configuration file."""
    from rich.console import Console

    from decbench.models.project import CompilationConfig, Project, ProjectConfig

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


@main.group()
def dataset() -> None:
    """Manage saved binary datasets (re-run without recompiling)."""
    pass


@dataset.command("save")
@click.argument("results_dir", type=click.Path(exists=True))
@click.argument("name")
@click.option(
    "--store",
    type=click.Path(),
    default=None,
    help="Dataset store root (default: ~/.local/share/decbench/datasets)",
)
def dataset_save(results_dir, name, store) -> None:
    """Save the compiled binaries under RESULTS_DIR as a reusable dataset NAME."""
    from rich.console import Console

    from decbench.dataset import save_dataset

    console = Console()
    manifest = save_dataset(Path(results_dir), name, store_root=Path(store) if store else None)
    console.print(
        f"Saved dataset [bold]{name}[/bold]: {len(manifest.binaries)} binaries "
        f"across {len(manifest.compile_sets())} compile-sets."
    )


@dataset.command("list")
@click.option(
    "--store",
    type=click.Path(),
    default=None,
    help="Dataset store root (default: ~/.local/share/decbench/datasets)",
)
def dataset_list(store) -> None:
    """List saved binary datasets."""
    from rich.console import Console
    from rich.table import Table

    from decbench.dataset import list_datasets

    console = Console()
    table = Table(title="Saved Datasets")
    table.add_column("Name", style="cyan")
    table.add_column("Binaries")
    table.add_column("Compile sets")
    for info in list_datasets(store_root=Path(store) if store else None):
        table.add_row(info["name"], str(info["binaries"]), str(info["compile_sets"]))
    console.print(table)


@dataset.command("materialize")
@click.argument("name")
@click.argument("dest", type=click.Path())
@click.option("--store", type=click.Path(), default=None)
def dataset_materialize(name, dest, store) -> None:
    """Lay dataset NAME back out under DEST so `run --skip-compile` finds it."""
    from rich.console import Console

    from decbench.dataset import materialize

    console = Console()
    materialize(name, Path(dest), store_root=Path(store) if store else None)
    console.print(f"Materialized [bold]{name}[/bold] into {dest}")


@main.command()
@click.argument("function_data", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    default="subset_large.json",
    help="Where to write the subset manifest",
)
@click.option(
    "--method",
    type=click.Choice(["std", "percentile"]),
    default="std",
    help="Tail selection: mean+k*std, or top-(100-k) percentile",
)
@click.option("--k", type=float, default=1.0, help="std multiplier or percentile")
def subset(function_data, output, method, k) -> None:
    """Compute the large-function subset (upper tail of the size bell curve)."""
    from rich.console import Console

    from decbench.models.function_data import FunctionData
    from decbench.scoring.subset import compute_large_subset, size_distribution

    console = Console()
    fd = FunctionData.from_json(Path(function_data))
    dist = size_distribution(fd)
    manifest = compute_large_subset(fd, method=method, k=k)
    manifest.to_json(Path(output))
    console.print(
        f"Sizes: mean={dist['mean']:.1f} std={dist['std']:.1f} "
        f"p90={dist.get('p90', 0):.0f} max={dist.get('max', 0):.0f}"
    )
    console.print(
        f"Large subset: [bold]{len(manifest.functions)}[/bold] / {dist['count']} "
        f"functions (threshold size >= {manifest.threshold:.1f}) -> {output}"
    )


@main.command()
@click.argument("results", type=click.Path(exists=True))
@click.option(
    "-b",
    "--base-decompiler",
    "base",
    required=True,
    help="Decompiler that is WINNING on the metric (the reference to learn from)",
)
@click.option(
    "-t",
    "--target-decompiler",
    "target",
    required=True,
    help="Decompiler that is LOSING on the metric (the one to improve)",
)
@click.option(
    "-m",
    "--metric",
    default="ged",
    show_default=True,
    help="Metric to compare on (e.g. ged, type_match, byte_match)",
)
@click.option(
    "--perfect-only",
    is_flag=True,
    help="Only show functions where the base decompiler is a PERFECT match on "
    "the metric (GED == 0, type_match/byte_match == 1)",
)
@click.option(
    "--include-target-missing",
    is_flag=True,
    help="Also include functions the base scored but for which the target has "
    "no usable score — it failed to decompile, or the metric errored (e.g. GED "
    "inf). Counts as the target losing.",
)
@click.option(
    "--limit",
    type=int,
    default=50,
    show_default=True,
    help="Maximum number of cases to show (0 = all)",
)
@click.option(
    "-f",
    "--format",
    "out_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format",
)
def improvements(
    results, base, target, metric, perfect_only, include_target_missing, limit, out_format
) -> None:
    """Find per-function cases where BASE beats TARGET on a metric.

    RESULTS is a benchmark results directory (or a function_results.json file).
    Each reported function is a concrete place the TARGET decompiler could
    improve: it lists the binary, the path to it on disk, and the function
    symbol + address (when resolvable). Respects each metric's direction, so
    "beats" means a genuinely better score.

    Example: places angr beats kuna on structural correctness, base perfect:

        decbench improvements results/full_run -b angr -t kuna -m ged --perfect-only
    """
    import json as _json

    from decbench.models.function_data import FunctionData
    from decbench.scoring.improvements import find_improvement_cases, render_text

    results_path = Path(results)
    if results_path.is_dir():
        fd_path = results_path / "function_results.json"
        results_root: Path | None = results_path
    else:
        fd_path = results_path
        results_root = results_path.parent

    if not fd_path.exists():
        raise click.ClickException(
            f"No function_results.json found at {fd_path}. Point RESULTS at a "
            "benchmark results directory (or the function_results.json itself)."
        )

    fd = FunctionData.from_json(fd_path)

    try:
        cases = find_improvement_cases(
            fd,
            base,
            target,
            metric,
            perfect_only=perfect_only,
            include_target_missing=include_target_missing,
            results_root=results_root,
        )
    except ValueError as e:
        raise click.ClickException(str(e)) from e

    shown = cases if limit in (0, None) else cases[:limit]

    if out_format == "json":
        click.echo(_json.dumps([c.to_dict() for c in shown], indent=2))
    else:
        # click.echo (not rich) so wide tabular rows are not soft-wrapped.
        click.echo(
            render_text(
                shown,
                fd,
                base=base,
                target=target,
                metric=metric,
                total=len(cases),
                perfect_only=perfect_only,
            )
        )


@main.command("decompiler-build")
@click.argument("name")
def decompiler_build(name) -> None:
    """Build the Docker image for a dockerized decompiler (reko/retdec/r2dec)."""
    from rich.console import Console

    import decbench.decompilers  # noqa: F401  (register backends)
    from decbench.decompilers.registry import DecompilerRegistry

    console = Console()
    dec = DecompilerRegistry.get(name)
    builder = getattr(dec, "build_image", None)
    if builder is None:
        console.print(f"[red]{name} is not a dockerized decompiler[/red]")
        return
    console.print(f"Building image for [bold]{name}[/bold]...")
    builder()
    console.print("Done.")


if __name__ == "__main__":
    main()
