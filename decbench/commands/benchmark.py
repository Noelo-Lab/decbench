"""Benchmark commands for DecBench."""

from __future__ import annotations

from pathlib import Path

import click

from decbench.models.project import OptimizationLevel, Project


@click.command()
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
@click.option(
    "--source-cfgs",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="Tree root with published <opt>/<project>/source_cfgs/*.json to use "
    "instead of extracting source CFGs from .i files (materialized datasets)",
)
def run(
    projects: tuple[str, ...],
    output: str,
    opt_level: tuple[str, ...],
    decompiler: tuple[str, ...],
    metric: tuple[str, ...],
    workers: int | None,
    skip_compile: bool,
    skip_decompile: bool,
    skip_evaluate: bool,
    binary_limit: int | None,
    binary_sample: int | None,
    source_cfgs: str | None,
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
        source_cfgs_root=Path(source_cfgs) if source_cfgs else None,
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


@click.command("evaluate-tree")
@click.argument("tree", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--source-cfgs",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="Root of <opt>/<project>/source_cfgs/*.json (default: TREE itself)",
)
@click.option("--metric", "-m", multiple=True, help="Metrics to compute (default: all)")
@click.option("--decompiler", "-d", multiple=True, help="Only these decompilers' artifacts")
@click.option(
    "--opt-level",
    "-O",
    multiple=True,
    type=click.Choice([o.value for o in OptimizationLevel]),
    help="Optimization levels (default: those present in TREE)",
)
@click.option("--workers", "-j", type=int, default=None, help="Number of parallel workers")
@click.option("--no-parallel", is_flag=True, help="Evaluate sequentially")
def evaluate_tree(
    tree: str,
    source_cfgs: str | None,
    metric: tuple[str, ...],
    decompiler: tuple[str, ...],
    opt_level: tuple[str, ...],
    workers: int | None,
    no_parallel: bool,
) -> None:
    """Evaluate a materialized dataset tree (no recompile, no re-decompile).

    TREE is a results tree laid out by ``decbench-data materialize``:
    binaries under ``<opt>/<project>/compiled/``, stored decompiler output
    under ``decompiled/<dec>_<stem>.c`` and published source CFGs under
    ``source_cfgs/<stem>.json``. Runs the evaluate stage over the stored
    artifacts and writes ``function_results.json`` + ``scoreboard.toml`` into
    TREE. Note: type_match needs recovered variables, which stored artifacts
    do not carry — use GED/byte_match on materialized trees.
    """
    from rich.console import Console

    from decbench.models.project import ProjectConfig
    from decbench.pipeline.executor import PipelineConfig, PipelineExecutor
    from decbench.pipeline.materialized import discover_tree_projects

    console = Console()
    tree_path = Path(tree)

    project_names, present_opts = discover_tree_projects(tree_path)
    if not project_names:
        console.print(f"[red]No <opt>/<project>/compiled dirs found under {tree}[/red]")
        raise SystemExit(1)
    opts = list(opt_level) if opt_level else present_opts
    projects = [Project(config=ProjectConfig(name=name)) for name in project_names]
    console.print(
        f"Evaluating materialized tree [bold]{tree}[/bold]: "
        f"{len(projects)} project(s), opts={', '.join(opts)}"
    )

    config = PipelineConfig(
        output_dir=tree_path,
        optimization_levels=[OptimizationLevel(o) for o in opts],
        decompilers=list(decompiler) if decompiler else None,
        metrics=list(metric) if metric else None,
        workers=workers,
        parallel=not no_parallel,
        skip_compile=True,
        skip_decompile=True,
        source_cfgs_root=Path(source_cfgs) if source_cfgs else tree_path,
    )

    executor = PipelineExecutor(config)
    results = executor.run(projects)
    if results.scoreboard:
        from decbench.scoring.scoreboard import render_scoreboard_text

        console.print(render_scoreboard_text(results.scoreboard))


@click.command()
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
def evaluate(binary: str, source: str | None, output: str, decompiler: tuple[str, ...]) -> None:
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


@click.command()
@click.argument("name")
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    default=".",
    help="Output directory for project file",
)
def init_project(name: str, output: str) -> None:
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
