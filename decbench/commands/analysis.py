"""Analysis commands for DecBench."""

from __future__ import annotations

from pathlib import Path

import click


@click.command()
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
def subset(function_data: str, output: str, method: str, k: float) -> None:
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


@click.command()
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
    results: str,
    base: str,
    target: str,
    metric: str,
    perfect_only: bool,
    include_target_missing: bool,
    limit: int,
    out_format: str,
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
