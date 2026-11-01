"""Datasets commands for DecBench."""

from __future__ import annotations

from pathlib import Path

import click


@click.group()
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
def dataset_save(results_dir: str, name: str, store: str | None) -> None:
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
def dataset_list(store: str | None) -> None:
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
def dataset_materialize(name: str, dest: str, store: str | None) -> None:
    """Lay dataset NAME back out under DEST so `run --skip-compile` finds it."""
    from rich.console import Console

    from decbench.dataset import materialize

    console = Console()
    materialize(name, Path(dest), store_root=Path(store) if store else None)
    console.print(f"Materialized [bold]{name}[/bold] into {dest}")


@click.command("download")
@click.argument("config")
@click.option(
    "--dest",
    type=click.Path(),
    default=None,
    help="Directory to download into (mirrors the dataset repo layout)",
)
@click.option(
    "--repo-path",
    type=click.Path(),
    default=None,
    help="Read from a LOCAL dataset repo directory instead of the HuggingFace hub",
)
@click.option(
    "--include",
    default=None,
    help="Comma-separated sections to fetch "
    "(binaries,sources,cfgs,results,scores); default: all",
)
@click.option(
    "--revision",
    default=None,
    help="Dataset repo revision/branch/tag to fetch (default: main)",
)
def download(
    config: str, dest: str | None, repo_path: str | None, include: str | None, revision: str | None
) -> None:
    """Download a published DecBench dataset config (alias for `decbench-data`).

    CONFIG is one of the published configs, e.g. sample-set / large /
    unoptimized / optimized / inlined / full.
    This is a thin alias that delegates to the standalone `decbench_data`
    package (shipped from the HuggingFace dataset repo), so no heavy DecBench
    imports are pulled in.
    """
    try:
        import decbench_data
    except ImportError:
        click.echo(
            "The dataset tooling isn't installed. Run: pip install decbench-data  "
            "(or: pip install "
            "git+https://huggingface.co/datasets/noelo-lab/decbench-dataset)",
            err=True,
        )
        raise SystemExit(1) from None

    entry = getattr(decbench_data, "download", None)
    if callable(entry):
        entry(
            config,
            dest=dest,
            repo_path=repo_path,
            include=include,
            revision=revision,
        )
        return

    cli = getattr(decbench_data, "main", None) or getattr(decbench_data, "cli", None)
    if cli is None:
        raise click.ClickException(
            "decbench_data is installed but exposes no download entrypoint; "
            "upgrade it or run the `decbench-data download` command directly."
        )
    argv = ["download", config]
    if dest:
        argv += ["--dest", dest]
    if repo_path:
        argv += ["--repo-path", repo_path]
    if include:
        argv += ["--include", include]
    if revision:
        argv += ["--revision", revision]
    cli(argv)
