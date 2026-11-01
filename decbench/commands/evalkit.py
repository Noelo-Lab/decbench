"""Evalkit commands for DecBench."""

from __future__ import annotations

from pathlib import Path

import click


@click.group()
def evalkit() -> None:
    """External evaluation kits (sample-set submissions from outside authors)."""
    pass


@evalkit.command("export")
@click.argument("tree", type=click.Path(exists=True, file_okay=False))
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    default=None,
    help="Kit output directory (default: ./decbench-evalkit-<dataset>)",
)
@click.option(
    "--dataset",
    default="sample-set",
    show_default=True,
    help="Dataset slice to export (only sample-set is supported for now)",
)
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Subset manifest path (default: TREE/sample_set_manifest.json)",
)
@click.option(
    "--seed",
    type=int,
    default=1337,
    show_default=True,
    help="Seed for the anonymized binary-name shuffle",
)
@click.option("--zip/--no-zip", "make_zip", default=True, help="Also write the kit zip")
@click.option(
    "--allow-unresolved",
    is_flag=True,
    help="Skip (with a warning) manifest entries that cannot be resolved, "
    "instead of failing the export",
)
def evalkit_export(
    tree: str,
    output: str | None,
    dataset: str,
    manifest: str | None,
    seed: int,
    make_zip: bool,
    allow_unresolved: bool,
) -> None:
    """Export a contributor kit from TREE's frozen sample-set manifest.

    Produces a kit directory (stripped+anonymized binaries, functions.json,
    package.py, results/ template) plus a zip for distribution.
    """
    from rich.console import Console

    from decbench.evalkit import EvalKitError
    from decbench.evalkit.export import export_kit

    console = Console()
    output_dir = Path(output) if output else Path(f"decbench-evalkit-{dataset}")

    try:
        summary = export_kit(
            Path(tree),
            output_dir,
            dataset=dataset,
            manifest=Path(manifest) if manifest else None,
            seed=seed,
            make_zip=make_zip,
            allow_unresolved=allow_unresolved,
        )
    except EvalKitError as e:
        raise click.ClickException(str(e)) from e

    console.print(
        f"Kit written to [bold]{summary.kit_dir}[/bold]: "
        f"{summary.n_binaries} binaries, {summary.n_functions} functions."
    )
    for note in summary.skipped:
        console.print(f"skipped: {note}", style="yellow", markup=False)
    if summary.zip_path is not None:
        console.print(f"Zip: [bold]{summary.zip_path}[/bold]")
        console.print(
            "Upload: copy the zip into the dataset repo checkout under kits/ "
            "(~/github/decbench-dataset) and git-lfs push; contributors download it "
            "from the HuggingFace dataset repo (see docs/decompilers.md)."
        )


@evalkit.command("ingest")
@click.argument("submission", type=click.Path(exists=True))
@click.argument("tree", type=click.Path(exists=True, file_okay=False))
@click.option("--id", "dec_id", required=True, help="Decompiler id for the new column (no '@')")
@click.option("--version", default=None, help="Decompiler version string")
@click.option(
    "--evaluate/--no-evaluate",
    "do_evaluate",
    default=True,
    help="Compute ged/type_match/byte_match inline after ingesting",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing checkpoint entries for --id instead of refusing",
)
def evalkit_ingest(
    submission: str, tree: str, dec_id: str, version: str | None, do_evaluate: bool, force: bool
) -> None:
    """Ingest a contributor's packaged results.zip into TREE as a new column.

    SUBMISSION is the results.zip emitted by the kit's package.py (or an
    unpacked directory containing the packaged results.json). Writes decompiled
    artifacts + checkpoint entries for --id, then prints the follow-up commands
    (overlays, finalize, site) needed to publish the new column.
    """
    from rich.console import Console

    from decbench.evalkit import EvalKitError
    from decbench.evalkit.ingest import ingest_submission

    console = Console()

    try:
        summary = ingest_submission(
            Path(submission),
            Path(tree),
            dec_id,
            version=version,
            evaluate=do_evaluate,
            force=force,
        )
    except EvalKitError as e:
        raise click.ClickException(str(e)) from e

    console.print(
        f"Ingested [bold]{summary.dec_id}[/bold]: {summary.n_binaries} binaries, "
        f"{summary.n_functions} functions ({summary.n_relabeled} relabeled to DWARF names, "
        f"{summary.n_dropped_extra} off-manifest dropped, {summary.n_failed} missing)."
    )
    for warning in summary.warnings:
        console.print(warning, style="yellow", markup=False)
    console.print("\n[bold]Next steps:[/bold]")
    console.print(summary.next_steps, markup=False)
