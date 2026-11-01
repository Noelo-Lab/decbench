"""Reporting commands for DecBench."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from decbench.rendering.content import Content


@click.command()
@click.argument("scoreboard_path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["text", "markdown", "json"]),
    default="text",
    help="Output format",
)
def show(scoreboard_path: str, format: str) -> None:
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


def _site_content() -> Content:
    """Load site content, injecting the repo-root CHANGELOG.md when it exists.

    The ``changelog`` view renders the repository's ``CHANGELOG.md`` as its body,
    so the log has a single source of truth; ``content/changelog.md`` is the
    fallback for installs with no repo checkout. The file is resolved relative to
    this package (``<repo>/CHANGELOG.md``), so a source/editable checkout picks it
    up and a wheel install falls back silently.
    """
    from decbench.rendering.content import load_content

    content = load_content()
    changelog = Path(__file__).resolve().parents[2] / "CHANGELOG.md"
    if changelog.is_file():
        content = content.with_view("changelog", changelog.read_text(encoding="utf-8"))
    return content


@click.command()
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
def report(scoreboard_path: str, output: str, function_data: str | None) -> None:
    """Generate an HTML report from a scoreboard."""
    from rich.console import Console

    from decbench.models.function_data import FunctionData
    from decbench.models.scoreboard import Scoreboard
    from decbench.rendering.html import render_html_report

    console = Console()

    scoreboard = Scoreboard.from_toml(Path(scoreboard_path))

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

    # Re-tag presets on every render so a rename or rule change takes effect without
    # a benchmark re-run. The sample-set pins to the tree's frozen manifest: a fresh
    # draw would tag functions the sample-set-only LLM backends never decompiled.
    if fd is not None:
        try:
            from decbench.results_store import load_sample_manifest
            from decbench.scoring.datasets import assign_datasets

            assign_datasets(fd, sample_members=load_sample_manifest(Path(scoreboard_path).parent))
        except Exception:
            pass

    render_html_report(scoreboard, Path(output), fd, _site_content())

    console.print(f"Report generated: [bold]{output}[/bold]")


@click.group()
def site() -> None:
    """Build the static site (the deployable GitHub Pages tree)."""


@site.command("build")
@click.argument("results_path", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    default="site",
    help="Output directory for the site tree",
)
@click.option(
    "--snapshots-dir",
    type=click.Path(),
    default=None,
    help="Snapshot store to publish (default: the repo-root snapshots/)",
)
def site_build(results_path: str, output: str, snapshots_dir: str | None) -> None:
    """Build the static site from a RESULTS TREE.

    RESULTS_PATH is a results directory containing scoreboard.toml and
    function_results.json (a scoreboard.toml path is also accepted).
    """
    from rich.console import Console

    from decbench.models.function_data import FunctionData
    from decbench.models.scoreboard import Scoreboard
    from decbench.rendering.site import build_site

    console = Console()

    tree = Path(results_path)
    if tree.is_file():
        tree = tree.parent
    scoreboard_path = tree / "scoreboard.toml"
    fd_path = tree / "function_results.json"

    if not scoreboard_path.exists():
        raise click.ClickException(f"No scoreboard.toml in {tree} — is this a results tree?")
    if not fd_path.exists():
        raise click.ClickException(
            f"No function_results.json in {tree}. The site is built entirely from "
            "per-function data; re-run the benchmark, or use `decbench report` for "
            "a static scoreboard-only report."
        )

    scoreboard = Scoreboard.from_toml(scoreboard_path)
    fd = FunctionData.from_json(fd_path)

    from decbench.results_store import load_sample_manifest
    from decbench.scoring.datasets import assign_datasets

    assign_datasets(fd, sample_members=load_sample_manifest(tree))

    from decbench.scoring.report_extras import build_sample_set_samples

    sample_set = build_sample_set_samples(fd, tree)
    fd.samples.extend(sample_set)
    console.print(f"Materialized [bold]{len(sample_set)}[/bold] sample-set View entries.")

    from decbench.rendering.snapshots import load_snapshots

    snaps = load_snapshots(Path(snapshots_dir) if snapshots_dir else None)
    console.print(f"Publishing [bold]{len(snaps)}[/bold] recorded scoreboard snapshots.")

    out_dir = Path(output)
    build_site(scoreboard, fd, out_dir, _site_content(), snapshots=snaps)

    total = 0
    for path in sorted(p for p in out_dir.rglob("*") if p.is_file()):
        size = path.stat().st_size
        total += size
        console.print(f"  {path.relative_to(out_dir)!s:<32} {_human_size(size):>10}")
    console.print(f"\nSite written to [bold]{out_dir}[/bold] ({_human_size(total)} total)")
    console.print("\nNext: [bold]git add site && git commit -m 'site: refresh' && git push[/bold]")


@site.command("snapshot")
@click.option(
    "-s",
    "--site-dir",
    type=click.Path(exists=True),
    default="site",
    help="The BUILT site tree to freeze (default: site)",
)
@click.option(
    "-d",
    "--date",
    "date_text",
    default=None,
    help="Snapshot day as DD-MM-YYYY or YYYY-MM-DD (default: today)",
)
@click.option("-l", "--label", default="", help="Short title shown in the snapshots list")
@click.option("-n", "--note", default="", help="Why this snapshot was taken")
@click.option(
    "--snapshots-dir",
    type=click.Path(),
    default=None,
    help="Snapshot store (default: the repo-root snapshots/)",
)
@click.option("--force", is_flag=True, help="Overwrite an existing snapshot for that day")
def site_snapshot(
    site_dir: str,
    date_text: str | None,
    label: str,
    note: str,
    snapshots_dir: str | None,
    force: bool,
) -> None:
    """Record a dated snapshot of the scoreboard from a BUILT site tree.

    Snapshots are never taken automatically. Take one whenever a change moves
    published scores or breaks comparability — the same moment CHANGELOG.md
    earns an entry — so the old numbers keep a stable link:
    https://decbench.com/leaderboard/?snapshot=DD-MM-YYYY
    """
    from datetime import date as date_cls

    from rich.console import Console

    from decbench.rendering.snapshots import (
        SnapshotError,
        capture,
        default_snapshots_dir,
        parse_date,
        write_snapshot_tree,
    )

    console = Console()
    store = Path(snapshots_dir) if snapshots_dir else default_snapshots_dir()

    try:
        day = parse_date(date_text) if date_text else date_cls.today()
        snap = capture(Path(site_dir), store, day, label=label, note=note, force=force)
    except SnapshotError as e:
        raise click.ClickException(str(e)) from e

    # Materialize into the tree straight away so the snapshot is live without a
    # rebuild; the next `site build` regenerates the same copy from the store.
    from decbench.rendering.snapshots import load_snapshots

    write_snapshot_tree(Path(site_dir) / "data", load_snapshots(store))

    size = sum(p.stat().st_size for p in snap.path.rglob("*") if p.is_file())
    console.print(f"Snapshot [bold]{snap.name}[/bold] written to {snap.path} ({_human_size(size)})")
    console.print(f"  scoreboard : {snap.meta['scoreboard']} v{snap.meta['version']}")
    console.print(f"  functions  : {snap.meta['functions']:,}")
    console.print(f"  decompilers: {', '.join(snap.meta['decompilers'])}")
    console.print(f"\nLink: [bold]https://decbench.com/leaderboard/?snapshot={snap.name}[/bold]")
    console.print("\nNext: [bold]git add snapshots site && git commit && git push[/bold]")


def _human_size(num_bytes: int) -> str:
    """Format a byte count for the build log (binary units, as git/Pages count)."""
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"
