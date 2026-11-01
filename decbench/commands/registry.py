"""Registry commands for DecBench."""

from __future__ import annotations

import click


@click.command()
def list_decompilers() -> None:
    """List available decompilers."""
    from rich.console import Console
    from rich.table import Table

    import decbench.decompilers  # noqa: F401
    from decbench.decompilers.registry import DecompilerRegistry

    console = Console()
    table = Table(title="Available Decompilers")
    table.add_column("Name", style="cyan")
    table.add_column("Kind")
    table.add_column("Available", style="green")
    table.add_column("Version")

    rows: list[tuple[str, str, str, str]] = []
    for name in DecompilerRegistry.list_registered():
        try:
            dec = DecompilerRegistry.get(name)
            kind = "plugin" if dec.runnable else "external"
            rows.append((name, kind, "Y" if dec.is_available() else "N", dec.get_version() or "-"))
        except Exception:
            rows.append((name, "plugin", "N", "-"))

    # Backends we can run first, then the external-submission ids; import order
    # would otherwise decide, and that shifts with whichever optional backend
    # imports on this host.
    for row in sorted(rows, key=lambda r: (r[1] == "external", r[0])):
        table.add_row(*row)

    console.print(table)


@click.command()
def list_metrics() -> None:
    """List available metrics."""
    from rich.console import Console
    from rich.table import Table

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


@click.command("decompiler-build")
@click.argument("name")
def decompiler_build(name: str) -> None:
    """Build the Docker image for a decompiler (reko/retdec/r2dec/manifold)."""
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
