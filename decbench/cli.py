"""Command-line entry point and command registration for DecBench."""

import click

from decbench.commands.analysis import improvements, subset
from decbench.commands.benchmark import evaluate, evaluate_tree, init_project, run
from decbench.commands.datasets import dataset, download
from decbench.commands.evalkit import evalkit
from decbench.commands.registry import decompiler_build, list_decompilers, list_metrics
from decbench.commands.reporting import report, show, site


@click.group()
@click.version_option()
def main() -> None:
    """DecBench - Decompiler Benchmarking Suite."""


for command in (
    run,
    evaluate_tree,
    evaluate,
    init_project,
    list_decompilers,
    list_metrics,
    decompiler_build,
    show,
    report,
    site,
    dataset,
    download,
    evalkit,
    subset,
    improvements,
):
    main.add_command(command)


if __name__ == "__main__":
    main()
