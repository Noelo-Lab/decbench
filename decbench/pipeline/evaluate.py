"""Evaluation pipeline step."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
from pathlib import Path
from typing import TYPE_CHECKING

from decbench.metrics.registry import MetricRegistry
from decbench.models.metrics import MetricCategory, MetricResult
from decbench.models.project import OptimizationLevel, Project
from decbench.utils.cfg import extract_cfgs_from_source, extract_cfgs_from_decompilation

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import DecompilationResult


def evaluate_decompilation(
    decompilation: DecompilationResult,
    source_cfgs: dict[str, DiGraph] | None = None,
    metrics: list[str] | None = None,
    parallel: bool = False,
) -> dict[str, MetricResult]:
    """Evaluate a single decompilation result.

    Args:
        decompilation: Decompilation to evaluate
        source_cfgs: Source CFGs keyed by function name
        metrics: List of metric names to compute
        parallel: Whether to compute metrics in parallel

    Returns:
        MetricResult keyed by metric name
    """
    # Get metrics to compute
    if metrics is None:
        metrics = MetricRegistry.list_registered()

    results: dict[str, MetricResult] = {}

    # Extract CFGs from decompilation if needed
    decompiled_cfgs = None
    needs_decomp_cfg = any(
        MetricRegistry.get(m).requires_decompiled_cfg for m in metrics
    )
    if needs_decomp_cfg:
        decompiled_cfgs = extract_cfgs_from_decompilation(decompilation)

    # Compute each metric
    for metric_name in metrics:
        try:
            metric = MetricRegistry.get(metric_name)

            # Skip if missing required CFGs
            if metric.requires_source_cfg and source_cfgs is None:
                continue

            result = metric.compute_for_binary(
                decompilation,
                source_cfgs=source_cfgs,
                decompiled_cfgs=decompiled_cfgs,
            )
            results[metric_name] = result

        except Exception as e:
            # Create error result
            results[metric_name] = MetricResult(
                metric_name=metric_name,
                decompiler_name=decompilation.decompiler.decompiler_name,
                binary_name=decompilation.binary_name,
                errors=[str(e)],
            )

    return results


def evaluate_project(
    project: Project,
    decompilations: dict[str, dict[str, DecompilationResult]],
    output_dir: Path,
    optimization: OptimizationLevel | str = OptimizationLevel.O2,
    metrics: list[str] | None = None,
    parallel: bool = True,
    workers: int | None = None,
) -> dict[str, dict[str, dict[str, MetricResult]]]:
    """Evaluate all decompilations for a project.

    Args:
        project: Project being evaluated
        decompilations: Decompilation results (binary -> decompiler -> result)
        output_dir: Directory for output files
        optimization: Optimization level
        metrics: Metrics to compute
        parallel: Run in parallel
        workers: Worker count

    Returns:
        Results: binary -> decompiler -> metric -> result
    """
    # Convert optimization level
    if isinstance(optimization, str):
        optimization = OptimizationLevel(optimization)

    # Create output directory
    eval_output_dir = output_dir / optimization.value / project.name / "evaluated"
    eval_output_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict[str, dict[str, MetricResult]]] = {}

    # Get source CFGs for each binary
    source_cfgs_by_binary: dict[str, dict[str, DiGraph]] = {}

    if optimization in project.preprocessed_sources:
        for name, i_path in project.preprocessed_sources[optimization].items():
            try:
                source_cfgs_by_binary[name] = extract_cfgs_from_source(i_path)
            except Exception:
                source_cfgs_by_binary[name] = {}

    # Evaluate each binary/decompiler combination
    if parallel:
        workers = workers or cpu_count()

        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {}

            for binary_name, dec_results in decompilations.items():
                source_cfgs = source_cfgs_by_binary.get(binary_name, {})

                for dec_name, decompilation in dec_results.items():
                    future = executor.submit(
                        evaluate_decompilation,
                        decompilation,
                        source_cfgs,
                        metrics,
                        False,  # No nested parallelism
                    )
                    futures[future] = (binary_name, dec_name)

            for future in as_completed(futures):
                binary_name, dec_name = futures[future]
                try:
                    metric_results = future.result()
                    if binary_name not in results:
                        results[binary_name] = {}
                    results[binary_name][dec_name] = metric_results
                except Exception as e:
                    if binary_name not in results:
                        results[binary_name] = {}
                    results[binary_name][dec_name] = {}
    else:
        for binary_name, dec_results in decompilations.items():
            source_cfgs = source_cfgs_by_binary.get(binary_name, {})
            results[binary_name] = {}

            for dec_name, decompilation in dec_results.items():
                results[binary_name][dec_name] = evaluate_decompilation(
                    decompilation,
                    source_cfgs,
                    metrics,
                )

    # Save results to TOML
    _save_evaluation_results(results, eval_output_dir)

    return results


def _save_evaluation_results(
    results: dict[str, dict[str, dict[str, MetricResult]]],
    output_dir: Path,
) -> None:
    """Save evaluation results to TOML files."""
    import toml

    for binary_name, dec_results in results.items():
        output_file = output_dir / f"{binary_name}.toml"

        data = {"binary": binary_name}

        for dec_name, metric_results in dec_results.items():
            for metric_name, result in metric_results.items():
                key = f"{dec_name}.{metric_name}"

                # Store aggregates
                data[f"{key}.total"] = result.total
                data[f"{key}.mean"] = result.mean
                data[f"{key}.median"] = result.median
                data[f"{key}.perfect_count"] = result.perfect_count
                data[f"{key}.perfect_percentage"] = result.perfect_percentage

                # Store per-function results
                for func_name, value in result.function_results.items():
                    data[f"{key}.functions.{func_name}"] = value.value

        with open(output_file, "w") as f:
            toml.dump(data, f)


def evaluate_projects(
    projects: list[Project],
    decompilations: dict[str, dict[OptimizationLevel, dict[str, dict[str, DecompilationResult]]]],
    output_dir: Path,
    optimization_levels: list[OptimizationLevel] | None = None,
    metrics: list[str] | None = None,
    parallel: bool = True,
    workers: int | None = None,
) -> dict[str, dict[OptimizationLevel, dict[str, dict[str, dict[str, MetricResult]]]]]:
    """Evaluate multiple projects.

    Args:
        projects: List of projects
        decompilations: All decompilation results
        output_dir: Output directory
        optimization_levels: Levels to evaluate
        metrics: Metrics to compute
        parallel: Run in parallel
        workers: Worker count

    Returns:
        Nested dict: project -> opt -> binary -> decompiler -> metric -> result
    """
    if optimization_levels is None:
        optimization_levels = [OptimizationLevel.O2]

    results = {}

    for project in projects:
        results[project.name] = {}

        if project.name not in decompilations:
            continue

        for opt in optimization_levels:
            if opt not in decompilations[project.name]:
                continue

            results[project.name][opt] = evaluate_project(
                project,
                decompilations[project.name][opt],
                output_dir,
                opt,
                metrics,
                parallel,
                workers,
            )

    return results
