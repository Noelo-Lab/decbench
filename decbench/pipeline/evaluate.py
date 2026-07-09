"""Evaluation pipeline step."""

from __future__ import annotations

import logging
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
from pathlib import Path
from typing import TYPE_CHECKING, Any

from decbench.metrics.registry import MetricRegistry

logger = logging.getLogger(__name__)
from decbench.models.metrics import MetricResult
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
    """Evaluate a single decompilation result."""
    if metrics is None:
        metrics = MetricRegistry.list_registered()

    results: dict[str, MetricResult] = {}

    # Extract CFGs from decompilation if needed
    decompiled_cfgs = None
    needs_decomp_cfg = any(MetricRegistry.get(m).requires_decompiled_cfg for m in metrics)
    if needs_decomp_cfg:
        decompiled_cfgs = extract_cfgs_from_decompilation(decompilation)

    for metric_name in metrics:
        try:
            metric = MetricRegistry.get(metric_name)

            if metric.requires_source_cfg and source_cfgs is None:
                logger.warning(
                    "Skipping metric '%s' for %s: source CFGs not available",
                    metric_name,
                    decompilation.binary_name,
                )
                continue

            result = metric.compute_for_binary(
                decompilation,
                source_cfgs=source_cfgs,
                decompiled_cfgs=decompiled_cfgs,
            )
            results[metric_name] = result

        except Exception as e:
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
    precomputed_source_cfgs: dict[str, dict[str, DiGraph]] | None = None,
) -> dict[str, dict[str, dict[str, MetricResult]]]:
    """Evaluate all decompilations for a project.

    Args:
        precomputed_source_cfgs: If given, used as the source CFGs keyed by
            binary name instead of re-extracting them from the preprocessed
            sources. Lets a caller extract source CFGs once and reuse them for
            both a decompile filter and this evaluation.
    """
    if isinstance(optimization, str):
        optimization = OptimizationLevel(optimization)

    eval_output_dir = output_dir / optimization.value / project.name / "evaluated"
    eval_output_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict[str, dict[str, MetricResult]]] = {}

    # Get source CFGs for each binary
    source_cfgs_by_binary: dict[str, dict[str, DiGraph]] = {}

    logger.debug("preprocessed_sources keys: %s", list(project.preprocessed_sources.keys()))
    if precomputed_source_cfgs is not None:
        source_cfgs_by_binary = precomputed_source_cfgs
    elif optimization in project.preprocessed_sources:
        sources = project.preprocessed_sources[optimization]
        logger.debug("Found %d preprocessed sources for %s", len(sources), optimization)
        # Source CFG extraction shells out to Joern (~seconds each); for projects
        # with many binaries (e.g. coreutils) doing this serially dominates the
        # run, so extract in parallel when there is more than one source.
        if parallel and len(sources) > 1:
            ex_workers = workers or cpu_count()
            with ProcessPoolExecutor(max_workers=ex_workers) as executor:
                futures = {
                    executor.submit(extract_cfgs_from_source, i_path): name
                    for name, i_path in sources.items()
                }
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        cfgs = future.result()
                        source_cfgs_by_binary[name] = cfgs or {}
                        if not cfgs:
                            logger.warning("Source CFG extraction returned empty for %s", name)
                    except Exception as e:  # noqa: BLE001
                        logger.warning("Source CFG extraction failed for %s: %s", name, e)
                        source_cfgs_by_binary[name] = {}
        else:
            for name, i_path in sources.items():
                try:
                    cfgs = extract_cfgs_from_source(i_path)
                    source_cfgs_by_binary[name] = cfgs
                    if not cfgs:
                        logger.warning(
                            "Source CFG extraction returned empty for %s (%s)", name, i_path
                        )
                    else:
                        logger.debug("Extracted %d CFGs from %s", len(cfgs), name)
                except Exception as e:
                    logger.warning("Source CFG extraction failed for %s: %s", name, e)
                    source_cfgs_by_binary[name] = {}
    else:
        logger.warning("No preprocessed sources for %s/%s", project.name, optimization)

    # Match each binary's decompiled functions against source CFGs TU-aware:
    # prefer the binary's OWN translation unit (so per-program functions like
    # main/usage/static helpers hit the RIGHT body, not an arbitrary same-named
    # function from another binary of the project), and fall back to the cross-TU
    # best-by-name only for functions the own TU doesn't define (statically-linked
    # library code). This replaces the old name-keyed union whose last-writer-wins
    # collisions scored, e.g., nologin's 5-node main against another binary's
    # 56-node main. See decbench.utils.cfg.resolved_source_for_binary.
    from decbench.utils.cfg import best_source_by_name, resolved_source_for_binary

    best_by_name = best_source_by_name(source_cfgs_by_binary)

    def _source_for(binary_name: str) -> dict:
        return resolved_source_for_binary(binary_name, source_cfgs_by_binary, best_by_name)

    if parallel:
        workers = workers or cpu_count()

        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {}

            for binary_name, dec_results in decompilations.items():
                source_cfgs = _source_for(binary_name)

                for dec_name, decompilation in dec_results.items():
                    future = executor.submit(
                        evaluate_decompilation,
                        decompilation,
                        source_cfgs,
                        metrics,
                        False,
                    )
                    futures[future] = (binary_name, dec_name)

            for future in as_completed(futures):
                binary_name, dec_name = futures[future]
                try:
                    metric_results = future.result()
                    if binary_name not in results:
                        results[binary_name] = {}
                    results[binary_name][dec_name] = metric_results
                except Exception:
                    if binary_name not in results:
                        results[binary_name] = {}
                    results[binary_name][dec_name] = {}
    else:
        for binary_name, dec_results in decompilations.items():
            source_cfgs = _source_for(binary_name)
            results[binary_name] = {}

            for dec_name, decompilation in dec_results.items():
                results[binary_name][dec_name] = evaluate_decompilation(
                    decompilation,
                    source_cfgs,
                    metrics,
                )

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

        data: dict[str, Any] = {"binary": binary_name}

        for dec_name, metric_results in dec_results.items():
            for metric_name, result in metric_results.items():
                key = f"{dec_name}.{metric_name}"

                data[f"{key}.total"] = result.total
                data[f"{key}.mean"] = result.mean
                data[f"{key}.median"] = result.median
                data[f"{key}.perfect_count"] = result.perfect_count
                data[f"{key}.perfect_percentage"] = result.perfect_percentage

                for func_name, value in result.function_results.items():
                    data[f"{key}.functions.{func_name}"] = value.value

        with open(output_file, "w") as f:
            toml.dump(data, f)


def evaluate_projects(
    projects: list[Project],
    decompilations: dict[
        str,
        dict[OptimizationLevel, dict[str, dict[str, DecompilationResult]]],
    ],
    output_dir: Path,
    optimization_levels: list[OptimizationLevel] | None = None,
    metrics: list[str] | None = None,
    parallel: bool = True,
    workers: int | None = None,
) -> dict[str, dict[OptimizationLevel, dict[str, dict[str, dict[str, MetricResult]]]]]:
    """Evaluate multiple projects."""
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
