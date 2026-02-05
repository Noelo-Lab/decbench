"""Decompilation pipeline step."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
from pathlib import Path
from typing import TYPE_CHECKING

from decbench.decompilers.registry import DecompilerRegistry
from decbench.models.project import OptimizationLevel, Project

if TYPE_CHECKING:
    from decbench.decompilers.base import DecompilerConfig
    from decbench.models.decompilation import DecompilationResult


def decompile_binary(
    binary_path: Path,
    decompiler_name: str,
    output_dir: Path | None = None,
    functions: list[tuple[str, int]] | None = None,
    config: DecompilerConfig | None = None,
) -> DecompilationResult:
    """Decompile a single binary.

    Args:
        binary_path: Path to binary file
        decompiler_name: Name of decompiler to use
        output_dir: Directory for output files
        functions: Optional list of (name, address) to decompile
        config: Decompiler configuration

    Returns:
        DecompilationResult with all function decompilations
    """
    decompiler = DecompilerRegistry.get(decompiler_name, config)

    if not decompiler.is_available():
        raise RuntimeError(f"Decompiler '{decompiler_name}' is not available")

    return decompiler.decompile_binary(
        binary_path,
        functions=functions,
        output_dir=output_dir,
    )


def decompile_project(
    project: Project,
    output_dir: Path,
    optimization: OptimizationLevel | str = OptimizationLevel.O2,
    decompilers: list[str] | None = None,
    config: DecompilerConfig | None = None,
    parallel: bool = True,
    workers: int | None = None,
) -> dict[str, dict[str, DecompilationResult]]:
    """Decompile all binaries in a project.

    Args:
        project: Project with compiled binaries
        output_dir: Directory for output files
        optimization: Optimization level to decompile
        decompilers: List of decompiler names to use
        config: Decompiler configuration
        parallel: Whether to run in parallel
        workers: Number of worker processes

    Returns:
        Results keyed by binary name and decompiler name
    """
    # Convert optimization level
    if isinstance(optimization, str):
        optimization = OptimizationLevel(optimization)

    # Get compiled binaries
    if optimization not in project.compiled_binaries:
        raise ValueError(
            f"Project '{project.name}' not compiled at {optimization.value}"
        )

    binaries = project.compiled_binaries[optimization]

    # Get available decompilers
    if decompilers is None:
        decompilers = DecompilerRegistry.list_available()

    if not decompilers:
        raise ValueError("No decompilers available")

    # Create output directory
    dec_output_dir = output_dir / optimization.value / project.name / "decompiled"
    dec_output_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict[str, DecompilationResult]] = {}

    if parallel and (len(binaries) * len(decompilers)) > 1:
        workers = workers or cpu_count()

        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {}

            for binary_path in binaries:
                for dec_name in decompilers:
                    future = executor.submit(
                        decompile_binary,
                        binary_path,
                        dec_name,
                        dec_output_dir,
                        None,  # All functions
                        config,
                    )
                    futures[future] = (binary_path.stem, dec_name)

            for future in as_completed(futures):
                binary_name, dec_name = futures[future]
                try:
                    result = future.result()
                    if binary_name not in results:
                        results[binary_name] = {}
                    results[binary_name][dec_name] = result
                except Exception as e:
                    # Create error result
                    from decbench.models.decompilation import (
                        DecompilationResult,
                        DecompilerMetadata,
                    )

                    if binary_name not in results:
                        results[binary_name] = {}
                    results[binary_name][dec_name] = DecompilationResult(
                        binary_path=binaries[0],  # Approximate
                        binary_name=binary_name,
                        decompiler=DecompilerMetadata(
                            decompiler_name=dec_name,
                            failed_functions=["all"],
                        ),
                    )
    else:
        for binary_path in binaries:
            binary_name = binary_path.stem
            results[binary_name] = {}

            for dec_name in decompilers:
                try:
                    results[binary_name][dec_name] = decompile_binary(
                        binary_path,
                        dec_name,
                        dec_output_dir,
                        config=config,
                    )
                except Exception as e:
                    from decbench.models.decompilation import (
                        DecompilationResult,
                        DecompilerMetadata,
                    )

                    results[binary_name][dec_name] = DecompilationResult(
                        binary_path=binary_path,
                        binary_name=binary_name,
                        decompiler=DecompilerMetadata(
                            decompiler_name=dec_name,
                            failed_functions=["all"],
                        ),
                    )

    return results


def decompile_projects(
    projects: list[Project],
    output_dir: Path,
    optimization_levels: list[OptimizationLevel] | None = None,
    decompilers: list[str] | None = None,
    parallel: bool = True,
    workers: int | None = None,
) -> dict[str, dict[OptimizationLevel, dict[str, dict[str, DecompilationResult]]]]:
    """Decompile multiple projects.

    Args:
        projects: List of projects
        output_dir: Output directory
        optimization_levels: Levels to decompile
        decompilers: Decompilers to use
        parallel: Run in parallel
        workers: Worker count

    Returns:
        Nested dict: project -> opt_level -> binary -> decompiler -> result
    """
    if optimization_levels is None:
        optimization_levels = [OptimizationLevel.O2]

    results: dict[str, dict[OptimizationLevel, dict[str, dict[str, DecompilationResult]]]] = {}

    for project in projects:
        results[project.name] = {}
        for opt in optimization_levels:
            try:
                results[project.name][opt] = decompile_project(
                    project,
                    output_dir,
                    opt,
                    decompilers,
                    parallel=parallel,
                    workers=workers,
                )
            except ValueError:
                # Project not compiled at this level
                results[project.name][opt] = {}

    return results
