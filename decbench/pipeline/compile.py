"""Compilation pipeline step."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from decbench.compilers.gcc import GCCCompiler
from decbench.models.project import OptimizationLevel, Project, RemoteType

if TYPE_CHECKING:
    from decbench.compilers.base import CompileResult


def download_source(project: Project, target_dir: Path) -> Path:
    """Download project source code.

    Args:
        project: Project configuration
        target_dir: Directory to download to

    Returns:
        Path to the downloaded source directory
    """
    config = project.config
    target_dir.mkdir(parents=True, exist_ok=True)

    if config.remote_type == RemoteType.LOCAL:
        # Just use local path
        if config.local_path:
            return config.local_path
        raise ValueError("Local project requires local_path")

    elif config.remote_type == RemoteType.GIT:
        # Git clone
        clone_dir = target_dir / (config.package_dir or config.name)

        cmd = ["git", "clone"]
        if config.version:
            cmd.extend(["--branch", config.version])
        cmd.extend(["--depth", "1", config.source_remote, str(clone_dir)])

        subprocess.run(cmd, check=True, timeout=600)
        return clone_dir

    elif config.remote_type == RemoteType.TAR:
        # Download and extract tarball
        import urllib.request

        tar_path = target_dir / "source.tar.gz"
        urllib.request.urlretrieve(config.source_remote, tar_path)

        # Extract
        shutil.unpack_archive(tar_path, target_dir)
        tar_path.unlink()

        # Find extracted directory
        dirs = [d for d in target_dir.iterdir() if d.is_dir()]
        if len(dirs) == 1:
            return dirs[0]

        return target_dir

    raise ValueError(f"Unknown remote type: {config.remote_type}")


def compile_project(
    project: Project,
    output_dir: Path,
    optimization: OptimizationLevel | str = OptimizationLevel.O2,
    clean: bool = True,
) -> list[CompileResult]:
    """Compile a project.

    Args:
        project: Project to compile
        output_dir: Directory for output files
        optimization: Optimization level
        clean: Whether to clean before compiling

    Returns:
        List of compilation results
    """
    config = project.config
    compilation = project.compilation

    # Convert optimization to string
    if isinstance(optimization, OptimizationLevel):
        opt_str = optimization.value
    else:
        opt_str = optimization

    # Create output directory
    opt_output_dir = output_dir / opt_str / config.name / "compiled"
    opt_output_dir.mkdir(parents=True, exist_ok=True)

    # Get source directory
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        if config.skip_compilation:
            # Use pre-built binaries
            if config.local_path:
                source_dir = config.local_path
            else:
                raise ValueError("skip_compilation requires local_path")
        else:
            # Download source
            source_dir = download_source(project, tmpdir)

            # Apply patch if specified
            if config.apply_patch:
                patch_path = Path(config.apply_patch)
                if patch_path.exists():
                    subprocess.run(
                        ["patch", "-p1", "-i", str(patch_path)],
                        cwd=source_dir,
                        check=False,
                    )

            # Run post-download commands
            for cmd in config.post_download_cmds:
                subprocess.run(
                    cmd,
                    shell=True,
                    cwd=source_dir,
                    timeout=600,
                    check=False,
                )

        # Create compiler
        compiler = GCCCompiler(
            gcc_path=compilation.c_compiler,
            base_flags=compilation.base_flags + compilation.extra_flags,
        )

        # Compile
        results = compiler.compile_project(
            project_dir=source_dir / config.source_dir if config.source_dir else source_dir,
            output_dir=opt_output_dir,
            optimization=opt_str,
            pre_commands=config.pre_make_cmds,
            make_command=config.make_cmd if config.make_cmd != "make" else None,
        )

        # Also copy original C files
        src_dir = source_dir / config.source_dir if config.source_dir else source_dir
        for c_file in src_dir.glob("*.c"):
            dest = opt_output_dir / c_file.name
            if not dest.exists():
                shutil.copy2(c_file, dest)

    # Update project state
    if optimization not in project.compiled_binaries:
        project.compiled_binaries[optimization] = []

    for result in results:
        if result.success and result.object_path:
            project.compiled_binaries[optimization].append(result.object_path)

            if result.preprocessed_path:
                if optimization not in project.preprocessed_sources:
                    project.preprocessed_sources[optimization] = {}
                project.preprocessed_sources[optimization][
                    result.source_path.stem
                ] = result.preprocessed_path

    return results


def compile_projects(
    projects: list[Project],
    output_dir: Path,
    optimization_levels: list[OptimizationLevel] | None = None,
    parallel: bool = True,
    workers: int | None = None,
) -> dict[str, dict[OptimizationLevel, list[CompileResult]]]:
    """Compile multiple projects.

    Args:
        projects: List of projects to compile
        output_dir: Output directory
        optimization_levels: Levels to compile at
        parallel: Whether to compile in parallel
        workers: Number of worker processes

    Returns:
        Results keyed by project name and optimization level
    """
    from concurrent.futures import ProcessPoolExecutor, as_completed
    from multiprocessing import cpu_count

    if optimization_levels is None:
        optimization_levels = [OptimizationLevel.O2]

    results: dict[str, dict[OptimizationLevel, list[CompileResult]]] = {}

    if parallel and len(projects) > 1:
        workers = workers or cpu_count()

        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {}

            for project in projects:
                for opt in optimization_levels:
                    future = executor.submit(
                        compile_project,
                        project,
                        output_dir,
                        opt,
                    )
                    futures[future] = (project.name, opt)

            for future in as_completed(futures):
                name, opt = futures[future]
                try:
                    result = future.result()
                    if name not in results:
                        results[name] = {}
                    results[name][opt] = result
                except Exception as e:
                    if name not in results:
                        results[name] = {}
                    results[name][opt] = []
    else:
        for project in projects:
            results[project.name] = {}
            for opt in optimization_levels:
                results[project.name][opt] = compile_project(
                    project, output_dir, opt
                )

    return results
