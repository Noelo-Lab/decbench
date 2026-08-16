"""Compilation pipeline step."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from decbench.compilers.gcc import GCCCompiler
from decbench.models.project import OptimizationLevel, Project, RemoteType
from decbench.utils.langs import SOURCE_EXTS

if TYPE_CHECKING:
    from decbench.compilers.base import CompileResult
    from decbench.models.project import CompilationConfig


_HOST_CC = "gcc"


def corpus_target(compilation: CompilationConfig) -> tuple[str, str | None]:
    """Resolve the (compiler, target_arch) pair: environment first, project TOML second.

    Only projects that declare the host compiler are retargeted. Anything naming
    its own cross toolchain (CPS, the MinGW malware targets) is left alone;
    ``mirai`` declares plain ``gcc`` and follows sailr.
    """
    if compilation.c_compiler != _HOST_CC:
        return compilation.c_compiler, compilation.target_arch
    return (
        os.environ.get("DECBENCH_CC") or compilation.c_compiler,
        os.environ.get("DECBENCH_TARGET_ARCH") or compilation.target_arch,
    )


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

    if config.download_cmd:
        src = target_dir / (config.package_dir or config.name)
        src.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            config.download_cmd, shell=True, cwd=src, timeout=600, check=True
        )
        return src

    if config.remote_type == RemoteType.LOCAL:
        if config.local_path:
            return config.local_path
        raise ValueError("Local project requires local_path")

    elif config.remote_type == RemoteType.GIT:
        clone_dir = target_dir / (config.package_dir or config.name)

        cmd = ["git", "clone"]
        if config.version:
            cmd.extend(["--branch", config.version])
        cmd.extend(["--depth", "1", config.source_remote, str(clone_dir)])

        subprocess.run(cmd, check=True, timeout=600)
        return clone_dir

    elif config.remote_type == RemoteType.TAR:
        import urllib.request
        from urllib.parse import urlparse

        url_path = urlparse(config.source_remote).path
        filename = Path(url_path).name or "source.tar.gz"
        tar_path = target_dir / filename
        urllib.request.urlretrieve(config.source_remote, tar_path)

        shutil.unpack_archive(tar_path, target_dir)
        tar_path.unlink()

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

    # SAFETY: malware targets are REAL malware — compiled (never executed) only
    # inside a container. Refuse a bare-host build unless explicitly overridden.
    if config.is_malware:
        import os

        in_container = os.path.exists("/.dockerenv") or os.environ.get(
            "DECBENCH_IN_CONTAINER"
        )
        if not in_container and os.environ.get("DECBENCH_ALLOW_MALWARE") != "1":
            raise RuntimeError(
                f"Refusing to compile malware target '{config.name}' outside a "
                "container. These are REAL malware sources — compile (never "
                "execute) only inside the decbench Docker image. Override with "
                "DECBENCH_ALLOW_MALWARE=1 if you really know what you're doing."
            )

    if isinstance(optimization, OptimizationLevel):
        opt_str = optimization.value
    else:
        opt_str = optimization

    opt_output_dir = output_dir / opt_str / config.name / "compiled"
    opt_output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        if config.skip_compilation:
            if config.local_path:
                source_dir = config.local_path
            else:
                raise ValueError("skip_compilation requires local_path")
        else:
            source_dir = download_source(project, tmpdir)

            if config.apply_patch:
                patch_path = Path(config.apply_patch)
                if patch_path.exists():
                    subprocess.run(
                        ["patch", "-p1", "-i", str(patch_path)],
                        cwd=source_dir,
                        check=False,
                    )

            for cmd in config.post_download_cmds:
                subprocess.run(
                    cmd,
                    shell=True,
                    cwd=source_dir,
                    timeout=600,
                    check=False,
                )

        gcc_path, target_arch = corpus_target(compilation)
        compiler = GCCCompiler(
            gcc_path=gcc_path,
            base_flags=compilation.base_flags + compilation.extra_flags,
            target_arch=target_arch,
        )

        results = compiler.compile_project(
            project_dir=source_dir / config.source_dir if config.source_dir else source_dir,
            output_dir=opt_output_dir,
            optimization=opt_str,
            pre_commands=config.pre_make_cmds,
            make_command=config.make_cmd,
            project_root=source_dir,
        )

        # Dedup by basename, SHALLOWEST path first: plain sorted() would put arch/foo.c
        # before foo.c and let an unrelated nested duplicate shadow the compiled file.
        src_dir = source_dir / config.source_dir if config.source_dir else source_dir
        candidates = [p for ext in SOURCE_EXTS for p in src_dir.rglob(f"*{ext}")]
        seen: set[str] = set()
        for c_file in sorted(candidates, key=lambda p: (len(p.parts), str(p))):
            if c_file.name in seen:
                continue
            seen.add(c_file.name)
            dest = opt_output_dir / c_file.name
            if not dest.exists():
                shutil.copy2(c_file, dest)

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
