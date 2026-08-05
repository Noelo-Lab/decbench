"""Pipeline executor for running full benchmarks."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from decbench.models.project import OptimizationLevel, Project
from decbench.pipeline.compile import compile_projects
from decbench.pipeline.decompile import decompile_projects
from decbench.pipeline.evaluate import evaluate_projects
from decbench.scoring.scoreboard import build_scoreboard_from_function_data
from decbench.utils.langs import PREPROC_EXTS

if TYPE_CHECKING:
    from decbench.models.scoreboard import Scoreboard


class PipelineConfig(BaseModel):
    """Configuration for the benchmark pipeline."""

    output_dir: Path = Field(
        default=Path("results"),
        description="Directory for all output files",
    )

    optimization_levels: list[OptimizationLevel] = Field(
        default=[OptimizationLevel.O2],
        description="Optimization levels to compile at",
    )

    decompilers: list[str] | None = Field(
        default=None,
        description="Decompilers to use (None for all available)",
    )

    metrics: list[str] | None = Field(
        default=None,
        description="Metrics to compute (None for all)",
    )

    parallel: bool = Field(
        default=True,
        description="Whether to run in parallel",
    )
    workers: int | None = Field(
        default=None,
        description="Number of worker processes (None for CPU count)",
    )

    skip_compile: bool = Field(
        default=False,
        description="Skip compilation step",
    )
    skip_decompile: bool = Field(
        default=False,
        description="Skip decompilation step",
    )
    skip_evaluate: bool = Field(
        default=False,
        description="Skip evaluation step",
    )

    binary_limit: int | None = Field(
        default=None,
        description="Limit number of binaries to process (None for all)",
    )
    binary_sample: int | None = Field(
        default=None,
        description="Deterministically sample N binaries to process (None for all)",
    )

    source_cfgs_root: Path | None = Field(
        default=None,
        description="Tree root holding published <opt>/<project>/source_cfgs/"
        "<stem>.json to use instead of extracting source CFGs from .i files",
    )


@dataclass
class PipelineResults:
    """Results from a pipeline run."""

    compile_results: dict = field(default_factory=dict)
    decompile_results: dict = field(default_factory=dict)
    evaluate_results: dict = field(default_factory=dict)

    scoreboard: Scoreboard | None = None

    total_binaries: int = 0
    total_functions: int = 0
    total_time_seconds: float = 0.0


class PipelineExecutor:
    """Executes the full benchmark pipeline.

    Usage:
        executor = PipelineExecutor(config)
        results = executor.run(projects)
        print(results.scoreboard.render_text())
    """

    def __init__(self, config: PipelineConfig | None = None):
        """Initialize the executor.

        Args:
            config: Pipeline configuration
        """
        self.config = config or PipelineConfig()

    def run(self, projects: list[Project]) -> PipelineResults:
        """Run the full benchmark pipeline.

        Args:
            projects: List of projects to benchmark

        Returns:
            PipelineResults with all results and scoreboard
        """
        import time

        start_time = time.time()
        results = PipelineResults()

        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        if not self.config.skip_compile:
            print(f"Compiling {len(projects)} projects...")
            results.compile_results = compile_projects(
                projects,
                output_dir,
                self.config.optimization_levels,
                self.config.parallel,
                self.config.workers,
            )
        else:
            print("Skipping compilation, discovering existing binaries...")
            self._discover_existing_binaries(projects, output_dir)

        if self.config.binary_limit is not None:
            for project in projects:
                for opt in self.config.optimization_levels:
                    if opt in project.compiled_binaries:
                        binaries = project.compiled_binaries[opt]
                        if len(binaries) > self.config.binary_limit:
                            project.compiled_binaries[opt] = binaries[: self.config.binary_limit]
                            print(
                                f"Limited to {self.config.binary_limit} binaries "
                                f"for {project.name}/{opt.value}"
                            )
                    if opt in project.preprocessed_sources:
                        limited_names = {b.stem for b in project.compiled_binaries.get(opt, [])}
                        project.preprocessed_sources[opt] = {
                            name: path
                            for name, path in project.preprocessed_sources[opt].items()
                            if name in limited_names
                        }

        if self.config.binary_sample is not None:
            import random

            for project in projects:
                for opt in self.config.optimization_levels:
                    if opt in project.compiled_binaries:
                        binaries = project.compiled_binaries[opt]
                        if len(binaries) > self.config.binary_sample:
                            rng = random.Random(42)
                            sampled = sorted(rng.sample(binaries, self.config.binary_sample))
                            project.compiled_binaries[opt] = sampled
                            names = [b.stem for b in sampled]
                            print(
                                f"Sampled {self.config.binary_sample} binaries "
                                f"for {project.name}/{opt.value}: {names}"
                            )
                    if opt in project.preprocessed_sources:
                        sampled_names = {b.stem for b in project.compiled_binaries.get(opt, [])}
                        project.preprocessed_sources[opt] = {
                            name: path
                            for name, path in project.preprocessed_sources[opt].items()
                            if name in sampled_names
                        }

        if not self.config.skip_decompile:
            print(f"Decompiling with {self.config.decompilers or 'all'} decompilers...")
            results.decompile_results = decompile_projects(
                projects,
                output_dir,
                self.config.optimization_levels,
                self.config.decompilers,
                self.config.parallel,
                self.config.workers,
            )
        else:
            print("Skipping decompilation, loading stored decompiled artifacts...")
            from decbench.pipeline.materialized import discover_decompilations

            results.decompile_results = discover_decompilations(
                output_dir,
                self.config.optimization_levels,
                [p.name for p in projects],
                self.config.decompilers,
            )
            n_loaded = sum(
                len(decs)
                for opts in results.decompile_results.values()
                for bins in opts.values()
                for decs in bins.values()
            )
            print(f"Loaded {n_loaded} stored decompilation artifact(s)")

        if not self.config.skip_evaluate:
            print(f"Evaluating with {self.config.metrics or 'all'} metrics...")
            results.evaluate_results = evaluate_projects(
                projects,
                results.decompile_results,
                output_dir,
                self.config.optimization_levels,
                self.config.metrics,
                self.config.parallel,
                self.config.workers,
                source_cfgs_root=self.config.source_cfgs_root,
            )

        # Built before the scoreboard: it carries the true function universe and each
        # metric's measurability, which the scoreboard denominators derive from, so
        # scoreboard.toml and the HTML report share one source of truth.
        from decbench.scoring.function_data_builder import build_function_data

        function_data = build_function_data(
            results.evaluate_results,
            projects,
            results.decompile_results,
        )

        print("Building scoreboard...")
        results.scoreboard = build_scoreboard_from_function_data(function_data)

        try:
            from decbench.scoring.report_extras import attach_extras

            attach_extras(
                function_data,
                evaluation_results=results.evaluate_results,
                decompile_results=results.decompile_results,
                projects=projects,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"Report extras unavailable ({exc}); continuing.")

        function_data_path = output_dir / "function_results.json"
        function_data.to_json(function_data_path)
        results.scoreboard.raw_data_path = function_data_path
        print(f"Function data saved to {function_data_path}")

        results.total_time_seconds = time.time() - start_time

        for project_results in results.decompile_results.values():
            for opt_results in project_results.values():
                results.total_binaries += len(opt_results)
                for binary_results in opt_results.values():
                    for dec_result in binary_results.values():
                        results.total_functions += dec_result.function_count

        scoreboard_path = output_dir / "scoreboard.toml"
        results.scoreboard.to_toml(scoreboard_path)
        print(f"Scoreboard saved to {scoreboard_path}")

        return results

    @staticmethod
    def _is_elf_executable(path: Path) -> bool:
        """Check if a file is a linked ELF binary (executable or shared object)."""
        import struct

        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return False
                f.seek(16)
                e_type = struct.unpack("<H", f.read(2))[0]
                return e_type in (2, 3)
        except (OSError, struct.error):
            return False

    def _discover_existing_binaries(self, projects: list[Project], output_dir: Path) -> None:
        """Populate project.compiled_binaries from previously compiled output.

        Scans ``<output_dir>/<opt>/<project>/compiled/`` for ELF executables
        and ``.i`` preprocessed sources so that downstream pipeline stages
        (decompile, evaluate) can run when compilation is skipped.
        """
        for project in projects:
            for opt in self.config.optimization_levels:
                compiled_dir = output_dir / opt.value / project.name / "compiled"
                if not compiled_dir.is_dir():
                    print(f"Warning: compiled directory not found: {compiled_dir}")
                    continue

                # The malware targets are MinGW PE, so the PE check is what gets them
                # decompiled at all; cps ARM firmware is ELF and already covered.
                from decbench.utils import binfmt

                binaries: list[Path] = []
                for entry in sorted(compiled_dir.iterdir()):
                    if not entry.is_file() or entry.is_symlink():
                        continue
                    if self._is_elf_executable(entry):
                        binaries.append(entry)
                        continue
                    info = binfmt.detect(entry)
                    if info is not None and info.fmt == "pe":
                        binaries.append(entry)

                if binaries:
                    project.compiled_binaries[opt] = binaries
                    print(f"Discovered {len(binaries)} binaries for " f"{project.name}/{opt.value}")
                else:
                    print(f"Warning: no ELF binaries found in {compiled_dir}")

                i_files = {
                    f.stem: f for ext in PREPROC_EXTS for f in sorted(compiled_dir.glob(f"*{ext}"))
                }
                if i_files:
                    project.preprocessed_sources[opt] = i_files
                    print(
                        f"Discovered {len(i_files)} preprocessed sources for "
                        f"{project.name}/{opt.value}"
                    )

    def run_single_binary(
        self,
        binary_path: Path,
        source_path: Path | None = None,
    ) -> PipelineResults:
        """Run evaluation on a single binary (without compilation).

        Args:
            binary_path: Path to binary file
            source_path: Optional path to source/preprocessed file

        Returns:
            PipelineResults
        """
        from decbench.decompilers.registry import DecompilerRegistry
        from decbench.pipeline.decompile import decompile_binary
        from decbench.pipeline.evaluate import evaluate_decompilation
        from decbench.utils.cfg import extract_cfgs_from_source

        results = PipelineResults()

        source_cfgs = None
        if source_path:
            source_cfgs = extract_cfgs_from_source(source_path)

        decompilers = self.config.decompilers or DecompilerRegistry.list_available()

        output_dir = self.config.output_dir / "single_binary"
        output_dir.mkdir(parents=True, exist_ok=True)

        binary_name = binary_path.stem
        results.decompile_results[binary_name] = {}
        results.evaluate_results[binary_name] = {}

        for dec_name in decompilers:
            try:
                dec_result = decompile_binary(
                    binary_path,
                    dec_name,
                    output_dir,
                )
                results.decompile_results[binary_name][dec_name] = dec_result

                eval_result = evaluate_decompilation(
                    dec_result,
                    source_cfgs,
                    self.config.metrics,
                )
                results.evaluate_results[binary_name][dec_name] = eval_result

            except Exception as e:
                print(f"Error with {dec_name}: {e}")

        return results
