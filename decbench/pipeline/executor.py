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
from decbench.scoring.aggregator import aggregate_results
from decbench.scoring.scoreboard import build_scoreboard

if TYPE_CHECKING:
    from decbench.models.scoreboard import Scoreboard


class PipelineConfig(BaseModel):
    """Configuration for the benchmark pipeline."""

    # Output configuration
    output_dir: Path = Field(
        default=Path("results"),
        description="Directory for all output files",
    )

    # Compilation settings
    optimization_levels: list[OptimizationLevel] = Field(
        default=[OptimizationLevel.O2],
        description="Optimization levels to compile at",
    )

    # Decompiler settings
    decompilers: list[str] | None = Field(
        default=None,
        description="Decompilers to use (None for all available)",
    )

    # Metric settings
    metrics: list[str] | None = Field(
        default=None,
        description="Metrics to compute (None for all)",
    )

    # Parallelism
    parallel: bool = Field(
        default=True,
        description="Whether to run in parallel",
    )
    workers: int | None = Field(
        default=None,
        description="Number of worker processes (None for CPU count)",
    )

    # Pipeline steps
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

    # Testing mode
    binary_limit: int | None = Field(
        default=None,
        description="Limit number of binaries to process (None for all)",
    )
    binary_sample: int | None = Field(
        default=None,
        description="Deterministically sample N binaries to process (None for all)",
    )


@dataclass
class PipelineResults:
    """Results from a pipeline run."""

    # Per-phase results
    compile_results: dict = field(default_factory=dict)
    decompile_results: dict = field(default_factory=dict)
    evaluate_results: dict = field(default_factory=dict)

    # Final scoreboard
    scoreboard: Scoreboard | None = None

    # Statistics
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

        # Step 1: Compile
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

        # Apply binary limit if set
        if self.config.binary_limit is not None:
            for project in projects:
                for opt in self.config.optimization_levels:
                    if opt in project.compiled_binaries:
                        binaries = project.compiled_binaries[opt]
                        if len(binaries) > self.config.binary_limit:
                            project.compiled_binaries[opt] = binaries[:self.config.binary_limit]
                            print(f"Limited to {self.config.binary_limit} binaries for {project.name}/{opt.value}")
                    if opt in project.preprocessed_sources:
                        # Keep only sources matching the limited binaries
                        limited_names = {
                            b.stem for b in project.compiled_binaries.get(opt, [])
                        }
                        project.preprocessed_sources[opt] = {
                            name: path
                            for name, path in project.preprocessed_sources[opt].items()
                            if name in limited_names
                        }

        # Apply binary sampling if set (deterministic random selection)
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
                            print(f"Sampled {self.config.binary_sample} binaries for {project.name}/{opt.value}: {names}")
                    if opt in project.preprocessed_sources:
                        sampled_names = {
                            b.stem for b in project.compiled_binaries.get(opt, [])
                        }
                        project.preprocessed_sources[opt] = {
                            name: path
                            for name, path in project.preprocessed_sources[opt].items()
                            if name in sampled_names
                        }

        # Step 2: Decompile
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

        # Step 3: Evaluate
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
            )

        # Step 4: Build scoreboard
        print("Building scoreboard...")
        aggregated = aggregate_results(results.evaluate_results)
        results.scoreboard = build_scoreboard(
            aggregated,
            projects=[p.name for p in projects],
            optimization_levels=[o.value for o in self.config.optimization_levels],
            decompilers=self.config.decompilers,
        )

        # Compute statistics
        results.total_time_seconds = time.time() - start_time

        for project_results in results.decompile_results.values():
            for opt_results in project_results.values():
                results.total_binaries += len(opt_results)
                for binary_results in opt_results.values():
                    for dec_result in binary_results.values():
                        results.total_functions += dec_result.function_count

        # Save scoreboard
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

    def _discover_existing_binaries(
        self, projects: list[Project], output_dir: Path
    ) -> None:
        """Populate project.compiled_binaries from previously compiled output.

        Scans ``<output_dir>/<opt>/<project>/compiled/`` for ELF executables
        and ``.i`` preprocessed sources so that downstream pipeline stages
        (decompile, evaluate) can run when compilation is skipped.
        """
        for project in projects:
            for opt in self.config.optimization_levels:
                compiled_dir = (
                    output_dir / opt.value / project.name / "compiled"
                )
                if not compiled_dir.is_dir():
                    print(
                        f"Warning: compiled directory not found: {compiled_dir}"
                    )
                    continue

                # Discover ELF binaries
                binaries: list[Path] = []
                for entry in sorted(compiled_dir.iterdir()):
                    if entry.is_file() and self._is_elf_executable(entry):
                        binaries.append(entry)

                if binaries:
                    project.compiled_binaries[opt] = binaries
                    print(
                        f"Discovered {len(binaries)} binaries for "
                        f"{project.name}/{opt.value}"
                    )
                else:
                    print(
                        f"Warning: no ELF binaries found in {compiled_dir}"
                    )

                # Discover preprocessed .i sources
                i_files = {
                    f.stem: f for f in sorted(compiled_dir.glob("*.i"))
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
        from decbench.pipeline.decompile import decompile_binary
        from decbench.pipeline.evaluate import evaluate_decompilation
        from decbench.decompilers.registry import DecompilerRegistry
        from decbench.utils.cfg import extract_cfgs_from_source

        results = PipelineResults()

        # Get source CFGs if source provided
        source_cfgs = None
        if source_path:
            source_cfgs = extract_cfgs_from_source(source_path)

        # Get decompilers
        decompilers = self.config.decompilers or DecompilerRegistry.list_available()

        # Decompile with each decompiler
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

                # Evaluate
                eval_result = evaluate_decompilation(
                    dec_result,
                    source_cfgs,
                    self.config.metrics,
                )
                results.evaluate_results[binary_name][dec_name] = eval_result

            except Exception as e:
                print(f"Error with {dec_name}: {e}")

        return results
