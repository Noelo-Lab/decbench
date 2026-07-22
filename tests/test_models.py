"""Tests for data models."""

import pytest
from pathlib import Path
import tempfile

from decbench.models.project import (
    Project,
    ProjectConfig,
    CompilationConfig,
    OptimizationLevel,
    RemoteType,
)
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.models.metrics import (
    MetricValue,
    MetricResult,
)
from decbench.models.scoreboard import Scoreboard, DecompilerScore, MetricScore


class TestProjectModels:

    def test_project_config_creation(self) -> None:
        config = ProjectConfig(
            name="test_project",
            version="1.0",
            source_dir="src",
        )
        assert config.name == "test_project"
        assert config.version == "1.0"
        assert config.remote_type == RemoteType.LOCAL

    def test_compilation_config_defaults(self) -> None:
        config = CompilationConfig()
        assert OptimizationLevel.O2 in config.optimization_levels
        assert "-g" in config.base_flags
        assert config.emit_preprocessed is True

    def test_project_from_toml(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
name = "test"
version = "1.0"
source_dir = "src"
remote_type = "local"

[compilation]
optimization_levels = ["O2"]
""")
            f.flush()

            project = Project.from_toml(Path(f.name))
            assert project.name == "test"
            assert project.config.version == "1.0"

    def test_opt_level_gcc_flags(self) -> None:
        from decbench.models.project import opt_gcc_flags

        assert OptimizationLevel.O0.gcc_flags == ["-O0"]
        assert OptimizationLevel.O2.gcc_flags == ["-O2"]
        assert OptimizationLevel.O2_NOINLINE.gcc_flags == ["-O2", "-fno-inline"]

        # String values and enum members map identically
        assert opt_gcc_flags("O2-noinline") == ["-O2", "-fno-inline"]
        assert opt_gcc_flags(OptimizationLevel.O2_NOINLINE) == ["-O2", "-fno-inline"]
        assert opt_gcc_flags("O0") == ["-O0"]
        # Unknown ad-hoc levels fall back to -<value>
        assert opt_gcc_flags("Og") == ["-Og"]

    def test_o2_noinline_round_trip(self) -> None:
        assert OptimizationLevel("O2-noinline") is OptimizationLevel.O2_NOINLINE

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
name = "test"
source_dir = "src"
remote_type = "local"

[compilation]
optimization_levels = ["O0", "O2", "O2-noinline"]
""")
            f.flush()
            project = Project.from_toml(Path(f.name))
            assert OptimizationLevel.O2_NOINLINE in project.compilation.optimization_levels

    def test_base_flags_no_inline_by_default(self) -> None:
        # Inlining is controlled by the opt level, not base flags
        config = CompilationConfig()
        assert "-fno-inline" not in config.base_flags
        assert "-fno-builtin" in config.base_flags

    def test_project_to_toml(self) -> None:
        project = Project(
            config=ProjectConfig(name="test", source_dir="src"),
            compilation=CompilationConfig(),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.toml"
            project.to_toml(path)

            assert path.exists()

            loaded = Project.from_toml(path)
            assert loaded.name == project.name


class TestDecompilationModels:

    def test_function_decompilation(self) -> None:
        func = FunctionDecompilation(
            name="main",
            address=0x1000,
            decompiled_code="int main() { return 0; }",
            line_count=1,
            metadata={"gotos": 0, "bools": 0},
        )
        assert func.name == "main"
        assert func.address == 0x1000
        assert func.has_gotos is False
        assert func.goto_count == 0

    def test_function_with_gotos(self) -> None:
        func = FunctionDecompilation(
            name="test",
            address=0x2000,
            decompiled_code="void test() { goto label; label: return; }",
            metadata={"gotos": 1},
        )
        assert func.has_gotos is True
        assert func.goto_count == 1

    def test_decompilation_result(self) -> None:
        result = DecompilationResult(
            binary_path=Path("/test/binary.o"),
            binary_name="binary",
            decompiler=DecompilerMetadata(
                decompiler_name="test_dec",
                total_time_seconds=1.5,
            ),
            functions={
                "main": FunctionDecompilation(
                    name="main",
                    address=0x1000,
                    decompiled_code="int main() {}",
                ),
            },
        )
        assert result.function_count == 1
        assert result.successful_count == 1


class TestMetricModels:

    def test_metric_value(self) -> None:
        value = MetricValue(value=0.0, metadata={"test": True})
        assert value.is_perfect is True

        value2 = MetricValue(value=5.0)
        assert value2.is_perfect is False

    def test_metric_result_aggregates(self) -> None:
        result = MetricResult(
            metric_name="test",
            decompiler_name="dec",
            binary_name="bin",
            function_results={
                "f1": MetricValue(value=0.0),
                "f2": MetricValue(value=10.0),
                "f3": MetricValue(value=0.0),
            },
        )
        result.compute_aggregates(perfect_value=0.0)

        assert result.total == 10.0
        assert result.perfect_count == 2
        assert result.perfect_percentage == pytest.approx(66.67, rel=0.01)


class TestScoreboardModels:

    def test_scoreboard_creation(self) -> None:
        scoreboard = Scoreboard(
            name="Test Scoreboard",
            projects_evaluated=["project1"],
            decompilers=["dec1", "dec2"],
            metrics=["ged", "type_match", "byte_match"],
            total_functions=100,
        )
        assert scoreboard.name == "Test Scoreboard"
        assert len(scoreboard.decompilers) == 2
        assert len(scoreboard.metrics) == 3

    def test_decompiler_score(self) -> None:
        dec_score = DecompilerScore(
            name="test_dec",
            metric_scores={
                "ged": MetricScore(
                    metric_name="ged",
                    decompiler_name="test_dec",
                    perfect_count=50,
                    total_count=100,
                    perfect_percentage=50.0,
                ),
            },
            overall_perfect_count=30,
            overall_total_count=100,
            overall_perfect_percentage=30.0,
        )
        assert dec_score.overall_perfect_percentage == 30.0
        assert dec_score.metric_scores["ged"].perfect_percentage == 50.0

    def test_scoreboard_rankings(self) -> None:
        scoreboard = Scoreboard(
            name="Test",
            metrics=["ged"],
            decompilers=["d1", "d2"],
            decompiler_scores={
                "d1": DecompilerScore(
                    name="d1",
                    metric_scores={
                        "ged": MetricScore(
                            metric_name="ged",
                            decompiler_name="d1",
                            perfect_percentage=80.0,
                        ),
                    },
                    overall_perfect_percentage=70.0,
                ),
                "d2": DecompilerScore(
                    name="d2",
                    metric_scores={
                        "ged": MetricScore(
                            metric_name="ged",
                            decompiler_name="d2",
                            perfect_percentage=60.0,
                        ),
                    },
                    overall_perfect_percentage=50.0,
                ),
            },
        )

        ged_rankings = scoreboard.get_metric_rankings("ged")
        assert ged_rankings[0] == ("d1", 80.0)
        assert ged_rankings[1] == ("d2", 60.0)

        overall_rankings = scoreboard.get_overall_rankings()
        assert overall_rankings[0] == ("d1", 70.0)

    def test_scoreboard_render_text(self) -> None:
        scoreboard = Scoreboard(
            name="Test Scoreboard",
            metrics=["ged"],
            decompilers=["dec1"],
            total_functions=50,
            decompiler_scores={
                "dec1": DecompilerScore(
                    name="dec1",
                    metric_scores={
                        "ged": MetricScore(
                            metric_name="ged",
                            decompiler_name="dec1",
                            perfect_percentage=75.0,
                        ),
                    },
                    overall_perfect_percentage=60.0,
                ),
            },
        )

        text = scoreboard.render_text()
        assert "Test Scoreboard" in text
        assert "GED" in text
        assert "dec1" in text
