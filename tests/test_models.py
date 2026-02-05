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
    MetricCategory,
    MetricValue,
    MetricResult,
    CategoryScore,
)
from decbench.models.scoreboard import Scoreboard, DecompilerScore


class TestProjectModels:
    """Tests for project-related models."""

    def test_project_config_creation(self):
        """Test creating a project configuration."""
        config = ProjectConfig(
            name="test_project",
            version="1.0",
            source_dir="src",
        )
        assert config.name == "test_project"
        assert config.version == "1.0"
        assert config.remote_type == RemoteType.LOCAL

    def test_compilation_config_defaults(self):
        """Test compilation config default values."""
        config = CompilationConfig()
        assert OptimizationLevel.O2 in config.optimization_levels
        assert "-g" in config.base_flags
        assert config.emit_preprocessed is True

    def test_project_from_toml(self):
        """Test loading project from TOML."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write('''
name = "test"
version = "1.0"
source_dir = "src"
remote_type = "local"

[compilation]
optimization_levels = ["O2"]
''')
            f.flush()

            project = Project.from_toml(Path(f.name))
            assert project.name == "test"
            assert project.config.version == "1.0"

    def test_project_to_toml(self):
        """Test saving project to TOML."""
        project = Project(
            config=ProjectConfig(name="test", source_dir="src"),
            compilation=CompilationConfig(),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.toml"
            project.to_toml(path)

            assert path.exists()

            # Load it back
            loaded = Project.from_toml(path)
            assert loaded.name == project.name


class TestDecompilationModels:
    """Tests for decompilation-related models."""

    def test_function_decompilation(self):
        """Test FunctionDecompilation model."""
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

    def test_function_with_gotos(self):
        """Test function with gotos."""
        func = FunctionDecompilation(
            name="test",
            address=0x2000,
            decompiled_code="void test() { goto label; label: return; }",
            metadata={"gotos": 1},
        )
        assert func.has_gotos is True
        assert func.goto_count == 1

    def test_decompilation_result(self):
        """Test DecompilationResult model."""
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
    """Tests for metric-related models."""

    def test_metric_value(self):
        """Test MetricValue model."""
        value = MetricValue(value=0.0, metadata={"test": True})
        assert value.is_perfect is True

        value2 = MetricValue(value=5.0)
        assert value2.is_perfect is False

    def test_metric_result_aggregates(self):
        """Test MetricResult aggregate computation."""
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

    def test_category_score(self):
        """Test CategoryScore model."""
        score = CategoryScore(
            category=MetricCategory.FAITHFUL,
            decompiler_name="test",
            metric_scores={"ged": 80.0, "ged_norm": 0.9},
            metric_weights={"ged": 1.0, "ged_norm": 0.5},
        )
        score.compute_weighted_score()

        # Weighted: (80 * 1.0 + 0.9 * 0.5) / (1.0 + 0.5)
        expected = (80.0 + 0.45) / 1.5
        assert score.weighted_score == pytest.approx(expected)


class TestScoreboardModels:
    """Tests for scoreboard-related models."""

    def test_scoreboard_creation(self):
        """Test Scoreboard creation."""
        scoreboard = Scoreboard(
            name="Test Scoreboard",
            projects_evaluated=["project1"],
            decompilers=["dec1", "dec2"],
            total_functions=100,
        )
        assert scoreboard.name == "Test Scoreboard"
        assert len(scoreboard.decompilers) == 2

    def test_decompiler_score(self):
        """Test DecompilerScore model."""
        dec_score = DecompilerScore(
            name="test_dec",
            category_scores={
                MetricCategory.FAITHFUL: CategoryScore(
                    category=MetricCategory.FAITHFUL,
                    decompiler_name="test_dec",
                    weighted_score=75.0,
                ),
            },
        )
        dec_score.compute_overall_score()

        assert dec_score.overall_score == 75.0

    def test_scoreboard_to_display_dict(self):
        """Test scoreboard display conversion."""
        scoreboard = Scoreboard(
            name="Test",
            projects_evaluated=["p1"],
            decompilers=["d1"],
            total_functions=50,
        )

        display = scoreboard.to_display_dict()
        assert display["name"] == "Test"
        assert display["total_functions"] == 50
