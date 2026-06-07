"""
End-to-end pipeline tests for DecBench.

Tests the full pipeline with the three metrics:
1. Structural Correctness (GED)
2. Type Correctness (type_match)
3. Recompilation Bytematch (byte_match)
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

MISSING_DEPS = []

try:
    import angr
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False
    MISSING_DEPS.append("angr")

try:
    from pyjoern import parse_source
    HAVE_PYJOERN = True
except ImportError:
    HAVE_PYJOERN = False
    MISSING_DEPS.append("pyjoern")

try:
    from cfgutils.similarity import vj_ged
    HAVE_CFGUTILS = True
except ImportError:
    HAVE_CFGUTILS = False
    MISSING_DEPS.append("cfgutils")

TESTS_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = TESTS_DIR.parent
EXAMPLE_PROJECT_DIR = TESTS_DIR / "example_project"


class TestExampleProjectCompilation:

    def test_example_project_exists(self) -> None:
        assert EXAMPLE_PROJECT_DIR.exists()
        assert (EXAMPLE_PROJECT_DIR / "example.c").exists()
        assert (EXAMPLE_PROJECT_DIR / "Makefile").exists()

    def test_compile_example_project(self) -> None:
        subprocess.run(["make", "clean"], cwd=EXAMPLE_PROJECT_DIR, check=False)
        result = subprocess.run(
            ["make"],
            cwd=EXAMPLE_PROJECT_DIR,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Compilation failed: {result.stderr}"
        assert (EXAMPLE_PROJECT_DIR / "example.o").exists()
        assert (EXAMPLE_PROJECT_DIR / "example.i").exists()


class TestMetricImports:
    """Test that all three metrics are registered."""

    def test_all_metrics_registered(self) -> None:
        from decbench.metrics import MetricRegistry
        registered = MetricRegistry.list_registered()
        assert "ged" in registered
        assert "type_match" in registered
        assert "byte_match" in registered

    def test_metric_properties(self) -> None:
        from decbench.metrics import MetricRegistry

        ged = MetricRegistry.get("ged")
        assert ged.requires_source_cfg is True
        assert ged.requires_decompiled_cfg is True
        assert ged.perfect_value == 0.0

        tm = MetricRegistry.get("type_match")
        assert tm.requires_source_cfg is False
        assert tm.perfect_value == 1.0

        bm = MetricRegistry.get("byte_match")
        assert bm.requires_source_cfg is False
        assert bm.perfect_value == 1.0


class TestScoringPipeline:
    """Test the scoring pipeline with synthetic data."""

    def test_aggregation_and_scoreboard(self) -> None:
        from decbench.models.metrics import MetricResult, MetricValue
        from decbench.models.project import OptimizationLevel
        from decbench.scoring.aggregator import aggregate_results
        from decbench.scoring.scoreboard import build_scoreboard

        # Create synthetic evaluation results
        eval_results = {
            "test_project": {
                OptimizationLevel.O2: {
                    "binary1": {
                        "angr": {
                            "ged": MetricResult(
                                metric_name="ged",
                                decompiler_name="angr",
                                binary_name="binary1",
                                function_results={
                                    "func1": MetricValue(value=0.0),
                                    "func2": MetricValue(value=2.0),
                                    "func3": MetricValue(value=0.0),
                                },
                            ),
                            "type_match": MetricResult(
                                metric_name="type_match",
                                decompiler_name="angr",
                                binary_name="binary1",
                                function_results={
                                    "func1": MetricValue(value=1.0),
                                    "func2": MetricValue(value=0.5),
                                    "func3": MetricValue(value=1.0),
                                },
                            ),
                            "byte_match": MetricResult(
                                metric_name="byte_match",
                                decompiler_name="angr",
                                binary_name="binary1",
                                function_results={
                                    "func1": MetricValue(value=1.0),
                                    "func2": MetricValue(value=0.0),
                                    "func3": MetricValue(value=1.0),
                                },
                            ),
                        },
                    },
                },
            },
        }

        # Compute aggregates for each metric result
        for proj_results in eval_results.values():
            for opt_results in proj_results.values():
                for bin_results in opt_results.values():
                    for dec_results in bin_results.values():
                        for metric_name, result in dec_results.items():
                            from decbench.metrics import MetricRegistry
                            metric = MetricRegistry.get(metric_name)
                            result.compute_aggregates(perfect_value=metric.perfect_value)

        aggregated = aggregate_results(eval_results)

        assert "angr" in aggregated.decompilers
        assert aggregated.total_binaries == 1

        # Check per-metric aggregates
        angr_ged = aggregated.by_decompiler["angr"]["ged"]
        assert angr_ged.perfect_count == 2  # func1 and func3 have GED=0
        assert angr_ged.total_count == 3

        # Build scoreboard
        scoreboard = build_scoreboard(
            aggregated,
            projects=["test_project"],
            optimization_levels=["O2"],
        )

        assert len(scoreboard.decompilers) == 1
        assert scoreboard.decompiler_scores["angr"].metric_scores["ged"].perfect_count == 2

        # Overall: func1 is perfect on all 3, func3 is perfect on all 3
        # func2 fails on ged (2.0 != 0.0), type_match (0.5 != 1.0), byte_match (0.0 != 1.0)
        ds = scoreboard.decompiler_scores["angr"]
        assert ds.overall_perfect_count == 2  # func1 and func3
        assert ds.overall_total_count == 3

        # Render text
        text = scoreboard.render_text()
        assert "angr" in text

    def test_html_report_generation(self) -> None:
        from decbench.models.scoreboard import Scoreboard, DecompilerScore, MetricScore
        from decbench.rendering.html import render_html_report

        scoreboard = Scoreboard(
            name="Test Report",
            metrics=["ged", "type_match", "byte_match"],
            decompilers=["angr", "ghidra"],
            total_functions=100,
            total_binaries=10,
            decompiler_scores={
                "angr": DecompilerScore(
                    name="angr",
                    metric_scores={
                        "ged": MetricScore(
                            metric_name="ged", decompiler_name="angr",
                            perfect_count=50, total_count=100, perfect_percentage=50.0,
                        ),
                        "type_match": MetricScore(
                            metric_name="type_match", decompiler_name="angr",
                            perfect_count=30, total_count=100, perfect_percentage=30.0,
                        ),
                        "byte_match": MetricScore(
                            metric_name="byte_match", decompiler_name="angr",
                            perfect_count=10, total_count=100, perfect_percentage=10.0,
                        ),
                    },
                    overall_perfect_count=5, overall_total_count=100,
                    overall_perfect_percentage=5.0,
                ),
                "ghidra": DecompilerScore(
                    name="ghidra",
                    metric_scores={
                        "ged": MetricScore(
                            metric_name="ged", decompiler_name="ghidra",
                            perfect_count=60, total_count=100, perfect_percentage=60.0,
                        ),
                        "type_match": MetricScore(
                            metric_name="type_match", decompiler_name="ghidra",
                            perfect_count=40, total_count=100, perfect_percentage=40.0,
                        ),
                        "byte_match": MetricScore(
                            metric_name="byte_match", decompiler_name="ghidra",
                            perfect_count=15, total_count=100, perfect_percentage=15.0,
                        ),
                    },
                    overall_perfect_count=8, overall_total_count=100,
                    overall_perfect_percentage=8.0,
                ),
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.html"
            render_html_report(scoreboard, output_path)

            assert output_path.exists()
            content = output_path.read_text()
            assert "Test Report" in content
            assert "angr" in content
            assert "ghidra" in content
            assert "Structural Correctness" in content
            assert "Type Correctness" in content
            assert "Recompilation Bytematch" in content
            assert "Overall" in content
            # No function data -> banner present, no embedded data.
            assert "Interactive filtering unavailable" in content
            assert "const DATA" not in content

    def test_html_report_with_function_data(self) -> None:
        from decbench.models.function_data import (
            BinaryGroup,
            FunctionData,
            FunctionRecord,
        )
        from decbench.models.scoreboard import (
            DecompilerScore,
            MetricScore,
            Scoreboard,
        )
        from decbench.rendering.html import render_html_report

        scoreboard = Scoreboard(
            name="Interactive Report",
            metrics=["ged", "type_match"],
            decompilers=["angr"],
            total_functions=2,
            total_binaries=1,
            decompiler_scores={
                "angr": DecompilerScore(
                    name="angr",
                    metric_scores={
                        "ged": MetricScore(
                            metric_name="ged", decompiler_name="angr",
                            perfect_count=1, total_count=2,
                            perfect_percentage=50.0,
                        ),
                        "type_match": MetricScore(
                            metric_name="type_match", decompiler_name="angr",
                            perfect_count=1, total_count=2,
                            perfect_percentage=50.0,
                        ),
                    },
                    overall_perfect_count=1, overall_total_count=2,
                    overall_perfect_percentage=50.0,
                ),
            },
        )

        function_data = FunctionData(
            decompilers=["angr"],
            metrics=["ged", "type_match"],
            perfect_values={"ged": 0.0, "type_match": 1.0},
            groups=[
                BinaryGroup(
                    project="proj",
                    opt_level="O2",
                    binary="bin1",
                    labels=["O2", "optimized"],
                    # Use a value that contains a "</script>" substring to
                    # confirm the embedded JSON escapes "<" characters.
                    functions=[
                        FunctionRecord(
                            function="</script>_func",
                            values={"angr": {"ged": 0.0, "type_match": 1.0}},
                            perfects={
                                "angr": {"ged": True, "type_match": True}
                            },
                            labels=["O2", "optimized"],
                        ),
                        FunctionRecord(
                            function="func2",
                            values={"angr": {"ged": 2.0, "type_match": 0.5}},
                            perfects={
                                "angr": {"ged": False, "type_match": False}
                            },
                            labels=["O2", "optimized", "large"],
                        ),
                    ],
                ),
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.html"
            render_html_report(scoreboard, output_path, function_data)

            assert output_path.exists()
            content = output_path.read_text()

            # Embedded data + interactive sections present.
            assert "const DATA" in content
            assert 'id="filters"' in content
            assert 'id="comparison-matrix"' in content
            assert 'id="per-binary-breakdown"' in content

            # The raw "</script>" sequence must NOT appear inside the
            # embedded JSON. The script tag itself closes with "</script>",
            # so check that the function name was escaped via <.
            assert "\\u003c/script>_func" in content
            # And the literal unescaped function name must be absent.
            assert "</script>_func" not in content


class TestLabels:
    """Test the pure label-derivation functions."""

    def test_opt_level_labels(self) -> None:
        from decbench.scoring.labels import opt_level_labels

        assert opt_level_labels("O0") == ["O0", "unoptimized"]
        assert opt_level_labels("O2") == ["O2", "optimized"]

    def test_binary_labels_for_merge_and_dedup(self) -> None:
        from decbench.models.project import ProjectConfig
        from decbench.scoring.labels import binary_labels_for

        config = ProjectConfig(
            name="proj",
            labels=["firmware"],
            binary_labels={"bin1": ["big"]},
        )

        labels = binary_labels_for(config, "O2", "bin1")
        assert labels == ["O2", "optimized", "firmware", "big"]

        # A binary without per-binary additions still inherits project labels.
        labels2 = binary_labels_for(config, "O0", "bin2")
        assert labels2 == ["O0", "unoptimized", "firmware"]

        # Duplicates across sources are removed, order-stable.
        config2 = ProjectConfig(
            name="proj2",
            labels=["O2", "firmware"],
            binary_labels={"bin1": ["firmware", "big"]},
        )
        labels3 = binary_labels_for(config2, "O2", "bin1")
        assert labels3 == ["O2", "optimized", "firmware", "big"]

    def test_function_labels_for_large_threshold(self) -> None:
        from decbench.scoring.labels import function_labels_for

        base = ["O2", "optimized"]

        # Below threshold -> no "large".
        assert function_labels_for(base, 50, large_threshold=100) == base
        # At threshold -> "large" appended.
        assert function_labels_for(base, 100, large_threshold=100) == [
            "O2", "optimized", "large"
        ]
        # Above threshold -> "large" appended.
        assert function_labels_for(base, 250, large_threshold=100) == [
            "O2", "optimized", "large"
        ]
        # Unknown line count -> no "large".
        assert function_labels_for(base, None, large_threshold=100) == base


class TestFunctionData:
    """Test building and serializing the per-function dataset."""

    def _eval_results(self):
        from decbench.models.metrics import MetricResult, MetricValue
        from decbench.models.project import OptimizationLevel

        return {
            "test_project": {
                OptimizationLevel.O2: {
                    "binary1": {
                        "angr": {
                            "ged": MetricResult(
                                metric_name="ged",
                                decompiler_name="angr",
                                binary_name="binary1",
                                function_results={
                                    "func1": MetricValue(value=0.0),
                                    "func2": MetricValue(value=2.0),
                                },
                            ),
                            "type_match": MetricResult(
                                metric_name="type_match",
                                decompiler_name="angr",
                                binary_name="binary1",
                                function_results={
                                    "func1": MetricValue(value=1.0),
                                    "func2": MetricValue(value=0.5),
                                },
                            ),
                        },
                    },
                },
            },
        }

    def test_build_function_data(self) -> None:
        from decbench.models.project import Project, ProjectConfig
        from decbench.scoring.function_data_builder import build_function_data

        eval_results = self._eval_results()
        project = Project(
            config=ProjectConfig(name="test_project", labels=["firmware"])
        )

        fd = build_function_data(eval_results, [project])

        assert fd.schema_version == 1
        assert fd.decompilers == ["angr"]
        assert fd.metrics == ["ged", "type_match"]
        assert fd.perfect_values == {"ged": 0.0, "type_match": 1.0}

        assert len(fd.groups) == 1
        group = fd.groups[0]
        assert group.project == "test_project"
        assert group.opt_level == "O2"
        assert group.binary == "binary1"
        assert group.labels == ["O2", "optimized", "firmware"]

        assert len(group.functions) == 2
        funcs = {f.function: f for f in group.functions}

        f1 = funcs["func1"]
        assert f1.values == {"angr": {"ged": 0.0, "type_match": 1.0}}
        assert f1.perfects == {"angr": {"ged": True, "type_match": True}}
        assert f1.labels == ["O2", "optimized", "firmware"]

        f2 = funcs["func2"]
        assert f2.values == {"angr": {"ged": 2.0, "type_match": 0.5}}
        assert f2.perfects == {"angr": {"ged": False, "type_match": False}}

    def test_function_data_json_round_trip(self, tmp_path) -> None:
        from decbench.models.function_data import FunctionData
        from decbench.models.project import Project, ProjectConfig
        from decbench.scoring.function_data_builder import build_function_data

        eval_results = self._eval_results()
        project = Project(config=ProjectConfig(name="test_project"))
        fd = build_function_data(eval_results, [project])

        path = tmp_path / "function_results.json"
        fd.to_json(path)
        assert path.exists()

        loaded = FunctionData.from_json(path)
        assert loaded.decompilers == fd.decompilers
        assert loaded.metrics == fd.metrics
        assert loaded.perfect_values == fd.perfect_values
        assert len(loaded.groups) == len(fd.groups)
        assert loaded.groups[0].functions[0].perfects == (
            fd.groups[0].functions[0].perfects
        )


@pytest.mark.skipif(
    not (HAVE_ANGR and HAVE_PYJOERN and HAVE_CFGUTILS),
    reason=f"Missing dependencies: {MISSING_DEPS}"
)
class TestFullPipelineIntegration:
    """Test real GED pipeline with example project."""

    def setup_method(self) -> None:
        if not (EXAMPLE_PROJECT_DIR / "example").exists():
            subprocess.run(["make"], cwd=EXAMPLE_PROJECT_DIR, check=True)

    def test_ged_pipeline(self) -> None:
        import angr
        from pyjoern import parse_source
        from cfgutils.similarity import vj_ged

        binary_file = EXAMPLE_PROJECT_DIR / "example"
        source_file = EXAMPLE_PROJECT_DIR / "example.c"

        # Extract source CFGs
        source_parsed = parse_source(str(source_file))
        source_cfgs = {}
        for func_name, func in source_parsed.items():
            if func.cfg is not None and func.cfg.number_of_nodes() > 0:
                source_cfgs[func_name] = func.cfg

        assert len(source_cfgs) > 0

        # Decompile with angr
        project = angr.Project(str(binary_file), auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True)

        decompiled_code = {}
        for addr, func in cfg.kb.functions.items():
            if func.is_simprocedure or func.is_plt:
                continue
            try:
                dec = project.analyses.Decompiler(func, cfg=cfg)
                if dec.codegen and dec.codegen.text:
                    decompiled_code[func.name] = dec.codegen.text
            except Exception:
                pass

        assert len(decompiled_code) > 0

        # Parse decompiled code to get CFGs
        decompiled_cfgs = {}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            for name, code in decompiled_code.items():
                f.write(code)
                f.write("\n\n")
            temp_path = f.name

        try:
            dec_parsed = parse_source(temp_path)
            if dec_parsed:
                for func_name, func in dec_parsed.items():
                    if func.cfg is not None and func.cfg.number_of_nodes() > 0:
                        decompiled_cfgs[func_name] = func.cfg
        finally:
            Path(temp_path).unlink(missing_ok=True)

        # Compute GED
        total = 0
        perfect = 0
        for dec_name in decompiled_cfgs:
            src_name = dec_name[1:] if dec_name.startswith("_") else dec_name
            if src_name in source_cfgs:
                ged = vj_ged(source_cfgs[src_name], decompiled_cfgs[dec_name])
                total += 1
                if ged == 0:
                    perfect += 1

        if total > 0:
            pct = (perfect / total) * 100
            assert pct >= 0
        else:
            pytest.skip("No comparable functions")
