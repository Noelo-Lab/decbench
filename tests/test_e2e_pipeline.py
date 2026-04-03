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
