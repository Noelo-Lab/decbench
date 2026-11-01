"""Pipeline coordination tests using synthetic stage results."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from decbench.models.function_data import FunctionData
from decbench.models.metrics import MetricResult, MetricValue
from decbench.models.project import OptimizationLevel, Project, ProjectConfig
from decbench.models.scoreboard import Scoreboard
from decbench.pipeline import executor
from decbench.pipeline.executor import PipelineConfig, PipelineExecutor


@pytest.mark.parametrize(
    ("limit", "sample", "expected"),
    [
        (None, None, ["a", "b", "c", "d", "e"]),
        (3, None, ["a", "b", "c"]),
        (None, 2, ["a", "e"]),
        (4, 2, ["a", "d"]),
        (0, None, []),
        (None, 0, []),
        (10, 10, ["a", "b", "c", "d", "e"]),
    ],
)
def test_pipeline_retains_selected_binaries_and_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: int | None,
    sample: int | None,
    expected: list[str],
) -> None:
    opt = OptimizationLevel.O2
    project = Project(config=ProjectConfig(name="demo"))
    project.compiled_binaries[opt] = [tmp_path / name for name in "abcde"]
    project.preprocessed_sources[opt] = {
        f"{name}.cc": tmp_path / f"{name}.cc.ii" for name in "abcde"
    }
    project.preprocessed_sources[opt]["unlinked"] = tmp_path / "unlinked.i"
    monkeypatch.setattr(executor, "compile_projects", Mock(return_value={}))
    decompile = Mock(return_value={})
    monkeypatch.setattr(executor, "decompile_projects", decompile)
    monkeypatch.setattr(executor, "evaluate_projects", Mock(return_value={}))
    config = PipelineConfig(output_dir=tmp_path, binary_limit=limit, binary_sample=sample)

    PipelineExecutor(config).run([project])

    assert [path.name for path in project.compiled_binaries[opt]] == expected
    expected_sources = {f"{name}.cc" for name in expected}
    if limit is None and sample is None:
        expected_sources.add("unlinked")
    assert set(project.preprocessed_sources[opt]) == expected_sources
    decompile.assert_called_once()


def test_pipeline_persists_scores_when_optional_extras_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from decbench.scoring import report_extras

    project = Project(config=ProjectConfig(name="demo"))
    metric = MetricResult(
        metric_name="ged",
        decompiler_name="ghidra",
        binary_name="demo",
        function_results={"main": MetricValue(value=0.0), "helper": MetricValue(value=2.0)},
    )
    evaluations = {"demo": {OptimizationLevel.O2: {"demo": {"ghidra": {"ged": metric}}}}}
    monkeypatch.setattr(executor, "compile_projects", Mock(return_value={}))
    monkeypatch.setattr(executor, "decompile_projects", Mock(return_value={}))
    monkeypatch.setattr(executor, "evaluate_projects", Mock(return_value=evaluations))
    monkeypatch.setattr(
        report_extras, "attach_extras", Mock(side_effect=RuntimeError("unavailable"))
    )

    results = PipelineExecutor(PipelineConfig(output_dir=tmp_path)).run([project])

    data = FunctionData.from_json(tmp_path / "function_results.json")
    scoreboard = Scoreboard.from_toml(tmp_path / "scoreboard.toml")
    assert {f.function for f in data.groups[0].functions} == {"main", "helper"}
    score = scoreboard.decompiler_scores["ghidra"].metric_scores["ged"]
    assert score.perfect_count == 1
    assert score.total_count == 2
    assert results.scoreboard is not None
    assert results.scoreboard.raw_data_path == tmp_path / "function_results.json"
