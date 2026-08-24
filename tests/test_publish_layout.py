"""Tests for decompiler exclusion in the dataset publisher (decbench.publish.layout).

Small synthetic FunctionData fixtures only — never the real results tree.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from decbench.models.function_data import (
    BinaryGroup,
    FunctionData,
    FunctionRecord,
    HardestEntry,
    HistoryPoint,
    SampleEntry,
)
from decbench.publish.layout import (
    EXCLUDED_DECOMPILERS,
    LayoutResult,
    _preset_description,
    load_dataset,
    strip_decompilers,
    write_master_scores,
)

KEPT = "angr"
STRIPPED = "hiddendec"


def make_fd() -> FunctionData:
    """Two-decompiler dataset with the stripped decompiler in every per-dec field."""
    per_dec_vals = {
        KEPT: {"ged": 0.0, "type_match": 1.0},
        STRIPPED: {"ged": 2.0, "type_match": 0.5},
    }
    fn = FunctionRecord(
        function="main",
        values={d: dict(v) for d, v in per_dec_vals.items()},
        perfects={KEPT: {"ged": True}, STRIPPED: {"ged": False}},
        metric_evidence={
            KEPT: {"type_match": "native"},
            STRIPPED: {"type_match": "fallback_only"},
        },
        producer_variable_occurrence_policy={KEPT: "exact", STRIPPED: "unavailable"},
        distances={KEPT: {"ged": 0.0}, STRIPPED: {"ged": 2.0}},
        decompiled={KEPT: True, STRIPPED: True},
        compiles={KEPT: True, STRIPPED: False},
        size=10,
    )
    group = BinaryGroup(project="proj", opt_level="O0", binary="bin", functions=[fn])
    sample = SampleEntry(
        project="proj",
        opt_level="O0",
        binary="bin",
        function="main",
        decompiled={KEPT: "int main(){}", STRIPPED: "int main(void){}"},
        values={d: dict(v) for d, v in per_dec_vals.items()},
        perfects={KEPT: {"ged": True}, STRIPPED: {"ged": False}},
    )
    hardest = [
        HardestEntry(
            metric="ged",
            decompiler=d,
            project="proj",
            opt_level="O0",
            binary="bin",
            function="main",
            value=5.0,
            perfect_value=0.0,
        )
        for d in (KEPT, STRIPPED)
    ]
    history = [
        HistoryPoint(decompiler=d, version="1.0", scores={"ged": 50.0}) for d in (KEPT, STRIPPED)
    ]
    return FunctionData(
        decompilers=[KEPT, STRIPPED],
        decompiler_versions={KEPT: "9.2", STRIPPED: "9.2-hidden"},
        metrics=["ged", "type_match"],
        perfect_values={"ged": 0.0, "type_match": 1.0},
        groups=[group],
        hardest=hardest,
        samples=[sample],
        compile_rates={KEPT: 0.9, STRIPPED: 0.8},
        history=history,
    )


def test_strip_decompilers_removes_all_traces():
    fd = make_fd()
    removed = strip_decompilers(fd, [STRIPPED])
    assert removed == [STRIPPED]
    dumped = json.dumps(fd.model_dump(mode="json"))
    assert STRIPPED not in dumped
    assert fd.decompilers == [KEPT]
    assert fd.decompiler_versions == {KEPT: "9.2"}
    assert fd.compile_rates == {KEPT: 0.9}
    fn = fd.groups[0].functions[0]
    assert set(fn.values) == {KEPT}
    assert set(fn.perfects) == {KEPT}
    assert set(fn.metric_evidence) == {KEPT}
    assert set(fn.producer_variable_occurrence_policy) == {KEPT}
    assert set(fn.distances) == {KEPT}
    assert set(fn.decompiled) == {KEPT}
    assert set(fn.compiles) == {KEPT}
    assert {h.decompiler for h in fd.hardest} == {KEPT}
    assert {h.decompiler for h in fd.history} == {KEPT}
    assert set(fd.samples[0].decompiled) == {KEPT}
    assert set(fd.samples[0].values) == {KEPT}
    assert set(fd.samples[0].perfects) == {KEPT}


def test_strip_decompilers_idempotent_and_unknown():
    fd = make_fd()
    assert strip_decompilers(fd, [STRIPPED]) == [STRIPPED]
    before = fd.model_dump(mode="json")
    assert strip_decompilers(fd, [STRIPPED]) == []
    assert fd.model_dump(mode="json") == before
    assert strip_decompilers(fd, ["nonexistent"]) == []
    assert strip_decompilers(fd, []) == []
    assert fd.model_dump(mode="json") == before


def test_strip_decompilers_reports_partial_traces():
    fd = make_fd()
    fd.decompilers = [KEPT]
    fd.decompiler_versions.pop(STRIPPED)
    fd.compile_rates.pop(STRIPPED)
    for f in fd.groups[0].functions:
        for d in (
            f.values,
            f.perfects,
            f.metric_evidence,
            f.producer_variable_occurrence_policy,
            f.distances,
            f.decompiled,
            f.compiles,
        ):
            d.pop(STRIPPED, None)
    for s in fd.samples:
        for d in (s.decompiled, s.values, s.perfects):
            d.pop(STRIPPED, None)
    fd.history = [h for h in fd.history if h.decompiler != STRIPPED]
    assert strip_decompilers(fd, [STRIPPED]) == [STRIPPED]
    assert {h.decompiler for h in fd.hardest} == {KEPT}


@pytest.fixture()
def results_tree(tmp_path: Path) -> Path:
    root = tmp_path / "results"
    root.mkdir()
    make_fd().to_json(root / "function_results.json")
    return root


def test_default_exclusions_are_empty(results_tree: Path):
    """EXCLUDED_DECOMPILERS is empty (the last excluded backend was fully
    removed 2026-07-23), so a default load strips nothing — any future
    exclusion must be a deliberate edit of the tuple."""
    assert EXCLUDED_DECOMPILERS == ()
    fd = load_dataset(results_tree)
    assert fd.decompilers == [KEPT, STRIPPED]


def test_load_dataset_strips_explicit_exclusions(results_tree: Path):
    fd = load_dataset(results_tree, exclude=(STRIPPED,))
    assert STRIPPED not in json.dumps(fd.model_dump(mode="json"))
    assert fd.decompilers == [KEPT]
    assert [p.name for p in fd.dataset_presets]


def test_load_dataset_no_exclusions_keeps_everything(results_tree: Path):
    fd = load_dataset(results_tree, exclude=())
    assert fd.decompilers == [KEPT, STRIPPED]


def _publish_master(root: Path, dest: Path, exclude: tuple[str, ...]) -> FunctionData:
    fd = load_dataset(root, exclude=exclude)
    write_master_scores(
        root,
        dest,
        fd,
        LayoutResult(),
        partial=False,
        excluded=exclude,
        log=lambda _msg: None,
    )
    return fd


def test_write_master_scores_excludes_and_regenerates_scoreboard(results_tree: Path, tmp_path):
    from decbench.scoring.scoreboard import build_scoreboard_from_function_data

    tree_sb = build_scoreboard_from_function_data(load_dataset(results_tree, exclude=()))
    tree_sb.to_toml(results_tree / "scoreboard.toml")

    dest = tmp_path / "dataset"
    _publish_master(results_tree, dest, exclude=(STRIPPED,))

    master = (dest / "results" / "function_results.json").read_text()
    assert STRIPPED not in master
    assert KEPT in master
    published = json.loads(master)
    assert published["groups"][0]["functions"][0]["producer_variable_occurrence_policy"] == {
        KEPT: "exact"
    }
    sb_text = (dest / "results" / "scoreboard.toml").read_text()
    assert STRIPPED not in sb_text
    assert KEPT in sb_text
    assert STRIPPED in (results_tree / "function_results.json").read_text()
    assert STRIPPED in (results_tree / "scoreboard.toml").read_text()


def test_write_master_scores_never_truncates_hardlinked_source(results_tree: Path, tmp_path):
    dest = tmp_path / "dataset"
    out = dest / "results" / "function_results.json"
    out.parent.mkdir(parents=True)
    os.link(results_tree / "function_results.json", out)

    _publish_master(results_tree, dest, exclude=(STRIPPED,))

    source = (results_tree / "function_results.json").read_text()
    assert STRIPPED in source
    assert STRIPPED not in out.read_text()
    assert (results_tree / "function_results.json").stat().st_ino != out.stat().st_ino


def test_write_master_scores_verbatim_scoreboard_without_exclusions(results_tree: Path, tmp_path):
    from decbench.scoring.scoreboard import build_scoreboard_from_function_data

    tree_sb = build_scoreboard_from_function_data(load_dataset(results_tree, exclude=()))
    tree_sb.to_toml(results_tree / "scoreboard.toml")

    dest = tmp_path / "dataset"
    _publish_master(results_tree, dest, exclude=())

    master = (dest / "results" / "function_results.json").read_text()
    assert STRIPPED in master
    sb_out = dest / "results" / "scoreboard.toml"
    assert sb_out.read_text() == (results_tree / "scoreboard.toml").read_text()


def test_full_config_has_publisher_description():
    assert _preset_description("full") != ""
    for name in ("unoptimized", "optimized", "inlined", "large", "sample-set"):
        assert _preset_description(name) != ""
