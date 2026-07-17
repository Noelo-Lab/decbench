"""Tests for the two delivery modes of the report page.

:func:`decbench.rendering.site.build_site` and
:func:`decbench.rendering.html.render_html_report` render the SAME skeleton and
differ only in how assets and data reach the browser. These tests pin that
difference — linked vs inlined — because getting it backwards fails in exactly the
place nobody tests: a site that inlines 7 MB into every page load, or a
single-file report that silently shows nothing when opened over ``file://``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from decbench.models.function_data import (
    BinaryGroup,
    DatasetPreset,
    FunctionData,
    FunctionRecord,
    HardestEntry,
    HistoryPoint,
    SampleEntry,
)
from decbench.models.scoreboard import Scoreboard
from decbench.rendering.html import render_html_report
from decbench.rendering.site import build_site

# `hardest` is deliberately absent: HardestEntry data is still stored in
# function_results.json but no longer shipped — the View page's `hard`
# difficulty tier (inside samples.json) replaced the Hardest view.
DATA_FILES = ["aggregates", "dataset", "history", "samples"]


@pytest.fixture
def scoreboard() -> Scoreboard:
    return Scoreboard(
        name="Site Test",
        metrics=["ged", "type_match"],
        decompilers=["angr"],
        total_functions=2,
        total_binaries=1,
    )


@pytest.fixture
def function_data() -> FunctionData:
    """A minimal but complete dataset: one group, and every extra payload filled."""
    return FunctionData(
        decompilers=["angr"],
        metrics=["ged", "type_match"],
        perfect_values={"ged": 0.0, "type_match": 1.0},
        groups=[
            BinaryGroup(
                project="proj",
                opt_level="O2",
                binary="bin1",
                labels=["O2", "parsing"],
                functions=[
                    FunctionRecord(
                        function="f1",
                        values={"angr": {"ged": 0.0, "type_match": 1.0}},
                        perfects={"angr": {"ged": True, "type_match": True}},
                        decompiled={"angr": True},
                        datasets=["unoptimized"],
                    ),
                    FunctionRecord(
                        function="f2",
                        values={"angr": {"ged": 2.0, "type_match": 0.5}},
                        perfects={"angr": {"ged": False, "type_match": False}},
                        decompiled={"angr": True},
                        datasets=["unoptimized", "sample-set"],
                    ),
                ],
            )
        ],
        dataset_presets=[DatasetPreset(name="unoptimized"), DatasetPreset(name="sample-set")],
        samples=[
            SampleEntry(
                project="proj",
                opt_level="O2",
                binary="bin1",
                function="f2",
                source_code="int f2(void) { return 0; }",
                decompiled={"angr": "int f2() { return 0; }"},
                values={"angr": {"ged": 2.0, "type_match": 0.5}},
                perfects={"angr": {"ged": False, "type_match": False}},
            )
        ],
        hardest=[
            HardestEntry(
                metric="ged",
                decompiler="angr",
                project="proj",
                opt_level="O2",
                binary="bin1",
                function="f2",
                value=2.0,
                perfect_value=0.0,
                decompiled_code="int f2() {}",
                source_code="int f2(void) {}",
            )
        ],
        history=[
            HistoryPoint(decompiler="angr", version="9.2", scores={"ged": 50.0}, overall=25.0)
        ],
    )


# -- the emitted tree ------------------------------------------------------


def test_build_site_writes_the_documented_tree(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """The tree is the contract in docs/SITE_DATA_SCHEMA.md; pages.yml deploys it."""
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)

    written = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()}
    assert written == {
        "index.html",
        "app.css",
        "app.js",
        ".nojekyll",
        "fonts/source-code-pro-latin.woff2",
        *(f"data/{name}.json" for name in DATA_FILES),
    }


def test_every_data_file_is_valid_json(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    for name in DATA_FILES:
        json.loads((out / "data" / f"{name}.json").read_text())


def test_aggregates_carry_the_registry_and_the_default_view(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """app.js labels every column from these; without them the site reads raw keys."""
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    agg = json.loads((out / "data" / "aggregates.json").read_text())

    assert agg["metric_registry"]["ged"]["short_name"] == "Structure"
    assert agg["default_view"] == "leaderboard"
    # Every (preset x normalize) combination is precomputed, not recomputed client-side.
    assert set(agg["combos"]) == {
        "unoptimized|0",
        "unoptimized|1",
        "sample-set|0",
        "sample-set|1",
    }


def test_preset_text_comes_from_the_content_registry(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """The dataset carries names only; datasets.toml supplies the words."""
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    agg = json.loads((out / "data" / "aggregates.json").read_text())

    unopt = next(p for p in agg["presets"] if p["name"] == "unoptimized")
    assert unopt["label"] == "unoptimized"
    assert "O0" in unopt["description"]
    assert unopt["default"] is True


def test_nojekyll_is_present(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """Without it Pages runs Jekyll, which drops anything starting with `_`."""
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    assert (out / ".nojekyll").exists()


# -- idempotency -----------------------------------------------------------


def test_rebuild_is_byte_identical(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    first = {p: p.read_bytes() for p in sorted(out.rglob("*")) if p.is_file()}
    build_site(scoreboard, function_data, out)
    second = {p: p.read_bytes() for p in sorted(out.rglob("*")) if p.is_file()}
    assert first == second


def test_rebuild_removes_stale_data_files(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """A renamed/dropped payload must not survive into a deploy.

    Stale JSON on a live site is worse than missing JSON: nothing reports it.
    """
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    stale = out / "data" / "old_payload.json"
    stale.write_text("{}")

    build_site(scoreboard, function_data, out)
    assert not stale.exists()
    assert (out / "data" / "aggregates.json").exists()


# -- linked vs inlined -----------------------------------------------------


def test_index_links_assets_and_does_not_inline_them(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """Split mode exists so the browser caches assets and lazy-loads the big pages."""
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    index = (out / "index.html").read_text()

    assert '<link rel="stylesheet" href="app.css">' in index
    assert '<script src="app.js"></script>' in index
    # No inline payload => app.js fetches data/*.json.
    assert "__DECBENCH_INLINE__" not in index
    assert "<style>" not in index
    # The stylesheet is a sibling of fonts/, so its relative url() resolves.
    assert "url(fonts/source-code-pro-latin.woff2)" in (out / "app.css").read_text()


def test_single_file_report_inlines_everything(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """It is opened over file://, where fetch() is CORS-blocked and url() is relative
    to the DOCUMENT — so the data rides along and the font becomes a data: URI."""
    path = tmp_path / "report.html"
    render_html_report(scoreboard, path, function_data)
    html = path.read_text()

    assert "<style>" in html
    assert "window.__DECBENCH_INLINE__" in html
    assert '<link rel="stylesheet"' not in html
    assert "<script src=" not in html
    # The font is embedded, not referenced by a path that would not resolve.
    assert "url(data:font/woff2;base64," in html
    assert "url(fonts/source-code-pro-latin.woff2)" not in html


def test_single_file_report_has_no_external_asset_references(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """Self-contained means self-contained: no CDN, no Google Fonts, no network."""
    path = tmp_path / "report.html"
    render_html_report(scoreboard, path, function_data)
    html = path.read_text()

    externals = re.findall(r'(?:src|href)\s*=\s*["\']https?://[^"\']+', html)
    assert externals == []
    assert "fonts.googleapis.com" not in html


def test_inline_payloads_are_keyed_like_the_data_files(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """app.js reads one shape either way: INLINE[name] mirrors data/<name>.json."""
    path = tmp_path / "report.html"
    render_html_report(scoreboard, path, function_data)
    html = path.read_text()

    match = re.search(r"window\.__DECBENCH_INLINE__ = (\{.*?\});</script>", html, re.DOTALL)
    assert match is not None
    payloads = json.loads(match.group(1).replace("\\u003c", "<"))
    assert sorted(payloads) == sorted(DATA_FILES)


def test_inline_json_cannot_close_the_script_tag(tmp_path: Path, scoreboard: Scoreboard) -> None:
    """Decompiled C is arbitrary text; a `</script>` in it must not end the script."""
    data = FunctionData(
        decompilers=["angr"],
        metrics=["ged"],
        groups=[],
        dataset_presets=[DatasetPreset(name="full")],
        samples=[
            SampleEntry(
                project="proj",
                opt_level="O2",
                binary="bin1",
                function="evil",
                source_code='char *s = "</script>";',
                decompiled={"angr": 'char *s = "</script>";'},
            )
        ],
    )
    path = tmp_path / "report.html"
    render_html_report(scoreboard, path, data)
    html = path.read_text()

    assert "\\u003c/script>" in html
    # The only literal </script> tags are the ones the renderer itself emits.
    assert html.count("</script>") == 2


def test_report_without_data_ships_no_client(tmp_path: Path, scoreboard: Scoreboard) -> None:
    """A scoreboard-only report is static markup and must stay silent.

    Shipping app.js with an empty payload would make it fail to find `aggregates`
    and paint a "could not load data" banner over three views that render fine.
    """
    path = tmp_path / "report.html"
    render_html_report(scoreboard, path, None)
    html = path.read_text()

    assert "__DECBENCH_INLINE__" not in html
    assert "<script" not in html
    # Still styled, and still showing real numbers from the scoreboard.
    assert "<style>" in html
    assert "interactive views unavailable" in html.lower()


# -- the shared skeleton ---------------------------------------------------


def test_both_modes_render_the_same_skeleton(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """One builder, two deliveries: the page body must not fork."""
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    index = (out / "index.html").read_text()

    report = tmp_path / "report.html"
    render_html_report(scoreboard, report, function_data)
    single = report.read_text()

    for marker in (
        '<section class="view active" id="view-leaderboard" data-view="leaderboard">',
        '<table id="leaderboard-table">',
        '<table id="metrics-perfect-table">',
        'data-view="about"',
        'data-view="view"',
        'id="view-difficulty"',
        'id="view-select"',
        'data-stat="functions"',
        'id="normalize-btn"',
    ):
        assert marker in index, marker
        assert marker in single, marker
