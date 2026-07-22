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
from decbench.rendering.content import load_content
from decbench.rendering.html import render_html_report
from decbench.rendering.site import build_site

# `hardest` and `history` are deliberately absent: both are still stored in
# function_results.json but no longer shipped — the View page's `hard` difficulty
# tier (inside samples.json) replaced the Hardest view, and the Historical view
# was removed outright.
DATA_FILES = ["aggregates", "dataset", "samples"]

# One `<view>/index.html` subpage per visible view (all six, given data), so
# /leaderboard/, /distance/, ... are directly linkable. `insights` and
# `changelog` are prose-only views (no per-function data, no generated table).
VIEW_IDS = ["leaderboard", "distance", "view", "insights", "changelog", "about"]


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
        "CNAME",
        "fonts/source-code-pro-latin.woff2",
        *(f"data/{name}.json" for name in DATA_FILES),
        *(f"{view}/index.html" for view in VIEW_IDS),
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


# -- the linkable subpage tree ---------------------------------------------


def test_each_visible_view_gets_a_subpage(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """`/leaderboard/`, `/distance/`, ... are directories a reader can link to."""
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    for view in VIEW_IDS:
        assert (out / view / "index.html").is_file(), view


def test_subpage_carries_prefixed_assets_and_opens_on_its_own_view(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """A subpage's asset links hop up to the root, and its own view opens.

    Deliberately NOT via ``<base href="../">``: a base rebases same-document
    references too, which strips SVG ``url(#marker)`` arrowheads and reroutes
    in-page ``#view`` anchors on every subpage.
    """
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    about = (out / "about" / "index.html").read_text()

    assert "<base" not in about
    assert 'window.__DECBENCH_ROOT__ = "../"' in about
    # Its own section (and nav item) is the active one, not the site default.
    assert '<section class="view active" id="view-about"' in about
    assert '<section class="view active" id="view-leaderboard"' not in about
    assert '<link rel="stylesheet" href="../app.css">' in about
    assert '<script src="../app.js"></script>' in about


def test_root_index_has_the_root_stamp_and_no_base(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """The root stamps an empty hop (so app.js knows it is split mode) and no <base>."""
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    index = (out / "index.html").read_text()

    assert 'window.__DECBENCH_ROOT__ = ""' in index
    assert "<base" not in index
    assert '<section class="view active" id="view-leaderboard"' in index


def test_rebuild_prunes_stale_view_dirs_but_spares_user_dirs(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """A removed/renamed view's subdir is pruned — but only ours, never a user's.

    Safety hinges on the skeleton marker: a directory whose index.html lacks it
    (a CNAME folder, a hand-added page) must survive the rebuild untouched.
    """
    from decbench.rendering.html import SITE_PAGE_MARKER

    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)

    stale = out / "oldview"
    stale.mkdir()
    (stale / "index.html").write_text(f"<head>{SITE_PAGE_MARKER}</head>stale")
    user = out / "extras"
    user.mkdir()
    (user / "index.html").write_text("my own page, no marker")
    user_file = out / "CNAME"
    user_file.write_text("example.com")

    build_site(scoreboard, function_data, out)

    assert not stale.exists(), "a marked stale view dir is pruned"
    assert user.exists(), "an unmarked user dir is left alone"
    assert user_file.exists()
    assert (out / "index.html").is_file()
    for view in VIEW_IDS:
        assert (out / view / "index.html").is_file()


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
    # The only literal </script> tags are the ones the renderer itself emits: the
    # <head> theme bootstrap, the inline data payload, and the client script.
    assert html.count("</script>") == 3


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


def test_theme_bootstrap_and_toggle_ship_in_both_data_modes(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """The light/dark toggle lives in the shared skeleton, so both delivery modes
    get it identically: a <head> script that applies the stored theme BEFORE the
    stylesheet (no flash of the default theme), and a sidebar button app.js wires.
    """
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    index = (out / "index.html").read_text()

    report = tmp_path / "report.html"
    render_html_report(scoreboard, report, function_data)
    single = report.read_text()

    # Split mode links app.css; the single-file report inlines a <style> block.
    for html, sheet in ((index, '<link rel="stylesheet"'), (single, "<style>")):
        assert "localStorage.getItem('decbench-theme')" in html
        assert "document.documentElement.dataset.theme" in html
        # The bootstrap must run BEFORE the stylesheet or the default theme flashes.
        assert html.index("decbench-theme") < html.index(sheet)
        # The sidebar toggle button ships both CSS-driven labels.
        assert 'id="theme-toggle"' in html
        assert "[ light mode ]" in html
        assert "[ dark mode ]" in html


def test_scoreboard_only_report_has_no_theme_ui(tmp_path: Path, scoreboard: Scoreboard) -> None:
    """The static, client-less report ships neither the theme bootstrap nor the
    toggle button: without app.js to wire it the button would be inert."""
    path = tmp_path / "report.html"
    render_html_report(scoreboard, path, None)
    html = path.read_text()

    # Functional markers only: the inlined stylesheet's comments mention the
    # localStorage key in prose, so match the bootstrap's actual code and the
    # button id instead.
    assert "localStorage.getItem('decbench-theme')" not in html
    assert "document.documentElement.dataset.theme" not in html
    assert 'id="theme-toggle"' not in html


def test_build_site_writes_the_custom_domain_cname(
    tmp_path: Path, scoreboard: Scoreboard, function_data: FunctionData
) -> None:
    """The configured Pages domain lands in CNAME (settings are authoritative;
    the file keeps the tree self-documenting and branch-publishing-safe)."""
    out = tmp_path / "site"
    build_site(scoreboard, function_data, out)
    domain = load_content().site.pages_domain
    assert domain  # site.toml carries one today
    assert (out / "CNAME").read_text() == f"{domain}\n"
