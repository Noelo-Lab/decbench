"""Tests for the report's content loader (:mod:`decbench.rendering.content`).

These guard the invariants the content files exist to protect: one file per view,
exactly one default dataset, a metric registry that covers the run's metrics, and
a Metrics page whose goal cards parse and agree with that registry.
"""

from __future__ import annotations

import pytest

from decbench.rendering.content import Content, load_content

BENCHMARK_METRICS = ["ged", "type_match", "byte_match"]


@pytest.fixture(scope="module")
def content() -> Content:
    """The parsed content/ directory."""
    return load_content()


# -- views -----------------------------------------------------------------


def test_every_registered_view_has_content(content: Content) -> None:
    """views.toml is the registry; each id must have a parsed <id>.md."""
    for spec in content.view_specs:
        view = content.view(spec.id)
        assert view.title, f"{spec.id}.md has no title"
        assert view.body_html, f"{spec.id}.md has no body"


def test_view_registry_ids_are_unique(content: Content) -> None:
    ids = [v.id for v in content.view_specs]
    assert len(ids) == len(set(ids))


def test_view_registry_covers_the_report(content: Content) -> None:
    assert [v.id for v in content.view_specs] == [
        "leaderboard",
        "distance",
        "compare",
        "hardest",
        "history",
        "about",
    ]


def test_history_view_id_differs_from_its_nav_label(content: Content) -> None:
    """Routing says "history"; the sidebar says "historical"."""
    spec = next(v for v in content.view_specs if v.id == "history")
    assert spec.nav_label == "historical"


def test_visible_views_drop_data_backed_views_without_data(content: Content) -> None:
    without = [v.id for v in content.visible_views(has_function_data=False)]
    with_data = [v.id for v in content.visible_views(has_function_data=True)]
    assert without == ["leaderboard", "about"]
    assert with_data == [v.id for v in content.view_specs]


def test_about_is_registered_last_and_needs_no_data(content: Content) -> None:
    """The about page explains the numbers, so it sits after them in the nav.

    Its id matches its nav label: it is "about" everywhere, and it is NOT the
    view the site opens on (see test_exactly_one_default_view).
    """
    spec = content.view_specs[-1]
    assert spec.id == "about"
    assert spec.nav_label == "about"
    assert not spec.requires_function_data
    assert content.view("about").body_html


def test_exactly_one_default_view(content: Content) -> None:
    """`default = true` is config; two defaults would make the choice arbitrary."""
    defaults = [v.id for v in content.view_specs if v.default]
    assert defaults == ["leaderboard"]


def test_default_view_is_the_leaderboard(content: Content) -> None:
    """People come for the numbers; the numbers are the front page."""
    assert content.default_view == "leaderboard"


def test_empty_states_are_parsed(content: Content) -> None:
    hardest = content.view("hardest")
    assert hardest.has_empty_state
    assert hardest.title == "hardest functions &mdash; hall of shame"
    assert hardest.empty_title == "hardest functions"
    assert "no hardest-function data" in hardest.empty_html


def test_inline_html_passes_through_unescaped(content: Content) -> None:
    """The prose is final markup: tags and entities must survive rendering."""
    body = content.view("leaderboard").body_html
    assert "<em>perfectly on at least one metric</em>" in body
    assert "&mdash;" in body
    assert "&amp;mdash;" not in body


def test_convention_comments_are_stripped(content: Content) -> None:
    for spec in content.view_specs:
        view = content.view(spec.id)
        assert "<!--" not in view.body_html + view.outro_html + view.empty_html


# -- metrics ---------------------------------------------------------------


def test_metrics_registry_covers_the_three_metrics(content: Content) -> None:
    assert [m.name for m in content.metrics] == BENCHMARK_METRICS


def test_metric_lookup_and_fallbacks(content: Content) -> None:
    assert content.short_name("ged") == "Structure"
    assert content.display_name("ged") == "Structural Correctness (GED)"
    assert content.metric("nope") is None
    # Unknown metrics fall back to their raw name rather than blowing up.
    assert content.short_name("nope") == "nope"


def test_ordered_metrics_sorts_known_and_appends_unknown(content: Content) -> None:
    assert content.ordered_metrics(["byte_match", "ged", "type_match"]) == BENCHMARK_METRICS
    assert content.ordered_metrics(["byte_match", "ged"]) == ["ged", "byte_match"]
    assert content.ordered_metrics(["zzz", "ged"]) == ["ged", "zzz"]


# -- goal cards (on the about page) -----------------------------------------


def test_goal_card_parse_yields_three_cards(content: Content) -> None:
    goals = content.view("about").goals
    assert len(goals) == 3
    assert [g.number for g in goals] == ["1", "2", "3"]
    assert [g.metric_key for g in goals] == BENCHMARK_METRICS


def test_goal_cards_are_fully_populated(content: Content) -> None:
    for card in content.view("about").goals:
        assert card.title
        assert card.metric_display_name
        assert card.body_html
        # Every metric card carries its collapsible how-it-works visualization.
        assert 'class="metric-viz"' in card.body_html
        assert "<svg" in card.body_html
        assert card.perfect.startswith("perfect = ")


def test_goal_card_perfect_lines_match_the_metric_registry(content: Content) -> None:
    """The explainer and metrics.toml must not drift apart."""
    for card in content.view("about").goals:
        spec = content.metric(card.metric_key)
        assert spec is not None
        assert card.perfect == spec.perfect_line


def test_about_view_keeps_intro_and_outro_around_the_cards(content: Content) -> None:
    view = content.view("about")
    assert "three separable goals" in view.body_html
    assert "[1]" not in view.body_html  # cards were lifted out of the body
    assert 'class="recovered"' in view.outro_html
    assert 'id="metrics-table-note"' in view.outro_html
    # The dataset section (scaffolds app.js fills from data/dataset.json)
    # merged into this page's outro.
    assert 'id="dataset-summary"' in view.outro_html
    assert 'id="dataset-projects"' in view.outro_html
    assert 'id="metrics-perfect-table"' in view.outro_html


# -- datasets --------------------------------------------------------------


def test_exactly_one_default_dataset(content: Content) -> None:
    defaults = [p for p in content.dataset_presets if p.default]
    assert len(defaults) == 1
    assert content.default_dataset is defaults[0]


def test_default_dataset_is_unoptimized_and_not_positional(content: Content) -> None:
    """The default is explicit, so reordering datasets.toml cannot change it."""
    assert content.default_dataset is not None
    assert content.default_dataset.name == "unoptimized"


def test_dataset_presets_cover_the_selector(content: Content) -> None:
    assert [p.name for p in content.dataset_presets] == [
        "unoptimized",
        "optimized",
        "inlined",
        "large",
        "sample-set",
    ]
    for preset in content.dataset_presets:
        assert preset.label and preset.description


# -- categories / site -----------------------------------------------------


def test_categories_carry_labels_in_display_order(content: Content) -> None:
    assert [c.name for c in content.categories] == [
        "parser",
        "webserver",
        "cryptography",
        "malware",
        "firmware",
    ]
    assert content.categories[0].labels == (
        "parsing",
        "text-processing",
        "compression",
        "archiving",
    )


def test_site_chrome(content: Content) -> None:
    site = content.site
    assert site.brand.prompt == "$ decbench"
    assert site.brand.title == "DecBench"
    assert site.brand.subtitle == "decompiler benchmark"
    assert "function_results.json" in site.no_function_data_banner
    # The leading space separates the label from the <span> holding the number.
    assert site.side_stats["functions"] == " functions"


def test_footer_renders_projects_and_falls_back_when_empty(content: Content) -> None:
    footer = content.site.footer
    assert footer.render("0.1.0", ["bash", "curl"]) == (
        "DecBench v0.1.0 &mdash; decompiler benchmarking suite " "&middot; projects: bash, curl"
    )
    assert footer.render("0.1.0", []).endswith("projects: -")


def test_load_content_is_cached(content: Content) -> None:
    assert load_content() is content
