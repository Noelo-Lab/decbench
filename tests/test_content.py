"""Tests for the report's content loader (:mod:`decbench.rendering.content`).

These guard the invariants the content files exist to protect: one file per view,
exactly one default dataset, a metric registry that covers the run's metrics, and
a Metrics page whose goal cards parse and agree with that registry.
"""

from __future__ import annotations

import pytest

from decbench.rendering.content import Content, DecompilerSpec, load_content

BENCHMARK_METRICS = ["ged", "type_match", "byte_match"]


@pytest.fixture(scope="module")
def content() -> Content:
    """The parsed content/ directory."""
    return load_content()


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
        "data",
        "view",
        "about",
        "changelog",
        "snapshots",
    ]


def test_visible_views_drop_data_backed_views_without_data(content: Content) -> None:
    without = [v.id for v in content.visible_views(has_function_data=False)]
    with_data = [v.id for v in content.visible_views(has_function_data=True)]
    assert without == ["leaderboard", "about", "changelog", "snapshots"]
    assert with_data == [v.id for v in content.view_specs]


def test_about_precedes_changelog_and_needs_no_data(content: Content) -> None:
    """The about page explains the numbers, so it sits after the data views
    (just before the changelog and the snapshots that close the nav).

    Its id matches its nav label: it is "about" everywhere, and it is NOT the
    view the site opens on (see test_exactly_one_default_view).
    """
    ids = [v.id for v in content.view_specs]
    assert ids[-3:] == ["about", "changelog", "snapshots"]
    spec = next(v for v in content.view_specs if v.id == "about")
    assert spec.nav_label == "about"
    assert not spec.requires_function_data
    assert content.view("about").body_html


def test_snapshots_view_ships_the_scaffold_app_js_fills(content: Content) -> None:
    """The filter controls and table host are the contract with buildSnapshots.

    The view must not require function data: a bad `?snapshot=` breaks the
    aggregates fetch, and this is the page a reader lands on to find a good date.
    """
    body = content.view("snapshots").body_html
    for element_id in ("snap-filters", "snap-dec", "snap-ver", "snap-count", "snapshots-body"):
        assert f'id="{element_id}"' in body, element_id
    spec = next(v for v in content.view_specs if v.id == "snapshots")
    assert not spec.requires_function_data


def test_exactly_one_default_view(content: Content) -> None:
    """`default = true` is config; two defaults would make the choice arbitrary."""
    defaults = [v.id for v in content.view_specs if v.default]
    assert defaults == ["leaderboard"]


def test_default_view_is_the_leaderboard(content: Content) -> None:
    """People come for the numbers; the numbers are the front page."""
    assert content.default_view == "leaderboard"


def test_empty_states_are_parsed(content: Content) -> None:
    view = content.view("view")
    assert view.empty_html
    assert view.title == "view"
    assert "No sample functions were attached" in view.empty_html
    for control in ("view-difficulty", "view-dec", "view-metric", "view-select"):
        assert f'id="{control}"' in view.body_html


def test_inline_html_passes_through_unescaped(content: Content) -> None:
    """Prose is markdown now, but the scaffolds and hand-authored viz islands are
    still final markup: their raw tags and entities must survive rendering
    byte-for-byte (the renderer's verbatim text() must not re-escape them)."""
    assert '<div class="controls">' in content.view("view").body_html
    assert "<strong>at least one</strong>" in content.view("about").outro_html
    ged = next(g for g in content.view("about").goals if g.metric_key == "ged")
    assert "&mdash;" in ged.body_html
    assert "&amp;mdash;" not in ged.body_html


def test_prose_renders_markdown_constructs(content: Content) -> None:
    """View-body prose is authored as plain markdown: bold/italic/links/inline code
    must render to real HTML, and literal unicode must not round-trip to entities.

    Guards the markdown-first rule — the literal `**`/`*`/`[..]` must be gone, and
    a bold run in a view body must become <strong>."""
    lb = content.view("leaderboard").body_html
    assert "<em>at least one</em>" in lb
    assert "*at least one*" not in lb
    assert '<a href="https://mahaloz.re/dec-history-pt1">the last 30 years</a>' in lb
    assert "—" in lb
    assert "&mdash;" not in lb
    di = content.view("data").body_html
    assert "<strong>GED</strong>" in di
    assert "**GED**" not in di
    injected = content.with_view("changelog", "# changelog\n\n- run `foo()` and **bar**.")
    body = injected.view("changelog").body_html
    assert "<code>foo()</code>" in body
    assert "<strong>bar</strong>" in body
    assert "<li>run <code>foo()</code> and <strong>bar</strong>.</li>" in body


def test_type_evidence_note_and_limitation_are_explained(content: Content) -> None:
    leaderboard = content.view("leaderboard").body_html
    assert 'id="type-evidence-note"' in leaderboard
    assert "may be conservative" in leaderboard
    assert "type-blind usage evidence" in leaderboard
    assert "usage/name evidence" not in leaderboard

    about = content.view("about").outro_html
    assert "mixed or fallback-only evidence" in about
    assert "scores or denominators" in about

    type_card = next(
        goal for goal in content.view("about").goals if goal.metric_key == "type_match"
    )
    assert "validated instruction-address overlap" in type_card.body_html
    assert "type-blind usage" in type_card.body_html
    assert "Names and recovered types are never correspondence evidence" in type_card.body_html
    assert "by exact name" not in type_card.body_html


def test_convention_comments_are_stripped(content: Content) -> None:
    for spec in content.view_specs:
        view = content.view(spec.id)
        assert "<!--" not in view.body_html + view.outro_html + view.empty_html


def test_prose_views_need_no_data_and_carry_a_body(content: Content) -> None:
    """changelog is prose-only: rendered from its .md, no data."""
    for vid in ("changelog",):
        spec = next(v for v in content.view_specs if v.id == vid)
        assert not spec.requires_function_data, vid
        assert content.view(vid).body_html, vid


def test_with_view_reparses_only_the_named_view(content: Content) -> None:
    """with_view swaps ONE view's prose from a string, leaving the rest intact.

    This is how the CLI injects the repo-root CHANGELOG.md into the changelog
    view at build time without writing into the packaged content/ tree.
    """
    injected = content.with_view("changelog", "# changelog\n\n- an injected bullet.")
    body = injected.view("changelog").body_html
    assert injected.view("changelog").title == "changelog"
    assert "<li>an injected bullet.</li>" in body
    assert injected.view("about") is content.view("about")
    assert "an injected bullet." not in content.view("changelog").body_html
    assert content.with_view("does-not-exist", "# x") is content


def test_data_view_has_four_section_anchors(content: Content) -> None:
    """The data page's four sections are LINKABLE: raw-HTML <h3 class="sub" id=...>
    headings (markdown ### renders without an id), plus the scaffolds app.js fills
    — and the pipeline-health scaffolds live HERE now, not on the about page."""
    body = content.view("data").body_html
    for anchor in ("distance", "compiles", "pipeline-health", "cost"):
        assert f'<h3 class="sub" id="{anchor}">' in body, anchor
    for scaffold in ("cost-table", "joern-source", "joern-output-table"):
        assert f'id="{scaffold}"' in body, scaffold
    for kept in ("distance-table", "distance-subset-note", "compile-table", "compile-subset-note"):
        assert f'id="{kept}"' in body, kept
    about = content.view("about")
    assert "joern-" not in about.body_html + about.outro_html + about.empty_html


def test_pricing_registry_loads(content: Content) -> None:
    """pricing.toml parses into ModelPricing cards for the two LLM decompiler
    models, and the is_priced gate distinguishes a filled card from an all-zero
    (unpriced -> rendered n/a, not $0.00) one."""
    from decbench.rendering.content import ModelPricing

    names = [p.name for p in content.pricing]
    assert "claude-opus-4-8" in names
    assert "gpt-5.6-sol" in names
    assert content.model_pricing("claude-opus-4-8") is not None
    assert content.model_pricing("no-such-model") is None
    assert ModelPricing(name="x", output_per_mtok=15.0).is_priced
    assert not ModelPricing(name="x").is_priced


def test_metrics_registry_covers_the_three_metrics(content: Content) -> None:
    assert [m.name for m in content.metrics] == BENCHMARK_METRICS


def test_metric_lookup_and_fallbacks(content: Content) -> None:
    assert content.short_name("ged") == "Structure"
    assert content.display_name("ged") == "Structural Correctness (GED)"
    assert content.metric("nope") is None
    assert content.short_name("nope") == "nope"


def test_ordered_metrics_sorts_known_and_appends_unknown(content: Content) -> None:
    assert content.ordered_metrics(["byte_match", "ged", "type_match"]) == BENCHMARK_METRICS
    assert content.ordered_metrics(["byte_match", "ged"]) == ["ged", "byte_match"]
    assert content.ordered_metrics(["zzz", "ged"]) == ["ged", "zzz"]


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
        assert 'class="metric-viz"' in card.body_html
        assert "<svg" in card.body_html or 'class="viz-diff"' in card.body_html
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
    assert "[1]" not in view.body_html
    assert 'class="recovered"' in view.outro_html
    assert 'id="dataset-summary"' in view.outro_html
    assert 'id="dataset-projects"' in view.outro_html


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
        assert preset.long_description
        assert preset.name.upper() in preset.long_description


def test_decompiler_registry_loads_with_names_links_and_overrides(content: Content) -> None:
    """decompilers.toml supplies the official names/links the leaderboard renders."""
    angr = content.decompiler("angr")
    assert angr is not None
    assert angr.display_name == "angr"
    assert angr.url == "https://angr.io"

    ida = content.decompiler("ida")
    assert ida is not None
    assert ida.display_name == "Hex-Rays"
    assert ida.pretty_version("920") == "9.2"
    assert ida.pretty_version("unknown") == "unknown"
    assert ida.pretty_version(None) is None


def test_decompiler_license_and_logo_are_parsed(content: Content) -> None:
    """The stacked name cell's license tag and the logo experiment come from here."""
    angr = content.decompiler("angr")
    assert angr is not None and angr.license == "open-source" and angr.logo is True

    ida = content.decompiler("ida")
    assert ida is not None and ida.license == "closed-source" and ida.logo is True

    for spec in content.decompilers:
        assert spec.license in {"open-source", "closed-source"}, spec.id
    assert content.decompiler("retdec").logo is False
    assert content.decompiler("reko").logo is False


def test_decompiler_lookup_matches_base_name_for_versioned_ids(content: Content) -> None:
    """A versioned id (ghidra@12.1) with no exact entry resolves to its base."""
    spec = content.decompiler("ghidra@12.1")
    assert spec is not None
    assert spec.id == "ghidra"
    assert spec.display_name == "Ghidra"


def test_decompiler_lookup_returns_none_for_unknown_id(content: Content) -> None:
    """An id the registry never heard of falls back (caller uses the raw id)."""
    assert content.decompiler("angr-declib") is None


def test_decompiler_url_is_optional() -> None:
    """A spec without a homepage renders unlinked; every shipped entry has one."""
    assert DecompilerSpec(id="x", display_name="X").url == ""


def test_kuna_links_to_its_homepage(content: Content) -> None:
    kuna = content.decompiler("kuna")
    assert kuna is not None
    assert kuna.url == "https://kuna.noelo.org"
    assert kuna.pretty_version("1.121") == "v1.121"


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
    assert site.side_stats["functions"] == " functions"


def test_footer_renders_projects_and_falls_back_when_empty(content: Content) -> None:
    footer = content.site.footer
    assert footer.render("0.1.0", ["bash", "curl"]) == (
        "DecBench v0.1.0 &mdash; decompiler benchmarking suite " "&middot; projects: bash, curl"
    )
    assert footer.render("0.1.0", []).endswith("projects: -")


def test_load_content_is_cached(content: Content) -> None:
    assert load_content() is content


def test_metric_viz_islands_pass_through_verbatim() -> None:
    """A blank-line-riddled SVG island must survive markdown rendering untouched.

    Mistune would otherwise wrap each blank-line-separated SVG child in a `<p>`
    INSIDE the `<svg>` — invalid foreign content the browser refuses to draw.
    """
    from decbench.rendering.content import _render_inline, _render_view, _render_with_islands

    island = (
        '<details class="metric-viz" open>\n<summary>how</summary>\n'
        '<svg viewBox="0 0 10 10">\n\n<rect x="1"/>\n\n<text x="2">hi</text>\n\n</svg>\n'
        "</details>"
    )
    markdown = f"intro prose\n\n{island}\n\nafter prose"
    for renderer in (_render_inline, _render_view):
        html = _render_with_islands(markdown, renderer)
        assert island in html


def test_about_goal_card_svgs_carry_no_stray_paragraphs(content: Content) -> None:
    import re

    for card in content.view("about").goals:
        for svg in re.findall(r"<svg.*?</svg>", card.body_html, re.DOTALL):
            assert not re.search(r"<p[\s>]", svg)


def test_about_goal_cards_use_theme_tokens_not_hardcoded_colors(content: Content) -> None:
    """The metric visualizations must be theme-aware: every SVG fill/stroke and
    inline color resolves a CSS var, so the light theme re-inks them. A stray
    ``#rrggbb`` would paint a dark-theme color onto the light page (marker-id refs
    like ``url(#tm-g)`` are not six hex digits, so they do not trip this)."""
    import re

    for card in content.view("about").goals:
        stray = re.findall(r"#[0-9a-fA-F]{6}\b", card.body_html)
        assert stray == [], (card.metric_key, stray)


def test_metric_viz_blocks_open_by_default_and_carry_a_visualization(content: Content) -> None:
    """The redone metric visualizations show without a click (`open`) and drop the
    now-redundant "[click to expand]" cue. GED and type_match draw inline SVG;
    byte_match uses an HTML assembly line-diff (.viz-diff)."""
    goals = {g.metric_key: g.body_html for g in content.view("about").goals}
    for body in goals.values():
        assert '<details class="metric-viz" open>' in body
        assert "[click to expand]" not in body
    assert "<svg" in goals["ged"]
    assert "<svg" in goals["type_match"]
    assert 'class="viz-diff"' in goals["byte_match"]
    assert "0.88" in goals["byte_match"]
    assert "0.87" not in goals["byte_match"]
