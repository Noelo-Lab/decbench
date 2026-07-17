"""Skeleton renderer for the DecBench report.

This module builds exactly one thing: the HTML *scaffold* — head, sidebar, nav,
one ``<section>`` per view — that ``assets/app.js`` then fills in. It deliberately
holds no CSS, no client logic and no prose; those live in ``assets/app.css``,
``assets/app.js`` and ``content/`` respectively, where a maintainer can edit them
without reading Python. What remains here is the join: content (what to say) x
scoreboard (what to say it about) x :class:`PageAssets` (how to ship it).

Two delivery modes share this one skeleton (:func:`build_page`) because a forked
copy would silently drift:

* **single file** — :func:`render_html_report`, behind ``decbench report``. CSS,
  font, JS and all five data payloads are inlined into the document, because the
  report is opened over ``file://`` where ``fetch()`` is CORS-blocked.
* **split** — :mod:`decbench.rendering.site`, behind ``decbench site build``.
  Assets and data are linked, so the browser caches them and the two big
  code-carrying payloads load only when their view is opened.

The only difference between the two is the :class:`PageAssets` passed in.

The scaffold's element ids (``leaderboard-table``, ``function-counter``,
``view-<id>``, ``data-view``, ``data-stat``, ...) are the contract with
``app.js``: it looks them up by id and renders into them. Renaming one here
silently blanks a view.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from html import escape as html_escape
from importlib.resources import files
from pathlib import Path
from typing import Any

from decbench.models.function_data import FunctionData
from decbench.models.scoreboard import Scoreboard
from decbench.rendering.aggregate import build_payloads, resolve_presets
from decbench.rendering.content import Content, GoalCard, ViewContent, ViewSpec, load_content

__all__ = [
    "CSS_FILE",
    "JS_FILE",
    "PageAssets",
    "asset_bytes",
    "asset_text",
    "build_page",
    "inline_assets",
    "iter_font_assets",
    "linked_assets",
    "render_html_report",
    "static_assets",
]

CSS_FILE = "app.css"
JS_FILE = "app.js"

_ASSETS_DIR = "assets"
_FONTS_DIR = "fonts"

# `url(fonts/x.woff2)` in app.css. It resolves against the STYLESHEET's url when
# the sheet is linked (site/app.css -> site/fonts/x.woff2, correct) but against
# the DOCUMENT's url when the sheet is inlined into a <style> — which is why the
# single-file mode substitutes a data: URI rather than shipping a broken path.
_FONT_URL_RE = re.compile(r"url\((?P<q>['\"]?)(?P<path>fonts/[^)'\"]+)(?P=q)\)")
_FONT_MIME = {
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
}


# --------------------------------------------------------------------------
# Packaged assets
# --------------------------------------------------------------------------


def asset_text(name: str) -> str:
    """Read one packaged asset as text (works from a wheel or a checkout)."""
    return (files(__package__).joinpath(_ASSETS_DIR) / name).read_text(encoding="utf-8")


def asset_bytes(name: str) -> bytes:
    """Read one packaged asset as bytes."""
    return (files(__package__).joinpath(_ASSETS_DIR) / name).read_bytes()


def iter_font_assets() -> Iterator[tuple[str, bytes]]:
    """Yield ``(filename, bytes)`` for every vendored font, name-sorted.

    The fonts are vendored so the report has no third-party runtime dependency:
    it must render identically offline, from a USB stick, in ten years.
    """
    root = files(__package__).joinpath(_ASSETS_DIR, _FONTS_DIR)
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if entry.is_file():
            yield entry.name, entry.read_bytes()


def _data_uri(rel_path: str) -> str:
    """Encode one asset (``fonts/x.woff2``) as a base64 ``data:`` URI."""
    suffix = Path(rel_path).suffix.lower()
    mime = _FONT_MIME.get(suffix, "application/octet-stream")
    encoded = base64.b64encode(asset_bytes(rel_path)).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def _inline_font_urls(css: str) -> str:
    """Rewrite every ``url(fonts/...)`` to a data: URI for single-file mode."""
    return _FONT_URL_RE.sub(lambda m: f"url({_data_uri(m.group('path'))})", css)


def _json_for_script(payload: Any) -> str:
    """Serialize a payload for embedding inside a ``<script>`` element.

    ``<`` is escaped so a ``</script>`` sequence inside the data — decompiled C
    can contain anything — cannot close the tag early and break the page.
    """
    return json.dumps(payload).replace("<", "\\u003c")


# --------------------------------------------------------------------------
# Delivery modes
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PageAssets:
    """How one page receives its CSS, JS and data.

    This is the *entire* difference between the single-file report and the split
    site tree, made explicit so the skeleton itself has no idea which it is
    building — and so the two cannot drift.
    """

    head_html: str
    """Markup for ``<head>``: a ``<style>`` block or a stylesheet ``<link>``."""

    body_end_html: str
    """Markup for the end of ``<body>``: the client script, plus any inline data."""


def linked_assets() -> PageAssets:
    """Split mode: link ``app.css``/``app.js``; the client fetches ``data/*.json``.

    Setting no ``__DECBENCH_INLINE__`` is what tells ``app.js`` to fetch.
    """
    return PageAssets(
        head_html=f'<link rel="stylesheet" href="{CSS_FILE}">',
        body_end_html=f'<script src="{JS_FILE}"></script>',
    )


def _inline_style() -> str:
    """The stylesheet as a ``<style>`` block, with its fonts embedded."""
    return f"<style>\n{_inline_font_urls(asset_text(CSS_FILE))}\n</style>"


def inline_assets(payloads: dict[str, Any]) -> PageAssets:
    """Single-file mode: inline the stylesheet, font, data and client script.

    ``payloads`` is keyed by data-file stem (``aggregates``/``dataset``/
    ``samples``/``hardest``/``history``) exactly as ``data/`` is named in the split
    tree, so ``app.js`` reads one shape either way. It is assigned *before* the
    client script so the module-level ``INLINE`` constant sees it.
    """
    data = _json_for_script(payloads)
    return PageAssets(
        head_html=_inline_style(),
        body_end_html=(
            f"<script>window.__DECBENCH_INLINE__ = {data};</script>\n"
            f"<script>\n{asset_text(JS_FILE)}\n</script>"
        ),
    )


def static_assets() -> PageAssets:
    """Single-file mode with no data: inline the stylesheet, ship no client.

    A report without ``function_results.json`` renders static tables from the
    scoreboard and has nothing for ``app.js`` to do. Shipping it anyway with an
    empty payload would be worse than useless: the client would find no
    ``aggregates`` to load and paint a "could not load data" banner across three
    views that are, in fact, fine.
    """
    return PageAssets(head_html=_inline_style(), body_end_html="")


# --------------------------------------------------------------------------
# Public entry points
# --------------------------------------------------------------------------


def render_html_report(
    scoreboard: Scoreboard,
    output_path: Path,
    function_data: FunctionData | None = None,
) -> None:
    """Render the self-contained single-file HTML report.

    Everything — stylesheet, font, client script and every data payload — is
    embedded, so the file works over ``file://`` and survives being emailed
    around. For the multi-file, Pages-deployable form see
    :func:`decbench.rendering.site.build_site`.

    Args:
        scoreboard: The scoreboard to render.
        output_path: Where to write the HTML file.
        function_data: Optional per-function dataset. Without it the report falls
            back to static tables built from the scoreboard alone.
    """
    if function_data is None:
        assets = static_assets()
    else:
        assets = inline_assets(build_payloads(function_data, scoreboard))
    html = build_page(scoreboard, function_data, assets)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def build_page(
    scoreboard: Scoreboard,
    function_data: FunctionData | None,
    assets: PageAssets,
    content: Content | None = None,
) -> str:
    """Assemble the page skeleton — the one shared by both delivery modes.

    Args:
        scoreboard: Supplies the page identity: name, version, timestamp,
            sidebar counters, and the static no-JS fallback tables.
        function_data: When present, the data-backed views are rendered as empty
            scaffolds for ``app.js`` to fill; when absent they are dropped and the
            leaderboard/metrics tables are rendered statically instead.
        assets: The delivery mode (see :func:`linked_assets` / :func:`inline_assets`).
        content: Parsed ``content/``; loaded (and cached) when omitted.
    """
    content = content or load_content()
    site = content.site
    has_data = function_data is not None
    visible = content.visible_views(has_data)
    default_view = _default_view_id(content, visible)

    nav = "".join(_nav_item(spec) for spec in visible)
    selector = _dataset_selector(function_data, content) if has_data else ""
    banner = f'<div class="banner">{site.no_function_data_banner}</div>' if not has_data else ""
    sections = "".join(
        _view_section(content, spec, scoreboard, function_data, active=spec.id == default_view)
        for spec in visible
    )
    footer = site.footer.render(
        html_escape(str(scoreboard.version)),
        [html_escape(p) for p in scoreboard.projects_evaluated],
    )
    stamp = scoreboard.generated_at.strftime("%Y-%m-%d %H:%M")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html_escape(scoreboard.name)}</title>
    {assets.head_html}
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="brand">
                <div class="brand-prompt">{site.brand.prompt}</div>
                <div class="brand-title">{site.brand.title}</div>
                <div class="brand-sub">{site.brand.subtitle}</div>
            </div>
            <nav class="nav">{nav}</nav>
            {selector}
            <div class="side-stats">{_side_stats(scoreboard, content)}</div>
            <div class="side-foot">[ {stamp} ]</div>
        </aside>

        <main class="main">
            {banner}
            {sections}
            <div class="rule"></div>
            <footer>{footer}</footer>
        </main>
    </div>
    {assets.body_end_html}
</body>
</html>"""


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------


def _default_view_id(content: Content, visible: tuple[ViewSpec, ...]) -> str:
    """The view the page opens on, as one line of ``views.toml`` config.

    Falls back to the first visible view if the configured default is one of the
    data-backed views and this report has no data.
    """
    ids = [spec.id for spec in visible]
    if content.default_view in ids:
        return content.default_view
    return ids[0] if ids else ""


def _nav_item(spec: ViewSpec) -> str:
    """One sidebar nav link. ``href`` doubles as the view's routing hash."""
    return (
        f'<a class="nav-item" data-view="{spec.id}" href="#{spec.id}">'
        f'<span class="nav-bullet">&gt;</span> {html_escape(spec.nav_label)}</a>'
    )


def _side_stats(scoreboard: Scoreboard, content: Content) -> str:
    """The sidebar counters.

    ``functions``/``binaries`` carry a ``data-stat`` hook because ``app.js``
    rewrites them to the selected dataset's counts; the other two are fixed.
    """
    stats = [
        ("functions", f"{scoreboard.total_functions:,}", True),
        ("binaries", f"{scoreboard.total_binaries:,}", True),
        ("decompilers", f"{len(scoreboard.decompilers)}", False),
        ("metrics", f"{len(scoreboard.metrics)}", False),
    ]
    out = ""
    for name, value, live in stats:
        hook = f' data-stat="{name}"' if live else ""
        label = content.site.side_stats.get(name, f" {name}")
        out += f'<div class="side-stat"><span class="side-num"{hook}>{value}</span>{label}</div>'
    return out


def _dataset_selector(function_data: FunctionData, content: Content) -> str:
    """The sidebar dataset selector (unoptimized / optimized / ... / sample-set).

    Preset *names* come from the run; their labels, descriptions and which one is
    preselected come from ``content/datasets.toml`` (see
    :func:`decbench.rendering.aggregate.resolve_presets`) — so the button that is
    active here and the one ``app.js`` activates from ``aggregates.json`` are the
    same button by construction.
    """
    presets = resolve_presets(function_data)
    if not presets:
        return ""
    buttons = ""
    for preset in presets:
        active = " active" if preset.get("default") else ""
        buttons += (
            f'<button class="ds-btn{active}" data-dataset="{html_escape(preset["name"])}" '
            f'title="{html_escape(preset["description"])}">{html_escape(preset["label"])}'
            f"</button>"
        )
    sidebar = content.site.sidebar
    return f"""
        <div class="side-section">
            <div class="side-label">{html_escape(sidebar.dataset_label)}</div>
            <div class="ds-controls">{buttons}</div>
            <div class="ds-desc" id="dataset-desc"></div>
            <div class="counter" id="function-counter"></div>
            <div class="ds-controls" style="margin-top:0.6rem;">
                <button class="ds-btn" id="normalize-btn"
                        title="{html_escape(sidebar.normalize_title)}">
                    {html_escape(sidebar.normalize_label)}
                </button>
            </div>
        </div>"""


# --------------------------------------------------------------------------
# View sections
# --------------------------------------------------------------------------


def _view_section(
    content: Content,
    spec: ViewSpec,
    scoreboard: Scoreboard,
    function_data: FunctionData | None,
    active: bool,
) -> str:
    """Render one view: title, prose, goal cards, outro, generated table.

    A view with nothing to show renders its ``# [empty]`` section instead of its
    body, so the reader gets a sentence explaining the blank rather than a blank.
    """
    view = content.view(spec.id)
    if _is_empty(spec.id, function_data):
        title, inner = view.empty_title, view.empty_html
    else:
        title = view.title
        inner = view.body_html + _goal_cards(view) + view.outro_html
        inner += _generated_table(spec.id, scoreboard, function_data, content)
    cls = "view active" if active else "view"
    return f"""
    <section class="{cls}" id="view-{spec.id}" data-view="{spec.id}">
        <h2 class="view-title">{title}</h2>
        {inner}
    </section>"""


def _is_empty(view_id: str, function_data: FunctionData | None) -> bool:
    """Whether a view has no data to render, and should show its empty state.

    Only the three code/history-carrying views can be legitimately empty: the
    others either need no data or are dropped from the nav without it.
    """
    if function_data is None:
        return False
    return {
        "compare": not function_data.samples,
        "hardest": not function_data.hardest,
        "history": not function_data.history,
    }.get(view_id, False)


def _goal_cards(view: ViewContent) -> str:
    """The About page's ``## [n]`` metric cards. Empty string for every other view."""
    return "".join(_goal_card(card) for card in view.goals)


def _goal_card(card: GoalCard) -> str:
    """One goal card: the decompilation goal, the metric, and what perfect means."""
    head = f'<span class="num">[{html_escape(card.number)}]</span>{html_escape(card.title)}'
    perfect = f'<span class="perfect">{html_escape(card.perfect)}</span>'
    return f"""
        <div class="goal">
            <div class="goal-head">{head}</div>
            <div class="goal-metric">metric: {html_escape(card.metric_display_name)}</div>
            <div class="goal-body">{card.body_html} {perfect}</div>
        </div>"""


def _generated_table(
    view_id: str,
    scoreboard: Scoreboard,
    function_data: FunctionData | None,
    content: Content,
) -> str:
    """The renderer-built table a view ends with, if it has one.

    With per-function data these are empty scaffolds ``app.js`` fills from the
    selected dataset. Without it, they are rendered statically from the
    scoreboard — the only thing on this page that survives with JS disabled.
    Every other view's scaffold is static markup that lives in its ``.md``.
    """
    if view_id == "leaderboard":
        if function_data is None:
            return _static_leaderboard_table(scoreboard, content)
        return '<table id="leaderboard-table"><thead><tr></tr></thead><tbody></tbody></table>'
    if view_id == "about" and function_data is None:
        # With data, about.md carries the empty `metrics-perfect-table` scaffold
        # inline (mid-page, where the metrics section sits) and app.js fills it;
        # only the no-JS/no-data report needs a renderer-built static table.
        return _static_metrics_table(scoreboard, content)
    return ""


# --------------------------------------------------------------------------
# No-JS static fallbacks
# --------------------------------------------------------------------------


def _pct_class(pct: float) -> str:
    """Color band for a perfect-rate percentage (mirrors ``pctClass`` in app.js)."""
    if pct >= 50:
        return "high"
    if pct >= 20:
        return "mid"
    return "low"


def _pct_cell(pct: float, extra_class: str = "") -> str:
    """One percentage cell, colored by band."""
    cls = f"metric-cell {extra_class}".strip()
    return f'<td class="{cls}"><span class="cell-pct pct-{_pct_class(pct)}">{pct:.1f}%</span></td>'


def _metric_headers(scoreboard: Scoreboard, content: Content) -> tuple[list[str], str]:
    """The run's metrics in registry order, plus their ``<th>`` markup."""
    metrics = content.ordered_metrics(scoreboard.metrics)
    headers = "".join(f"<th>{html_escape(content.short_name(m))}</th>" for m in metrics)
    return metrics, headers


def _metric_pct(scoreboard: Scoreboard, dec: str, metric: str) -> float:
    """One decompiler's perfect rate for one metric, 0 when it has no score."""
    scores = scoreboard.decompiler_scores.get(dec)
    if scores is None:
        return 0.0
    score = scores.metric_scores.get(metric)
    return score.perfect_percentage if score else 0.0


def _static_leaderboard_table(scoreboard: Scoreboard, content: Content) -> str:
    """No-JS leaderboard, ranked by Union, straight from the scoreboard."""
    metrics, headers = _metric_headers(scoreboard, content)
    head = f"<th>#</th><th>decompiler</th><th>Union</th>{headers}"
    rows = ""
    for rank, (dec, overall_pct) in enumerate(scoreboard.get_overall_rankings(), 1):
        cells = _pct_cell(overall_pct, "col-overall")
        cells += "".join(_pct_cell(_metric_pct(scoreboard, dec, m)) for m in metrics)
        rows += (
            f'<tr class="binrow"><td class="lb-rank">#{rank}</td>'
            f'<td class="lb-name">{html_escape(dec)}</td>{cells}</tr>'
        )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>"


def _static_metrics_table(scoreboard: Scoreboard, content: Content) -> str:
    """No-JS per-decompiler perfect-rate table, in the scoreboard's own order."""
    metrics, headers = _metric_headers(scoreboard, content)
    head = f"<th>decompiler</th>{headers}<th>Union</th>"
    rows = ""
    for dec in scoreboard.decompilers:
        scores = scoreboard.decompiler_scores.get(dec)
        cells = "".join(_pct_cell(_metric_pct(scoreboard, dec, m)) for m in metrics)
        cells += _pct_cell(scores.overall_perfect_percentage if scores else 0.0)
        rows += f'<tr><td class="lb-name">{html_escape(dec)}</td>{cells}</tr>'
    return f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>"
