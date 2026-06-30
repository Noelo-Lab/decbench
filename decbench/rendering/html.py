"""HTML report renderer for DecBench results.

Single-page app with a left **sidebar** that switches between views, themed in
the mahaloz.re terminal aesthetic (pure-black bg, Source Code Pro mono, dashed
rules, ASCII bars). Views:

* **Leaderboard** — a swebench.com-style ranked table: one row per decompiler,
  one column per metric (perfect %) plus an Overall column; sortable; recomputes
  live over the selected dataset.
* **Metrics** — explains the three decompilation goals (control-flow structure,
  types, recompilation) and the metric used for each, with each decompiler's
  perfect rate + compile rate.
* **Compare** — side-by-side original source vs each decompiler's output for a
  curated set of functions, with per-metric scores.
* **Hardest** — the worst-scoring functions (decompiled + source).
* **Historical** — per-metric perfect % across decompiler versions (SVG).

Everything below the leaderboard is driven client-side from the embedded
per-function dataset, so the dataset selector recomputes all aggregates without a
server round-trip.
"""

from __future__ import annotations

import json
from html import escape as html_escape
from pathlib import Path

from decbench.models.function_data import FunctionData
from decbench.models.scoreboard import Scoreboard

METRIC_DISPLAY_NAMES = {
    "ged": "Structural Correctness (GED)",
    "type_match": "Type Correctness",
    "byte_match": "Recompilation Bytematch",
}

# Short column labels for the leaderboard table.
METRIC_SHORT_NAMES = {
    "ged": "Structure",
    "type_match": "Types",
    "byte_match": "Recompile",
}

# Preferred display order: the three decompilation goals (structure, types,
# recompilation). Unknown metrics are appended in their given order.
_METRIC_ORDER = ["ged", "type_match", "byte_match"]


def _ordered_metrics(metrics: list[str]) -> list[str]:
    known = [m for m in _METRIC_ORDER if m in metrics]
    extra = [m for m in metrics if m not in _METRIC_ORDER]
    return known + extra


def render_html_report(
    scoreboard: Scoreboard,
    output_path: Path,
    function_data: FunctionData | None = None,
) -> None:
    """Render a self-contained HTML report from scoreboard data.

    Args:
        scoreboard: The scoreboard to render.
        output_path: Where to write the HTML file.
        function_data: Optional per-function dataset enabling interactivity.
    """
    html = _build_html(scoreboard, function_data)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)


def _build_html(scoreboard: Scoreboard, function_data: FunctionData | None) -> str:
    """Build the complete HTML string."""
    has_data = function_data is not None
    date_str = scoreboard.generated_at.strftime("%Y-%m-%d")
    time_str = scoreboard.generated_at.strftime("%H:%M")

    nav_items = [
        ("leaderboard", "leaderboard", True),
        ("metrics", "metrics", True),
        ("dataset", "dataset", has_data),
        ("compare", "compare", has_data),
        ("hardest", "hardest", has_data),
        ("history", "historical", has_data),
    ]
    nav = ""
    for view, label, enabled in nav_items:
        if not enabled:
            continue
        nav += (
            f'<a class="nav-item" data-view="{view}" href="#{view}">'
            f'<span class="nav-bullet">&gt;</span> {html_escape(label)}</a>'
        )

    dataset_selector = _build_dataset_selector(function_data) if has_data else ""

    leaderboard = _build_leaderboard_section(scoreboard, function_data)
    metrics_view = _build_metrics_section(scoreboard, function_data)
    dataset_view = _build_dataset_overview_section(function_data) if has_data else ""
    compare_view = _build_compare_section(function_data) if has_data else ""
    hardest_view = _build_hardest_section(function_data) if has_data else ""
    history_view = _build_history_section(function_data) if has_data else ""

    banner = ""
    if not has_data:
        banner = (
            '<div class="banner">[ note ] interactive views unavailable: '
            "per-function data (function_results.json) not found next to the "
            "scoreboard.</div>"
        )

    script = _build_script(function_data) if has_data else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html_escape(scoreboard.name)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Source+Code+Pro:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
{_build_css()}
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="brand">
                <div class="brand-prompt">$ decbench</div>
                <div class="brand-title">DecBench</div>
                <div class="brand-sub">decompiler benchmark</div>
            </div>
            <nav class="nav">{nav}</nav>
            {dataset_selector}
            <div class="side-stats">
                <div class="side-stat"><span class="side-num" data-stat="functions">{scoreboard.total_functions:,}</span> functions</div>
                <div class="side-stat"><span class="side-num" data-stat="binaries">{scoreboard.total_binaries:,}</span> binaries</div>
                <div class="side-stat"><span class="side-num">{len(scoreboard.decompilers)}</span> decompilers</div>
                <div class="side-stat"><span class="side-num">{len(scoreboard.metrics)}</span> metrics</div>
            </div>
            <div class="side-foot">[ {date_str} {time_str} ]</div>
        </aside>

        <main class="main">
            {banner}
            {leaderboard}
            {metrics_view}
            {dataset_view}
            {compare_view}
            {hardest_view}
            {history_view}
            <div class="rule"></div>
            <footer>
                DecBench v{html_escape(str(scoreboard.version))} &mdash; decompiler benchmarking suite
                &middot; projects: {html_escape(', '.join(scoreboard.projects_evaluated) or '-')}
            </footer>
        </main>
    </div>
    {script}
</body>
</html>"""


def _build_dataset_selector(function_data: FunctionData) -> str:
    """Sidebar dataset selector (full / hard / hard-inlined / tiny)."""
    presets = function_data.dataset_presets or []
    if not presets:
        return ""
    buttons = ""
    for i, preset in enumerate(presets):
        active = " active" if i == 0 else ""
        buttons += (
            f'<button class="ds-btn{active}" data-dataset="{html_escape(preset.name)}" '
            f'title="{html_escape(preset.description)}">{html_escape(preset.label)}</button>'
        )
    return f"""
        <div class="side-section">
            <div class="side-label">dataset</div>
            <div class="ds-controls">{buttons}</div>
            <div class="ds-desc" id="dataset-desc"></div>
            <div class="counter" id="function-counter"></div>
            <div class="ds-controls" style="margin-top:0.6rem;">
                <button class="ds-btn" id="normalize-btn"
                        title="Only count functions that EVERY decompiler decompiled successfully (apples-to-apples).">
                    normalize failures
                </button>
            </div>
        </div>"""


def _build_css() -> str:
    """Return the full terminal-aesthetic stylesheet (sidebar layout)."""
    return """        :root {
            --bg: #000;
            --code-bg: #141414;
            --code-border: #545454;
            --text: #DBDBDB;
            --text-muted: #8a8a8a;
            --border-color: rgba(219, 219, 219, 0.9);
            --green: #6ab04c;
            --amber: #d4a72c;
            --red: #c0504d;
            --sidebar-w: 230px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html { background: var(--bg); }
        body {
            font-family: "Source Code Pro", ui-monospace, Menlo, Consolas, monospace;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
            font-size: 15px;
        }
        a { color: var(--text); text-decoration: none; }
        .layout { display: flex; align-items: flex-start; min-height: 100vh; }

        /* ---- Sidebar ---- */
        .sidebar {
            width: var(--sidebar-w);
            min-width: var(--sidebar-w);
            position: sticky;
            top: 0;
            align-self: flex-start;
            height: 100vh;
            overflow-y: auto;
            border-right: dashed 1px var(--border-color);
            padding: 1.4rem 1rem;
            display: flex;
            flex-direction: column;
            gap: 1.1rem;
        }
        .brand-prompt { color: var(--text-muted); font-size: 0.8em; }
        .brand-title { font-size: 1.35rem; font-weight: 700; letter-spacing: 0.02em; }
        .brand-sub { color: var(--text-muted); font-size: 0.78em; }
        .nav { display: flex; flex-direction: column; gap: 0.15rem; }
        .nav-item {
            padding: 0.25rem 0.4rem;
            font-size: 0.92em;
            border: dashed 1px transparent;
        }
        .nav-bullet { color: var(--text-muted); }
        .nav-item:hover { color: #000; background: var(--text); }
        .nav-item.active {
            border-color: var(--border-color);
            color: var(--green);
        }
        .nav-item.active .nav-bullet { color: var(--green); }
        .side-section { border-top: dashed 1px rgba(219,219,219,0.25); padding-top: 0.9rem; }
        .side-label { color: var(--text-muted); font-size: 0.78em; margin-bottom: 0.4rem; }
        .ds-controls { display: flex; flex-wrap: wrap; gap: 0.3rem; }
        .ds-desc { color: var(--text-muted); font-size: 0.74em; margin-top: 0.4rem; line-height: 1.35; }
        .side-stats { border-top: dashed 1px rgba(219,219,219,0.25); padding-top: 0.9rem; font-size: 0.85em; }
        .side-stat { color: var(--text-muted); padding: 0.05rem 0; }
        .side-num { color: var(--text); font-weight: 700; }
        .side-foot { color: var(--text-muted); font-size: 0.78em; margin-top: auto; }

        /* ---- Main ---- */
        .main {
            flex: 1;
            min-width: 0;
            max-width: 1100px;
            padding: 1.8rem 2rem 3rem;
        }
        .view { display: none; }
        .view.active { display: block; }
        .rule { border: none; border-top: dashed 1px var(--border-color); margin: 1.4rem 0; }
        .banner {
            border: dashed 1px var(--amber); color: var(--amber);
            padding: 0.6rem 0.9rem; margin: 0 0 1rem; font-size: 0.9em;
        }
        h2.view-title { font-size: 1.3rem; font-weight: 700; margin-bottom: 0.2rem; }
        h2.view-title:before { content: "## "; color: var(--text-muted); }
        .view-desc { color: var(--text-muted); font-size: 0.88em; margin-bottom: 1.1rem; max-width: 70ch; }
        h3.sub { font-size: 1rem; font-weight: 700; margin: 1.4rem 0 0.4rem; }
        h3.sub:before { content: "> "; color: var(--text-muted); }

        /* ---- Tables ---- */
        table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
        th, td {
            text-align: left; padding: 0.45rem 0.8rem 0.45rem 0;
            border-bottom: dashed 1px rgba(219, 219, 219, 0.22);
            vertical-align: middle;
        }
        th {
            color: var(--text-muted); font-weight: 600; font-size: 0.82em;
            border-bottom: dashed 1px var(--border-color); white-space: nowrap;
        }
        th.sortable { cursor: pointer; user-select: none; }
        th.sortable:hover { color: var(--text); }
        th .arrow { color: var(--green); }
        tr:last-child td { border-bottom: none; }
        .lb-rank { color: var(--text-muted); width: 2.6em; }
        .lb-name { font-weight: 700; font-size: 1.02em; }
        .lb-name .ver { color: var(--text-muted); font-weight: 400; font-size: 0.85em; }
        td.metric-cell { white-space: nowrap; }
        .cell-pct { font-weight: 700; }
        .cell-count { color: var(--text-muted); font-size: 0.82em; }
        .bar-ascii { color: var(--text-muted); white-space: pre; letter-spacing: -0.02em; }
        .pct-high { color: var(--green); }
        .pct-mid { color: var(--amber); }
        .pct-low { color: var(--red); }
        .binrow:hover td { background: rgba(219, 219, 219, 0.06); }
        .col-overall { border-left: dashed 1px rgba(219,219,219,0.25); }
        .cat-btn.active { color: #000; background: var(--green); border-style: solid; font-weight: 700; }
        tr.cat-hl td { background: rgba(106, 176, 76, 0.16); }

        /* ---- Buttons / inputs ---- */
        button, select, input[type=text] {
            background: var(--bg); border: dashed 1px var(--border-color);
            color: var(--text); padding: 0.25rem 0.6rem; cursor: pointer;
            font-family: inherit; font-size: 0.88em;
        }
        button:hover, select:hover { color: #000; background: var(--text); }
        .ds-btn { padding: 0.15rem 0.5rem; font-size: 0.82em; }
        .ds-btn.active { color: #000; background: var(--text); border-style: solid; font-weight: 700; }
        .controls { display: flex; align-items: center; gap: 0.7rem; margin: 0.8rem 0; flex-wrap: wrap; font-size: 0.9em; }
        .controls label { color: var(--text-muted); }
        .counter { color: var(--text-muted); font-size: 0.82em; }

        /* ---- Metrics cards ---- */
        .goal {
            border: dashed 1px rgba(219,219,219,0.4);
            padding: 0.9rem 1.1rem; margin: 0.9rem 0;
        }
        .goal-head { font-weight: 700; font-size: 1.02em; margin-bottom: 0.2rem; }
        .goal-head .num { color: var(--green); margin-right: 0.4rem; }
        .goal-metric { color: var(--amber); font-size: 0.82em; margin-bottom: 0.5rem; }
        .goal-body { color: var(--text); font-size: 0.88em; max-width: 75ch; }
        .goal-body .perfect { color: var(--text-muted); }
        .formula { color: var(--text-muted); font-size: 0.82em; margin-top: 0.5rem; }
        .recovered {
            border: dashed 1px var(--green); color: var(--green);
            padding: 0.7rem 1rem; margin: 1.2rem 0; font-size: 0.9em;
        }

        /* ---- Code blocks / compare ---- */
        pre {
            background: var(--code-bg); border: 0.1em solid var(--code-border);
            box-shadow: inset 0 0 0.4em rgba(0,0,0,0.8);
            padding: 0.7rem 0.9rem; overflow: auto; margin: 0.4rem 0;
            font-size: 0.8em; line-height: 1.45; max-height: 560px;
        }
        pre code { font-family: Consolas, "Source Code Pro", monospace; color: var(--text); white-space: pre; }
        .code-label { color: var(--text-muted); font-size: 0.8em; margin: 0.6rem 0 0.1rem; }
        .cmp-grid { display: grid; gap: 0.8rem; margin-top: 0.6rem; }
        .cmp-col { min-width: 0; }
        .cmp-col h4 {
            font-size: 0.9em; font-weight: 700; margin-bottom: 0.2rem;
            border-bottom: dashed 1px var(--border-color); padding-bottom: 0.2rem;
        }
        .cmp-col.src h4 { color: var(--green); }
        .cmp-scores { font-size: 0.78em; color: var(--text-muted); margin: 0.2rem 0; }
        .cmp-scores .sc { margin-right: 0.7rem; }
        .cmp-meta { color: var(--text-muted); font-size: 0.82em; margin-bottom: 0.4rem; }

        /* ---- Hardest ---- */
        .hard-entry { border: dashed 1px rgba(219,219,219,0.4); padding: 0.7rem 0.9rem; margin: 0.9rem 0; }
        .hard-head { font-size: 0.95em; margin-bottom: 0.2rem; }
        .hard-head .fn { font-weight: 700; }
        .hard-meta { color: var(--text-muted); font-size: 0.82em; margin-bottom: 0.3rem; }
        .hard-meta .tag { margin-right: 0.6rem; }
        .hard-meta .score-bad { color: var(--red); }

        /* ---- Charts ---- */
        .chart-block { margin: 1.2rem 0; }
        .chart-block h3 { font-size: 0.95em; font-weight: 600; margin-bottom: 0.3rem; }
        .chart-block h3:before { content: "> "; color: var(--text-muted); }
        svg { display: block; max-width: 100%; }
        .legend { font-size: 0.82em; color: var(--text-muted); margin-top: 0.3rem; }
        .legend .item { margin-right: 1rem; white-space: nowrap; }
        .legend .swatch { display: inline-block; width: 1.4em; height: 0.5em; vertical-align: middle; margin-right: 0.3rem; }
        footer { color: var(--text-muted); font-size: 0.82em; margin-top: 1.5rem; }

        @media (max-width: 820px) {
            .layout { flex-direction: column; }
            .sidebar { width: 100%; min-width: 0; height: auto; position: static;
                       border-right: none; border-bottom: dashed 1px var(--border-color); }
            .main { padding: 1.2rem 1rem 3rem; }
            .nav { flex-direction: row; flex-wrap: wrap; }
            .side-foot { margin-top: 0.5rem; }
        }"""


# --------------------------------------------------------------------------
# Static section scaffolds (filled/recomputed by JS when data is present).
# --------------------------------------------------------------------------


def _ascii_bar(pct: float, width: int = 12) -> str:
    p = max(0.0, min(pct, 100.0))
    filled = int(round((p / 100.0) * width))
    filled = max(0, min(filled, width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _pct_class(pct: float) -> str:
    if pct >= 50:
        return "high"
    if pct >= 20:
        return "mid"
    return "low"


def _build_leaderboard_section(scoreboard: Scoreboard, function_data: FunctionData | None) -> str:
    """The swebench-style leaderboard. JS rebuilds it; we render a static
    fallback from the scoreboard so a no-JS / no-data view still works."""
    active = " active"  # leaderboard is the default view
    intro = (
        "ranked by Overall &mdash; the share of functions a decompiler recovers "
        "<em>perfectly on all three metrics</em>. click a column to sort."
    )
    if function_data is None:
        # Static table straight from the scoreboard.
        table = _static_leaderboard_table(scoreboard)
        return f"""
    <section class="view{active}" id="view-leaderboard" data-view="leaderboard">
        <h2 class="view-title">leaderboard</h2>
        <p class="view-desc">{intro}</p>
        {table}
    </section>"""

    return f"""
    <section class="view{active}" id="view-leaderboard" data-view="leaderboard">
        <h2 class="view-title">leaderboard</h2>
        <p class="view-desc">{intro}</p>
        <table id="leaderboard-table">
            <thead><tr></tr></thead>
            <tbody></tbody>
        </table>
    </section>"""


def _static_leaderboard_table(scoreboard: Scoreboard) -> str:
    """No-JS fallback leaderboard from the scoreboard object."""
    rankings = scoreboard.get_overall_rankings()
    headers = "<th>#</th><th>decompiler</th><th>Overall</th>"
    for m in _ordered_metrics(scoreboard.metrics):
        headers += f"<th>{html_escape(METRIC_SHORT_NAMES.get(m, m))}</th>"
    rows = ""
    for rank, (dec, overall_pct) in enumerate(rankings, 1):
        ds = scoreboard.decompiler_scores.get(dec)
        cells = (
            f'<td class="metric-cell col-overall"><span class="cell-pct pct-{_pct_class(overall_pct)}">'
            f"{overall_pct:.1f}%</span></td>"
        )
        for m in _ordered_metrics(scoreboard.metrics):
            ms = ds.metric_scores.get(m) if ds else None
            p = ms.perfect_percentage if ms else 0.0
            cells += (
                f'<td class="metric-cell"><span class="cell-pct pct-{_pct_class(p)}">'
                f"{p:.1f}%</span></td>"
            )
        rows += (
            f'<tr class="binrow"><td class="lb-rank">#{rank}</td>'
            f'<td class="lb-name">{html_escape(dec)}</td>{cells}</tr>'
        )
    return f"<table><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table>"


def _build_metrics_section(scoreboard: Scoreboard, function_data: FunctionData | None) -> str:
    """The Metrics explainer: three goals, their metrics, perfect rates."""
    goals = [
        (
            "1",
            "Control-flow structure correctness",
            "Structural Correctness (GED)",
            "Does the decompiled code branch and loop the same way the source "
            "does? We compare the control-flow graphs of the source and the "
            "decompilation with a Graph Edit Distance (GED) &mdash; the number of "
            "node/edge insertions, deletions, and substitutions needed to turn "
            "one CFG into the other.",
            "perfect = GED of 0 (graph-isomorphic control flow).",
        ),
        (
            "2",
            "Type correctness",
            "Type Correctness",
            "Did the decompiler recover the right variable and argument types? "
            "We match the decompiled variables against DWARF ground truth "
            "(arguments by ABI position, stack variables by calibrated offset, "
            "the rest by name) and score the fraction recovered correctly.",
            "perfect = 1.0 (every recoverable variable typed correctly).",
        ),
        (
            "3",
            "Recompilation correctness",
            "Recompilation Bytematch",
            "Does the decompiled code recompile to the same machine code? We run "
            "a uniform compilability fixup (define decompiler pseudo-types, strip "
            "illegal symbol-version tokens, declare missing symbols) so every "
            "decompiler gets a fair shot at building, recompile each function with "
            "the original toolchain, and compare the resulting assembly &mdash; "
            "normalizing link-time-dependent operands (call/jump targets, "
            "PC-relative offsets) so only real differences count.",
            "perfect = 1.0 (recompiled assembly matches the original).",
        ),
    ]
    cards = ""
    for num, title, metric_disp, body, perfect in goals:
        cards += f"""
        <div class="goal">
            <div class="goal-head"><span class="num">[{num}]</span>{html_escape(title)}</div>
            <div class="goal-metric">metric: {html_escape(metric_disp)}</div>
            <div class="goal-body">{body} <span class="perfect">{html_escape(perfect)}</span></div>
        </div>"""

    perfect_table = (
        '<table id="metrics-perfect-table"><thead><tr></tr></thead><tbody></tbody></table>'
        if function_data is not None
        else _static_metrics_table(scoreboard)
    )

    return f"""
    <section class="view" id="view-metrics" data-view="metrics">
        <h2 class="view-title">metrics</h2>
        <p class="view-desc">
            Decompilation has three goals; DecBench measures each with one metric
            and reports how often a decompiler gets it <em>perfect</em>.
        </p>
        {cards}
        <div class="recovered">
            [ = ] When a function is perfect on <strong>all three</strong> metrics,
            the decompiler has precisely recovered the original source: same control
            flow, same types, and code that recompiles to the same bytes. That is the
            Overall column on the leaderboard.
        </div>
        <h3 class="sub">how often each decompiler is perfect</h3>
        <p class="view-desc" id="metrics-table-note">over the selected dataset.</p>
        {perfect_table}
    </section>"""


def _static_metrics_table(scoreboard: Scoreboard) -> str:
    headers = "<th>decompiler</th>"
    for m in _ordered_metrics(scoreboard.metrics):
        headers += f"<th>{html_escape(METRIC_SHORT_NAMES.get(m, m))}</th>"
    headers += "<th>Overall</th>"
    rows = ""
    for dec in scoreboard.decompilers:
        ds = scoreboard.decompiler_scores.get(dec)
        cells = ""
        for m in _ordered_metrics(scoreboard.metrics):
            ms = ds.metric_scores.get(m) if ds else None
            p = ms.perfect_percentage if ms else 0.0
            cells += f'<td><span class="cell-pct pct-{_pct_class(p)}">{p:.1f}%</span></td>'
        op = ds.overall_perfect_percentage if ds else 0.0
        cells += f'<td><span class="cell-pct pct-{_pct_class(op)}">{op:.1f}%</span></td>'
        rows += f'<tr><td class="lb-name">{html_escape(dec)}</td>{cells}</tr>'
    return f"<table><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table>"


def _build_dataset_overview_section(function_data: FunctionData) -> str:
    """The Dataset/About page: software types, projects, total LOC, Joern health.

    Rendered client-side from the embedded dataset (categories from per-binary
    labels) + ``dataset_info`` (LOC, Joern parse failures).
    """
    return """
    <section class="view" id="view-dataset" data-view="dataset">
        <h2 class="view-title">dataset</h2>
        <p class="view-desc">
            The benchmark corpus: the kinds of software it covers, every project,
            its size, and how much of the GED pipeline is lost to our own tooling
            (Joern source-parse failures) rather than to the decompilers.
        </p>
        <h3 class="sub">software types</h3>
        <p class="view-desc">click a type to highlight the projects it covers (a
            project can span several).</p>
        <div class="controls" id="category-controls"></div>
        <h3 class="sub">summary</h3>
        <div id="dataset-summary" class="goal"></div>
        <h3 class="sub">pipeline health (our own tooling)</h3>
        <p class="view-desc">
            GED depends on Joern parsing both the source and the decompiler output.
            When Joern fails on the <strong>source</strong>, that's our tooling — those
            functions are excluded from GED for every decompiler (never counted against
            them). When Joern fails on a single decompiler's <strong>output</strong>,
            that's reported here (per decompiler), not folded into the headline score.
        </p>
        <div id="joern-source" class="goal"></div>
        <table id="joern-output-table"><thead><tr></tr></thead><tbody></tbody></table>
        <h3 class="sub">projects</h3>
        <table id="dataset-projects"><thead><tr></tr></thead><tbody></tbody></table>
    </section>"""


def _build_compare_section(function_data: FunctionData) -> str:
    """Side-by-side source vs decompiler output, picked from curated samples."""
    if not function_data.samples:
        return """
    <section class="view" id="view-compare" data-view="compare">
        <h2 class="view-title">compare</h2>
        <p class="view-desc">no sample functions were attached to this report.</p>
    </section>"""
    return """
    <section class="view" id="view-compare" data-view="compare">
        <h2 class="view-title">compare</h2>
        <p class="view-desc">
            original source next to each decompiler's output for a curated set of
            functions, with this function's per-metric scores. pick one below.
        </p>
        <div class="controls">
            <label for="cmp-filter">filter:</label>
            <input type="text" id="cmp-filter" placeholder="function / project / binary" size="28">
            <label for="cmp-select">function:</label>
            <select id="cmp-select"></select>
            <span class="counter" id="cmp-counter"></span>
        </div>
        <div id="compare-body"></div>
    </section>"""


def _build_hardest_section(function_data: FunctionData) -> str:
    if not function_data.hardest:
        return """
    <section class="view" id="view-hardest" data-view="hardest">
        <h2 class="view-title">hardest functions</h2>
        <p class="view-desc">no hardest-function data was attached to this report.</p>
    </section>"""
    return """
    <section class="view" id="view-hardest" data-view="hardest">
        <h2 class="view-title">hardest functions &mdash; hall of shame</h2>
        <p class="view-desc">
            the functions decompilers struggled with most (farthest from the
            metric's perfect value), with decompiled output and original source.
        </p>
        <div class="controls">
            <label for="hard-metric">metric:</label>
            <select id="hard-metric"><option value="__all__">all</option></select>
            <label for="hard-dec">decompiler:</label>
            <select id="hard-dec"><option value="__all__">all</option></select>
            <span class="counter" id="hard-counter"></span>
        </div>
        <div id="hardest-list"></div>
    </section>"""


def _build_history_section(function_data: FunctionData) -> str:
    if not function_data.history:
        return """
    <section class="view" id="view-history" data-view="history">
        <h2 class="view-title">historical</h2>
        <p class="view-desc">
            shows how each decompiler's metric scores change across versions.
            appears once &ge;2 versions have been benchmarked
            (e.g. ghidra@12.0 vs ghidra@12.1).
        </p>
    </section>"""
    return """
    <section class="view" id="view-history" data-view="history">
        <h2 class="view-title">historical</h2>
        <p class="view-desc">
            per-metric perfect % across decompiler versions (x = version order,
            y = perfect %, one line per decompiler).
        </p>
        <div id="history-charts"></div>
    </section>"""


def _build_script(function_data: FunctionData) -> str:
    """Inline JS: view routing + live recomputation + compare/hardest/history."""
    data_json = json.dumps(function_data.model_dump(mode="json")).replace("<", "\\u003c")
    js = _JS_TEMPLATE
    return js.replace("__DATA__", data_json)


_JS_TEMPLATE = """
    <script>
    const DATA = __DATA__;
    const METRIC_NAMES = {
        "ged": "Structural Correctness (GED)",
        "type_match": "Type Correctness",
        "byte_match": "Recompilation Bytematch"
    };
    const METRIC_SHORT = {"ged": "Structure", "type_match": "Types", "byte_match": "Recompile"};
    // Display metrics in goal order (structure -> types -> recompile), with any
    // extra/unknown metrics appended.
    const METRIC_ORDER = ["ged", "type_match", "byte_match"];
    function orderedMetrics() {
        const known = METRIC_ORDER.filter(m => DATA.metrics.indexOf(m) >= 0);
        const extra = DATA.metrics.filter(m => METRIC_ORDER.indexOf(m) < 0);
        return known.concat(extra);
    }
    const PRESETS = DATA.dataset_presets || [];
    const state = {
        dataset: PRESETS.length ? PRESETS[0].name : null,
        view: "leaderboard",
        sortKey: "__overall__",
        sortDir: -1,
        normalize: false
    };

    function binaryKey(g) { return g.project + "/" + g.opt_level + "/" + g.binary; }
    // Did decompiler d produce output for this function? (back-compat: infer from
    // metric presence if older data lacks the `decompiled` map.)
    function decompiledBy(func, d) {
        const dd = func.decompiled;
        if (dd && (d in dd)) return dd[d];
        return !!func.perfects[d];
    }
    function allDecompiled(func) {
        for (const d of DATA.decompilers) if (!decompiledBy(func, d)) return false;
        return true;
    }
    function isActive(group, func) {
        if (state.normalize && !allDecompiled(func)) return false;
        if (!state.dataset) return true;
        return (func.datasets || []).indexOf(state.dataset) >= 0;
    }
    function groupHasActive(group) {
        return group.functions.some(f => isActive(group, f));
    }
    function pctClass(p) { return p >= 50 ? "high" : (p >= 20 ? "mid" : "low"); }
    function asciiBar(pct, width) {
        width = width || 12;
        let p = Math.max(0, Math.min(pct, 100));
        let filled = Math.round((p / 100) * width);
        filled = Math.max(0, Math.min(filled, width));
        return "[" + "#".repeat(filled) + "-".repeat(width - filled) + "]";
    }
    function escapeHtml(s) {
        return (s == null ? "" : String(s))
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
    function pct(cell) { return cell.total > 0 ? (cell.perfect / cell.total) * 100 : 0; }

    // GED's source CFG is decompiler-independent: a function's source parsed iff
    // SOME decompiler obtained a GED value for it. Joern failing on the SOURCE is
    // our own tooling's fault, so those functions are excluded from GED for every
    // decompiler (not counted against anyone). Joern failing on a single
    // decompiler's OUTPUT (source parsed, but that decompiler has no GED value)
    // still counts as a GED miss for it AND is reported as a per-decompiler
    // tooling stat on the Dataset page.
    function hasGed(func, d) {
        const v = func.values[d];
        return !!(v && ("ged" in v));
    }
    function sourceParsed(func) {
        if (DATA.metrics.indexOf("ged") < 0) return true;
        for (const d of DATA.decompilers) if (hasGed(func, d)) return true;
        return false;
    }

    // ---- Recompute aggregates over the active dataset ----
    function recompute() {
        const decs = DATA.decompilers, metrics = DATA.metrics;
        const perMetric = {}, overall = {}, errors = {}, joernOutFail = {};
        for (const d of decs) {
            perMetric[d] = {};
            for (const m of metrics) perMetric[d][m] = {perfect: 0, total: 0};
            overall[d] = {perfect: 0, total: 0};
            errors[d] = {errored: 0, scope: 0};  // scope = functions d attempted
            joernOutFail[d] = {failed: 0, scope: 0};  // Joern failed on d's output
        }
        let activeFunctions = 0, totalFunctions = 0, activeBins = 0;
        for (const group of DATA.groups) {
            let groupActive = false;
            for (const func of group.functions) {
                totalFunctions += 1;
                if (!isActive(group, func)) continue;
                activeFunctions += 1; groupActive = true;
                const srcOk = sourceParsed(func);
                for (const d of decs) {
                    // Errors: a function is "in scope" for d if d attempted it
                    // (present in the decompiled map); errored if it didn't
                    // produce output (failed / timed out).
                    const dd = func.decompiled || {};
                    if (d in dd) {
                        errors[d].scope += 1;
                        if (!dd[d]) errors[d].errored += 1;
                    }
                    // DENOMINATOR = functions d decompiled (one denominator for
                    // every metric). A metric not computed on a decompiled
                    // function counts as not-perfect (it still counts in total) —
                    // EXCEPT GED excludes functions where our source parser (Joern)
                    // failed on the source, since that's not the decompiler's fault.
                    if (!decompiledBy(func, d)) continue;
                    const fperf = func.perfects[d] || {};
                    for (const m of metrics) {
                        if (m === "ged" && !srcOk) continue;  // source-parse fail: exclude
                        perMetric[d][m].total += 1;
                        if (fperf[m]) perMetric[d][m].perfect += 1;
                    }
                    // Per-decompiler Joern-on-output failure (source parsed but
                    // Joern couldn't parse THIS decompiler's output) — a tooling
                    // diagnostic surfaced on the Dataset page, not a score.
                    if (srcOk) {
                        joernOutFail[d].scope += 1;
                        if (!hasGed(func, d)) joernOutFail[d].failed += 1;
                    }
                    // Overall (perfect on ALL metrics) needs GED, so it too
                    // excludes source-parse failures from its denominator.
                    if (srcOk) {
                        overall[d].total += 1;
                        let allPerfect = true;
                        for (const m of metrics) { if (!fperf[m]) { allPerfect = false; break; } }
                        if (allPerfect) overall[d].perfect += 1;
                    }
                }
            }
            if (groupActive) activeBins += 1;
        }
        return {perMetric, overall, errors, joernOutFail, activeFunctions, totalFunctions, activeBins};
    }

    // ---- Leaderboard (swebench-style sortable table) ----
    function cellPctHtml(cell) {
        const p = pct(cell);
        return '<span class="bar-ascii">' + asciiBar(p, 8) + '</span> ' +
            '<span class="cell-pct pct-' + pctClass(p) + '">' + p.toFixed(1) + '%</span> ' +
            '<span class="cell-count">(' + cell.perfect + '/' + cell.total + ')</span>';
    }
    // Errors: lower is better, so the color scale is inverted vs metrics.
    function errPctClass(p) { return p < 2 ? "high" : (p < 10 ? "mid" : "low"); }
    function errRate(cell) { return cell.scope > 0 ? (cell.errored / cell.scope) * 100 : 0; }
    function errorCellHtml(cell) {
        const p = errRate(cell);
        return '<span class="cell-pct pct-' + errPctClass(p) + '">' + p.toFixed(1) + '%</span> ' +
            '<span class="cell-count">(' + cell.errored + '/' + cell.scope + ')</span>';
    }
    function sortValue(d, key, result) {
        if (key === "__name__") return d;
        if (key === "__errors__") return errRate(result.errors[d]);
        const cell = key === "__overall__" ? result.overall[d] : result.perMetric[d][key];
        return pct(cell);
    }
    function buildLeaderboard(result) {
        const tbl = document.getElementById("leaderboard-table");
        if (!tbl) return;
        const decs = DATA.decompilers.slice(), metrics = orderedMetrics();
        // Header. "Errors" = how often the decompiler failed/timed out on a
        // function it was asked to decompile (lower is better).
        const cols = [["__name__", "decompiler"], ["__overall__", "Overall"]];
        for (const m of metrics) cols.push([m, METRIC_SHORT[m] || m]);
        cols.push(["__errors__", "Errors"]);
        let head = "<th>#</th>";
        for (const [key, label] of cols) {
            const arrow = state.sortKey === key ? (state.sortDir < 0 ? " ▼" : " ▲") : "";
            const cls = "sortable" + (key === "__overall__" ? " col-overall" : "");
            head += '<th class="' + cls + '" data-sort="' + key + '">' +
                escapeHtml(label) + '<span class="arrow">' + arrow + '</span></th>';
        }
        tbl.querySelector("thead tr").innerHTML = head;
        // Sort.
        decs.sort((a, b) => {
            let va = sortValue(a, state.sortKey, result), vb = sortValue(b, state.sortKey, result);
            if (typeof va === "string") return state.sortDir * va.localeCompare(vb);
            return state.sortDir * (va - vb);
        });
        // Rows.
        let body = "";
        decs.forEach((d, i) => {
            const ver = DATA.decompiler_versions && DATA.decompiler_versions[d];
            const tip = ver ? (d + " — version " + ver) : d;
            let row = '<tr class="binrow"><td class="lb-rank">#' + (i + 1) + '</td>' +
                '<td class="lb-name" title="' + escapeHtml(tip) + '">' + escapeHtml(d) + '</td>';
            row += '<td class="metric-cell col-overall">' + cellPctHtml(result.overall[d]) + '</td>';
            for (const m of metrics) row += '<td class="metric-cell">' + cellPctHtml(result.perMetric[d][m]) + '</td>';
            row += '<td class="metric-cell">' + errorCellHtml(result.errors[d]) + '</td>';
            row += '</tr>';
            body += row;
        });
        tbl.querySelector("tbody").innerHTML = body;
        tbl.querySelectorAll("th.sortable").forEach(th => {
            th.addEventListener("click", () => {
                const key = th.getAttribute("data-sort");
                if (state.sortKey === key) state.sortDir *= -1;
                else { state.sortKey = key; state.sortDir = (key === "__name__") ? 1 : -1; }
                buildLeaderboard(lastResult);
            });
        });
    }

    // ---- Metrics perfect-rate table ----
    function buildMetricsTable(result) {
        const tbl = document.getElementById("metrics-perfect-table");
        if (!tbl) return;
        const decs = DATA.decompilers, metrics = orderedMetrics();
        let head = "<th>decompiler</th>";
        for (const m of metrics) head += "<th>" + escapeHtml(METRIC_SHORT[m] || m) + "</th>";
        head += '<th class="col-overall">Overall</th><th>Errors</th>';
        tbl.querySelector("thead tr").innerHTML = head;
        let body = "";
        for (const d of decs) {
            const ver = DATA.decompiler_versions && DATA.decompiler_versions[d];
            const tip = ver ? (d + " — version " + ver) : d;
            let row = '<tr><td class="lb-name" title="' + escapeHtml(tip) + '">' + escapeHtml(d) + '</td>';
            for (const m of metrics) row += '<td class="metric-cell">' + cellPctHtml(result.perMetric[d][m]) + '</td>';
            row += '<td class="metric-cell col-overall">' + cellPctHtml(result.overall[d]) + '</td>';
            row += '<td class="metric-cell">' + errorCellHtml(result.errors[d]) + '</td>';
            row += '</tr>';
            body += row;
        }
        tbl.querySelector("tbody").innerHTML = body;
    }

    // ---- Dataset / About page (static; describes the whole corpus) ----
    const CATEGORY_LABELS = {
        "parser": ["parsing", "text-processing", "compression", "archiving"],
        "webserver": ["server", "daemon"],
        "cryptography": ["crypto", "security"],
        "malware": ["malware"],
        "firmware": ["cps"]
    };
    function projectStats() {
        const m = {};
        for (const g of DATA.groups) {
            let p = m[g.project];
            if (!p) p = m[g.project] = {labels: new Set(), binaries: new Set(), functions: 0};
            (g.labels || []).forEach(l => p.labels.add(l));
            p.binaries.add(g.binary);
            p.functions += g.functions.length;
        }
        return m;
    }
    function categoriesOf(labelSet) {
        const cats = [];
        for (const cat in CATEGORY_LABELS) {
            if (CATEGORY_LABELS[cat].some(l => labelSet.has(l))) cats.push(cat);
        }
        return cats;
    }
    function buildDataset() {
        const di = DATA.dataset_info || {};
        const loc = di.loc_by_project || {};
        const stats = projectStats();
        const proj = Object.keys(stats).sort().map(n => ({
            name: n, cats: categoriesOf(stats[n].labels), loc: loc[n] || 0,
            binaries: stats[n].binaries.size, functions: stats[n].functions
        }));
        // Category highlight buttons.
        const cc = document.getElementById("category-controls");
        const ORDER = ["parser", "webserver", "cryptography", "malware", "firmware"];
        if (cc) {
            cc.innerHTML = ORDER.map(cat => {
                const cnt = proj.filter(p => p.cats.indexOf(cat) >= 0).length;
                return '<button class="ds-btn cat-btn" data-cat="' + cat + '">' +
                    cat + ' (' + cnt + ')</button>';
            }).join("");
            cc.querySelectorAll(".cat-btn").forEach(b => b.addEventListener("click", () => {
                const cat = b.getAttribute("data-cat");
                const turnOn = !b.classList.contains("active");
                cc.querySelectorAll(".cat-btn").forEach(x => x.classList.remove("active"));
                document.querySelectorAll("#dataset-projects tbody tr")
                    .forEach(tr => tr.classList.remove("cat-hl"));
                if (turnOn) {
                    b.classList.add("active");
                    document.querySelectorAll('#dataset-projects tbody tr[data-cats~="' + cat + '"]')
                        .forEach(tr => tr.classList.add("cat-hl"));
                }
            }));
        }
        // Summary.
        const totalLoc = di.total_loc || 0;
        const totalFuncs = proj.reduce((a, p) => a + p.functions, 0);
        const totalBins = proj.reduce((a, p) => a + p.binaries, 0);
        const j = di.joern || {};
        const builds = DATA.groups.length;  // binary × opt-level instances
        const sum = document.getElementById("dataset-summary");
        if (sum) {
            sum.innerHTML = '<div class="goal-body">' +
                '<div><span class="num" style="color:var(--green)">' + proj.length +
                '</span> projects &middot; <strong>' + totalBins.toLocaleString() +
                '</strong> unique binaries &middot; <strong>' + builds.toLocaleString() +
                '</strong> builds (across opt levels) &middot; <strong>' + totalFuncs.toLocaleString() +
                '</strong> function instances</div>' +
                '<div><strong>' + totalLoc.toLocaleString() +
                '</strong> total source lines of code (project .c files)</div>' +
                '</div>';
        }
        // Pipeline health: source-side GED loss, measured from the run itself —
        // a benchmark function has NO source CFG iff no decompiler ever got a GED
        // value for it (source CFGs are decompiler-independent). This is the real
        // share of functions GED can't score because OUR source front-end (Joern)
        // failed or was too slow on the source.
        let srcTotal = 0, srcLost = 0;
        for (const g of DATA.groups) for (const f of g.functions) {
            if (!DATA.decompilers.some(d => decompiledBy(f, d))) continue;
            srcTotal += 1;
            if (!sourceParsed(f)) srcLost += 1;
        }
        const srcPct = srcTotal ? (100 * srcLost / srcTotal) : 0;
        const js = document.getElementById("joern-source");
        if (js) {
            js.innerHTML = '<div class="goal-body"><div class="perfect">' +
                'No source CFG (GED unmeasurable — our source front-end failed/timed out): ' +
                '<strong>' + srcPct.toFixed(1) + '%</strong> of benchmark functions (' +
                srcLost.toLocaleString() + '/' + srcTotal.toLocaleString() +
                '). These are excluded from GED for every decompiler.</div>' +
                (j.files_sampled ? ('<div class="view-desc" style="margin-top:0.3rem;">' +
                    'Direct re-parse spot-check: ' + j.files_failed + '/' + j.files_sampled +
                    ' sampled source files outright failed' +
                    (j.files_timed_out ? (' (' + j.files_timed_out +
                    ' more too slow to finish — the dominant real-world failure mode)') : '') +
                    '.</div>') : '') +
                '</div>';
        }
        // Pipeline health: Joern failures on each decompiler's OUTPUT (corpus-wide).
        const jof = {};
        DATA.decompilers.forEach(d => jof[d] = {failed: 0, scope: 0});
        for (const g of DATA.groups) for (const f of g.functions) {
            if (!sourceParsed(f)) continue;
            for (const d of DATA.decompilers) {
                if (!decompiledBy(f, d)) continue;
                jof[d].scope += 1;
                if (!hasGed(f, d)) jof[d].failed += 1;
            }
        }
        const jt = document.getElementById("joern-output-table");
        if (jt) {
            jt.querySelector("thead tr").innerHTML =
                "<th>decompiler</th><th>Joern failed on output</th>";
            jt.querySelector("tbody").innerHTML = DATA.decompilers.slice().sort((a, b) =>
                (jof[a].scope ? jof[a].failed / jof[a].scope : 0) -
                (jof[b].scope ? jof[b].failed / jof[b].scope : 0)
            ).map(d => {
                const s = jof[d], p = s.scope ? (100 * s.failed / s.scope) : 0;
                return '<tr><td class="lb-name">' + escapeHtml(d) + '</td>' +
                    '<td class="metric-cell"><span class="cell-pct pct-' + errPctClass(p) + '">' +
                    p.toFixed(1) + '%</span> <span class="cell-count">(' + s.failed + '/' +
                    s.scope + ')</span></td></tr>';
            }).join("");
        }
        // Projects table (sorted by LOC desc).
        const tbl = document.getElementById("dataset-projects");
        if (tbl) {
            tbl.querySelector("thead tr").innerHTML =
                "<th>project</th><th>types</th><th>LOC</th><th>binaries</th><th>functions</th>";
            tbl.querySelector("tbody").innerHTML = proj.sort((a, b) => b.loc - a.loc).map(p =>
                '<tr data-cats="' + p.cats.join(" ") + '">' +
                '<td class="lb-name">' + escapeHtml(p.name) + '</td>' +
                '<td class="cell-count">' + (p.cats.join(", ") || "—") + '</td>' +
                '<td>' + (p.loc ? p.loc.toLocaleString() : "—") + '</td>' +
                '<td>' + p.binaries + '</td>' +
                '<td>' + p.functions.toLocaleString() + '</td></tr>'
            ).join("");
        }
    }

    function updateStats(result) {
        const fnEl = document.querySelector('[data-stat="functions"]');
        if (fnEl) fnEl.textContent = result.activeFunctions.toLocaleString();
        const binEl = document.querySelector('[data-stat="binaries"]');
        if (binEl) binEl.textContent = result.activeBins.toLocaleString();
        const counter = document.getElementById("function-counter");
        if (counter) {
            const ds = state.dataset ? ("[" + state.dataset + "] ") : "";
            counter.textContent = ds + result.activeFunctions + " / " + result.totalFunctions + " fns";
        }
    }

    let lastResult = null;
    function refresh() {
        lastResult = recompute();
        buildLeaderboard(lastResult);
        buildMetricsTable(lastResult);
        updateStats(lastResult);
    }

    // ---- Compare view ----
    function sampleLabel(s) {
        return s.project + "/" + s.opt_level + "/" + s.binary + " :: " + s.function;
    }
    function renderCompare() {
        const sel = document.getElementById("cmp-select");
        const body = document.getElementById("compare-body");
        if (!sel || !body) return;
        const idx = parseInt(sel.value, 10);
        const samples = DATA.samples || [];
        const s = samples[idx];
        if (!s) { body.innerHTML = '<p class="view-desc">no sample selected.</p>'; return; }
        const decs = Object.keys(s.decompiled || {});
        const cols = (s.source_code ? 1 : 0) + decs.length;
        let html = '<div class="cmp-meta">' + escapeHtml(s.project) + '/' +
            escapeHtml(s.opt_level) + '/' + escapeHtml(s.binary) +
            ' &middot; ' + escapeHtml(s.function) +
            (s.size != null ? (' &middot; ' + s.size + ' lines') : '') +
            (s.labels && s.labels.length ? (' &middot; ' + escapeHtml(s.labels.join(", "))) : '') +
            '</div>';
        html += '<div class="cmp-grid" style="grid-template-columns:repeat(' +
            Math.max(1, cols) + ',minmax(0,1fr));">';
        if (s.source_code) {
            html += '<div class="cmp-col src"><h4>source (ground truth)</h4>' +
                '<pre><code>' + escapeHtml(s.source_code) + '</code></pre></div>';
        }
        for (const d of decs) {
            const vals = (s.values && s.values[d]) || {};
            const perf = (s.perfects && s.perfects[d]) || {};
            let scores = "";
            for (const m of DATA.metrics) {
                if (!(m in vals)) continue;
                const ok = perf[m] ? "pct-high" : "pct-low";
                scores += '<span class="sc ' + ok + '">' + (METRIC_SHORT[m] || m) +
                    ' ' + Number(vals[m]).toFixed(2) + '</span>';
            }
            html += '<div class="cmp-col"><h4>' + escapeHtml(d) + '</h4>' +
                '<div class="cmp-scores">' + (scores || '&mdash;') + '</div>' +
                '<pre><code>' + escapeHtml(s.decompiled[d]) + '</code></pre></div>';
        }
        html += '</div>';
        body.innerHTML = html;
    }
    function populateCompare() {
        const sel = document.getElementById("cmp-select");
        const filter = document.getElementById("cmp-filter");
        const counter = document.getElementById("cmp-counter");
        if (!sel) return;
        const samples = DATA.samples || [];
        function fill() {
            const q = (filter && filter.value || "").toLowerCase();
            sel.innerHTML = "";
            let shown = 0;
            samples.forEach((s, i) => {
                const label = sampleLabel(s);
                if (q && label.toLowerCase().indexOf(q) < 0) return;
                const o = document.createElement("option");
                o.value = i; o.textContent = label;
                sel.appendChild(o); shown += 1;
            });
            if (counter) counter.textContent = shown + " / " + samples.length + " samples";
            renderCompare();
        }
        sel.addEventListener("change", renderCompare);
        if (filter) filter.addEventListener("input", fill);
        fill();
    }

    // ---- Hardest view ----
    function renderHardest() {
        const list = document.getElementById("hardest-list");
        if (!list) return;
        const entries = DATA.hardest || [];
        const mSel = document.getElementById("hard-metric");
        const dSel = document.getElementById("hard-dec");
        const mFilter = mSel ? mSel.value : "__all__";
        const dFilter = dSel ? dSel.value : "__all__";
        let shown = 0, html = "";
        for (const e of entries) {
            if (mFilter !== "__all__" && e.metric !== mFilter) continue;
            if (dFilter !== "__all__" && e.decompiler !== dFilter) continue;
            shown += 1;
            const metricLabel = METRIC_NAMES[e.metric] || e.metric;
            const sizeStr = (e.size != null) ? (e.size + " lines") : "? lines";
            html += '<div class="hard-entry">';
            html += '<div class="hard-head"><span class="fn">' + escapeHtml(e.function) +
                '</span> &middot; ' + escapeHtml(e.decompiler) + ' &middot; ' +
                escapeHtml(metricLabel) + '</div>';
            html += '<div class="hard-meta"><span class="tag">' + escapeHtml(e.project) + '/' +
                escapeHtml(e.opt_level) + '/' + escapeHtml(e.binary) + '</span>' +
                '<span class="tag score-bad">score ' + Number(e.value).toFixed(3) +
                ' (perfect ' + Number(e.perfect_value).toFixed(3) + ')</span>' +
                '<span class="tag">' + escapeHtml(sizeStr) + '</span></div>';
            const cols = (e.decompiled_code ? 1 : 0) + (e.source_code ? 1 : 0);
            html += '<div class="cmp-grid" style="grid-template-columns:repeat(' +
                Math.max(1, cols) + ',minmax(0,1fr));">';
            if (e.decompiled_code) {
                html += '<div class="cmp-col"><h4>' + escapeHtml(e.decompiler) +
                    '</h4><pre><code>' + escapeHtml(e.decompiled_code) + '</code></pre></div>';
            }
            if (e.source_code) {
                html += '<div class="cmp-col src"><h4>source</h4><pre><code>' +
                    escapeHtml(e.source_code) + '</code></pre></div>';
            }
            html += '</div></div>';
        }
        if (shown === 0) html = '<p class="view-desc">no entries match the current filter.</p>';
        list.innerHTML = html;
        const counter = document.getElementById("hard-counter");
        if (counter) counter.textContent = "showing " + shown + " / " + entries.length;
    }
    function initHardest() {
        const entries = DATA.hardest || [];
        if (!entries.length) return;
        const mSel = document.getElementById("hard-metric"), dSel = document.getElementById("hard-dec");
        if (!mSel || !dSel) return;
        const metrics = [], decs = [];
        for (const e of entries) {
            if (metrics.indexOf(e.metric) < 0) metrics.push(e.metric);
            if (decs.indexOf(e.decompiler) < 0) decs.push(e.decompiler);
        }
        metrics.sort(); decs.sort();
        for (const m of metrics) {
            const o = document.createElement("option");
            o.value = m; o.textContent = METRIC_NAMES[m] || m; mSel.appendChild(o);
        }
        for (const d of decs) {
            const o = document.createElement("option");
            o.value = d; o.textContent = d; dSel.appendChild(o);
        }
        mSel.addEventListener("change", renderHardest);
        dSel.addEventListener("change", renderHardest);
        renderHardest();
    }

    // ---- Historical (SVG) ----
    const CHART_COLORS = ["#6ab04c","#4a90d9","#d4a72c","#c0504d","#9b59b6","#1abc9c","#e67e22","#7f8c8d","#e84393","#00cec9"];
    function baseName(dec) { const a = dec.indexOf("@"); return a >= 0 ? dec.substring(0, a) : dec; }
    function svgEl(tag, attrs) {
        const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
        for (const k in attrs) el.setAttribute(k, attrs[k]);
        return el;
    }
    function buildChart(container, metricKey, title) {
        const history = DATA.history || [];
        const versions = [];
        for (const h of history) if (versions.indexOf(h.version) < 0) versions.push(h.version);
        const lines = {};
        for (const h of history) {
            const bn = baseName(h.decompiler);
            let val = metricKey === "__overall__" ? h.overall :
                (h.scores && (metricKey in h.scores) ? h.scores[metricKey] : null);
            if (val == null) continue;
            if (!lines[bn]) lines[bn] = {};
            lines[bn][h.version] = val;
        }
        const decNames = Object.keys(lines).sort();
        if (!decNames.length || versions.length < 1) return;
        const block = document.createElement("div");
        block.className = "chart-block";
        const h3 = document.createElement("h3"); h3.textContent = title; block.appendChild(h3);
        const W = 760, H = 280, padL = 46, padR = 16, padT = 14, padB = 40;
        const plotW = W - padL - padR, plotH = H - padT - padB;
        const svg = svgEl("svg", {viewBox: "0 0 " + W + " " + H, width: W, height: H, role: "img"});
        const xFor = i => versions.length === 1 ? padL + plotW / 2 : padL + (plotW * i) / (versions.length - 1);
        const yFor = v => padT + plotH - (plotH * Math.max(0, Math.min(v, 100)) / 100);
        for (let g = 0; g <= 100; g += 25) {
            const y = yFor(g);
            svg.appendChild(svgEl("line", {x1: padL, y1: y, x2: W - padR, y2: y, stroke: "#333", "stroke-width": 1, "stroke-dasharray": "3 3"}));
            const lbl = svgEl("text", {x: padL - 6, y: y + 4, "text-anchor": "end", fill: "#8a8a8a", "font-size": 11, "font-family": "Source Code Pro, monospace"});
            lbl.textContent = g + "%"; svg.appendChild(lbl);
        }
        svg.appendChild(svgEl("line", {x1: padL, y1: padT, x2: padL, y2: padT + plotH, stroke: "#666", "stroke-width": 1}));
        svg.appendChild(svgEl("line", {x1: padL, y1: padT + plotH, x2: W - padR, y2: padT + plotH, stroke: "#666", "stroke-width": 1}));
        for (let i = 0; i < versions.length; i++) {
            const t = svgEl("text", {x: xFor(i), y: padT + plotH + 18, "text-anchor": "middle", fill: "#8a8a8a", "font-size": 11, "font-family": "Source Code Pro, monospace"});
            t.textContent = versions[i]; svg.appendChild(t);
        }
        const colorByDec = {};
        decNames.forEach((dn, idx) => {
            const color = CHART_COLORS[idx % CHART_COLORS.length];
            colorByDec[dn] = color;
            const pts = [];
            for (let i = 0; i < versions.length; i++) {
                const v = lines[dn][versions[i]];
                if (v == null) continue;
                const x = xFor(i), y = yFor(v);
                pts.push(x + "," + y);
                svg.appendChild(svgEl("circle", {cx: x, cy: y, r: 3, fill: color}));
            }
            if (pts.length >= 2) svg.appendChild(svgEl("polyline", {points: pts.join(" "), fill: "none", stroke: color, "stroke-width": 2}));
        });
        block.appendChild(svg);
        const legend = document.createElement("div"); legend.className = "legend";
        for (const dn of decNames) {
            const span = document.createElement("span"); span.className = "item";
            const sw = document.createElement("span"); sw.className = "swatch"; sw.style.background = colorByDec[dn];
            span.appendChild(sw); span.appendChild(document.createTextNode(dn)); legend.appendChild(span);
        }
        block.appendChild(legend); container.appendChild(block);
    }
    function initHistory() {
        const container = document.getElementById("history-charts");
        if (!container || !(DATA.history || []).length) return;
        for (const m of (DATA.metrics || [])) buildChart(container, m, METRIC_NAMES[m] || m);
        buildChart(container, "__overall__", "Overall (perfect on all metrics)");
    }

    // ---- View routing ----
    function showView(name) {
        state.view = name;
        document.querySelectorAll(".view").forEach(v => {
            v.classList.toggle("active", v.getAttribute("data-view") === name);
        });
        document.querySelectorAll(".nav-item").forEach(a => {
            a.classList.toggle("active", a.getAttribute("data-view") === name);
        });
    }
    function initNav() {
        document.querySelectorAll(".nav-item").forEach(a => {
            a.addEventListener("click", e => {
                e.preventDefault();
                showView(a.getAttribute("data-view"));
            });
        });
        const initial = (location.hash || "").replace("#", "");
        const valid = Array.from(document.querySelectorAll(".view")).map(v => v.getAttribute("data-view"));
        showView(valid.indexOf(initial) >= 0 ? initial : "leaderboard");
    }

    function setDatasetDesc() {
        const el = document.getElementById("dataset-desc");
        if (!el) return;
        const p = PRESETS.filter(x => x.name === state.dataset)[0];
        el.textContent = p ? p.description : "";
    }
    function initDatasetSelector() {
        // Only the preset buttons carry data-dataset (the normalize toggle does not).
        const btns = document.querySelectorAll(".ds-btn[data-dataset]");
        btns.forEach(b => b.addEventListener("click", () => {
            state.dataset = b.getAttribute("data-dataset");
            btns.forEach(x => x.classList.remove("active"));
            b.classList.add("active");
            setDatasetDesc();
            refresh();
        }));
        setDatasetDesc();
        // "normalize failures": restrict to functions every decompiler decompiled.
        const nb = document.getElementById("normalize-btn");
        if (nb) nb.addEventListener("click", () => {
            state.normalize = !state.normalize;
            nb.classList.toggle("active", state.normalize);
            refresh();
        });
    }

    function init() {
        initNav();
        initDatasetSelector();
        refresh();
        buildDataset();
        populateCompare();
        initHardest();
        initHistory();
    }
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
    </script>"""
