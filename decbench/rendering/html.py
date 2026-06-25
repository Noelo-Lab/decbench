"""HTML report renderer for DecBench results.

Re-skinned to the mahaloz.re terminal aesthetic (pure-black bg, Source Code Pro
monospace, dashed rules, Unix-path nav, dash-prefixed lists, ASCII-ish bars).
All existing interactivity is preserved verbatim — label chips + per-binary
toggles live-recompute the comparison matrix, per-binary breakdown, ranking
tables, and stats. Two new views are added: a "Hardest Functions" hall of shame
and a "Historical" view of per-metric line charts rendered as inline SVG in JS.
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


def render_html_report(
    scoreboard: Scoreboard,
    output_path: Path,
    function_data: FunctionData | None = None,
) -> None:
    """Render a self-contained HTML report from scoreboard data.

    Generates sections for:
    1. Overall - functions perfect on ALL metrics
    2. Each individual metric

    When ``function_data`` is provided, the report additionally embeds the
    per-function dataset and interactive client-side filtering controls, plus
    the Hardest Functions and Historical views.

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
    metric_sections = ""
    for metric_name in scoreboard.metrics:
        metric_sections += _build_metric_section(scoreboard, metric_name)

    overall_section = _build_overall_section(scoreboard)

    if function_data is None:
        banner = (
            '<div class="banner" id="no-data-banner">'
            "[ note ] interactive filtering unavailable: per-function data "
            "(function_results.json) not found."
            "</div>"
        )
        interactive_sections = ""
        hardest_section = ""
        history_section = ""
        script = ""
        nav = _build_nav(has_extras=False)
    else:
        banner = ""
        interactive_sections = (
            _build_filters_section(function_data)
            + _build_comparison_matrix_section(function_data)
            + _build_per_binary_section(function_data)
        )
        hardest_section = _build_hardest_section(function_data)
        history_section = _build_history_section(function_data)
        script = _build_script(function_data)
        nav = _build_nav(has_extras=True)

    date_str = scoreboard.generated_at.strftime("%Y-%m-%d")
    time_str = scoreboard.generated_at.strftime("%H:%M")

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
    <div class="container">
        <header>
            <div class="prompt">$ decbench report --scoreboard {html_escape(scoreboard.name)}</div>
            <h1>{html_escape(scoreboard.name)}</h1>
            <div class="subtitle">
                [ {date_str} {time_str} ]
                &middot; projects: {html_escape(', '.join(scoreboard.projects_evaluated) or '-')}
                &middot; opt: {html_escape(', '.join(scoreboard.optimization_levels) or '-')}
            </div>
            {nav}
        </header>

        <div class="rule"></div>

        {banner}

        <div class="stats">
            <span class="stat"><span class="stat-value" data-stat="functions">{scoreboard.total_functions:,}</span> functions</span>
            <span class="sep">&middot;</span>
            <span class="stat"><span class="stat-value" data-stat="binaries">{scoreboard.total_binaries:,}</span> binaries</span>
            <span class="sep">&middot;</span>
            <span class="stat"><span class="stat-value">{len(scoreboard.decompilers)}</span> decompilers</span>
            <span class="sep">&middot;</span>
            <span class="stat"><span class="stat-value">{len(scoreboard.metrics)}</span> metrics</span>
        </div>

        {interactive_sections}
        {overall_section}
        {metric_sections}
        {hardest_section}
        {history_section}

        <div class="rule"></div>
        <footer>
            DecBench v{html_escape(str(scoreboard.version))} &mdash; decompiler benchmarking suite
            &middot; [ {date_str} ]
        </footer>
    </div>
    {script}
</body>
</html>"""


def _build_nav(has_extras: bool) -> str:
    """Build the Unix-path style nav bar."""
    links = [
        ('#overall', '/decbench'),
        ('#metrics', '/metrics'),
    ]
    if has_extras:
        links.append(('#hardest', '/hardest'))
        links.append(('#history', '/history'))
    inner = " ".join(
        f'<a href="{href}">{html_escape(label)}</a>' for href, label in links
    )
    return f'<nav class="nav">{inner}</nav>'


def _build_css() -> str:
    """Return the full terminal-aesthetic stylesheet."""
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
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html { background: var(--bg); }
        body {
            font-family: "Source Code Pro", ui-monospace, Menlo, Consolas, monospace;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
            font-size: 15px;
            padding: 2rem 1rem 3rem;
        }
        .container { width: 90%; max-width: 850px; margin: 0 auto; }
        a {
            color: var(--text);
            text-decoration: none;
            border-bottom: 1px dotted var(--border-color);
        }
        a:hover { color: #000; background: var(--text); border-bottom-color: transparent; }
        .rule {
            border: none;
            border-top: dashed 1px var(--border-color);
            margin: 1.4rem 0;
            height: 0;
        }
        header { margin-bottom: 0.4rem; }
        .prompt { color: var(--text-muted); font-size: 0.85em; margin-bottom: 0.4rem; }
        h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.4rem; }
        .subtitle { color: var(--text-muted); font-size: 0.85em; margin-bottom: 0.6rem; }
        .nav { font-size: 0.9em; }
        .nav a { margin-right: 0.6rem; border-bottom: none; }
        .nav a:hover { color: #000; background: var(--text); }
        .banner {
            border: dashed 1px var(--amber);
            color: var(--amber);
            padding: 0.6rem 0.9rem;
            margin: 1rem 0;
            font-size: 0.9em;
        }
        .stats { font-size: 0.95em; margin: 0.6rem 0 0.4rem; }
        .stats .sep { color: var(--text-muted); margin: 0 0.3rem; }
        .stat-value { font-weight: 700; }
        .section { margin: 1.6rem 0; }
        .section h2 {
            font-size: 1.05rem;
            font-weight: 700;
            margin-bottom: 0.2rem;
        }
        .section h2:before { content: "## "; color: var(--text-muted); }
        .section .desc {
            color: var(--text-muted);
            font-size: 0.85em;
            margin-bottom: 0.8rem;
        }
        .section.overall h2 { color: var(--green); }
        table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
        th, td {
            text-align: left;
            padding: 0.35rem 0.7rem 0.35rem 0;
            border-bottom: dashed 1px rgba(219, 219, 219, 0.25);
            vertical-align: middle;
        }
        th {
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.85em;
            border-bottom: dashed 1px var(--border-color);
        }
        tr:last-child td { border-bottom: none; }
        .rank { color: var(--text-muted); width: 3.5em; }
        .bar-ascii {
            color: var(--text-muted);
            white-space: pre;
            letter-spacing: -0.02em;
        }
        .pct { font-weight: 700; text-align: right; white-space: nowrap; }
        .pct-high { color: var(--green); }
        .pct-mid { color: var(--amber); }
        .pct-low { color: var(--red); }
        .counts { color: var(--text-muted); font-size: 0.85em; text-align: right; }
        .chips { margin-bottom: 0.6rem; }
        .chip {
            display: inline-block;
            border: dashed 1px var(--border-color);
            padding: 0.1rem 0.5rem;
            margin: 0 0.3rem 0.3rem 0;
            font-size: 0.85em;
            cursor: pointer;
            user-select: none;
        }
        .chip:hover { color: #000; background: var(--text); }
        .chip input { cursor: pointer; vertical-align: middle; margin-right: 0.3rem; }
        details { margin: 0.6rem 0; }
        details summary {
            cursor: pointer;
            color: var(--text-muted);
            font-size: 0.85em;
            margin-bottom: 0.4rem;
        }
        .binary-list label {
            display: block;
            font-size: 0.85em;
            padding: 0.05rem 0;
        }
        .binary-list label:before { content: "- "; color: var(--text-muted); }
        .controls {
            display: flex;
            align-items: center;
            gap: 0.8rem;
            margin: 0.6rem 0;
            flex-wrap: wrap;
            font-size: 0.9em;
        }
        button, select, input[type=text] {
            background: var(--bg);
            border: dashed 1px var(--border-color);
            color: var(--text);
            padding: 0.25rem 0.7rem;
            cursor: pointer;
            font-family: inherit;
            font-size: 0.9em;
        }
        button:hover, select:hover { color: #000; background: var(--text); }
        .counter { color: var(--text-muted); font-size: 0.9em; }
        .ul-dash { list-style: none; padding: 0; }
        .ul-dash li { padding: 0.1rem 0; }
        .ul-dash li:before { content: "- "; color: var(--text-muted); }
        pre {
            background: var(--code-bg);
            border: 0.1em solid var(--code-border);
            box-shadow: inset 0 0 0.4em rgba(0, 0, 0, 0.8);
            padding: 0.7rem 0.9rem;
            overflow-x: auto;
            margin: 0.5rem 0;
            font-size: 0.85em;
            line-height: 1.45;
        }
        pre code {
            font-family: Consolas, "Source Code Pro", monospace;
            color: var(--text);
            white-space: pre;
        }
        .code-label {
            color: var(--text-muted);
            font-size: 0.8em;
            margin: 0.6rem 0 0.1rem;
        }
        /* Hardest functions */
        .hard-entry {
            border: dashed 1px rgba(219, 219, 219, 0.4);
            padding: 0.7rem 0.9rem;
            margin: 0.9rem 0;
        }
        .hard-head { font-size: 0.92em; margin-bottom: 0.2rem; }
        .hard-head .fn { font-weight: 700; }
        .hard-meta { color: var(--text-muted); font-size: 0.82em; margin-bottom: 0.3rem; }
        .hard-meta .tag { margin-right: 0.6rem; }
        .hard-meta .score-bad { color: var(--red); }
        /* Historical charts */
        .chart-block { margin: 1.2rem 0; }
        .chart-block h3 { font-size: 0.95em; font-weight: 600; margin-bottom: 0.3rem; }
        .chart-block h3:before { content: "> "; color: var(--text-muted); }
        svg { display: block; max-width: 100%; }
        .legend { font-size: 0.82em; color: var(--text-muted); margin-top: 0.3rem; }
        .legend .item { margin-right: 1rem; white-space: nowrap; }
        .legend .swatch {
            display: inline-block; width: 1.4em; height: 0.5em;
            vertical-align: middle; margin-right: 0.3rem;
        }
        footer { color: var(--text-muted); font-size: 0.85em; }"""


def _ascii_bar(pct: float, width: int = 12) -> str:
    """Build an ASCII ``[####----]`` bar for a percentage."""
    p = max(0.0, min(pct, 100.0))
    filled = int(round((p / 100.0) * width))
    filled = max(0, min(filled, width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _pct_class(pct: float) -> str:
    if pct >= 50:
        return "high"
    elif pct >= 20:
        return "mid"
    return "low"


def _build_ranking_table(
    rankings: list[tuple[str, float]],
    scoreboard: Scoreboard,
    metric_name: str | None = None,
) -> str:
    """Build an HTML table for rankings."""
    rows = ""
    metric_attr = metric_name if metric_name is not None else "__overall__"
    for rank, (dec_name, pct) in enumerate(rankings, 1):
        cls = _pct_class(pct)

        # Get count info if available
        count_str = ""
        if metric_name and dec_name in scoreboard.decompiler_scores:
            ms = scoreboard.decompiler_scores[dec_name].metric_scores.get(metric_name)
            if ms:
                count_str = f"{ms.perfect_count}/{ms.total_count}"
        elif metric_name is None and dec_name in scoreboard.decompiler_scores:
            ds = scoreboard.decompiler_scores[dec_name]
            count_str = f"{ds.overall_perfect_count}/{ds.overall_total_count}"

        esc_dec = html_escape(dec_name)
        bar = _ascii_bar(pct)
        rows += f"""
        <tr data-ranking-row="{html_escape(metric_attr)}" data-decompiler="{esc_dec}">
            <td class="rank">#{rank}</td>
            <td>{esc_dec}</td>
            <td class="bar-ascii" data-bar="1">{bar}</td>
            <td class="pct pct-{cls}" data-pct="1">{pct:.1f}%</td>
            <td class="counts" data-count="1">{count_str}</td>
        </tr>"""

    return f"""
    <table>
        <thead>
            <tr>
                <th>rank</th>
                <th>decompiler</th>
                <th>progress</th>
                <th>perfect %</th>
                <th>count</th>
            </tr>
        </thead>
        <tbody>{rows}
        </tbody>
    </table>"""


def _build_overall_section(scoreboard: Scoreboard) -> str:
    rankings = scoreboard.get_overall_rankings()
    if not rankings:
        return ""

    table = _build_ranking_table(rankings, scoreboard)
    return f"""
    <div class="section overall" id="overall">
        <h2>Overall &mdash; perfect on all metrics</h2>
        <p class="desc">
            functions where the decompiler achieves a 100% match on
            all three metrics (GED, type, bytematch).
        </p>
        {table}
    </div>"""


def _build_metric_section(scoreboard: Scoreboard, metric_name: str) -> str:
    rankings = scoreboard.get_metric_rankings(metric_name)
    if not rankings:
        return ""

    display_name = METRIC_DISPLAY_NAMES.get(metric_name, metric_name)
    table = _build_ranking_table(rankings, scoreboard, metric_name)

    # Anchor the first metric section so /metrics nav lands somewhere.
    anchor = ' id="metrics"' if metric_name == scoreboard.metrics[0] else ""
    return f"""
    <div class="section"{anchor}>
        <h2>{html_escape(display_name)}</h2>
        {table}
    </div>"""


def _distinct_labels(function_data: FunctionData) -> list[str]:
    """Return all distinct labels across binaries and functions, order-stable."""
    seen: set[str] = set()
    result: list[str] = []
    for group in function_data.groups:
        for label in group.labels:
            if label not in seen:
                seen.add(label)
                result.append(label)
        for func in group.functions:
            for label in func.labels:
                if label not in seen:
                    seen.add(label)
                    result.append(label)
    return result


def _build_filters_section(function_data: FunctionData) -> str:
    """Build the filter chips, per-binary toggles, and counter."""
    labels = _distinct_labels(function_data)
    chips = ""
    for label in labels:
        # Escape user-supplied strings: the attribute value must survive HTML
        # parsing intact so dataset.label matches the JSON-carried labels.
        esc = html_escape(label)
        chips += (
            f'<label class="chip"><input type="checkbox" data-label="{esc}" '
            f"checked> {esc}</label>"
        )

    binary_checks = ""
    for group in function_data.groups:
        key = f"{group.project}/{group.opt_level}/{group.binary}"
        esc = html_escape(key)
        binary_checks += (
            f'<label><input type="checkbox" data-binary="{esc}" checked> '
            f"{esc}</label>"
        )

    return f"""
    <div class="section" id="filters">
        <h2>filters</h2>
        <div class="chips">{chips}</div>
        <details>
            <summary>per-binary toggles</summary>
            <div class="binary-list">{binary_checks}</div>
        </details>
        <div class="controls">
            <button id="reset-filters">reset</button>
            <span class="counter" id="function-counter"></span>
        </div>
    </div>"""


def _build_comparison_matrix_section(function_data: FunctionData) -> str:
    """Build the metric x decompiler comparison matrix (filled by JS)."""
    return """
    <div class="section" id="comparison-matrix">
        <h2>comparison matrix</h2>
        <table>
            <thead>
                <tr><th>metric</th></tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>"""


def _build_per_binary_section(function_data: FunctionData) -> str:
    """Build the per-binary breakdown with a metric selector (filled by JS)."""
    return """
    <div class="section" id="per-binary-breakdown">
        <h2>per-binary breakdown</h2>
        <div class="controls">
            <label class="counter" for="breakdown-metric">metric:</label>
            <select id="breakdown-metric"></select>
        </div>
        <table>
            <thead>
                <tr><th>binary</th></tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>"""


def _build_hardest_section(function_data: FunctionData) -> str:
    """Build the Hardest Functions 'hall of shame' (filtered client-side)."""
    if not function_data.hardest:
        return """
    <div class="section" id="hardest">
        <h2>hardest functions &mdash; hall of shame</h2>
        <p class="desc">
            no hardest-function data was attached to this report.
        </p>
    </div>"""

    return """
    <div class="section" id="hardest">
        <h2>hardest functions &mdash; hall of shame</h2>
        <p class="desc">
            the functions decompilers struggled with most (farthest from the
            metric's perfect value), with their decompiled output.
        </p>
        <div class="controls">
            <label class="counter" for="hard-metric">metric:</label>
            <select id="hard-metric"><option value="__all__">all</option></select>
            <label class="counter" for="hard-dec">decompiler:</label>
            <select id="hard-dec"><option value="__all__">all</option></select>
            <span class="counter" id="hard-counter"></span>
        </div>
        <div id="hardest-list"></div>
    </div>"""


def _build_history_section(function_data: FunctionData) -> str:
    """Build the Historical view container (charts drawn by JS)."""
    if not function_data.history:
        return """
    <div class="section" id="history">
        <h2>historical</h2>
        <p class="desc">
            this view shows how each decompiler's metric scores change across
            versions. it appears once &ge;2 versions have been benchmarked.
        </p>
    </div>"""

    return """
    <div class="section" id="history">
        <h2>historical</h2>
        <p class="desc">
            per-metric perfect % across decompiler versions (x = version order,
            y = perfect %, one line per decompiler).
        </p>
        <div id="history-charts"></div>
    </div>"""


def _build_script(function_data: FunctionData) -> str:
    """Build the inline <script> that powers interactive recomputation."""
    # Escape "<" to avoid breaking out of the <script> element.
    data_json = json.dumps(function_data.model_dump(mode="json")).replace(
        "<", "\\u003c"
    )

    js = """
    <script>
    const DATA = __DATA__;
    const METRIC_NAMES = {
        "ged": "Structural Correctness (GED)",
        "type_match": "Type Correctness",
        "byte_match": "Recompilation Bytematch"
    };
    const state = {
        disabledLabels: new Set(),
        disabledBinaries: new Set()
    };

    function binaryKey(g) {
        return g.project + "/" + g.opt_level + "/" + g.binary;
    }

    function isActive(group, func) {
        if (state.disabledBinaries.has(binaryKey(group))) return false;
        for (const label of func.labels) {
            if (state.disabledLabels.has(label)) return false;
        }
        return true;
    }

    function pctClass(pct) {
        if (pct >= 50) return "high";
        if (pct >= 20) return "mid";
        return "low";
    }

    function asciiBar(pct, width) {
        width = width || 12;
        let p = Math.max(0, Math.min(pct, 100));
        let filled = Math.round((p / 100) * width);
        filled = Math.max(0, Math.min(filled, width));
        return "[" + "#".repeat(filled) + "-".repeat(width - filled) + "]";
    }

    // Recompute per (decompiler, metric) perfect counts plus Overall over
    // active functions only, mirroring scoring/scoreboard.py semantics.
    function recompute() {
        const decs = DATA.decompilers;
        const metrics = DATA.metrics;

        // dec -> metric -> {perfect, total}
        const perMetric = {};
        // dec -> {perfect, total}
        const overall = {};
        for (const d of decs) {
            perMetric[d] = {};
            for (const m of metrics) perMetric[d][m] = {perfect: 0, total: 0};
            overall[d] = {perfect: 0, total: 0};
        }

        // binKey -> dec -> metric -> {perfect, total}
        const perBinary = {};
        let activeFunctions = 0;
        let totalFunctions = 0;

        for (const group of DATA.groups) {
            const bk = binaryKey(group);
            perBinary[bk] = {};
            for (const d of decs) {
                perBinary[bk][d] = {};
                for (const m of metrics) {
                    perBinary[bk][d][m] = {perfect: 0, total: 0};
                }
                perBinary[bk][d].__overall__ = {perfect: 0, total: 0};
            }

            for (const func of group.functions) {
                totalFunctions += 1;
                if (!isActive(group, func)) continue;
                activeFunctions += 1;

                for (const d of decs) {
                    const fperf = func.perfects[d];
                    if (!fperf) continue;

                    for (const m of metrics) {
                        if (!(m in fperf)) continue;
                        perMetric[d][m].total += 1;
                        perBinary[bk][d][m].total += 1;
                        if (fperf[m]) {
                            perMetric[d][m].perfect += 1;
                            perBinary[bk][d][m].perfect += 1;
                        }
                    }

                    // Overall: perfect on EVERY metric in DATA.metrics that
                    // appears in perfects[d], AND all DATA.metrics present.
                    let hasAll = true;
                    let allPerfect = true;
                    for (const m of metrics) {
                        if (!(m in fperf)) { hasAll = false; break; }
                        if (!fperf[m]) allPerfect = false;
                    }
                    overall[d].total += 1;
                    perBinary[bk][d].__overall__.total += 1;
                    if (hasAll && allPerfect) {
                        overall[d].perfect += 1;
                        perBinary[bk][d].__overall__.perfect += 1;
                    }
                }
            }
        }

        return {perMetric, overall, perBinary, activeFunctions, totalFunctions};
    }

    function pct(cell) {
        return cell.total > 0 ? (cell.perfect / cell.total) * 100 : 0;
    }

    function cellHtml(cell) {
        const p = pct(cell);
        const cls = pctClass(p);
        return '<span class="bar-ascii">' + asciiBar(p, 10) + '</span> ' +
            '<span class="pct-' + cls + '">' +
            p.toFixed(1) + '% (' + cell.perfect + '/' + cell.total + ')</span>';
    }

    function buildMatrix(result) {
        const decs = DATA.decompilers;
        const metrics = DATA.metrics;
        const tbl = document.querySelector("#comparison-matrix table");
        const thead = tbl.querySelector("thead tr");
        thead.innerHTML = "<th>metric</th>";
        for (const d of decs) {
            const th = document.createElement("th");
            th.textContent = d;
            thead.appendChild(th);
        }
        const tbody = tbl.querySelector("tbody");
        tbody.innerHTML = "";
        const rows = metrics.slice();
        rows.push("__overall__");
        for (const m of rows) {
            const tr = document.createElement("tr");
            const label = m === "__overall__"
                ? "Overall" : (METRIC_NAMES[m] || m);
            const tdName = document.createElement("td");
            tdName.textContent = label;
            tr.appendChild(tdName);
            for (const d of decs) {
                const td = document.createElement("td");
                const cell = m === "__overall__"
                    ? result.overall[d] : result.perMetric[d][m];
                td.innerHTML = cellHtml(cell);
                tr.appendChild(td);
            }
            tbody.appendChild(tr);
        }
    }

    function buildPerBinary(result) {
        const decs = DATA.decompilers;
        const sel = document.getElementById("breakdown-metric");
        const metric = sel.value || "__overall__";
        const tbl = document.querySelector("#per-binary-breakdown table");
        const thead = tbl.querySelector("thead tr");
        thead.innerHTML = "<th>binary</th>";
        for (const d of decs) {
            const th = document.createElement("th");
            th.textContent = d;
            thead.appendChild(th);
        }
        const tbody = tbl.querySelector("tbody");
        tbody.innerHTML = "";
        for (const group of DATA.groups) {
            const bk = binaryKey(group);
            if (state.disabledBinaries.has(bk)) continue;
            const tr = document.createElement("tr");
            const tdName = document.createElement("td");
            tdName.textContent = bk;
            tr.appendChild(tdName);
            for (const d of decs) {
                const td = document.createElement("td");
                const cell = result.perBinary[bk][d][metric];
                td.innerHTML = cellHtml(cell);
                tr.appendChild(td);
            }
            tbody.appendChild(tr);
        }
    }

    function updateRankingTables(result) {
        const decs = DATA.decompilers;
        const metrics = DATA.metrics;
        const targets = metrics.slice();
        targets.push("__overall__");
        for (const m of targets) {
            for (const d of decs) {
                const row = document.querySelector(
                    'tr[data-ranking-row="' + m + '"][data-decompiler="' +
                    d + '"]');
                if (!row) continue;
                const cell = m === "__overall__"
                    ? result.overall[d] : result.perMetric[d][m];
                const p = pct(cell);
                const cls = pctClass(p);
                const bar = row.querySelector('[data-bar]');
                if (bar) {
                    bar.textContent = asciiBar(p, 12);
                }
                const pctEl = row.querySelector('[data-pct]');
                if (pctEl) {
                    pctEl.className = "pct pct-" + cls;
                    pctEl.textContent = p.toFixed(1) + "%";
                }
                const cnt = row.querySelector('[data-count]');
                if (cnt) cnt.textContent = cell.perfect + "/" + cell.total;
            }
        }
    }

    function updateStats(result) {
        const fnEl = document.querySelector('[data-stat="functions"]');
        if (fnEl) fnEl.textContent = result.activeFunctions.toLocaleString();
        const binEl = document.querySelector('[data-stat="binaries"]');
        if (binEl) {
            let active = 0;
            for (const group of DATA.groups) {
                if (!state.disabledBinaries.has(binaryKey(group))) active += 1;
            }
            binEl.textContent = active.toLocaleString();
        }
    }

    function refresh() {
        const result = recompute();
        buildMatrix(result);
        buildPerBinary(result);
        updateRankingTables(result);
        updateStats(result);
        const counter = document.getElementById("function-counter");
        if (counter) {
            counter.textContent = "showing " + result.activeFunctions +
                " / " + result.totalFunctions + " functions";
        }
    }

    // ---- Hardest Functions view -----------------------------------------
    function escapeHtml(s) {
        return (s == null ? "" : String(s))
            .replace(/&/g, "&amp;").replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
    }

    function renderHardest() {
        const list = document.getElementById("hardest-list");
        if (!list) return;
        const entries = DATA.hardest || [];
        const mSel = document.getElementById("hard-metric");
        const dSel = document.getElementById("hard-dec");
        const mFilter = mSel ? mSel.value : "__all__";
        const dFilter = dSel ? dSel.value : "__all__";

        let shown = 0;
        let html = "";
        for (const e of entries) {
            if (mFilter !== "__all__" && e.metric !== mFilter) continue;
            if (dFilter !== "__all__" && e.decompiler !== dFilter) continue;
            shown += 1;
            const metricLabel = METRIC_NAMES[e.metric] || e.metric;
            const sizeStr = (e.size != null) ? (e.size + " lines") : "? lines";
            html += '<div class="hard-entry">';
            html += '<div class="hard-head"><span class="fn">' +
                escapeHtml(e.function) + '</span> &middot; ' +
                escapeHtml(e.decompiler) + ' &middot; ' +
                escapeHtml(metricLabel) + '</div>';
            html += '<div class="hard-meta">' +
                '<span class="tag">' + escapeHtml(e.project) + '/' +
                escapeHtml(e.opt_level) + '/' + escapeHtml(e.binary) + '</span>' +
                '<span class="tag score-bad">score ' +
                Number(e.value).toFixed(3) + ' (perfect ' +
                Number(e.perfect_value).toFixed(3) + ')</span>' +
                '<span class="tag">' + escapeHtml(sizeStr) + '</span>' +
                '</div>';
            if (e.decompiled_code) {
                html += '<div class="code-label">decompiled:</div>';
                html += '<pre><code>' + escapeHtml(e.decompiled_code) +
                    '</code></pre>';
            }
            if (e.source_code) {
                html += '<div class="code-label">source:</div>';
                html += '<pre><code>' + escapeHtml(e.source_code) +
                    '</code></pre>';
            }
            html += '</div>';
        }
        if (shown === 0) {
            html = '<p class="desc">no entries match the current filter.</p>';
        }
        list.innerHTML = html;
        const counter = document.getElementById("hard-counter");
        if (counter) {
            counter.textContent = "showing " + shown + " / " +
                entries.length + " entries";
        }
    }

    function initHardest() {
        const entries = DATA.hardest || [];
        if (!entries.length) return;
        const mSel = document.getElementById("hard-metric");
        const dSel = document.getElementById("hard-dec");
        if (!mSel || !dSel) return;
        const metrics = [];
        const decs = [];
        for (const e of entries) {
            if (metrics.indexOf(e.metric) < 0) metrics.push(e.metric);
            if (decs.indexOf(e.decompiler) < 0) decs.push(e.decompiler);
        }
        metrics.sort();
        decs.sort();
        for (const m of metrics) {
            const o = document.createElement("option");
            o.value = m;
            o.textContent = METRIC_NAMES[m] || m;
            mSel.appendChild(o);
        }
        for (const d of decs) {
            const o = document.createElement("option");
            o.value = d;
            o.textContent = d;
            dSel.appendChild(o);
        }
        mSel.addEventListener("change", renderHardest);
        dSel.addEventListener("change", renderHardest);
        renderHardest();
    }

    // ---- Historical view (inline SVG line charts) -----------------------
    const CHART_COLORS = [
        "#6ab04c", "#4a90d9", "#d4a72c", "#c0504d", "#9b59b6",
        "#1abc9c", "#e67e22", "#7f8c8d", "#e84393", "#00cec9"
    ];

    function baseName(dec) {
        // Strip a "@version" suffix for grouping by base decompiler name.
        const at = dec.indexOf("@");
        return at >= 0 ? dec.substring(0, at) : dec;
    }

    function svgEl(tag, attrs) {
        const NS = "http://www.w3.org/2000/svg";
        const el = document.createElementNS(NS, tag);
        for (const k in attrs) el.setAttribute(k, attrs[k]);
        return el;
    }

    // Build one chart: metricKey is a metric name or "__overall__".
    function buildChart(container, metricKey, title) {
        const history = DATA.history || [];
        // Ordered list of distinct versions (x-axis), in first-seen order.
        const versions = [];
        for (const h of history) {
            if (versions.indexOf(h.version) < 0) versions.push(h.version);
        }
        // dec base name -> {version -> value}
        const lines = {};
        for (const h of history) {
            const bn = baseName(h.decompiler);
            let val;
            if (metricKey === "__overall__") val = h.overall;
            else val = (h.scores && (metricKey in h.scores)) ?
                h.scores[metricKey] : null;
            if (val == null) continue;
            if (!lines[bn]) lines[bn] = {};
            lines[bn][h.version] = val;
        }
        const decNames = Object.keys(lines).sort();
        if (!decNames.length || versions.length < 1) return;

        const block = document.createElement("div");
        block.className = "chart-block";
        const h3 = document.createElement("h3");
        h3.textContent = title;
        block.appendChild(h3);

        const W = 760, H = 280;
        const padL = 46, padR = 16, padT = 14, padB = 40;
        const plotW = W - padL - padR;
        const plotH = H - padT - padB;
        const svg = svgEl("svg", {
            viewBox: "0 0 " + W + " " + H, width: W, height: H,
            role: "img"
        });

        function xFor(i) {
            if (versions.length === 1) return padL + plotW / 2;
            return padL + (plotW * i) / (versions.length - 1);
        }
        function yFor(v) {
            return padT + plotH - (plotH * Math.max(0, Math.min(v, 100)) / 100);
        }

        // Gridlines + y-axis labels (0..100 step 25).
        for (let g = 0; g <= 100; g += 25) {
            const y = yFor(g);
            svg.appendChild(svgEl("line", {
                x1: padL, y1: y, x2: W - padR, y2: y,
                stroke: "#333", "stroke-width": 1,
                "stroke-dasharray": "3 3"
            }));
            const lbl = svgEl("text", {
                x: padL - 6, y: y + 4, "text-anchor": "end",
                fill: "#8a8a8a", "font-size": 11,
                "font-family": "Source Code Pro, monospace"
            });
            lbl.textContent = g + "%";
            svg.appendChild(lbl);
        }

        // Axes.
        svg.appendChild(svgEl("line", {
            x1: padL, y1: padT, x2: padL, y2: padT + plotH,
            stroke: "#666", "stroke-width": 1
        }));
        svg.appendChild(svgEl("line", {
            x1: padL, y1: padT + plotH, x2: W - padR, y2: padT + plotH,
            stroke: "#666", "stroke-width": 1
        }));

        // X-axis version labels.
        for (let i = 0; i < versions.length; i++) {
            const t = svgEl("text", {
                x: xFor(i), y: padT + plotH + 18, "text-anchor": "middle",
                fill: "#8a8a8a", "font-size": 11,
                "font-family": "Source Code Pro, monospace"
            });
            t.textContent = versions[i];
            svg.appendChild(t);
        }
        // Axis titles.
        const yTitle = svgEl("text", {
            x: 12, y: padT + plotH / 2, fill: "#8a8a8a", "font-size": 11,
            "text-anchor": "middle",
            "font-family": "Source Code Pro, monospace",
            transform: "rotate(-90 12 " + (padT + plotH / 2) + ")"
        });
        yTitle.textContent = "perfect %";
        svg.appendChild(yTitle);
        const xTitle = svgEl("text", {
            x: padL + plotW / 2, y: H - 4, fill: "#8a8a8a", "font-size": 11,
            "text-anchor": "middle",
            "font-family": "Source Code Pro, monospace"
        });
        xTitle.textContent = "version";
        svg.appendChild(xTitle);

        // Polylines per decompiler.
        const colorByDec = {};
        decNames.forEach(function (dn, idx) {
            const color = CHART_COLORS[idx % CHART_COLORS.length];
            colorByDec[dn] = color;
            const pts = [];
            for (let i = 0; i < versions.length; i++) {
                const v = lines[dn][versions[i]];
                if (v == null) continue;
                const x = xFor(i), y = yFor(v);
                pts.push(x + "," + y);
                svg.appendChild(svgEl("circle", {
                    cx: x, cy: y, r: 3, fill: color
                }));
            }
            if (pts.length >= 2) {
                svg.appendChild(svgEl("polyline", {
                    points: pts.join(" "), fill: "none",
                    stroke: color, "stroke-width": 2
                }));
            }
        });

        block.appendChild(svg);

        // Legend.
        const legend = document.createElement("div");
        legend.className = "legend";
        for (const dn of decNames) {
            const span = document.createElement("span");
            span.className = "item";
            const sw = document.createElement("span");
            sw.className = "swatch";
            sw.style.background = colorByDec[dn];
            span.appendChild(sw);
            span.appendChild(document.createTextNode(dn));
            legend.appendChild(span);
        }
        block.appendChild(legend);

        container.appendChild(block);
    }

    function initHistory() {
        const container = document.getElementById("history-charts");
        if (!container) return;
        const history = DATA.history || [];
        if (!history.length) return;
        // One chart per metric, plus an overall chart.
        const metrics = DATA.metrics || [];
        for (const m of metrics) {
            buildChart(container, m, METRIC_NAMES[m] || m);
        }
        buildChart(container, "__overall__", "Overall (perfect on all metrics)");
    }

    function init() {
        // Metric selector options.
        const sel = document.getElementById("breakdown-metric");
        for (const m of DATA.metrics) {
            const opt = document.createElement("option");
            opt.value = m;
            opt.textContent = METRIC_NAMES[m] || m;
            sel.appendChild(opt);
        }
        const overallOpt = document.createElement("option");
        overallOpt.value = "__overall__";
        overallOpt.textContent = "Overall";
        sel.appendChild(overallOpt);
        sel.addEventListener("change", refresh);

        document.querySelectorAll('input[data-label]').forEach(function (cb) {
            cb.addEventListener("change", function () {
                if (cb.checked) state.disabledLabels.delete(cb.dataset.label);
                else state.disabledLabels.add(cb.dataset.label);
                refresh();
            });
        });
        document.querySelectorAll('input[data-binary]').forEach(function (cb) {
            cb.addEventListener("change", function () {
                if (cb.checked) state.disabledBinaries.delete(cb.dataset.binary);
                else state.disabledBinaries.add(cb.dataset.binary);
                refresh();
            });
        });

        document.getElementById("reset-filters").addEventListener(
            "click", function () {
                state.disabledLabels.clear();
                state.disabledBinaries.clear();
                document.querySelectorAll(
                    'input[data-label], input[data-binary]'
                ).forEach(function (cb) { cb.checked = true; });
                refresh();
            });

        refresh();
        initHardest();
        initHistory();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
    </script>"""

    return js.replace("__DATA__", data_json)
