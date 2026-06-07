"""HTML report renderer for DecBench results."""

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
    per-function dataset and interactive client-side filtering controls.

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
            "Interactive filtering unavailable: per-function data "
            "(function_results.json) not found."
            "</div>"
        )
        interactive_sections = ""
        script = ""
    else:
        banner = ""
        interactive_sections = (
            _build_filters_section(function_data)
            + _build_comparison_matrix_section(function_data)
            + _build_per_binary_section(function_data)
        )
        script = _build_script(function_data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{scoreboard.name}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --green: #3fb950;
            --yellow: #d29922;
            --red: #f85149;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
                Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
            color: var(--accent);
        }}
        .subtitle {{
            color: var(--text-muted);
            margin-bottom: 2rem;
            font-size: 0.9rem;
        }}
        .banner {{
            background: var(--surface);
            border: 1px solid var(--yellow);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            margin-bottom: 1.5rem;
            color: var(--yellow);
            font-size: 0.9rem;
        }}
        .stats {{
            display: flex;
            gap: 2rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }}
        .stat {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            min-width: 140px;
        }}
        .stat-value {{
            font-size: 1.8rem;
            font-weight: bold;
            color: var(--accent);
        }}
        .stat-label {{
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .section h2 {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .section.overall h2 {{
            color: var(--green);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            text-align: left;
            padding: 0.7rem 1rem;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        tr:last-child td {{ border-bottom: none; }}
        .rank {{ color: var(--text-muted); width: 60px; }}
        .pct {{
            font-weight: bold;
            font-size: 1.1rem;
            text-align: right;
            width: 120px;
        }}
        .pct-high {{ color: var(--green); }}
        .pct-mid {{ color: var(--yellow); }}
        .pct-low {{ color: var(--red); }}
        .bar-container {{
            width: 200px;
            background: var(--bg);
            border-radius: 4px;
            overflow: hidden;
            height: 8px;
        }}
        .bar {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }}
        .bar-high {{ background: var(--green); }}
        .bar-mid {{ background: var(--yellow); }}
        .bar-low {{ background: var(--red); }}
        .counts {{
            color: var(--text-muted);
            font-size: 0.85rem;
            text-align: right;
            width: 100px;
        }}
        .chips {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }}
        .chip {{
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 999px;
            padding: 0.3rem 0.8rem;
            font-size: 0.85rem;
            cursor: pointer;
            user-select: none;
        }}
        .chip input {{ cursor: pointer; }}
        details {{
            margin-bottom: 1rem;
        }}
        details summary {{
            cursor: pointer;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-bottom: 0.5rem;
        }}
        .binary-list label {{
            display: block;
            font-size: 0.85rem;
            padding: 0.15rem 0;
        }}
        .controls {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }}
        button {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            padding: 0.4rem 0.9rem;
            cursor: pointer;
            font-size: 0.85rem;
        }}
        button:hover {{ border-color: var(--accent); }}
        select {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            padding: 0.4rem 0.9rem;
            font-size: 0.85rem;
        }}
        .counter {{
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
        .mini-bar {{
            width: 120px;
            display: inline-block;
            background: var(--bg);
            border-radius: 4px;
            overflow: hidden;
            height: 6px;
            vertical-align: middle;
            margin-right: 0.5rem;
        }}
        .mini-bar > div {{
            height: 100%;
            border-radius: 4px;
        }}
        footer {{
            text-align: center;
            color: var(--text-muted);
            margin-top: 2rem;
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{html_escape(scoreboard.name)}</h1>
        <div class="subtitle">
            Generated {scoreboard.generated_at.strftime('%Y-%m-%d %H:%M')}
            | Projects: {html_escape(', '.join(scoreboard.projects_evaluated))}
            | Opt levels: {html_escape(', '.join(scoreboard.optimization_levels))}
        </div>

        {banner}

        <div class="stats">
            <div class="stat">
                <div class="stat-value" data-stat="functions">{scoreboard.total_functions:,}</div>
                <div class="stat-label">Functions</div>
            </div>
            <div class="stat">
                <div class="stat-value" data-stat="binaries">{scoreboard.total_binaries:,}</div>
                <div class="stat-label">Binaries</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(scoreboard.decompilers)}</div>
                <div class="stat-label">Decompilers</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(scoreboard.metrics)}</div>
                <div class="stat-label">Metrics</div>
            </div>
        </div>

        {interactive_sections}
        {overall_section}
        {metric_sections}

        <footer>
            DecBench v{scoreboard.version} &mdash; Decompiler Benchmarking Suite
        </footer>
    </div>
    {script}
</body>
</html>"""


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
        rows += f"""
        <tr data-ranking-row="{html_escape(metric_attr)}" data-decompiler="{esc_dec}">
            <td class="rank">#{rank}</td>
            <td>{esc_dec}</td>
            <td>
                <div class="bar-container">
                    <div class="bar bar-{cls}" data-bar="1"
                        style="width: {min(pct, 100):.1f}%"></div>
                </div>
            </td>
            <td class="pct pct-{cls}" data-pct="1">{pct:.1f}%</td>
            <td class="counts" data-count="1">{count_str}</td>
        </tr>"""

    return f"""
    <table>
        <thead>
            <tr>
                <th>Rank</th>
                <th>Decompiler</th>
                <th>Progress</th>
                <th>Perfect %</th>
                <th>Count</th>
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
    <div class="section overall">
        <h2>Overall - Perfect on All Metrics</h2>
        <p style="color: var(--text-muted); margin-bottom: 1rem;">
            Functions where the decompiler achieves a 100% match on
            <strong>all three metrics</strong> (GED, Type, Bytematch).
        </p>
        {table}
    </div>"""


def _build_metric_section(scoreboard: Scoreboard, metric_name: str) -> str:
    rankings = scoreboard.get_metric_rankings(metric_name)
    if not rankings:
        return ""

    display_name = METRIC_DISPLAY_NAMES.get(metric_name, metric_name)
    table = _build_ranking_table(rankings, scoreboard, metric_name)

    return f"""
    <div class="section">
        <h2>{display_name}</h2>
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
        <h2>Filters</h2>
        <div class="chips">{chips}</div>
        <details>
            <summary>Per-binary toggles</summary>
            <div class="binary-list">{binary_checks}</div>
        </details>
        <div class="controls">
            <button id="reset-filters">Reset</button>
            <span class="counter" id="function-counter"></span>
        </div>
    </div>"""


def _build_comparison_matrix_section(function_data: FunctionData) -> str:
    """Build the metric x decompiler comparison matrix (filled by JS)."""
    return """
    <div class="section" id="comparison-matrix">
        <h2>Comparison Matrix</h2>
        <table>
            <thead>
                <tr><th>Metric</th></tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>"""


def _build_per_binary_section(function_data: FunctionData) -> str:
    """Build the per-binary breakdown with a metric selector (filled by JS)."""
    return """
    <div class="section" id="per-binary-breakdown">
        <h2>Per-Binary Breakdown</h2>
        <div class="controls">
            <label class="counter" for="breakdown-metric">Metric:</label>
            <select id="breakdown-metric"></select>
        </div>
        <table>
            <thead>
                <tr><th>Binary</th></tr>
            </thead>
            <tbody></tbody>
        </table>
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

    function miniBar(p) {
        const cls = pctClass(p);
        const w = Math.min(p, 100).toFixed(1);
        return '<span class="mini-bar"><div class="bar-' + cls +
            '" style="width:' + w + '%"></div></span>';
    }

    function cellHtml(cell) {
        const p = pct(cell);
        const cls = pctClass(p);
        return miniBar(p) + '<span class="pct-' + cls + '">' +
            p.toFixed(1) + '% (' + cell.perfect + '/' + cell.total + ')</span>';
    }

    function buildMatrix(result) {
        const decs = DATA.decompilers;
        const metrics = DATA.metrics;
        const tbl = document.querySelector("#comparison-matrix table");
        const thead = tbl.querySelector("thead tr");
        thead.innerHTML = "<th>Metric</th>";
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
        thead.innerHTML = "<th>Binary</th>";
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
                    bar.className = "bar bar-" + cls;
                    bar.style.width = Math.min(p, 100).toFixed(1) + "%";
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
            counter.textContent = "Showing " + result.activeFunctions +
                " / " + result.totalFunctions + " functions";
        }
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
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
    </script>"""

    return js.replace("__DATA__", data_json)
