"""HTML report renderer for DecBench results."""

from __future__ import annotations

from pathlib import Path

from decbench.models.scoreboard import Scoreboard


METRIC_DISPLAY_NAMES = {
    "ged": "Structural Correctness (GED)",
    "type_match": "Type Correctness",
    "byte_match": "Recompilation Bytematch",
}


def render_html_report(scoreboard: Scoreboard, output_path: Path) -> None:
    """Render a self-contained HTML report from scoreboard data.

    Generates sections for:
    1. Overall - functions perfect on ALL metrics
    2. Each individual metric
    """
    html = _build_html(scoreboard)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)


def _build_html(scoreboard: Scoreboard) -> str:
    """Build the complete HTML string."""
    metric_sections = ""
    for metric_name in scoreboard.metrics:
        metric_sections += _build_metric_section(scoreboard, metric_name)

    overall_section = _build_overall_section(scoreboard)

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
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
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
        <h1>{scoreboard.name}</h1>
        <div class="subtitle">
            Generated {scoreboard.generated_at.strftime('%Y-%m-%d %H:%M')}
            | Projects: {', '.join(scoreboard.projects_evaluated)}
            | Opt levels: {', '.join(scoreboard.optimization_levels)}
        </div>

        <div class="stats">
            <div class="stat">
                <div class="stat-value">{scoreboard.total_functions:,}</div>
                <div class="stat-label">Functions</div>
            </div>
            <div class="stat">
                <div class="stat-value">{scoreboard.total_binaries:,}</div>
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

        {overall_section}
        {metric_sections}

        <footer>
            DecBench v{scoreboard.version} &mdash; Decompiler Benchmarking Suite
        </footer>
    </div>
</body>
</html>"""


def _pct_class(pct: float) -> str:
    if pct >= 50:
        return "high"
    elif pct >= 20:
        return "mid"
    return "low"


def _build_ranking_table(rankings: list[tuple[str, float]], scoreboard: Scoreboard, metric_name: str | None = None) -> str:
    """Build an HTML table for rankings."""
    rows = ""
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

        rows += f"""
        <tr>
            <td class="rank">#{rank}</td>
            <td>{dec_name}</td>
            <td>
                <div class="bar-container">
                    <div class="bar bar-{cls}" style="width: {min(pct, 100):.1f}%"></div>
                </div>
            </td>
            <td class="pct pct-{cls}">{pct:.1f}%</td>
            <td class="counts">{count_str}</td>
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
