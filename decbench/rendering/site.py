"""Builder for the deployable static site — the GitHub Pages tree.

Same page as :func:`decbench.rendering.html.render_html_report`, different
delivery. The single-file report inlines everything because it must open over
``file://``; a site is served over HTTP, so it splits:

* the browser caches ``app.css``/``app.js``/the font across navigations, and
* the two big code-carrying payloads (``samples``, ``hardest`` — ~7 MB of
  embedded C between them) are fetched only when their view is opened, so first
  paint costs ``aggregates.json`` alone.

The tree is specified in ``docs/site.md``; this module is its only
writer. It is built locally by a maintainer and committed — see
``.github/workflows/pages.yml``, which deploys but never generates.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from decbench.models.function_data import FunctionData
from decbench.models.scoreboard import Scoreboard
from decbench.rendering.aggregate import (
    ALL_PRESET,
    SAMPLE_SET_PRESET,
    build_payloads,
    union_leaders,
)
from decbench.rendering.content import Content, load_content
from decbench.rendering.html import (
    CARD_FILE,
    CSS_FILE,
    JS_FILE,
    SITE_PAGE_MARKER,
    SocialMeta,
    asset_text,
    build_page,
    iter_font_assets,
    iter_site_icons,
    linked_assets,
)

__all__ = ["build_site"]

_DATA_DIR = "data"
_FONTS_DIR = "fonts"
_INDEX = "index.html"

_ROOT_HOP = ""
_SUBPAGE_HOP = "../"

# Pages runs Jekyll over an uploaded tree unless this file exists, and Jekyll
# silently drops paths starting with `_` — in production and nowhere else.
_NOJEKYLL = ".nojekyll"

_LEGACY_REDIRECTS = {"distance": ("data", "distance")}

# Deliberately carries no SITE_PAGE_MARKER: the subpage prune deletes marked
# non-current view directories, and these stubs must survive every rebuild. The
# script hop preserves ?query and #hash, which a bare meta refresh drops.
_REDIRECT_STUB = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DecBench &mdash; moved to /{target}/#{anchor}</title>
<link rel="canonical" href="{canonical}">
<meta http-equiv="refresh" content="0; url=../{target}/#{anchor}">
<script>location.replace("../{target}/" + location.search + (location.hash || "#{anchor}"))</script>
</head>
<body><p>This page moved to <a href="../{target}/#{anchor}">/{target}/#{anchor}</a>.</p></body>
</html>
"""


def build_site(
    scoreboard: Scoreboard,
    function_data: FunctionData,
    out_dir: Path,
    content: Content | None = None,
) -> None:
    """Write the complete static site tree to ``out_dir``.

    Idempotent: ``data/`` and ``fonts/`` are wholly generated, so both are cleared
    first. A rebuild after a payload is renamed or dropped must not leave the old
    file behind for the deploy to publish — stale JSON on a live site is worse
    than missing JSON, because nothing reports it.

    Args:
        scoreboard: Supplies the run's identity (name, version, timestamp).
        function_data: The per-function dataset every page is computed from.
            Required: a site with no data has nothing to show.
        out_dir: The tree root, e.g. ``site/``.
        content: Parsed ``content/``; loaded (and cached) when omitted. The CLI
            passes one with the repo-root ``CHANGELOG.md`` injected into the
            ``changelog`` view (see :meth:`Content.with_view`).
    """
    from decbench.rendering.visibility import apply_hidden_decompilers

    scoreboard, function_data = apply_hidden_decompilers(scoreboard, function_data)
    content = content or load_content()

    out_dir.mkdir(parents=True, exist_ok=True)

    for generated in (out_dir / _DATA_DIR, out_dir / _FONTS_DIR):
        if generated.exists():
            shutil.rmtree(generated)
    (out_dir / _DATA_DIR).mkdir()
    (out_dir / _FONTS_DIR).mkdir()

    payloads = build_payloads(function_data, scoreboard)
    root_social, view_social = _social_meta(content, payloads["aggregates"])

    (out_dir / _INDEX).write_text(
        build_page(
            scoreboard, function_data, linked_assets(_ROOT_HOP), content, social=root_social
        ),
        encoding="utf-8",
    )
    (out_dir / CSS_FILE).write_text(asset_text(CSS_FILE), encoding="utf-8")
    (out_dir / JS_FILE).write_text(asset_text(JS_FILE), encoding="utf-8")
    (out_dir / _NOJEKYLL).write_text("", encoding="utf-8")
    if content.site.pages_domain:
        (out_dir / "CNAME").write_text(content.site.pages_domain + "\n", encoding="utf-8")

    for name, blob in iter_font_assets():
        (out_dir / _FONTS_DIR / name).write_bytes(blob)
    for name, blob in iter_site_icons():
        (out_dir / name).write_bytes(blob)

    for name, payload in payloads.items():
        _write_json(out_dir / _DATA_DIR / f"{name}.json", payload)

    _write_view_subpages(scoreboard, function_data, content, out_dir, view_social)
    current = {spec.id for spec in content.visible_views(function_data is not None)}
    _write_legacy_redirects(out_dir, current, content.site.pages_domain)


def _write_legacy_redirects(out_dir: Path, current_view_ids: set[str], domain: str) -> None:
    """Write a redirect stub for each renamed view's OLD URL (``_LEGACY_REDIRECTS``).

    ``site/distance/index.html`` etc.: a standalone page that canonicalizes to and
    hops (meta refresh + a script that preserves query/hash) to the view's new
    home. It carries NO ``SITE_PAGE_MARKER``, so the stale-view prune in
    :func:`_write_view_subpages` treats it like a hand-added page and keeps it.

    Skipped when the old id is (somehow) a current view again — a real view's
    subpage must never be clobbered by a redirect to somewhere else.
    """
    for old_id, (target, anchor) in _LEGACY_REDIRECTS.items():
        if old_id in current_view_ids:
            continue
        canonical = f"https://{domain}/{target}/" if domain else f"../{target}/"
        stub_dir = out_dir / old_id
        stub_dir.mkdir(exist_ok=True)
        (stub_dir / _INDEX).write_text(
            _REDIRECT_STUB.format(target=target, anchor=anchor, canonical=canonical),
            encoding="utf-8",
        )


def _write_view_subpages(
    scoreboard: Scoreboard,
    function_data: FunctionData,
    content: Content,
    out_dir: Path,
    view_social: dict[str, SocialMeta],
) -> None:
    """Write one ``<out_dir>/<view-id>/index.html`` per visible view, and prune stale ones.

    Each subpage is the SAME skeleton with that view active and root-prefixed asset
    links, so ``/leaderboard/`` etc. are directly linkable and reload cleanly. A view
    removed or renamed leaves a subdirectory behind; it is pruned, but ONLY when its
    ``index.html`` carries :data:`~decbench.rendering.html.SITE_PAGE_MARKER`, never an
    arbitrary directory a maintainer added under ``site/``.
    """
    visible = content.visible_views(function_data is not None)
    current = {spec.id for spec in visible}

    for child in out_dir.iterdir():
        if not child.is_dir() or child.name in (_DATA_DIR, _FONTS_DIR) or child.name in current:
            continue
        index = child / _INDEX
        try:
            ours = index.is_file() and SITE_PAGE_MARKER in index.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            ours = False
        if ours:
            shutil.rmtree(child)

    for spec in visible:
        view_dir = out_dir / spec.id
        view_dir.mkdir(exist_ok=True)
        (view_dir / _INDEX).write_text(
            build_page(
                scoreboard,
                function_data,
                linked_assets(_SUBPAGE_HOP),
                content,
                spec.id,
                social=view_social.get(spec.id),
            ),
            encoding="utf-8",
        )


_GENERIC_DESC = (
    "A ground-truth decompiler benchmark: control flow, types, and recompilation "
    "over real C projects, firmware, and malware."
)


def _social_meta(
    content: Content, aggregates: dict[str, Any]
) -> tuple[SocialMeta | None, dict[str, SocialMeta]]:
    """Per-page Open Graph / Twitter metadata for the split site.

    Returns ``(root_social, {view_id: social})``. Only emitted when a
    ``pages_domain`` is configured — the tags need absolute URLs, and a
    github.io-less build has no canonical host — so a domain-less build gets
    ``(None, {})`` and every page falls back to no og/twitter tags (crawlers then
    read the page ``<title>`` alone, exactly as before).
    """
    domain = content.site.pages_domain
    if not domain:
        return None, {}
    base = f"https://{domain}/"
    image = f"{base}{CARD_FILE}"
    descriptions = _view_descriptions(aggregates)

    per_view: dict[str, SocialMeta] = {}
    for spec in content.visible_views(True):
        per_view[spec.id] = SocialMeta(
            title=f"DecBench — {spec.nav_label}",
            description=descriptions.get(spec.id, _GENERIC_DESC),
            canonical_url=f"{base}{spec.id}/",
            image_url=image,
        )

    root = SocialMeta(
        title="DecBench — decompiler benchmark",
        description=descriptions.get(content.default_view, _GENERIC_DESC),
        canonical_url=base,
        image_url=image,
    )
    return root, per_view


def _default_preset(aggregates: dict[str, Any]) -> str:
    """The preset the leaderboard opens on — the one flagged ``default`` in the payload.

    Falls back to the first preset, then to the reserved all-corpus combo of a
    preset-less run, so :func:`union_leaders` always has a real combo to read.
    """
    presets = aggregates.get("presets") or []
    for preset in presets:
        if preset.get("default"):
            return str(preset["name"])
    return str(presets[0]["name"]) if presets else ALL_PRESET


def _format_leaders(ranked: list[tuple[float, str, str]], count: int = 3) -> str:
    """A ranking as ``"1. Hex-Rays 47.7% · 2. Kuna 47.5% · 3. angr 45.3%"``.

    Percentages at one decimal, names via the decompiler registry (already resolved
    inside :func:`union_leaders`). Empty string when the ranking is empty.
    """
    return " · ".join(
        f"{i}. {name} {pct:.1f}%" for i, (pct, name, _dec) in enumerate(ranked[:count], 1)
    )


def _view_descriptions(aggregates: dict[str, Any]) -> dict[str, str]:
    """Per-view og/twitter descriptions, each derived from the aggregates payload.

    The leaderboard/distance texts quote the default-preset (leaderboard) top-3 by
    Union over the on-screen decompilers; the view page quotes the sample-set top-3
    (all decompilers, since that is where the LLM agents render). Kept <= 200 chars.
    """
    default_preset = _default_preset(aggregates)
    unopt_top3 = _format_leaders(
        union_leaders(aggregates, default_preset, exclude_sample_set_only=True)
    )
    sample_top3 = _format_leaders(
        union_leaders(aggregates, SAMPLE_SET_PRESET, exclude_sample_set_only=False)
    )
    n_functions = aggregates.get("totals", {}).get("functions", 0)
    n_decompilers = len(aggregates.get("decompilers", []))
    n_metrics = len(aggregates.get("metrics", []))

    leaderboard = (
        f"Decompiler leaderboard — {unopt_top3}. Perfect-function rate across "
        f"{n_functions:,} functions, {n_decompilers} decompilers, "
        f"{n_metrics} ground-truth metrics."
    )
    view = "Browse source vs decompiled code side-by-side."
    if sample_top3:
        view += f" sample-set top 3: {sample_top3}"
    return {
        "leaderboard": leaderboard,
        "data": (
            f"The run's data: edit distance from perfect per metric, compile rates, "
            f"pipeline health, and decompile time + estimated LLM cost. {unopt_top3}"
        ),
        "view": view,
        "changelog": "What changed in the DecBench benchmark and site.",
        "about": (
            "How DecBench works: three ground-truth metrics (control flow, types, "
            "recompilation) over real C projects, firmware, and malware."
        ),
    }


def _write_json(path: Path, payload: Any) -> None:
    """Write one data file: compact, no gratuitous whitespace.

    These are machine-read only, and ``samples.json`` alone is megabytes of
    embedded source — pretty-printing would inflate the site and every git commit
    of it for nobody's benefit.

    ``allow_nan=False``: browsers parse JSON strictly, so a single ``Infinity``
    Python let through would break an entire payload client-side. Failing the
    build here is the loud version of that bug.
    """
    path.write_text(json.dumps(payload, separators=(",", ":"), allow_nan=False), encoding="utf-8")
