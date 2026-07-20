"""Builder for the deployable static site — the GitHub Pages tree.

Same page as :func:`decbench.rendering.html.render_html_report`, different
delivery. The single-file report inlines everything because it must open over
``file://``; a site is served over HTTP, so it splits:

* the browser caches ``app.css``/``app.js``/the font across navigations, and
* the two big code-carrying payloads (``samples``, ``hardest`` — ~7 MB of
  embedded C between them) are fetched only when their view is opened, so first
  paint costs ``aggregates.json`` alone.

The tree is specified in ``docs/SITE_DATA_SCHEMA.md``; this module is its only
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
from decbench.rendering.aggregate import build_payloads
from decbench.rendering.content import Content, load_content
from decbench.rendering.html import (
    CSS_FILE,
    JS_FILE,
    SITE_PAGE_MARKER,
    asset_text,
    build_page,
    iter_font_assets,
    linked_assets,
)

__all__ = ["build_site"]

_DATA_DIR = "data"
_FONTS_DIR = "fonts"
_INDEX = "index.html"

#: The root's own hop to itself, and a subpage's hop up to the root (used for the
#: ``<base href>`` and the ``__DECBENCH_ROOT__`` stamp — see :func:`linked_assets`).
_ROOT_HOP = ""
_SUBPAGE_HOP = "../"

#: Pages runs Jekyll over an uploaded tree unless this file exists, and Jekyll
#: silently drops paths that start with `_`. We have none today; one added later
#: would vanish in production and nowhere else.
_NOJEKYLL = ".nojekyll"


def build_site(scoreboard: Scoreboard, function_data: FunctionData, out_dir: Path) -> None:
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
    """
    from decbench.rendering.visibility import apply_hidden_decompilers

    # Hide site-hidden decompilers (content/site.toml) from EVERY page and
    # payload; their results stay on disk, untouched.
    scoreboard, function_data = apply_hidden_decompilers(scoreboard, function_data)
    content = load_content()

    out_dir.mkdir(parents=True, exist_ok=True)

    for generated in (out_dir / _DATA_DIR, out_dir / _FONTS_DIR):
        if generated.exists():
            shutil.rmtree(generated)
    (out_dir / _DATA_DIR).mkdir()
    (out_dir / _FONTS_DIR).mkdir()

    (out_dir / _INDEX).write_text(
        build_page(scoreboard, function_data, linked_assets(_ROOT_HOP), content),
        encoding="utf-8",
    )
    (out_dir / CSS_FILE).write_text(asset_text(CSS_FILE), encoding="utf-8")
    (out_dir / JS_FILE).write_text(asset_text(JS_FILE), encoding="utf-8")
    (out_dir / _NOJEKYLL).write_text("", encoding="utf-8")
    # GitHub Pages custom domain. Workflow deploys take the domain from the repo's
    # Pages settings, but the CNAME file keeps the tree self-documenting and keeps
    # the domain if publishing ever moves back to a branch source.
    if content.site.pages_domain:
        (out_dir / "CNAME").write_text(content.site.pages_domain + "\n", encoding="utf-8")

    for name, blob in iter_font_assets():
        (out_dir / _FONTS_DIR / name).write_bytes(blob)

    for name, payload in build_payloads(function_data, scoreboard).items():
        _write_json(out_dir / _DATA_DIR / f"{name}.json", payload)

    _write_view_subpages(scoreboard, function_data, content, out_dir)


def _write_view_subpages(
    scoreboard: Scoreboard, function_data: FunctionData, content: Content, out_dir: Path
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
        # An unreadable / non-UTF-8 index.html is by definition not one of ours —
        # skip it rather than abort the build over a hand-added page.
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
            build_page(scoreboard, function_data, linked_assets(_SUBPAGE_HOP), content, spec.id),
            encoding="utf-8",
        )


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
