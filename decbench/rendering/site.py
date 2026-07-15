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
from decbench.rendering.html import (
    CSS_FILE,
    JS_FILE,
    asset_text,
    build_page,
    iter_font_assets,
    linked_assets,
)

__all__ = ["build_site"]

_DATA_DIR = "data"
_FONTS_DIR = "fonts"
_INDEX = "index.html"

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
    out_dir.mkdir(parents=True, exist_ok=True)

    for generated in (out_dir / _DATA_DIR, out_dir / _FONTS_DIR):
        if generated.exists():
            shutil.rmtree(generated)
    (out_dir / _DATA_DIR).mkdir()
    (out_dir / _FONTS_DIR).mkdir()

    (out_dir / _INDEX).write_text(
        build_page(scoreboard, function_data, linked_assets()), encoding="utf-8"
    )
    (out_dir / CSS_FILE).write_text(asset_text(CSS_FILE), encoding="utf-8")
    (out_dir / JS_FILE).write_text(asset_text(JS_FILE), encoding="utf-8")
    (out_dir / _NOJEKYLL).write_text("", encoding="utf-8")

    for name, blob in iter_font_assets():
        (out_dir / _FONTS_DIR / name).write_bytes(blob)

    for name, payload in build_payloads(function_data, scoreboard).items():
        _write_json(out_dir / _DATA_DIR / f"{name}.json", payload)


def _write_json(path: Path, payload: Any) -> None:
    """Write one data file: compact, no gratuitous whitespace.

    These are machine-read only, and ``samples.json`` alone is megabytes of
    embedded source — pretty-printing would inflate the site and every git commit
    of it for nobody's benefit.
    """
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
