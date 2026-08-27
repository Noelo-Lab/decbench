"""Day-based scoreboard snapshots — a stable link back to a past leaderboard.

A snapshot freezes the two SMALL payloads of an already-published site
(``aggregates.json`` + ``dataset.json``, ~54 KB together) under a date, so
``https://decbench.com/leaderboard/?snapshot=27-08-2026`` renders that day's
numbers forever. The 31 MB ``samples.json`` is deliberately NOT frozen: the View
page's source code is not what anyone cites, and copying it per snapshot would
grow the repo by a full corpus each time. The View page therefore says so and
links back to live when a snapshot is selected.

Two locations, one source of truth:

* ``<repo>/snapshots/<DD-MM-YYYY>/`` — the canonical, git-tracked store, written
  ONLY by ``decbench site snapshot``. Snapshots are never created automatically:
  a snapshot is an editorial act, taken when a score-changing change lands (the
  same moment ``CHANGELOG.md`` gets an entry).
* ``site/data/snapshots/`` — a copy the build materializes into the deployable
  tree, because GitHub Pages serves nothing outside it. ``data/`` is wiped and
  regenerated on every build, so the copy is derived, never edited.

Snapshots are frozen AFTER render-time filtering (hidden decompilers, malware
exclusion), because they are copied from a built tree rather than recomputed.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from decbench.rendering.aggregate import default_preset_name, union_leaders

__all__ = [
    "DATE_PATTERN",
    "INDEX_FILE",
    "META_FILE",
    "SNAPSHOTS_DIR",
    "SNAPSHOT_PAYLOADS",
    "Snapshot",
    "SnapshotError",
    "build_index",
    "capture",
    "default_snapshots_dir",
    "format_date",
    "load_snapshots",
    "parse_date",
    "write_snapshot_tree",
]

# The URL/directory form the user types: `?snapshot=27-08-2026`.
_DATE_FORMAT = "%d-%m-%Y"
_ISO_FORMAT = "%Y-%m-%d"

# Mirrors app.js's SNAPSHOT_RE. Validated on both sides: the client must never
# turn an arbitrary query param into a fetch path.
DATE_PATTERN = re.compile(r"^\d{2}-\d{2}-\d{4}$")

SNAPSHOTS_DIR = "snapshots"
META_FILE = "meta.json"
INDEX_FILE = "index.json"

# The payloads a snapshot freezes, by data-file stem. `samples` is excluded on
# purpose (see the module docstring); mirrored by app.js's SNAPSHOT_PAYLOADS.
SNAPSHOT_PAYLOADS = ("aggregates", "dataset")


class SnapshotError(Exception):
    """A snapshot could not be captured or read."""


@dataclass(frozen=True)
class Snapshot:
    """One recorded snapshot: its day, its directory, and its index entry."""

    day: date
    path: Path
    meta: dict[str, Any]

    @property
    def name(self) -> str:
        """The directory / URL form of this snapshot's date."""
        return format_date(self.day)


def format_date(day: date) -> str:
    """Render a day in the canonical ``DD-MM-YYYY`` snapshot form."""
    return day.strftime(_DATE_FORMAT)


def parse_date(text: str) -> date:
    """Parse a snapshot date, accepting ``DD-MM-YYYY`` or ISO ``YYYY-MM-DD``.

    ISO is accepted because every other date in the repo (``CHANGELOG.md``,
    results-tree names) is year-first, so it is what a maintainer reaches for;
    it always normalizes to the ``DD-MM-YYYY`` canonical form.
    """
    for fmt in (_DATE_FORMAT, _ISO_FORMAT):
        try:
            return datetime.strptime(text.strip(), fmt).date()
        except ValueError:
            continue
    raise SnapshotError(f"Not a snapshot date: {text!r} (expected DD-MM-YYYY or YYYY-MM-DD)")


def default_snapshots_dir() -> Path:
    """``<repo>/snapshots`` — resolved like the CLI resolves ``CHANGELOG.md``.

    A wheel install has no repo checkout beside it, so the directory simply will
    not exist and the site builds with an empty snapshot list.
    """
    return Path(__file__).resolve().parents[2] / SNAPSHOTS_DIR


def load_snapshots(root: Path | None = None) -> list[Snapshot]:
    """Read every snapshot under ``root``, newest first.

    A directory whose name is not a snapshot date, or which is missing its
    ``meta.json`` or a frozen payload, is skipped rather than failing the build:
    the site must still deploy when one snapshot is half-written.
    """
    root = default_snapshots_dir() if root is None else root
    if not root.is_dir():
        return []

    found: list[Snapshot] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir() or not DATE_PATTERN.match(child.name):
            continue
        meta_path = child / META_FILE
        if not meta_path.is_file():
            continue
        if any(not (child / f"{name}.json").is_file() for name in SNAPSHOT_PAYLOADS):
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            day = parse_date(child.name)
        except (OSError, ValueError, SnapshotError):
            continue
        found.append(Snapshot(day=day, path=child, meta=meta))

    found.sort(key=lambda s: s.day, reverse=True)
    return found


def build_index(snapshots: list[Snapshot]) -> list[dict[str, Any]]:
    """The ``data/snapshots/index.json`` payload: every meta record, newest first.

    The index is nothing but the concatenated ``meta.json`` files, so the listing
    page and a snapshot's own record can never disagree.
    """
    return [dict(snap.meta) for snap in snapshots]


def write_snapshot_tree(data_dir: Path, snapshots: list[Snapshot]) -> None:
    """Materialize the snapshot store into a built site's ``data/`` directory.

    Writes ``data/snapshots/index.json`` plus one ``data/snapshots/<date>/``
    holding the frozen payloads. Called by the site builder after it has wiped
    and regenerated ``data/``, which is why nothing here has to prune.
    """
    out = data_dir / SNAPSHOTS_DIR
    out.mkdir(parents=True, exist_ok=True)
    for snap in snapshots:
        dest = out / snap.name
        dest.mkdir(exist_ok=True)
        for name in SNAPSHOT_PAYLOADS:
            shutil.copyfile(snap.path / f"{name}.json", dest / f"{name}.json")
    index = json.dumps(build_index(snapshots), separators=(",", ":"), allow_nan=False)
    (out / INDEX_FILE).write_text(index, encoding="utf-8")


def capture(
    site_dir: Path,
    snapshots_dir: Path,
    day: date,
    *,
    label: str = "",
    note: str = "",
    force: bool = False,
) -> Snapshot:
    """Freeze a built site's small payloads into ``snapshots_dir/<DD-MM-YYYY>/``.

    Reads the BUILT tree rather than recomputing from results, so a snapshot is
    byte-for-byte the numbers that were published that day — including whatever
    decompilers were hidden and whichever preset was default at the time.
    """
    data_dir = site_dir / "data"
    sources = {name: data_dir / f"{name}.json" for name in SNAPSHOT_PAYLOADS}
    missing = [str(p) for p in sources.values() if not p.is_file()]
    if missing:
        raise SnapshotError(
            f"{site_dir} is not a built site (missing {', '.join(missing)}). "
            "Run `decbench site build` first."
        )

    dest = snapshots_dir / format_date(day)
    if dest.exists() and not force:
        raise SnapshotError(f"Snapshot {format_date(day)} already exists at {dest} (use --force).")

    aggregates = json.loads(sources["aggregates"].read_text(encoding="utf-8"))
    meta = _build_meta(aggregates, day, label=label, note=note)

    dest.mkdir(parents=True, exist_ok=True)
    for name, src in sources.items():
        shutil.copyfile(src, dest / f"{name}.json")
    (dest / META_FILE).write_text(
        json.dumps(meta, indent=2, sort_keys=False, allow_nan=False) + "\n", encoding="utf-8"
    )
    return Snapshot(day=day, path=dest, meta=meta)


def _build_meta(aggregates: dict[str, Any], day: date, *, label: str, note: str) -> dict[str, Any]:
    """The snapshot's index entry, derived entirely from the frozen aggregates.

    ``decompiler_versions`` is the reason the listing page can filter by version:
    it records the prettified version each decompiler was on that day, straight
    from the payload's registry (so IDA reads ``9.2``, not ``920``).
    """
    registry = aggregates.get("decompiler_registry", {}) or {}
    decompilers = list(aggregates.get("decompilers", []))
    preset = default_preset_name(aggregates)
    leaders = union_leaders(aggregates, preset, exclude_sample_set_only=True)[:3]

    versions: dict[str, str] = {}
    names: dict[str, str] = {}
    for dec in decompilers:
        entry = registry.get(dec, {})
        version = str(entry.get("version") or "")
        if version:
            versions[dec] = version
        names[dec] = str(entry.get("display_name") or dec)

    totals = aggregates.get("totals", {}) or {}
    return {
        "date": format_date(day),
        "iso_date": day.isoformat(),
        "label": label,
        "note": note,
        "scoreboard": str(aggregates.get("name") or ""),
        "version": str(aggregates.get("version") or ""),
        "generated_at": str(aggregates.get("generated_at") or ""),
        "functions": int(totals.get("functions") or 0),
        "binaries": int(totals.get("binaries") or 0),
        "preset": preset,
        "decompilers": decompilers,
        "decompiler_names": names,
        "decompiler_versions": versions,
        "metrics": list(aggregates.get("metrics", [])),
        "leaders": [{"dec": dec, "name": name, "pct": pct} for pct, name, dec in leaders],
    }
