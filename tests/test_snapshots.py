"""Tests for day-based scoreboard snapshots.

A snapshot is the benchmark's only promise of permanence: a number someone cited
must still resolve after the corpus, the metrics and the decompiler set have all
moved on. These pin the properties that promise rests on — that a snapshot is
copied from what was actually published rather than recomputed, that the
canonical store is the single source of truth, and that a half-written or
hand-mangled snapshot degrades to absence instead of failing a deploy.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from decbench.rendering.snapshots import (
    SnapshotError,
    build_index,
    capture,
    format_date,
    load_snapshots,
    parse_date,
    write_snapshot_tree,
)

AGGREGATES = {
    "name": "sailr_full",
    "version": "1.1.0",
    "generated_at": "2026-07-15T15:28:00",
    "totals": {"functions": 91483, "binaries": 806},
    "decompilers": ["angr", "ghidra", "ida"],
    "metrics": ["ged", "type_match"],
    "presets": [{"name": "unoptimized", "default": True}],
    "sample_set_only": [],
    "decompiler_registry": {
        "angr": {"display_name": "angr", "version": "9.2.223"},
        "ghidra": {"display_name": "Ghidra", "version": "12.1"},
        "ida": {"display_name": "Hex-Rays"},
    },
    "combos": {
        "unoptimized|0": {
            "overall": {"angr": [45, 100], "ghidra": [60, 100], "ida": [70, 100]},
        }
    },
}


@pytest.fixture
def built_site(tmp_path: Path) -> Path:
    """A minimal stand-in for a built tree: just the payloads a snapshot copies."""
    site = tmp_path / "site"
    data = site / "data"
    data.mkdir(parents=True)
    (data / "aggregates.json").write_text(json.dumps(AGGREGATES))
    (data / "dataset.json").write_text(json.dumps({"summary": {"projects": 40}}))
    (data / "samples.json").write_text("[]")
    return site


def test_parse_date_accepts_both_orders() -> None:
    """ISO input is accepted because every other date in the repo is year-first."""
    assert parse_date("27-08-2026") == date(2026, 8, 27)
    assert parse_date("2026-08-27") == date(2026, 8, 27)
    assert format_date(parse_date("2026-08-27")) == "27-08-2026"


@pytest.mark.parametrize("bad", ["", "27/08/2026", "2026", "tomorrow", "32-08-2026"])
def test_parse_date_rejects_anything_else(bad: str) -> None:
    with pytest.raises(SnapshotError):
        parse_date(bad)


def test_capture_freezes_the_two_small_payloads(built_site: Path, tmp_path: Path) -> None:
    """samples.json is deliberately NOT frozen — it is ~31 MB per build."""
    snap = capture(built_site, tmp_path / "store", date(2026, 8, 27))

    assert snap.name == "27-08-2026"
    assert json.loads((snap.path / "aggregates.json").read_text()) == AGGREGATES
    assert (snap.path / "dataset.json").is_file()
    assert not (snap.path / "samples.json").exists()


def test_capture_records_the_versions_the_listing_filters_on(
    built_site: Path, tmp_path: Path
) -> None:
    """`decompiler_versions` is what answers "which snapshots had Ghidra 12.1?".

    A decompiler with no known version stays in `decompilers` but is absent from
    the version map, so filtering on it never claims a version it did not have.
    """
    meta = capture(built_site, tmp_path / "store", date(2026, 8, 27), label="v1.2").meta

    assert meta["decompiler_versions"] == {"angr": "9.2.223", "ghidra": "12.1"}
    assert meta["decompilers"] == ["angr", "ghidra", "ida"]
    assert meta["decompiler_names"]["ida"] == "Hex-Rays"
    assert meta["label"] == "v1.2"
    assert meta["functions"] == 91483
    assert [leader["dec"] for leader in meta["leaders"]] == ["ida", "ghidra", "angr"]


def test_capture_refuses_to_overwrite_without_force(built_site: Path, tmp_path: Path) -> None:
    """Silently replacing a published day would break every link that cites it."""
    store = tmp_path / "store"
    capture(built_site, store, date(2026, 8, 27), label="first")
    with pytest.raises(SnapshotError, match="already exists"):
        capture(built_site, store, date(2026, 8, 27))

    again = capture(built_site, store, date(2026, 8, 27), label="second", force=True)
    assert again.meta["label"] == "second"


def test_capture_needs_a_built_site(tmp_path: Path) -> None:
    """A snapshot is a copy of what was published, never a fresh computation."""
    with pytest.raises(SnapshotError, match="not a built site"):
        capture(tmp_path / "nothing", tmp_path / "store", date(2026, 8, 27))


def test_load_snapshots_orders_newest_first(built_site: Path, tmp_path: Path) -> None:
    store = tmp_path / "store"
    for day in (date(2026, 8, 27), date(2026, 7, 22), date(2026, 8, 8)):
        capture(built_site, store, day)

    assert [s.name for s in load_snapshots(store)] == ["27-08-2026", "08-08-2026", "22-07-2026"]


def test_load_snapshots_skips_incomplete_directories(built_site: Path, tmp_path: Path) -> None:
    """One half-written snapshot must not take the whole site down with it."""
    store = tmp_path / "store"
    capture(built_site, store, date(2026, 8, 27))
    (store / "not-a-date").mkdir()
    (store / "01-01-2026").mkdir()
    (store / "02-01-2026").mkdir()
    (store / "02-01-2026" / "meta.json").write_text("{}")

    assert [s.name for s in load_snapshots(store)] == ["27-08-2026"]


def test_load_snapshots_tolerates_a_missing_store(tmp_path: Path) -> None:
    """A wheel install has no repo checkout beside it; the site still builds."""
    assert load_snapshots(tmp_path / "absent") == []


def test_index_is_exactly_the_meta_records(built_site: Path, tmp_path: Path) -> None:
    """One source: the listing page and a snapshot's own record cannot disagree."""
    store = tmp_path / "store"
    capture(built_site, store, date(2026, 8, 27))
    snaps = load_snapshots(store)
    assert build_index(snaps) == [snaps[0].meta]


def test_write_snapshot_tree_materializes_the_store(built_site: Path, tmp_path: Path) -> None:
    store = tmp_path / "store"
    capture(built_site, store, date(2026, 8, 27))
    data = tmp_path / "out" / "data"
    data.mkdir(parents=True)

    write_snapshot_tree(data, load_snapshots(store))

    frozen = data / "snapshots" / "27-08-2026"
    assert json.loads((frozen / "aggregates.json").read_text()) == AGGREGATES
    assert (frozen / "dataset.json").is_file()
    index = json.loads((data / "snapshots" / "index.json").read_text())
    assert [entry["date"] for entry in index] == ["27-08-2026"]
