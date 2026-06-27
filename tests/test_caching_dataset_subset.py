"""Tests for metric caching, the binary dataset store, and large-subset selection.

Covers the DATA cluster deliverables:
- Metric caching: a 2nd identical compute is served from cache (heavy work runs once).
- Binary dataset: save -> list -> load -> materialize round-trip with fake ELFs.
- Large subset: distribution stats, std/percentile selection, and filtering.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import networkx as nx
import pytest

import decbench.caching as caching
from decbench.dataset import (
    BinaryDatasetManifest,
    list_datasets,
    load_dataset,
    materialize,
    save_dataset,
)
from decbench.metrics.byte_match import ByteMatchMetric
from decbench.utils.binfmt import function_bytes as _extract_function_bytes
from decbench.metrics.ged import GEDMetric
from decbench.metrics.type_match import TypeMatchMetric
from decbench.models.decompilation import FunctionDecompilation, VariableInfo
from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
from decbench.models.metrics import MetricValue
from decbench.scoring.subset import (
    SubsetManifest,
    compute_large_subset,
    filter_function_data,
    size_distribution,
)


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Point the cache at a temp dir, enabled, with a clean process-global cache."""
    d = tmp_path / "cache"
    monkeypatch.setenv("DECBENCH_CACHE_DIR", str(d))
    monkeypatch.delenv("DECBENCH_NO_CACHE", raising=False)
    caching._CACHES.clear()
    yield d
    caching._CACHES.clear()


# --------------------------------------------------------------------------- #
# Metric caching
# --------------------------------------------------------------------------- #


def test_metric_value_json_round_trip():
    mv = MetricValue(value=0.5, raw_value=0.5, metadata={"a": 1})
    again = MetricValue(**mv.model_dump(mode="json"))
    assert again.value == mv.value
    assert again.metadata == mv.metadata


def test_ged_caches_second_identical_compute(cache_dir):
    g1 = nx.DiGraph()
    g1.add_edges_from([(0, 1), (1, 2)])
    g2 = nx.DiGraph()
    g2.add_edges_from([(0, 1), (1, 2)])
    fd = FunctionDecompilation(name="f", address=0x1000, decompiled_code="", line_count=0)

    metric = GEDMetric()
    calls = {"n": 0}
    orig = metric._compute_uncached

    def counting(*a, **k):
        calls["n"] += 1
        return orig(*a, **k)

    metric._compute_uncached = counting

    v1 = metric.compute_for_function(fd, source_cfg=g1, decompiled_cfg=g2)
    v2 = metric.compute_for_function(fd, source_cfg=g1, decompiled_cfg=g2)

    assert v1.value == v2.value
    assert calls["n"] == 1, "second identical compute should be cached"

    files = list((cache_dir / "metric").rglob("*.json"))
    assert files, "expected a metric cache file on disk"


def test_ged_cache_hit_across_fresh_instance(cache_dir):
    """A fresh metric instance with an empty in-memory layer hits the disk cache."""
    g1 = nx.DiGraph()
    g1.add_edges_from([(0, 1)])
    g2 = nx.DiGraph()
    g2.add_edges_from([(0, 1)])
    fd = FunctionDecompilation(name="f", address=0x10, decompiled_code="", line_count=0)

    GEDMetric().compute_for_function(fd, source_cfg=g1, decompiled_cfg=g2)

    caching._CACHES.clear()  # drop in-memory layer; force on-disk lookup
    metric2 = GEDMetric()
    calls = {"n": 0}
    orig = metric2._compute_uncached
    metric2._compute_uncached = lambda *a, **k: (
        calls.__setitem__("n", calls["n"] + 1) or orig(*a, **k)
    )
    metric2.compute_for_function(fd, source_cfg=g1, decompiled_cfg=g2)
    assert calls["n"] == 0, "value should come from the on-disk cache"


def test_no_cache_disables_caching(cache_dir, monkeypatch):
    monkeypatch.setenv("DECBENCH_NO_CACHE", "1")
    caching._CACHES.clear()

    g1 = nx.DiGraph()
    g1.add_edges_from([(0, 1)])
    g2 = nx.DiGraph()
    g2.add_edges_from([(0, 1)])
    fd = FunctionDecompilation(name="f", address=0x10, decompiled_code="", line_count=0)

    metric = GEDMetric()
    calls = {"n": 0}
    orig = metric._compute_uncached
    metric._compute_uncached = lambda *a, **k: (
        calls.__setitem__("n", calls["n"] + 1) or orig(*a, **k)
    )
    metric.compute_for_function(fd, source_cfg=g1, decompiled_cfg=g2)
    metric.compute_for_function(fd, source_cfg=g1, decompiled_cfg=g2)
    assert calls["n"] == 2, "DECBENCH_NO_CACHE must disable caching"


def test_type_match_caches(cache_dir):
    fd = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int x;",
        line_count=1,
        variables=[
            VariableInfo(name="a0", type="int", stack_offset=None, size=4, kind="arg", arg_index=0)
        ],
    )
    gt = [
        {
            "name": "n",
            "type": ["int"],
            "rbp_offset": [],
            "size": 4,
            "is_arg": True,
            "arg_index": 0,
        }
    ]

    metric = TypeMatchMetric()
    calls = {"n": 0}
    orig = metric._compute_uncached
    metric._compute_uncached = lambda *a, **k: (
        calls.__setitem__("n", calls["n"] + 1) or orig(*a, **k)
    )

    v1 = metric.compute_for_function(fd, ground_truth_vars=gt, calibration_shift=0)
    v2 = metric.compute_for_function(fd, ground_truth_vars=gt, calibration_shift=0)
    assert v1.value == v2.value == 1.0
    assert calls["n"] == 1


def test_byte_match_caches_with_real_binary(cache_dir, tmp_path):
    import shutil as _shutil

    if _shutil.which("gcc") is None:
        pytest.skip("gcc not available")

    src = tmp_path / "bm.c"
    src.write_text("int add(int a, int b){return a+b;}\n")
    obj = tmp_path / "bm.o"
    import subprocess

    rc = subprocess.run(["gcc", "-O2", "-g", "-c", "-o", str(obj), str(src)], capture_output=True)
    if rc.returncode != 0 or not obj.exists():
        pytest.skip("gcc compilation failed")

    if _extract_function_bytes(obj, "add", 0) is None:
        pytest.skip("could not extract function bytes from object")

    fd = FunctionDecompilation(
        name="add",
        address=0,
        decompiled_code="int add(int a, int b){return a+b;}",
        line_count=1,
    )
    metric = ByteMatchMetric()
    calls = {"n": 0}
    orig = metric._compute_uncached
    metric._compute_uncached = lambda *a, **k: (
        calls.__setitem__("n", calls["n"] + 1) or orig(*a, **k)
    )

    v1 = metric.compute_for_function(fd, original_binary_path=obj)
    v2 = metric.compute_for_function(fd, original_binary_path=obj)
    assert v1.value == v2.value
    assert calls["n"] == 1


# --------------------------------------------------------------------------- #
# Binary dataset store
# --------------------------------------------------------------------------- #


def _fake_elf(path: Path, body: bytes) -> None:
    """Write a minimal ELF header (ET_EXEC) plus a payload body."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = b"\x7fELF" + b"\x00" * 12 + struct.pack("<H", 2) + body
    path.write_bytes(data)


@pytest.fixture
def fake_results(tmp_path) -> Path:
    results = tmp_path / "results"
    c1 = results / "O0" / "projA" / "compiled"
    _fake_elf(c1 / "bin1", b"AAAA")
    (c1 / "src1.i").write_text("int main(){return 0;}\n")
    (c1 / "src1.c").write_text("ignored\n")
    (c1 / "notelf.txt").write_text("not an elf")

    c2 = results / "O2" / "projA" / "compiled"
    _fake_elf(c2 / "bin2", b"BBBBBB")
    return results


def test_save_dataset_records_binaries_and_sources(fake_results, tmp_path):
    store = tmp_path / "store"
    manifest = save_dataset(fake_results, "myset", store_root=store)

    assert isinstance(manifest, BinaryDatasetManifest)
    assert len(manifest.binaries) == 2
    assert set(manifest.compile_sets()) == {("projA", "O0"), ("projA", "O2")}

    entry1 = next(e for e in manifest.binaries if e.stem == "bin1")
    expected = hashlib.sha256(
        (fake_results / "O0" / "projA" / "compiled" / "bin1").read_bytes()
    ).hexdigest()
    assert entry1.sha256 == expected
    assert entry1.size == (fake_results / "O0" / "projA" / "compiled" / "bin1").stat().st_size
    assert entry1.source_relpaths, "expected .i sources recorded"
    assert (store / "myset" / "manifest.json").is_file()


def test_list_and_load_dataset(fake_results, tmp_path):
    store = tmp_path / "store"
    save_dataset(fake_results, "myset", store_root=store)

    listing = list_datasets(store_root=store)
    assert listing == [{"name": "myset", "binaries": 2, "compile_sets": 2}]

    loaded = load_dataset("myset", store_root=store)
    assert len(loaded.binaries) == 2


def test_materialize_round_trip(fake_results, tmp_path):
    store = tmp_path / "store"
    save_dataset(fake_results, "myset", store_root=store)

    dest = tmp_path / "out"
    materialize("myset", dest, store_root=store)

    mat_bin1 = dest / "O0" / "projA" / "compiled" / "bin1"
    mat_src1 = dest / "O0" / "projA" / "compiled" / "src1.i"
    mat_bin2 = dest / "O2" / "projA" / "compiled" / "bin2"
    assert mat_bin1.is_file()
    assert mat_src1.is_file()
    assert mat_bin2.is_file()

    orig = fake_results / "O0" / "projA" / "compiled" / "bin1"
    assert (
        hashlib.sha256(mat_bin1.read_bytes()).hexdigest()
        == hashlib.sha256(orig.read_bytes()).hexdigest()
    )


def test_load_missing_dataset_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_dataset("nope", store_root=tmp_path / "store")


# --------------------------------------------------------------------------- #
# Large-function subset
# --------------------------------------------------------------------------- #


def _make_function_data() -> FunctionData:
    sizes = {"a": 5, "b": 7, "c": 6, "d": 8, "e": 4, "big1": 200, "big2": 150}
    group = BinaryGroup(
        project="proj",
        opt_level="O0",
        binary="bin",
        functions=[FunctionRecord(function=n, size=s) for n, s in sizes.items()],
    )
    group2 = BinaryGroup(
        project="proj",
        opt_level="O2",
        binary="bin2",
        functions=[
            FunctionRecord(function="x", size=6),
            FunctionRecord(function="nosize", size=None),
        ],
    )
    return FunctionData(
        schema_version=2,
        decompilers=["angr"],
        metrics=["ged"],
        perfect_values={"ged": 0.0},
        groups=[group, group2],
    )


def test_size_distribution_ignores_none():
    fd = _make_function_data()
    dist = size_distribution(fd)
    assert dist["count"] == 8  # the None-size record is excluded
    assert dist["min"] == 4
    assert dist["max"] == 200
    assert dist["p90"] >= dist["p50"]


def test_size_distribution_empty():
    fd = FunctionData(schema_version=2, groups=[])
    dist = size_distribution(fd)
    assert dist["count"] == 0
    assert dist["mean"] == 0.0


def test_compute_large_subset_std_picks_outliers():
    fd = _make_function_data()
    sub = compute_large_subset(fd, method="std", k=1.0)
    names = {f["function"] for f in sub.functions}
    assert "big1" in names and "big2" in names
    assert "a" not in names and "e" not in names
    assert sub.method == "std" and sub.k == 1.0


def test_compute_large_subset_percentile():
    fd = _make_function_data()
    sub = compute_large_subset(fd, method="percentile", k=90)
    assert sub.functions
    assert all(f["function"] in {"big1", "big2"} for f in sub.functions)


def test_compute_large_subset_bad_method():
    fd = _make_function_data()
    with pytest.raises(ValueError):
        compute_large_subset(fd, method="bogus")


def test_filter_function_data_shrinks_and_drops_empty():
    fd = _make_function_data()
    sub = compute_large_subset(fd, method="std", k=1.0)
    filtered = filter_function_data(fd, sub)

    remaining = [(g.binary, r.function) for g in filtered.groups for r in g.functions]
    assert all(name in {"big1", "big2"} for _, name in remaining)
    # bin2 had no large functions -> its group is dropped.
    assert all(g.binary == "bin" for g in filtered.groups)
    # Top-level metadata is preserved.
    assert filtered.decompilers == ["angr"]
    assert filtered.perfect_values == {"ged": 0.0}


def test_subset_manifest_json_round_trip(tmp_path):
    fd = _make_function_data()
    sub = compute_large_subset(fd, method="std", k=1.0)
    p = tmp_path / "sub.json"
    sub.to_json(p)
    back = SubsetManifest.from_json(p)
    assert back.threshold == sub.threshold
    assert len(back.functions) == len(sub.functions)
