from __future__ import annotations

import json
from pathlib import Path

import pytest

from decbench.scoring.typematch_ab import keyset_sha256, load_manifest
from decbench.scoring.typematch_sharding import (
    audit_manifest_shards,
    partition_manifest_by_binary,
)
from scripts.shard_typematch_manifest import main


def _keys() -> set[tuple[str, str, str, str]]:
    return (
        {("alpha", "O0", "large", f"f{index}") for index in range(7)}
        | {("alpha", "O2", "medium", f"g{index}") for index in range(4)}
        | {
            ("beta", "O0", "small", "only"),
            ("beta", "O2", "small", "only"),
        }
    )


def _write_manifest(path: Path, keys: set[tuple[str, str, str, str]]) -> None:
    rows = [
        {"project": project, "opt": opt, "binary": binary, "function": function}
        for project, opt, binary, function in sorted(keys)
    ]
    path.write_text(json.dumps({"functions": rows}))


def test_binary_local_partition_is_deterministic_balanced_and_exact() -> None:
    keys = _keys()
    first = partition_manifest_by_binary(keys, 3)
    second = partition_manifest_by_binary(reversed(sorted(keys)), 3)

    assert first == second
    assert sorted(map(len, first)) == [2, 4, 7]
    audit = audit_manifest_shards(keys, first)
    assert audit.valid
    assert audit.binary_split_count == 0
    assert audit.selected_key_sha256 == keyset_sha256(keys)


def test_shard_audit_rejects_overlap_missing_unexpected_and_binary_split() -> None:
    keys = _keys()
    large = sorted(key for key in keys if key[2] == "large")
    shards = (
        tuple(large[:3]) + (("extra", "O0", "binary", "function"),),
        tuple(large[3:]) + (large[0],),
    )

    audit = audit_manifest_shards(keys, shards)
    assert not audit.valid
    assert audit.overlap_count == 1
    assert audit.missing_count == len(keys) - len(large)
    assert audit.unexpected_count == 1
    assert audit.binary_split_count == 1


def test_partition_rejects_empty_duplicate_and_invalid_shard_inputs() -> None:
    key = ("project", "O0", "binary", "function")
    with pytest.raises(ValueError, match="no function keys"):
        partition_manifest_by_binary([], 2)
    with pytest.raises(ValueError, match="duplicate function keys"):
        partition_manifest_by_binary([key, key], 2)
    with pytest.raises(ValueError, match="positive"):
        partition_manifest_by_binary([key], 0)


def test_cli_writes_self_auditing_whole_binary_manifests(tmp_path: Path) -> None:
    source = tmp_path / "selected.json"
    output = tmp_path / "partition"
    keys = _keys()
    _write_manifest(source, keys)

    assert main([str(source), str(output), "--shards", "3"]) == 0
    index = json.loads((output / "manifest_index.json").read_text())
    shards = [load_manifest(output / row["manifest"]) for row in index["shards"]]

    assert index["valid"] is True
    assert index["binary_split_count"] == 0
    assert index["selected_key_sha256"] == keyset_sha256(keys)
    assert audit_manifest_shards(keys, shards).valid
