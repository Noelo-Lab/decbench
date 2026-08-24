"""Whole-binary manifest sharding for reproducible TypeMatch re-evaluation."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from decbench.scoring.typematch_ab import FunctionKey, keyset_sha256

BinaryKey = tuple[str, str, str]
SHARD_METHOD = "binary-indivisible-deterministic-lpt"
SHARD_SCHEMA = "decbench-binary-indivisible-shards-v1"


def binary_key(function_key: FunctionKey) -> BinaryKey:
    """Return the project/optimization/binary calibration identity."""

    return function_key[:3]


@dataclass(frozen=True)
class ManifestShardAudit:
    """Coverage and whole-binary invariants for one manifest partition."""

    function_count: int
    binary_count: int
    overlap_count: int
    missing_count: int
    unexpected_count: int
    binary_split_count: int
    selected_key_sha256: str

    @property
    def valid(self) -> bool:
        return not any(
            (
                self.overlap_count,
                self.missing_count,
                self.unexpected_count,
                self.binary_split_count,
            )
        )

    def to_dict(self) -> dict[str, int | str | bool]:
        return {
            "schema": SHARD_SCHEMA,
            "method": SHARD_METHOD,
            "function_count": self.function_count,
            "binary_count": self.binary_count,
            "overlap_count": self.overlap_count,
            "missing_count": self.missing_count,
            "unexpected_count": self.unexpected_count,
            "binary_split_count": self.binary_split_count,
            "selected_key_sha256": self.selected_key_sha256,
            "exact_union": not self.missing_count and not self.unexpected_count,
            "valid": self.valid,
        }


def partition_manifest_by_binary(
    keys: Iterable[FunctionKey],
    shard_count: int,
) -> tuple[tuple[FunctionKey, ...], ...]:
    """Assign complete binaries to deterministic least-loaded shards."""

    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    rows = tuple(keys)
    unique = set(rows)
    if not unique:
        raise ValueError("manifest has no function keys")
    if len(rows) != len(unique):
        raise ValueError("manifest contains duplicate function keys")

    groups: dict[BinaryKey, list[FunctionKey]] = defaultdict(list)
    for key in unique:
        groups[binary_key(key)].append(key)
    if shard_count > len(groups):
        raise ValueError(f"shard_count ({shard_count}) exceeds binary group count ({len(groups)})")

    shards: list[list[FunctionKey]] = [[] for _ in range(shard_count)]
    loads = [0] * shard_count
    ordered_groups = sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))
    for _, group in ordered_groups:
        shard_index = min(range(shard_count), key=lambda index: (loads[index], index))
        shards[shard_index].extend(group)
        loads[shard_index] += len(group)

    return tuple(tuple(sorted(shard)) for shard in shards)


def audit_manifest_shards(
    expected: Iterable[FunctionKey],
    shards: Sequence[Iterable[FunctionKey]],
) -> ManifestShardAudit:
    """Validate exact coverage and forbid a binary from spanning shards."""

    expected_keys = set(expected)
    occurrences: Counter[FunctionKey] = Counter()
    binary_shards: dict[BinaryKey, set[int]] = defaultdict(set)
    for shard_index, shard in enumerate(shards):
        for key in shard:
            occurrences[key] += 1
            binary_shards[binary_key(key)].add(shard_index)

    actual_keys = set(occurrences)
    return ManifestShardAudit(
        function_count=len(actual_keys),
        binary_count=len({binary_key(key) for key in expected_keys}),
        overlap_count=sum(count - 1 for count in occurrences.values() if count > 1),
        missing_count=len(expected_keys - actual_keys),
        unexpected_count=len(actual_keys - expected_keys),
        binary_split_count=sum(len(indices) > 1 for indices in binary_shards.values()),
        selected_key_sha256=keyset_sha256(actual_keys),
    )
