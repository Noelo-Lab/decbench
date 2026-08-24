#!/usr/bin/env python
"""Partition a TypeMatch manifest without splitting binary-wide calibration groups."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import tempfile
from pathlib import Path

from decbench.scoring.typematch_ab import file_sha256, keyset_sha256, load_manifest
from decbench.scoring.typematch_sharding import (
    SHARD_METHOD,
    audit_manifest_shards,
    binary_key,
    partition_manifest_by_binary,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="complete selected-function manifest")
    parser.add_argument("output_dir", type=Path, help="new directory for manifests and index")
    parser.add_argument("--shards", type=int, required=True, help="positive shard count")
    parser.add_argument("--force", action="store_true", help="replace existing generated files")
    return parser.parse_args(argv)


def _write_json_atomic(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def _function_row(key: tuple[str, str, str, str]) -> dict[str, str]:
    project, optimization, binary, function = key
    return {
        "project": project,
        "opt": optimization,
        "binary": binary,
        "function": function,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.shards < 1:
        raise SystemExit("error: --shards must be positive")

    source = args.manifest.resolve()
    expected = load_manifest(source)
    partition = partition_manifest_by_binary(expected, args.shards)
    audit = audit_manifest_shards(expected, partition)
    if not audit.valid or audit.selected_key_sha256 != keyset_sha256(expected):
        raise RuntimeError(f"internal manifest partition audit failed: {audit.to_dict()}")

    output_dir = args.output_dir.resolve()
    manifests_dir = output_dir / "manifests"
    targets = [manifests_dir / f"shard{index:02d}.json" for index in range(1, args.shards + 1)]
    targets.append(output_dir / "manifest_index.json")
    existing = [path for path in targets if path.exists()]
    if existing and not args.force:
        names = ", ".join(str(path) for path in existing[:3])
        raise SystemExit(f"error: generated files already exist ({names}); pass --force to replace")

    source_sha256 = file_sha256(source)
    shard_rows: list[dict[str, object]] = []
    for index, keys in enumerate(partition, start=1):
        path = manifests_dir / f"shard{index:02d}.json"
        payload = {
            "binary_count": len({binary_key(key) for key in keys}),
            "functions": [_function_row(key) for key in keys],
            "method": SHARD_METHOD,
            "selected_key_sha256": keyset_sha256(keys),
            "shard": index,
            "shard_count": args.shards,
            "source_manifest_sha256": source_sha256,
        }
        _write_json_atomic(path, payload)
        shard_rows.append(
            {
                "binary_count": payload["binary_count"],
                "function_count": len(keys),
                "manifest": str(path.relative_to(output_dir)),
                "manifest_sha256": file_sha256(path),
                "selected_key_sha256": payload["selected_key_sha256"],
                "shard": index,
            }
        )

    index_payload = {
        **audit.to_dict(),
        "shards": shard_rows,
        "source_manifest": str(source),
        "source_manifest_sha256": source_sha256,
    }
    _write_json_atomic(output_dir / "manifest_index.json", index_payload)
    print(
        f"wrote {args.shards} whole-binary shards: {audit.function_count} functions, "
        f"{audit.binary_count} binaries, key_sha256={audit.selected_key_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
