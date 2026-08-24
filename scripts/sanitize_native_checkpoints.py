#!/usr/bin/env python
"""Create an atomic, sanitized copy of benchmark checkpoint pickles.

The source results tree and its canonical ``checkpoints/`` directory are never
modified. The output directory must not already exist; it is published only
after every selected checkpoint has been loaded, relocated to the source tree's
compiled binaries, sanitized, and serialized successfully.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import shutil
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import decbench.decompilers  # noqa: F401
from decbench.decompilers.provenance import SANITIZER_SCHEMA, sanitize_native_provenance
from decbench.models.decompilation import DecompilationResult
from decbench.utils.results_tree import compiled_dir, resolve_binary

COPY_SCHEMA = "decbench-native-provenance-checkpoint-copy-v1"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_root", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "projects",
        nargs="*",
        help="checkpoint project stems to copy (default: every checkpoint)",
    )
    return parser.parse_args(argv)


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checkpoint_paths(results_root: Path, projects: Sequence[str]) -> list[Path]:
    checkpoint_dir = results_root / "checkpoints"
    if projects:
        if len(projects) != len(set(projects)) or any(
            not name or Path(name).name != name for name in projects
        ):
            raise ValueError("project names must be unique checkpoint stems")
        paths = [checkpoint_dir / f"{name}.pkl" for name in projects]
    else:
        paths = sorted(checkpoint_dir.glob("*.pkl"))
    if not paths:
        raise ValueError(f"no checkpoint pickles found under {checkpoint_dir}")
    missing = [path for path in paths if not path.is_file() or path.is_symlink()]
    if missing:
        raise ValueError(f"checkpoint is missing or not a regular file: {missing[0]}")
    return paths


def _load_checkpoint(path: Path) -> dict[Any, Any]:
    try:
        with path.open("rb") as stream:
            payload = pickle.load(stream)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"could not load checkpoint {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("decompile"), Mapping):
        raise ValueError(f"checkpoint has no decompile mapping: {path}")
    return payload


def _sanitize_checkpoint(
    payload: dict[Any, Any],
    results_root: Path,
    project: str,
) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    totals: Counter[str] = Counter()
    result_count = 0
    skipped_results = 0
    for optimization, binaries in payload["decompile"].items():
        if not isinstance(binaries, Mapping):
            raise ValueError(f"{project}: malformed decompile optimization mapping")
        opt_name = str(getattr(optimization, "value", optimization))
        directory = compiled_dir(results_root, opt_name, project)
        for binary_name, decompilers in binaries.items():
            if not isinstance(decompilers, Mapping):
                raise ValueError(f"{project}/{opt_name}/{binary_name}: malformed backend mapping")
            name = str(binary_name)
            binary_path = resolve_binary(directory, name) or directory / name
            for backend, result in decompilers.items():
                if not isinstance(result, DecompilationResult):
                    raise ValueError(
                        f"{project}/{opt_name}/{binary_name}/{backend}: "
                        "checkpoint value is not a DecompilationResult"
                    )
                result.binary_path = binary_path
                metadata = sanitize_native_provenance(result, binary_path)
                result_count += 1
                status_counts[str(metadata["status"])] += 1
                for key, value in metadata.items():
                    if key.endswith("_dropped") and isinstance(value, int):
                        totals[key] += value
    return {
        "results_sanitized": result_count,
        "results_skipped": skipped_results,
        "status_counts": dict(sorted(status_counts.items())),
        "drop_totals": dict(sorted(totals.items())),
    }


def create_sanitized_copy(
    results_root: Path,
    output_dir: Path,
    *,
    projects: Sequence[str] = (),
) -> dict[str, Any]:
    """Sanitize selected checkpoints and atomically publish a new directory."""

    root = results_root.resolve()
    checkpoint_dir = (root / "checkpoints").resolve()
    output = output_dir.resolve()
    if output.exists() or output.is_symlink():
        raise ValueError(f"output directory already exists: {output}")
    if _inside(output, checkpoint_dir):
        raise ValueError("output directory must be outside the canonical checkpoints directory")
    paths = _checkpoint_paths(root, projects)
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    checkpoint_rows: list[dict[str, Any]] = []
    try:
        for source in paths:
            payload = _load_checkpoint(source)
            summary = _sanitize_checkpoint(payload, root, source.stem)
            destination = stage / source.name
            with destination.open("wb") as stream:
                pickle.dump(payload, stream)
                stream.flush()
                os.fsync(stream.fileno())
            checkpoint_rows.append(
                {
                    "project": source.stem,
                    "source_sha256": _sha256(source),
                    "output_sha256": _sha256(destination),
                    **summary,
                }
            )
        manifest = {
            "schema": COPY_SCHEMA,
            "sanitizer_schema": SANITIZER_SCHEMA,
            "source_results_root": str(root),
            "checkpoints": checkpoint_rows,
        }
        manifest_path = stage / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        with manifest_path.open("rb") as stream:
            os.fsync(stream.fileno())
        if output.exists() or output.is_symlink():
            raise ValueError(f"output directory appeared during copy: {output}")
        os.replace(stage, output)
        return manifest
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        manifest = create_sanitized_copy(
            args.results_root,
            args.output_dir,
            projects=args.projects,
        )
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print(f"native checkpoint sanitization failed: {exc}")
        return 2
    count = len(manifest["checkpoints"])
    print(f"wrote {count} sanitized checkpoint(s) to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
