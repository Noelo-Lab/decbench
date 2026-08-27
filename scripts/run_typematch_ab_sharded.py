#!/usr/bin/env python
"""Run a digest-bound, resumable, non-canonical TypeMatch v11 A/B evaluation.

The driver partitions a frozen function manifest by whole binary, evaluates
each backend/mode/shard in an isolated subprocess, validates every overlay
against the checkpoint-derived expected key set, and only then merges and
reports the four production matcher modes.  All outputs live below the
explicit analysis directory; this script never promotes a canonical overlay.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import pickle
import platform
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from decbench.metrics.base import MetricConfig  # noqa: E402
from decbench.metrics.type_match import TypeMatchMetric  # noqa: E402
from decbench.models.decompilation import VARIABLE_OCCURRENCE_POLICY_SCHEMA  # noqa: E402
from decbench.rendering.content import load_content  # noqa: E402
from decbench.rendering.visibility import is_hidden  # noqa: E402
from decbench.results_store import (  # noqa: E402
    TypeMatchOverlayError,
    read_typematch_overlay,
    typematch_overlay_manifest_path,
    typematch_overlay_provenance,
    write_typematch_overlay_atomic,
)
from decbench.scoring.typematch_ab import (  # noqa: E402
    _producer_evidence_sha256,
    file_sha256,
    key_text,
    keyset_sha256,
    load_manifest,
    load_producer_evidence,
)
from decbench.scoring.typematch_sharding import audit_manifest_shards  # noqa: E402
from decbench.utils.langs import preprocessed_by_stem  # noqa: E402
from scripts.reeval_typematch import (  # noqa: E402
    _function_data_scope,
    _resolve_checkpoint_binary,
    _validate_checkpoint_decompilation,
)

FunctionKey = tuple[str, str, str, str]
ScoreKey = tuple[str, str, str, str, str]

MODES = ("address", "usage", "address+usage", "auto")
RUN_SCOPES = ("full", "sample-set", "experimental-full")
RUN_PLAN_SCHEMA = "decbench-typematch-ab-sharded-plan-v2"
JOB_RECEIPT_SCHEMA = "decbench-typematch-ab-sharded-job-v2"
FINAL_RECEIPT_SCHEMA = "decbench-typematch-ab-sharded-result-v3"
PROCESS_RECORD_SCHEMA = "decbench-typematch-ab-worker-process-v1"
MERGE_RECEIPT_SCHEMA = "decbench-typematch-ab-merge-v1"
REPORT_RECEIPT_SCHEMA = "decbench-typematch-ab-report-v2"
MAX_WORKERS = 32
DEFAULT_JOB_TIMEOUT_SECONDS = 6 * 60 * 60
PROCESS_TERMINATION_SECONDS = 5.0
_PROCESS_RECORD_FIELDS = {
    "schema",
    "attempt_id",
    "job",
    "command",
    "pid",
    "pgid",
    "proc_start_ticks",
    "status",
    "returncode",
    "timed_out",
}

_ORCHESTRATED_SCRIPTS = (
    "scripts/run_typematch_ab_sharded.py",
    "scripts/shard_typematch_manifest.py",
    "scripts/reeval_typematch.py",
    "scripts/report_typematch_ab.py",
)
_KNOWN_METRIC_WARNING_PREFIXES = (
    "No DWARF ground truth types for ",
    "type_match scored 0 for all matched functions in ",
)
_RUNTIME_ENVIRONMENT_KEYS = (
    "PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONNOUSERSITE",
    "PYTHONOPTIMIZE",
    "PYTHONSAFEPATH",
    "PYTHONUSERBASE",
    "VIRTUAL_ENV",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
)
_RUNTIME_MODULES = (
    "capstone",
    "declib",
    "elftools",
    "networkx",
    "pycparser",
    "pydantic",
    "pydantic_core",
    "tree_sitter",
    "tree_sitter_c",
)


class ShardedTypeMatchError(RuntimeError):
    """Raised when an A/B run cannot be continued without mixing evidence."""


class IncompleteWorkerAttempt(ShardedTypeMatchError):
    """Raised when unreceipted worker artifacts must be preserved before retry."""


@dataclass(frozen=True)
class WorkerJob:
    """One backend/mode/whole-binary-shard replay."""

    backend: str
    mode: str
    shard: int
    manifest: Path
    function_data: Path
    manifest_sha256: str
    selected_key_sha256: str
    expected: frozenset[ScoreKey]
    output: Path
    stdout_log: Path
    stderr_log: Path
    cache_dir: Path
    process_record: Path
    receipt: Path
    attempts_dir: Path

    @property
    def label(self) -> str:
        return f"{self.backend}/{self.mode}/shard{self.shard:02d}"


@dataclass(frozen=True)
class WorkerOutcome:
    """Captured result from an isolated reevaluation subprocess."""

    label: str
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


@dataclass(frozen=True)
class WorkerAttempt:
    """Attempt-unique paths that cannot be reused by a later retry."""

    attempt_id: str
    directory: Path
    output: Path
    stdout_log: Path
    stderr_log: Path
    cache_dir: Path
    process_record: Path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_dir", type=Path, help="frozen results tree")
    parser.add_argument("manifest", type=Path, help="fixed selected-function manifest")
    parser.add_argument("output_dir", type=Path, help="new non-canonical analysis directory")
    parser.add_argument(
        "--function-data",
        type=Path,
        help=(
            "explicit frozen function_results.json denominator "
            "(default: RESULTS_DIR/function_results.json)"
        ),
    )
    parser.add_argument(
        "--scope",
        choices=RUN_SCOPES,
        required=True,
        help="declared denominator policy; full and sample-set runs use separate plans",
    )
    parser.add_argument("--shards", type=int, default=8, help="whole-binary shard count")
    parser.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument(
        "--backend",
        action="append",
        default=[],
        help="exact backend id to score; repeatable (default: every backend in scope)",
    )
    parser.add_argument(
        "--job-timeout",
        type=int,
        default=DEFAULT_JOB_TIMEOUT_SECONDS,
        help="hard wall-clock seconds per backend/mode/shard subprocess",
    )
    parser.add_argument("--regression-limit", type=int, default=100)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print the plan without writing or evaluating",
    )
    args = parser.parse_args(argv)
    if args.shards < 1:
        parser.error("--shards must be positive")
    if not 1 <= args.workers <= MAX_WORKERS:
        parser.error(f"--workers must be between 1 and {MAX_WORKERS}")
    if args.job_timeout < 1:
        parser.error("--job-timeout must be positive")
    if args.regression_limit < 0:
        parser.error("--regression-limit must be non-negative")
    if len(args.backend) != len(set(args.backend)):
        parser.error("--backend values must be unique")
    return args


def _json_bytes(payload: object, *, pretty: bool = True) -> bytes:
    if pretty:
        return (json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    return json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True).encode()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_bytes_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json_atomic(path: Path, payload: object) -> None:
    _write_bytes_atomic(path, _json_bytes(payload))


def _stable_file_record(path: Path, *, relative_to: Path | None = None) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ShardedTypeMatchError(f"input is not a regular file: {resolved}")
    before = resolved.stat()
    digest = file_sha256(resolved)
    after = resolved.stat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise ShardedTypeMatchError(f"input changed while it was hashed: {resolved}")
    if relative_to is not None:
        try:
            name = str(resolved.relative_to(relative_to.resolve()))
        except ValueError:
            name = str(resolved)
    else:
        name = str(resolved)
    return {"path": name, "sha256": digest, "size": after.st_size}


def _score_key_sha256(keys: Iterable[ScoreKey]) -> str:
    rows = [list(key) for key in sorted(keys)]
    return _sha256_bytes(_json_bytes(rows, pretty=False))


def _overlay_score_keys(payload: Mapping[str, Mapping[str, object]]) -> set[ScoreKey]:
    keys: set[ScoreKey] = set()
    for backend, per_backend in payload.items():
        for raw_key in per_backend:
            parts = raw_key.split("::", 3)
            if len(parts) != 4 or any(not part for part in parts):
                raise ShardedTypeMatchError(f"invalid overlay key {backend}/{raw_key!r}")
            keys.add((parts[0], parts[1], parts[2], parts[3], str(backend)))
    return keys


def _metric_provenance(mode: str) -> dict[str, Any]:
    metric = TypeMatchMetric(MetricConfig(extra_options={"variable_match_mode": mode}))
    try:
        cache_version = int(str(metric.cache_version))
    except ValueError:
        cache_version = -1
    if cache_version < 11:
        raise ShardedTypeMatchError(
            f"this driver requires TypeMatch cache version >= 11, got {metric.cache_version!r}"
        )
    return typematch_overlay_provenance(
        mode=mode,
        resolved_mode="address+usage" if mode == "auto" else mode,
        policy=metric.variable_match_policy,
        metric_cache_version=metric.cache_version,
        structured_occurrence_mode="producer",
        variable_occurrence_policy_schema=VARIABLE_OCCURRENCE_POLICY_SCHEMA,
    )


def _code_inventory() -> list[dict[str, object]]:
    paths = set((_REPO_ROOT / "decbench").rglob("*.py"))
    paths.update(_REPO_ROOT / relative for relative in _ORCHESTRATED_SCRIPTS)
    paths.add(_REPO_ROOT / "pyproject.toml")
    return [
        _stable_file_record(path, relative_to=_REPO_ROOT)
        for path in sorted(paths, key=lambda item: str(item.relative_to(_REPO_ROOT)))
    ]


def _canonical_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _distribution_inventory() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for distribution in importlib.metadata.distributions():
        name = str(distribution.metadata.get("Name") or "")
        if not name:
            continue
        record: dict[str, object] = {
            "name": _canonical_distribution_name(name),
            "version": str(distribution.version),
        }
        metadata_files: list[dict[str, object]] = []
        wanted = {"METADATA", "RECORD", "direct_url.json"}
        for package_path in distribution.files or ():
            if Path(str(package_path)).name not in wanted:
                continue
            candidate = Path(str(distribution.locate_file(package_path)))
            if candidate.is_file() and not candidate.is_symlink():
                metadata_files.append(_stable_file_record(candidate))
        record["metadata_files"] = sorted(metadata_files, key=lambda row: str(row["path"]))
        rows.append(record)
    return sorted(
        rows,
        key=lambda row: (
            str(row["name"]),
            str(row["version"]),
            _json_bytes(row, pretty=False),
        ),
    )


def _module_inventory() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    suffixes = {".dll", ".dylib", ".json", ".py", ".pyi", ".pyd", ".so"}
    for module in _RUNTIME_MODULES:
        spec = importlib.util.find_spec(module)
        if spec is None:
            rows.append({"module": module, "status": "missing"})
            continue
        candidates: set[Path] = set()
        if spec.origin and spec.origin not in {"built-in", "frozen"}:
            candidates.add(Path(spec.origin))
        for location in spec.submodule_search_locations or ():
            root = Path(location)
            candidates.update(
                path
                for path in root.rglob("*")
                if "__pycache__" not in path.parts and path.suffix in suffixes
            )
        files = [
            _stable_file_record(path)
            for path in sorted(candidates)
            if path.is_file() and not path.is_symlink()
        ]
        rows.append(
            {
                "module": module,
                "status": "available",
                "file_count": len(files),
                "byte_count": sum(int(row["size"]) for row in files),
                "inventory_sha256": _sha256_bytes(_json_bytes(files, pretty=False)),
            }
        )
    return rows


def _subprocess_environment(
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(_REPO_ROOT)
        if not existing_pythonpath
        else os.pathsep.join((str(_REPO_ROOT), existing_pythonpath))
    )
    environment["PYTHONHASHSEED"] = "0"
    if overrides is not None:
        environment.update(overrides)
    return environment


def _runtime_inventory() -> dict[str, object]:
    environment = _subprocess_environment({"DECBENCH_NO_CACHE": "0"})
    return {
        "python": {
            "command": sys.executable,
            "executable": _stable_file_record(Path(sys.executable)),
            "version": sys.version,
            "implementation": platform.python_implementation(),
            "build": list(platform.python_build()),
            "prefix": sys.prefix,
            "base_prefix": sys.base_prefix,
            "flags": repr(sys.flags),
            "sys_path": list(sys.path),
        },
        "platform": platform.platform(),
        "machine": platform.machine(),
        "environment": {
            key: environment[key] for key in _RUNTIME_ENVIRONMENT_KEYS if key in environment
        }
        | {
            "DECBENCH_NO_CACHE": "0",
            "PYTHONHASHSEED": "0",
        },
        "distributions": _distribution_inventory(),
        "modules": _module_inventory(),
    }


def _load_checkpoint(path: Path) -> Mapping[str, Any]:
    import decbench.decompilers  # noqa: F401

    try:
        with path.open("rb") as stream:
            payload = pickle.load(stream)
    except Exception as exc:  # noqa: BLE001
        raise ShardedTypeMatchError(f"could not load checkpoint {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ShardedTypeMatchError(f"checkpoint is not a mapping: {path}")
    return payload


def _normalized_decompile(checkpoint: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    raw = checkpoint.get("decompile", {})
    if not isinstance(raw, Mapping):
        raise ShardedTypeMatchError("checkpoint decompile payload is not a mapping")
    normalized: dict[str, Mapping[str, Any]] = {}
    for optimization, binaries in raw.items():
        opt = str(getattr(optimization, "value", optimization))
        if opt in normalized:
            raise ShardedTypeMatchError(f"checkpoint repeats optimization level {opt!r}")
        if not isinstance(binaries, Mapping):
            raise ShardedTypeMatchError(f"checkpoint optimization {opt!r} is not a mapping")
        normalized[opt] = binaries
    return normalized


def _selected_source_inventory(
    root: Path,
    selected: set[FunctionKey],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    binaries: list[dict[str, object]] = []
    sources: list[dict[str, object]] = []
    binary_groups = sorted({key[:3] for key in selected})
    for project, optimization, binary in binary_groups:
        path = _resolve_checkpoint_binary(root, optimization, project, binary)
        row = _stable_file_record(path, relative_to=root)
        row.update({"project": project, "opt": optimization, "binary": binary})
        binaries.append(row)

    source_groups = sorted({(key[0], key[1]) for key in selected})
    seen: set[Path] = set()
    for project, optimization in source_groups:
        compiled = root / optimization / project / "compiled"
        for path in sorted(preprocessed_by_stem(compiled).values()):
            resolved = path.resolve(strict=True)
            if resolved in seen:
                continue
            seen.add(resolved)
            row = _stable_file_record(resolved, relative_to=root)
            row.update({"project": project, "opt": optimization})
            sources.append(row)
    return binaries, sources


def _checkpoint_scope(
    root: Path,
    selected: set[FunctionKey],
    measurable: set[FunctionKey],
    requested_backends: Sequence[str],
) -> tuple[
    list[str],
    list[dict[str, object]],
    dict[str, set[ScoreKey]],
]:
    projects = sorted({key[0] for key in selected})
    checkpoint_inventory: list[dict[str, object]] = []
    available: set[str] = set()
    expected_candidates: defaultdict[str, set[ScoreKey]] = defaultdict(set)
    selected_functions: defaultdict[tuple[str, str, str], set[str]] = defaultdict(set)
    for project, optimization, binary, function in selected:
        selected_functions[(project, optimization, binary)].add(function)

    for project in projects:
        path = root / "checkpoints" / f"{project}.pkl"
        if not path.is_file() or path.is_symlink():
            raise ShardedTypeMatchError(f"missing regular checkpoint: {path}")
        checkpoint_inventory.append(_stable_file_record(path, relative_to=root))
        normalized = _normalized_decompile(_load_checkpoint(path))
        project_groups = [
            (optimization, binary, functions)
            for (group_project, optimization, binary), functions in selected_functions.items()
            if group_project == project
        ]
        for optimization, binary, functions in sorted(project_groups):
            per_backend = normalized.get(optimization, {}).get(binary, {})
            if not isinstance(per_backend, Mapping):
                raise ShardedTypeMatchError(
                    f"checkpoint slice {project}/{optimization}/{binary} is not a mapping"
                )
            if any(not isinstance(backend, str) for backend in per_backend):
                raise ShardedTypeMatchError(
                    f"checkpoint slice {project}/{optimization}/{binary} has a non-string "
                    "backend id"
                )
            normalized_backends = dict(per_backend)
            if len(normalized_backends) != len(per_backend):
                raise ShardedTypeMatchError(
                    f"checkpoint slice {project}/{optimization}/{binary} repeats a backend id"
                )
            available.update(normalized_backends)
            candidate_backends = requested_backends or tuple(normalized_backends)
            for backend in candidate_backends:
                result = normalized_backends.get(backend)
                if result is None:
                    continue
                try:
                    validated = _validate_checkpoint_decompilation(
                        result,
                        binary_name=binary,
                        backend_name=backend,
                        coordinate=f"{project}/{optimization}/{binary}/{backend}",
                    )
                except Exception as exc:
                    raise ShardedTypeMatchError(str(exc)) from exc
                available_functions = validated.functions
                for raw_name in available_functions:
                    name = raw_name
                    if name not in functions:
                        continue
                    function_key = (project, optimization, binary, name)
                    if function_key in measurable:
                        expected_candidates[backend].add((*function_key, backend))

    backends = list(requested_backends) if requested_backends else sorted(available)
    absent = sorted(set(backends) - available)
    if absent:
        raise ShardedTypeMatchError(
            "requested backend(s) absent from selected checkpoints: " + ", ".join(absent)
        )
    if not backends:
        raise ShardedTypeMatchError("selected checkpoints contain no decompiler backends")

    expected_by_backend = {backend: expected_candidates[backend] for backend in backends}

    empty = sorted(backend for backend, keys in expected_by_backend.items() if not keys)
    if empty:
        raise ShardedTypeMatchError(
            "backend(s) have no producer-found functions in the fixed TypeMatch denominator: "
            + ", ".join(empty)
        )
    return backends, checkpoint_inventory, expected_by_backend


def _sample_set_only_backends() -> tuple[str, ...]:
    return tuple(sorted(set(load_content().site.sample_set_only_decompilers)))


def _validate_run_scope(
    *,
    scope: str,
    root: Path,
    selected: set[FunctionKey],
    function_keys: set[FunctionKey],
    backends: Sequence[str],
    explicitly_requested: Sequence[str],
) -> dict[str, object]:
    configured = _sample_set_only_backends()
    sample_only = sorted(backend for backend in backends if is_hidden(backend, configured))
    sample_manifest = root / "sample_set_manifest.json"
    sample_record: dict[str, object]
    sample_keys: set[FunctionKey] | None
    if sample_manifest.is_symlink() or (sample_manifest.exists() and not sample_manifest.is_file()):
        raise ShardedTypeMatchError(
            "sample_set_manifest.json must be a regular non-symlink file when present"
        )
    if sample_manifest.is_file() and not sample_manifest.is_symlink():
        sample_record = {
            "status": "available",
            **_stable_file_record(sample_manifest, relative_to=root),
        }
        sample_keys = load_manifest(sample_manifest)
    else:
        sample_record = {
            "status": "missing",
            "path": "sample_set_manifest.json",
        }
        sample_keys = None
    site_policy = _stable_file_record(
        _REPO_ROOT / "decbench" / "rendering" / "content" / "site.toml",
        relative_to=_REPO_ROOT,
    )

    if scope == "sample-set":
        if sample_keys is None:
            raise ShardedTypeMatchError(
                "sample-set scope requires a regular frozen sample_set_manifest.json"
            )
        if selected != sample_keys:
            raise ShardedTypeMatchError(
                "sample-set scope requires an exact copy of the frozen "
                f"sample_set_manifest.json ({len(sample_keys)} functions)"
            )
        fairness = "frozen-sample-set"
    elif scope == "full":
        if selected != function_keys:
            raise ShardedTypeMatchError(
                "full scope requires every function in the frozen function_results.json "
                f"({len(function_keys)} functions)"
            )
        if sample_only:
            raise ShardedTypeMatchError(
                "sample-set-only backend(s) cannot use the full denominator; run a separate "
                "--scope sample-set plan: " + ", ".join(sample_only)
            )
        fairness = "full-corpus"
    elif scope == "experimental-full":
        if selected != function_keys:
            raise ShardedTypeMatchError(
                "experimental-full scope requires every function in function_results.json"
            )
        if not explicitly_requested:
            raise ShardedTypeMatchError(
                "experimental-full scope requires explicit --backend selectors"
            )
        non_sample_only = sorted(set(backends) - set(sample_only))
        if non_sample_only:
            raise ShardedTypeMatchError(
                "experimental-full is reserved for explicitly selected backends configured "
                "as sample-set-only: " + ", ".join(non_sample_only)
            )
        fairness = "experimental-full-sample-only-backend"
    else:
        raise ShardedTypeMatchError(f"unsupported run scope: {scope!r}")

    return {
        "name": scope,
        "fairness": fairness,
        "sample_set_only_backends": list(configured),
        "selected_sample_set_only_backends": sample_only,
        "sample_set_manifest": sample_record,
        "sample_set_selected_key_sha256": (
            keyset_sha256(sample_keys) if sample_keys is not None else None
        ),
        "site_policy": site_policy,
    }


def _proc_identity(pid: int) -> tuple[int, int] | None:
    stat_path = Path("/proc") / str(pid) / "stat"
    try:
        raw = stat_path.read_text()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ShardedTypeMatchError(f"could not inspect process {pid}: {exc}") from exc
    close = raw.rfind(")")
    fields = raw[close + 2 :].split() if close >= 0 else []
    if len(fields) <= 19:
        raise ShardedTypeMatchError(f"invalid process identity record for pid {pid}")
    return int(fields[2]), int(fields[19])


def _validate_process_payload(
    raw: object,
    *,
    coordinate: str,
    expected_attempt_id: str | None = None,
    expected_job: str | None = None,
    expected_command: Sequence[str] | None = None,
    require_completed_success: bool = False,
) -> dict[str, object]:
    if not isinstance(raw, Mapping) or set(raw) != _PROCESS_RECORD_FIELDS:
        raise ShardedTypeMatchError(f"process record has invalid fields at {coordinate}")
    attempt_id = raw.get("attempt_id")
    job = raw.get("job")
    command = raw.get("command")
    pid = raw.get("pid")
    pgid = raw.get("pgid")
    start_ticks = raw.get("proc_start_ticks")
    status = raw.get("status")
    returncode = raw.get("returncode")
    timed_out = raw.get("timed_out")
    if raw.get("schema") != PROCESS_RECORD_SCHEMA:
        raise ShardedTypeMatchError(f"process record schema mismatch at {coordinate}")
    if not isinstance(attempt_id, str) or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None:
        raise ShardedTypeMatchError(f"process attempt identity is invalid at {coordinate}")
    if not isinstance(job, str) or not job:
        raise ShardedTypeMatchError(f"process job identity is invalid at {coordinate}")
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(value, str) for value in command)
    ):
        raise ShardedTypeMatchError(f"process command is invalid at {coordinate}")
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 1
        or not isinstance(pgid, int)
        or isinstance(pgid, bool)
        or pgid != pid
        or not isinstance(start_ticks, int)
        or isinstance(start_ticks, bool)
        or start_ticks < 0
    ):
        raise ShardedTypeMatchError(f"process identity is invalid at {coordinate}")
    if status == "running":
        if returncode is not None or timed_out is not None:
            raise ShardedTypeMatchError(f"running process state is invalid at {coordinate}")
    elif status == "completed":
        if (
            not isinstance(returncode, int)
            or isinstance(returncode, bool)
            or not isinstance(timed_out, bool)
        ):
            raise ShardedTypeMatchError(f"completed process state is invalid at {coordinate}")
    else:
        raise ShardedTypeMatchError(f"process status is invalid at {coordinate}")
    if expected_attempt_id is not None and attempt_id != expected_attempt_id:
        raise ShardedTypeMatchError(f"process attempt identity mismatch at {coordinate}")
    if expected_job is not None and job != expected_job:
        raise ShardedTypeMatchError(f"process job identity mismatch at {coordinate}")
    if expected_command is not None and command != list(expected_command):
        raise ShardedTypeMatchError(f"process command mismatch at {coordinate}")
    if require_completed_success and (
        status != "completed" or returncode != 0 or timed_out is not False
    ):
        raise ShardedTypeMatchError(f"process did not complete successfully at {coordinate}")
    return dict(raw)


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        raise ShardedTypeMatchError(f"cannot inspect process group {pgid}: {exc}") from exc
    return True


def _terminate_recorded_process_group(process_record: Path) -> None:
    try:
        record = json.loads(process_record.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ShardedTypeMatchError(
            f"cannot prove an incomplete worker is dead; invalid process record "
            f"{process_record}: {exc}"
        ) from exc
    try:
        validated = _validate_process_payload(record, coordinate=str(process_record))
    except ShardedTypeMatchError as exc:
        raise ShardedTypeMatchError(f"cannot prove an incomplete worker is dead; {exc}") from exc
    pid = int(validated["pid"])
    pgid = int(validated["pgid"])
    start_ticks = int(validated["proc_start_ticks"])

    current = _proc_identity(pid)
    if current is None:
        if _process_group_exists(pgid):
            raise ShardedTypeMatchError(
                f"worker leader {pid} exited but process group {pgid} survives; "
                "refusing an unsafe retry"
            )
        return
    current_pgid, current_start = current
    if current_pgid != pgid or current_start != start_ticks:
        if _process_group_exists(pgid):
            raise ShardedTypeMatchError(
                f"recorded pid/process-group identity was reused for {process_record}; "
                "refusing to signal an unrelated process"
            )
        return

    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + PROCESS_TERMINATION_SECONDS
    while _process_group_exists(pgid) and time.monotonic() < deadline:
        time.sleep(0.05)
    if _process_group_exists(pgid):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pgid, signal.SIGKILL)
        deadline = time.monotonic() + PROCESS_TERMINATION_SECONDS
        while _process_group_exists(pgid) and time.monotonic() < deadline:
            time.sleep(0.05)
    if _process_group_exists(pgid):
        raise ShardedTypeMatchError(
            f"recorded worker process group {pgid} survived SIGKILL; refusing retry"
        )


def _run_subprocess(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: int,
    environment_overrides: Mapping[str, str] | None = None,
    process_record: Path | None = None,
    process_identity: Mapping[str, str] | None = None,
) -> WorkerOutcome:
    environment = _subprocess_environment(environment_overrides)
    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    process_payload: dict[str, object] | None = None
    if process_record is not None:
        identity = _proc_identity(process.pid)
        if identity is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise ShardedTypeMatchError(
                f"worker process {process.pid} disappeared before its identity was recorded"
            )
        pgid, start_ticks = identity
        if pgid != process.pid:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            process.communicate()
            raise ShardedTypeMatchError(
                f"worker process {process.pid} did not create its expected process group"
            )
        process_payload = {
            "schema": PROCESS_RECORD_SCHEMA,
            "attempt_id": str((process_identity or {}).get("attempt_id", "")),
            "job": str((process_identity or {}).get("job", "")),
            "command": list(command),
            "pid": process.pid,
            "pgid": pgid,
            "proc_start_ticks": start_ticks,
            "status": "running",
            "returncode": None,
            "timed_out": None,
        }
        try:
            _write_json_atomic(process_record, process_payload)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
    if process_record is not None and process_payload is not None:
        process_payload.update(
            {
                "status": "completed",
                "returncode": int(process.returncode),
                "timed_out": timed_out,
            }
        )
        _write_json_atomic(process_record, process_payload)
    return WorkerOutcome(
        label="",
        command=tuple(command),
        returncode=int(process.returncode),
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


def _worker_command(job: WorkerJob, root: Path, output: Path) -> tuple[str, ...]:
    return (
        sys.executable,
        str(_REPO_ROOT / "scripts/reeval_typematch.py"),
        str(root),
        "--mode",
        job.mode,
        "--manifest",
        str(job.manifest),
        "--function-data",
        str(job.function_data),
        "--backend",
        job.backend,
        "--output",
        str(output),
    )


def _run_worker(
    job: WorkerJob,
    root: Path,
    timeout: int,
) -> tuple[WorkerAttempt, WorkerOutcome]:
    attempt = _new_worker_attempt(job)
    command = _worker_command(job, root, attempt.output)
    outcome = _run_subprocess(
        command,
        cwd=_REPO_ROOT,
        timeout=timeout,
        environment_overrides={
            "DECBENCH_CACHE_DIR": str(attempt.cache_dir),
            "DECBENCH_NO_CACHE": "0",
        },
        process_record=attempt.process_record,
        process_identity={"attempt_id": attempt.attempt_id, "job": job.label},
    )
    return (
        attempt,
        WorkerOutcome(
            label=job.label,
            command=outcome.command,
            returncode=outcome.returncode,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            timed_out=outcome.timed_out,
        ),
    )


def _unexpected_stderr(stderr: str) -> list[str]:
    unexpected: list[str] = []
    for line in stderr.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(prefix) for prefix in _KNOWN_METRIC_WARNING_PREFIXES):
            continue
        unexpected.append(stripped)
    return unexpected


def _validate_worker_transcript(outcome: WorkerOutcome, output: Path) -> None:
    problems: list[str] = []
    if outcome.timed_out:
        problems.append("timed out")
    if outcome.returncode != 0:
        problems.append(f"exit status {outcome.returncode}")
    alert_lines = [
        line.strip()
        for line in outcome.stdout.splitlines()
        if line.lstrip().startswith("!")
        or line.lstrip().lower().startswith(("error:", "traceback"))
    ]
    if alert_lines:
        problems.append(f"stdout reported {len(alert_lines)} failure marker(s)")
    unexpected = _unexpected_stderr(outcome.stderr)
    if unexpected:
        problems.append(f"stderr contained {len(unexpected)} unexpected line(s)")
    expected_marker = f"wrote {output}"
    if not any(line.strip() == expected_marker for line in outcome.stdout.splitlines()):
        problems.append("stdout lacks the exact output completion marker")
    if problems:
        detail = "; ".join(problems)
        raise ShardedTypeMatchError(f"worker {outcome.label} failed closed: {detail}")


def _validate_overlay(
    path: Path,
    *,
    mode: str,
    expected: set[ScoreKey] | frozenset[ScoreKey],
    backend: str | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    try:
        payload, provenance = read_typematch_overlay(path)
    except (OSError, json.JSONDecodeError, TypeMatchOverlayError) as exc:
        raise ShardedTypeMatchError(f"invalid TypeMatch overlay {path}: {exc}") from exc
    if provenance is None:
        raise ShardedTypeMatchError(f"overlay lacks digest-bound provenance: {path}")
    expected_provenance = _metric_provenance(mode)
    for field, value in expected_provenance.items():
        if provenance.get(field) != value:
            raise ShardedTypeMatchError(
                f"overlay provenance mismatch for {path}: {field}={provenance.get(field)!r}, "
                f"expected {value!r}"
            )
    if backend is not None and set(payload) != {backend}:
        raise ShardedTypeMatchError(
            f"overlay {path} has backends {sorted(payload)}, expected only {backend!r}"
        )
    actual = _overlay_score_keys(payload)
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        unexpected = sorted(actual - set(expected))
        raise ShardedTypeMatchError(
            f"overlay key mismatch for {path}: expected {len(expected)}, got {len(actual)}, "
            f"missing={len(missing)}, unexpected={len(unexpected)}"
        )
    return payload, provenance


def _cache_inventory(directory: Path) -> dict[str, object]:
    if not directory.is_dir() or directory.is_symlink():
        raise ShardedTypeMatchError(f"worker cache is not a regular directory: {directory}")
    rows: list[dict[str, object]] = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ShardedTypeMatchError(f"worker cache contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ShardedTypeMatchError(f"worker cache contains a special file: {path}")
        rows.append(_stable_file_record(path, relative_to=directory))
    if not rows:
        raise ShardedTypeMatchError(f"fresh worker cache remained empty: {directory}")
    return {
        "path": str(directory),
        "file_count": len(rows),
        "byte_count": sum(int(row["size"]) for row in rows),
        "inventory_sha256": _sha256_bytes(_json_bytes(rows, pretty=False)),
        "files": rows,
    }


def _seal_cache(directory: Path) -> dict[str, object]:
    inventory = _cache_inventory(directory)
    for path in sorted(directory.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    directory.chmod(0o555)
    return inventory


def _validate_sealed_cache(directory: Path, expected: Mapping[str, Any]) -> None:
    current = _cache_inventory(directory)
    if current != dict(expected):
        raise ShardedTypeMatchError(f"sealed worker cache inventory changed: {directory}")
    for path in (directory, *directory.rglob("*")):
        if path.stat().st_mode & 0o222:
            raise ShardedTypeMatchError(f"sealed worker cache is writable: {path}")


def _optional_tree_inventory(directory: Path) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    if directory.exists():
        if not directory.is_dir() or directory.is_symlink():
            raise ShardedTypeMatchError(f"artifact inventory root is invalid: {directory}")
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ShardedTypeMatchError(f"artifact inventory contains a symlink: {path}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ShardedTypeMatchError(f"artifact inventory contains a special file: {path}")
            rows.append(_stable_file_record(path, relative_to=directory))
    return {
        "path": str(directory),
        "file_count": len(rows),
        "byte_count": sum(int(row["size"]) for row in rows),
        "inventory_sha256": _sha256_bytes(_json_bytes(rows, pretty=False)),
    }


def _job_receipt_payload(
    job: WorkerJob,
    outcome: WorkerOutcome,
    *,
    root: Path,
    attempt_id: str,
    plan_sha256: str,
    cache_inventory: Mapping[str, object],
) -> dict[str, object]:
    payload, provenance = _validate_overlay(
        job.output,
        mode=job.mode,
        expected=job.expected,
        backend=job.backend,
    )
    attempt_directory = job.attempts_dir / attempt_id
    expected_command = _worker_command(job, root, attempt_directory / "overlay.json")
    if outcome.command != expected_command:
        raise ShardedTypeMatchError(f"worker command identity mismatch for {job.label}")
    try:
        raw_process = json.loads(job.process_record.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ShardedTypeMatchError(
            f"invalid completed process record {job.process_record}: {exc}"
        ) from exc
    process = _validate_process_payload(
        raw_process,
        coordinate=str(job.process_record),
        expected_attempt_id=attempt_id,
        expected_job=job.label,
        expected_command=expected_command,
        require_completed_success=True,
    )
    return {
        "schema": JOB_RECEIPT_SCHEMA,
        "plan_sha256": plan_sha256,
        "job": {
            "backend": job.backend,
            "mode": job.mode,
            "shard": job.shard,
            "manifest": str(job.manifest),
            "manifest_sha256": job.manifest_sha256,
            "selected_key_sha256": job.selected_key_sha256,
        },
        "command": list(outcome.command),
        "attempt": {
            "id": attempt_id,
            "directory": str(attempt_directory),
            "process_record": {
                "path": str(job.process_record),
                "sha256": file_sha256(job.process_record),
                "payload": process,
            },
        },
        "returncode": outcome.returncode,
        "timed_out": outcome.timed_out,
        "expected_entry_count": len(job.expected),
        "expected_score_key_sha256": _score_key_sha256(job.expected),
        "output": {
            "path": str(job.output),
            "sha256": file_sha256(job.output),
            "manifest_sha256": file_sha256(typematch_overlay_manifest_path(job.output)),
            "entry_count": sum(len(entries) for entries in payload.values()),
            "score_key_sha256": _score_key_sha256(_overlay_score_keys(payload)),
            "provenance": provenance,
        },
        "stdout": {
            "path": str(job.stdout_log),
            "sha256": file_sha256(job.stdout_log),
            "size": job.stdout_log.stat().st_size,
        },
        "stderr": {
            "path": str(job.stderr_log),
            "sha256": file_sha256(job.stderr_log),
            "size": job.stderr_log.stat().st_size,
        },
        "cache": dict(cache_inventory),
    }


def _attempt_directories(job: WorkerJob) -> list[Path]:
    if not job.attempts_dir.exists():
        return []
    if not job.attempts_dir.is_dir() or job.attempts_dir.is_symlink():
        raise ShardedTypeMatchError(f"worker attempts root is invalid: {job.attempts_dir}")
    return sorted(job.attempts_dir.iterdir())


def _job_receipt_temporaries(job: WorkerJob) -> list[Path]:
    return sorted(job.receipt.parent.glob(f".{job.receipt.name}.*.tmp"))


def _validate_job_receipt(job: WorkerJob, *, root: Path, plan_sha256: str) -> bool:
    committed_artifacts = (
        job.output,
        typematch_overlay_manifest_path(job.output),
        job.stdout_log,
        job.stderr_log,
        job.cache_dir,
        job.process_record,
    )
    present = [path.exists() for path in committed_artifacts]
    attempt_directories = _attempt_directories(job)
    receipt_temporaries = _job_receipt_temporaries(job)
    if not job.receipt.exists():
        if any(present) or attempt_directories or receipt_temporaries:
            raise IncompleteWorkerAttempt(f"unreceipted artifacts exist for {job.label}")
        return False
    if not all(present) or attempt_directories or receipt_temporaries:
        raise ShardedTypeMatchError(
            f"receipt exists with incomplete artifacts for {job.label}; "
            "use a new output directory"
        )
    try:
        receipt = json.loads(job.receipt.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ShardedTypeMatchError(f"invalid job receipt {job.receipt}: {exc}") from exc
    attempt = receipt.get("attempt")
    if not isinstance(attempt, Mapping):
        raise ShardedTypeMatchError(f"job receipt attempt record is invalid: {job.receipt}")
    attempt_id = attempt.get("id")
    if not isinstance(attempt_id, str) or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None:
        raise ShardedTypeMatchError(f"job receipt attempt token is invalid: {job.receipt}")
    expected_command = _worker_command(job, root, job.attempts_dir / attempt_id / "overlay.json")
    replay = WorkerOutcome(
        label=job.label,
        command=expected_command,
        returncode=0,
        stdout=job.stdout_log.read_text(),
        stderr=job.stderr_log.read_text(),
        timed_out=False,
    )
    _validate_worker_transcript(replay, job.attempts_dir / attempt_id / "overlay.json")
    cache_inventory = _cache_inventory(job.cache_dir)
    expected_receipt = _job_receipt_payload(
        job,
        replay,
        root=root,
        attempt_id=attempt_id,
        plan_sha256=plan_sha256,
        cache_inventory=cache_inventory,
    )
    if receipt != expected_receipt:
        raise ShardedTypeMatchError(f"job receipt content mismatch: {job.receipt}")
    _validate_sealed_cache(job.cache_dir, cache_inventory)
    return True


def _quarantine_incomplete_attempt(job: WorkerJob) -> Path:
    output_root = job.output.parents[3]
    quarantine_root = output_root / "failed_attempts"
    quarantine_root.mkdir(parents=True, exist_ok=True)
    label_digest = hashlib.sha256(job.label.encode()).hexdigest()[:16]
    directory = Path(
        tempfile.mkdtemp(
            prefix=f"{label_digest}-",
            dir=quarantine_root,
        )
    )
    moved: list[dict[str, str]] = []
    stable_process: Mapping[str, object] | None = None
    if job.process_record.exists():
        _terminate_recorded_process_group(job.process_record)
        try:
            raw_stable_process = json.loads(job.process_record.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ShardedTypeMatchError(
                f"invalid stable process record for {job.label}: {exc}"
            ) from exc
        if isinstance(raw_stable_process, Mapping):
            stable_process = raw_stable_process

    attempt_directories = _attempt_directories(job)
    for attempt_directory in attempt_directories:
        if not attempt_directory.is_dir() or attempt_directory.is_symlink():
            raise ShardedTypeMatchError(f"worker attempt path is invalid: {attempt_directory}")
        process_record = attempt_directory / "process.json"
        if process_record.exists():
            _terminate_recorded_process_group(process_record)
        elif stable_process is None or stable_process.get("attempt_id") != attempt_directory.name:
            raise ShardedTypeMatchError(
                f"cannot prove incomplete attempt {attempt_directory} is dead; "
                "its process record is missing"
            )

    artifacts = (
        job.output,
        typematch_overlay_manifest_path(job.output),
        job.stdout_log,
        job.stderr_log,
        job.cache_dir,
        job.process_record,
        *_job_receipt_temporaries(job),
    )
    for path in artifacts:
        if not path.exists():
            continue
        target = directory / path.name
        if path == job.cache_dir:
            path.chmod(0o755)
        os.replace(path, target)
        if path == job.cache_dir:
            target.chmod(0o555)
        moved.append({"from": str(path), "to": str(target)})
    for attempt_directory in attempt_directories:
        target = directory / attempt_directory.name
        os.replace(attempt_directory, target)
        moved.append({"from": str(attempt_directory), "to": str(target)})
    _write_json_atomic(
        directory / "quarantine.json",
        {
            "schema": "decbench-typematch-ab-worker-quarantine-v1",
            "job": job.label,
            "reason": "artifacts existed without a committed receipt",
            "moved": moved,
        },
    )
    return directory


def _new_worker_attempt(job: WorkerJob) -> WorkerAttempt:
    job.attempts_dir.mkdir(parents=True, exist_ok=True)
    attempt_id = secrets.token_hex(16)
    directory = job.attempts_dir / attempt_id
    directory.mkdir(exist_ok=False)
    cache_dir = directory / "cache"
    cache_dir.mkdir(exist_ok=False)
    return WorkerAttempt(
        attempt_id=attempt_id,
        directory=directory,
        output=directory / "overlay.json",
        stdout_log=directory / "stdout.log",
        stderr_log=directory / "stderr.log",
        cache_dir=cache_dir,
        process_record=directory / "process.json",
    )


def _promote_worker_attempt(job: WorkerJob, attempt: WorkerAttempt) -> None:
    sources = (
        (attempt.output, job.output),
        (
            typematch_overlay_manifest_path(attempt.output),
            typematch_overlay_manifest_path(job.output),
        ),
        (attempt.stdout_log, job.stdout_log),
        (attempt.stderr_log, job.stderr_log),
        (attempt.cache_dir, job.cache_dir),
        (attempt.process_record, job.process_record),
    )
    for source, target in sources:
        if not source.exists():
            raise ShardedTypeMatchError(f"attempt artifact is missing for {job.label}: {source}")
        if target.exists():
            raise ShardedTypeMatchError(
                f"committed artifact already exists for {job.label}: {target}"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        if source == attempt.cache_dir:
            source.chmod(0o755)
        os.replace(source, target)
        if target == job.cache_dir:
            target.chmod(0o555)
    attempt.directory.rmdir()


def _run_sharder(
    manifest: Path,
    directory: Path,
    shards: int,
    timeout: int,
    *,
    process_record: Path | None = None,
    attempt_id: str = "",
) -> None:
    command = [
        sys.executable,
        str(_REPO_ROOT / "scripts/shard_typematch_manifest.py"),
        str(manifest),
        str(directory),
        "--shards",
        str(shards),
    ]
    outcome = _run_subprocess(
        command,
        cwd=_REPO_ROOT,
        timeout=timeout,
        process_record=process_record,
        process_identity={"attempt_id": attempt_id, "job": "shard-manifest"},
    )
    if outcome.timed_out or outcome.returncode != 0 or outcome.stderr.strip():
        raise ShardedTypeMatchError(
            "manifest sharder failed: "
            f"exit={outcome.returncode}, timeout={outcome.timed_out}, stderr={outcome.stderr!r}"
        )
    if not outcome.stdout.startswith(f"wrote {shards} whole-binary shards:"):
        raise ShardedTypeMatchError("manifest sharder emitted an unexpected success transcript")


def _load_shard_index(
    directory: Path,
    *,
    source_manifest: Path,
    source_keys: set[FunctionKey],
    shard_count: int,
) -> tuple[dict[str, Any], list[tuple[Path, set[FunctionKey], Mapping[str, Any]]]]:
    index_path = directory / "manifest_index.json"
    try:
        index = json.loads(index_path.read_text())
        rows = index["shards"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ShardedTypeMatchError(f"invalid shard index {index_path}: {exc}") from exc
    if (
        not isinstance(rows, list)
        or len(rows) != shard_count
        or index.get("valid") is not True
        or index.get("exact_union") is not True
        or index.get("binary_split_count") != 0
        or index.get("source_manifest_sha256") != file_sha256(source_manifest)
        or index.get("selected_key_sha256") != keyset_sha256(source_keys)
    ):
        raise ShardedTypeMatchError(f"shard index invariants failed: {index_path}")
    loaded: list[tuple[Path, set[FunctionKey], Mapping[str, Any]]] = []
    for expected_number, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping) or row.get("shard") != expected_number:
            raise ShardedTypeMatchError(f"shard index ordering is invalid: {index_path}")
        path = (directory / str(row["manifest"])).resolve()
        try:
            path.relative_to(directory.resolve())
        except ValueError as exc:
            raise ShardedTypeMatchError(f"shard manifest escapes output directory: {path}") from exc
        keys = load_manifest(path)
        if (
            row.get("manifest_sha256") != file_sha256(path)
            or row.get("selected_key_sha256") != keyset_sha256(keys)
            or row.get("function_count") != len(keys)
        ):
            raise ShardedTypeMatchError(f"shard manifest digest/count mismatch: {path}")
        loaded.append((path, keys, row))
    audit = audit_manifest_shards(source_keys, [keys for _path, keys, _row in loaded])
    if not audit.valid or audit.selected_key_sha256 != keyset_sha256(source_keys):
        raise ShardedTypeMatchError(f"whole-binary shard union audit failed: {audit.to_dict()}")
    return index, loaded


def _build_plan(
    *,
    root: Path,
    selected: set[FunctionKey],
    measurable: set[FunctionKey],
    backends: list[str],
    expected_by_backend: Mapping[str, set[ScoreKey]],
    checkpoints: list[dict[str, object]],
    binaries: list[dict[str, object]],
    sources: list[dict[str, object]],
    shard_directory: Path,
    recorded_shard_directory: Path,
    shard_index: Mapping[str, Any],
    shard_rows: Sequence[tuple[Path, set[FunctionKey], Mapping[str, Any]]],
    manifest_record: Mapping[str, object],
    function_data_record: Mapping[str, object],
    scope_policy: Mapping[str, object],
    regression_limit: int,
) -> dict[str, object]:
    denominator = selected & measurable
    return {
        "schema": RUN_PLAN_SCHEMA,
        "results_root": str(root),
        "runtime": _runtime_inventory(),
        "scope": dict(scope_policy),
        "report_policy": {"regression_limit": regression_limit},
        "calibration_contract": {
            "input": "complete producer function set for each selected binary",
            "emission": "manifest-selected producer rows only",
        },
        "cache_contract": {
            "scope": "one attempt-unique fresh cache per backend/mode/shard worker",
            "environment": "DECBENCH_CACHE_DIR",
            "initial_state": "new empty directory",
            "completed_state": "digest-inventoried and recursively read-only",
        },
        "modes": list(MODES),
        "backends": backends,
        "metric": {mode: _metric_provenance(mode) for mode in MODES},
        "manifest": {
            **manifest_record,
            "selected_count": len(selected),
            "selected_key_sha256": keyset_sha256(selected),
        },
        "function_data": {
            **function_data_record,
            "selected_count": len(selected),
            "measurable_count": len(denominator),
            "measurable_key_sha256": keyset_sha256(denominator),
        },
        "checkpoint_inventory": checkpoints,
        "binary_inventory": binaries,
        "preprocessed_source_inventory": sources,
        "code_inventory": _code_inventory(),
        "expected_by_backend": {
            backend: {
                "entry_count": len(expected_by_backend[backend]),
                "score_key_sha256": _score_key_sha256(expected_by_backend[backend]),
            }
            for backend in backends
        },
        "sharding": {
            "directory": str(recorded_shard_directory),
            "index_sha256": file_sha256(shard_directory / "manifest_index.json"),
            "index": dict(shard_index),
            "shards": [
                {
                    "shard": int(row["shard"]),
                    "manifest": str(recorded_shard_directory / "manifests" / path.name),
                    "manifest_sha256": file_sha256(path),
                    "selected_count": len(keys),
                    "selected_key_sha256": keyset_sha256(keys),
                }
                for path, keys, row in shard_rows
            ],
        },
    }


def _validate_inventory(plan: Mapping[str, Any], root: Path) -> None:
    manifest_record = plan.get("manifest")
    function_data_record = plan.get("function_data")
    if not isinstance(manifest_record, Mapping) or not isinstance(function_data_record, Mapping):
        raise ShardedTypeMatchError("run plan manifest/function-data records are invalid")
    manifest = Path(str(manifest_record["path"]))
    function_data = Path(str(function_data_record["path"]))
    for record, path in ((manifest_record, manifest), (function_data_record, function_data)):
        current = _stable_file_record(path)
        if current["sha256"] != record.get("sha256") or current["size"] != record.get("size"):
            raise ShardedTypeMatchError(f"frozen input changed since the plan was made: {path}")

    selected = load_manifest(manifest)
    current_checkpoints = [
        _stable_file_record(root / "checkpoints" / f"{project}.pkl", relative_to=root)
        for project in sorted({key[0] for key in selected})
    ]
    if current_checkpoints != plan.get("checkpoint_inventory"):
        raise ShardedTypeMatchError("selected checkpoint inventory changed since plan creation")
    current_binaries, current_sources = _selected_source_inventory(root, selected)
    if current_binaries != plan.get("binary_inventory"):
        raise ShardedTypeMatchError(
            "selected compiled-binary inventory changed since plan creation"
        )
    if current_sources != plan.get("preprocessed_source_inventory"):
        raise ShardedTypeMatchError(
            "selected preprocessed-source inventory changed since plan creation"
        )
    current_code = _code_inventory()
    if current_code != plan.get("code_inventory"):
        raise ShardedTypeMatchError("Python code inventory changed since the plan was made")
    if _runtime_inventory() != plan.get("runtime"):
        raise ShardedTypeMatchError("Python runtime/dependency environment changed since planning")
    scope = plan.get("scope")
    if not isinstance(scope, Mapping):
        raise ShardedTypeMatchError("run plan scope policy is invalid")
    sample_record = scope.get("sample_set_manifest")
    site_record = scope.get("site_policy")
    if not isinstance(sample_record, Mapping) or not isinstance(site_record, Mapping):
        raise ShardedTypeMatchError("run plan scope input records are invalid")
    sample_path = root / "sample_set_manifest.json"
    if sample_record.get("status") == "available":
        if sample_path.is_symlink() or not sample_path.is_file():
            raise ShardedTypeMatchError("sample-set manifest availability changed since planning")
        current_sample: dict[str, object] = {
            "status": "available",
            **_stable_file_record(sample_path, relative_to=root),
        }
    elif (
        sample_record.get("status") == "missing"
        and not sample_path.exists()
        and not sample_path.is_symlink()
    ):
        current_sample = {"status": "missing", "path": "sample_set_manifest.json"}
    else:
        raise ShardedTypeMatchError("sample-set manifest availability changed since planning")
    current_site = _stable_file_record(
        _REPO_ROOT / "decbench" / "rendering" / "content" / "site.toml",
        relative_to=_REPO_ROOT,
    )
    if current_sample != dict(sample_record) or current_site != dict(site_record):
        raise ShardedTypeMatchError("scope policy inputs changed since the plan was made")


def _jobs(
    *,
    output: Path,
    function_data: Path,
    shards: Sequence[tuple[Path, set[FunctionKey], Mapping[str, Any]]],
    backends: Sequence[str],
    expected_by_backend: Mapping[str, set[ScoreKey]],
) -> list[WorkerJob]:
    jobs: list[WorkerJob] = []
    for path, shard_keys, row in shards:
        shard_number = int(row["shard"])
        for backend in backends:
            expected = frozenset(
                key for key in expected_by_backend[backend] if key[:4] in shard_keys
            )
            if not expected:
                continue
            backend_directory = "backend-" + hashlib.sha256(backend.encode()).hexdigest()
            for mode in MODES:
                base = output / "workers" / backend_directory / mode / f"shard{shard_number:02d}"
                jobs.append(
                    WorkerJob(
                        backend=backend,
                        mode=mode,
                        shard=shard_number,
                        manifest=path,
                        function_data=function_data,
                        manifest_sha256=file_sha256(path),
                        selected_key_sha256=keyset_sha256(shard_keys),
                        expected=expected,
                        output=base.with_suffix(".json"),
                        stdout_log=base.with_suffix(".stdout.log"),
                        stderr_log=base.with_suffix(".stderr.log"),
                        cache_dir=base.with_suffix(".cache"),
                        process_record=base.with_suffix(".process.json"),
                        receipt=base.with_suffix(".receipt.json"),
                        attempts_dir=base.with_suffix(".attempts"),
                    )
                )
    return jobs


def _execute_jobs(
    jobs: Sequence[WorkerJob],
    *,
    root: Path,
    workers: int,
    timeout: int,
    plan_sha256: str,
) -> None:
    pending: list[WorkerJob] = []
    for job in jobs:
        try:
            completed = _validate_job_receipt(job, root=root, plan_sha256=plan_sha256)
        except IncompleteWorkerAttempt:
            quarantine = _quarantine_incomplete_attempt(job)
            print(f"[retry] {job.label}: preserved incomplete attempt in {quarantine}")
            completed = False
        if completed:
            print(f"[resume] {job.label}")
            continue
        pending.append(job)
    if not pending:
        return

    failures: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_jobs = {executor.submit(_run_worker, job, root, timeout): job for job in pending}
        for future in as_completed(future_jobs):
            job = future_jobs[future]
            try:
                attempt, outcome = future.result()
            except BaseException as exc:
                failures.append(f"{job.label}: worker process failed: {type(exc).__name__}: {exc}")
                continue
            _write_bytes_atomic(attempt.stdout_log, outcome.stdout.encode())
            _write_bytes_atomic(attempt.stderr_log, outcome.stderr.encode())
            try:
                _validate_worker_transcript(outcome, attempt.output)
                _validate_overlay(
                    attempt.output,
                    mode=job.mode,
                    expected=job.expected,
                    backend=job.backend,
                )
                _seal_cache(attempt.cache_dir)
                _promote_worker_attempt(job, attempt)
                cache_inventory = _cache_inventory(job.cache_dir)
                receipt = _job_receipt_payload(
                    job,
                    outcome,
                    root=root,
                    attempt_id=attempt.attempt_id,
                    plan_sha256=plan_sha256,
                    cache_inventory=cache_inventory,
                )
                _write_json_atomic(job.receipt, receipt)
                print(f"[done] {job.label}: {len(job.expected)} entries")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{job.label}: {exc}")
    if failures:
        raise ShardedTypeMatchError(
            "one or more TypeMatch workers failed; no merge/report was written:\n  - "
            + "\n  - ".join(failures)
        )


def _quarantine_owned_artifacts(
    *,
    output: Path,
    label: str,
    paths: Sequence[Path],
    reason: str,
    require_process_record_for_directories: bool = False,
) -> Path | None:
    existing = [path for path in paths if path.exists()]
    if not existing:
        return None
    for path in existing:
        if path.is_symlink():
            raise ShardedTypeMatchError(f"owned incomplete artifact is a symlink: {path}")
        process_record = path / "process.json" if path.is_dir() else None
        if process_record is not None:
            if process_record.exists():
                _terminate_recorded_process_group(process_record)
            elif require_process_record_for_directories:
                raise ShardedTypeMatchError(
                    f"cannot prove an incomplete {label} process is dead; "
                    f"process record is missing from {path}"
                )

    quarantine_root = output / "failed_attempts"
    quarantine_root.mkdir(parents=True, exist_ok=True)
    directory = Path(
        tempfile.mkdtemp(
            prefix=f"{hashlib.sha256(label.encode()).hexdigest()[:16]}-",
            dir=quarantine_root,
        )
    )
    moved: list[dict[str, str]] = []
    for index, path in enumerate(existing):
        target = directory / f"{index:02d}-{path.name}"
        os.replace(path, target)
        moved.append({"from": str(path), "to": str(target)})
    _write_json_atomic(
        directory / "quarantine.json",
        {
            "schema": "decbench-typematch-ab-owned-quarantine-v1",
            "label": label,
            "reason": reason,
            "moved": moved,
        },
    )
    return directory


def _merge_receipt_payload(
    *,
    mode: str,
    attempt_id: str,
    target: Path,
    expected: set[ScoreKey],
) -> dict[str, object]:
    payload, provenance = _validate_overlay(
        target,
        mode=mode,
        expected=expected,
        backend=None,
    )
    return {
        "schema": MERGE_RECEIPT_SCHEMA,
        "mode": mode,
        "attempt_id": attempt_id,
        "expected_entry_count": len(expected),
        "expected_score_key_sha256": _score_key_sha256(expected),
        "output": {
            "path": str(target),
            "sha256": file_sha256(target),
            "manifest_path": str(typematch_overlay_manifest_path(target)),
            "manifest_sha256": file_sha256(typematch_overlay_manifest_path(target)),
            "entry_count": sum(len(entries) for entries in payload.values()),
            "score_key_sha256": _score_key_sha256(_overlay_score_keys(payload)),
            "provenance": provenance,
        },
    }


def _validate_merge_receipt(
    *,
    receipt_path: Path,
    mode: str,
    target: Path,
    expected: set[ScoreKey],
) -> bool:
    if not receipt_path.exists():
        return False
    try:
        receipt = json.loads(receipt_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ShardedTypeMatchError(f"invalid merge receipt {receipt_path}: {exc}") from exc
    attempt_id = receipt.get("attempt_id") if isinstance(receipt, Mapping) else None
    if not isinstance(attempt_id, str) or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None:
        raise ShardedTypeMatchError(f"invalid merge attempt token in {receipt_path}")
    expected_receipt = _merge_receipt_payload(
        mode=mode,
        attempt_id=attempt_id,
        target=target,
        expected=expected,
    )
    if receipt != expected_receipt:
        raise ShardedTypeMatchError(f"merge receipt content mismatch: {receipt_path}")
    return True


def _merge_modes(
    jobs: Sequence[WorkerJob],
    *,
    output: Path,
    expected_by_backend: Mapping[str, set[ScoreKey]],
) -> dict[str, Path]:
    merged_paths: dict[str, Path] = {}
    for mode in MODES:
        merged: dict[str, dict[str, Any]] = {}
        seen: set[ScoreKey] = set()
        mode_jobs = [job for job in jobs if job.mode == mode]
        for job in sorted(mode_jobs, key=lambda item: (item.shard, item.backend)):
            payload, _provenance = _validate_overlay(
                job.output,
                mode=mode,
                expected=job.expected,
                backend=job.backend,
            )
            keys = _overlay_score_keys(payload)
            overlap = seen & keys
            if overlap:
                raise ShardedTypeMatchError(
                    f"mode {mode!r} shard outputs overlap on {len(overlap)} score keys"
                )
            seen.update(keys)
            for backend, per_backend in payload.items():
                target = merged.setdefault(backend, {})
                duplicate = set(target) & set(per_backend)
                if duplicate:
                    raise ShardedTypeMatchError(
                        f"mode {mode!r} repeats {len(duplicate)} {backend!r} function keys"
                    )
                target.update(per_backend)
        expected = set().union(*expected_by_backend.values())
        if seen != expected:
            raise ShardedTypeMatchError(
                f"mode {mode!r} merged union mismatch: expected {len(expected)}, got {len(seen)}"
            )
        target = output / "merged" / f"type_match_{mode.replace('+', '_plus_')}.json"
        provenance = _metric_provenance(mode)
        receipt_path = target.with_suffix(".receipt.json")
        stage_root = output / "stages" / "merge" / mode.replace("+", "_plus_")
        stale_stages = sorted(stage_root.iterdir()) if stage_root.is_dir() else []
        if _validate_merge_receipt(
            receipt_path=receipt_path,
            mode=mode,
            target=target,
            expected=expected,
        ):
            if stale_stages:
                receipt_attempt = str(json.loads(receipt_path.read_text())["attempt_id"])
                for stale in stale_stages:
                    if stale.name != receipt_attempt or not stale.is_dir() or any(stale.iterdir()):
                        raise ShardedTypeMatchError(
                            f"completed merge has unexpected stale stage: {stale}"
                        )
                    stale.rmdir()
            existing, _existing_provenance = _validate_overlay(
                target,
                mode=mode,
                expected=expected,
                backend=None,
            )
            if existing != merged:
                raise ShardedTypeMatchError(
                    f"completed merged overlay differs from validated shard union: {target}"
                )
            merged_paths[mode] = target
            continue

        partials = [target, typematch_overlay_manifest_path(target), *stale_stages]
        partials.extend(target.parent.glob(f".{receipt_path.name}.*.tmp"))
        quarantine = _quarantine_owned_artifacts(
            output=output,
            label=f"merge/{mode}",
            paths=partials,
            reason="merge artifacts existed without a committed receipt",
        )
        if quarantine is not None:
            print(f"[retry] merge/{mode}: preserved incomplete stage in {quarantine}")

        attempt_id = secrets.token_hex(16)
        stage = stage_root / attempt_id
        stage.mkdir(parents=True, exist_ok=False)
        staged_target = stage / target.name
        write_typematch_overlay_atomic(staged_target, merged, provenance)
        staged, _staged_provenance = _validate_overlay(
            staged_target,
            mode=mode,
            expected=expected,
            backend=None,
        )
        if staged != merged:
            raise ShardedTypeMatchError(f"staged merged overlay changed for mode {mode}")
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(
            typematch_overlay_manifest_path(staged_target),
            typematch_overlay_manifest_path(target),
        )
        os.replace(staged_target, target)
        receipt = _merge_receipt_payload(
            mode=mode,
            attempt_id=attempt_id,
            target=target,
            expected=expected,
        )
        _write_json_atomic(receipt_path, receipt)
        stage.rmdir()
        merged_paths[mode] = target
    return merged_paths


def _report_command(
    *,
    root: Path,
    function_data: Path,
    manifest: Path,
    merged: Mapping[str, Path],
    backends: Sequence[str],
    scope_policy: Mapping[str, object],
    regression_limit: int,
    report: Path,
    markdown: Path,
) -> tuple[str, ...]:
    command = [
        sys.executable,
        str(_REPO_ROOT / "scripts/report_typematch_ab.py"),
        "--function-data",
        str(function_data),
        "--results-root",
        str(root),
        "--manifest",
        str(manifest),
        "--baseline-mode",
        "address",
        "--checkpoint-dir",
        str(root / "checkpoints"),
        "--regression-limit",
        str(regression_limit),
        "--run-scope",
        str(scope_policy["name"]),
        "--scope-fairness",
        str(scope_policy["fairness"]),
        "--output",
        str(report),
        "--markdown",
        str(markdown),
    ]
    for mode in MODES:
        command.extend(("--mode", f"{mode}={merged[mode]}"))
    for backend in backends:
        command.extend(("--backend", backend))
    return tuple(command)


def _validate_report_contents(
    report_path: Path,
    backends: Sequence[str],
    *,
    root: Path,
    function_data: Path,
    manifest: Path,
    merged: Mapping[str, Path],
    scope_policy: Mapping[str, object],
) -> None:
    try:
        report = json.loads(report_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ShardedTypeMatchError(f"report output is invalid: {exc}") from exc
    if report.get("validation", {}).get("valid_for_apples_to_apples") is not True:
        raise ShardedTypeMatchError("report rejected the merged overlays as incomparable")
    report_backends = report.get("scope", {}).get("backends")
    if report_backends != list(backends):
        raise ShardedTypeMatchError(
            f"report backend scope changed: expected {list(backends)}, got {report_backends}"
        )
    _old, function_keys, measurable = _function_data_scope(root, function_data)
    selected = load_manifest(manifest)
    if not selected <= function_keys:
        raise ShardedTypeMatchError("report manifest is outside the frozen function universe")
    denominator = selected & measurable
    expected_scope = {
        "selected_functions": len(selected),
        "globally_type_measurable_functions": len(denominator),
        "globally_unmeasurable_functions": len(selected) - len(denominator),
        "selected_key_sha256": keyset_sha256(selected),
        "shared_denominator_key_sha256": keyset_sha256(denominator),
        "declared_run_scope": scope_policy.get("name"),
        "declared_scope_fairness": scope_policy.get("fairness"),
    }
    report_scope = report.get("scope")
    if not isinstance(report_scope, Mapping) or any(
        report_scope.get(field) != value for field, value in expected_scope.items()
    ):
        raise ShardedTypeMatchError("report scope/denominator provenance changed")

    producer, _warnings = load_producer_evidence(root / "checkpoints", denominator, backends)
    expected_provenance = {
        "function_data": {
            "path": str(function_data),
            "sha256": file_sha256(function_data),
        },
        "results_root": str(root),
        "manifest": {"path": str(manifest), "sha256": file_sha256(manifest)},
        "checkpoint_evidence": {
            "directory": str(root / "checkpoints"),
            "selected_entry_count": len(producer),
            "selected_evidence_sha256": _producer_evidence_sha256(producer),
        },
    }
    provenance = report.get("provenance")
    if not isinstance(provenance, Mapping) or any(
        provenance.get(field) != value for field, value in expected_provenance.items()
    ):
        raise ShardedTypeMatchError("report frozen-input/checkpoint provenance changed")
    report_modes = provenance.get("modes")
    if not isinstance(report_modes, Mapping):
        raise ShardedTypeMatchError("report mode provenance is invalid")
    for mode, path in merged.items():
        row = report_modes.get(mode)
        if not isinstance(row, Mapping):
            raise ShardedTypeMatchError(f"report lacks provenance for mode {mode}")
        if row.get("path") != str(path) or row.get("sha256") != file_sha256(path):
            raise ShardedTypeMatchError(f"report overlay provenance changed for mode {mode}")


def _report_receipt_payload(
    *,
    root: Path,
    function_data: Path,
    manifest: Path,
    output: Path,
    merged: Mapping[str, Path],
    backends: Sequence[str],
    scope_policy: Mapping[str, object],
    regression_limit: int,
    attempt_id: str,
) -> dict[str, object]:
    report_path = output / "report" / "typematch_ab.json"
    markdown_path = output / "report" / "typematch_ab.md"
    stdout_path = output / "report" / "typematch_ab.stdout.log"
    stderr_path = output / "report" / "typematch_ab.stderr.log"
    process_path = output / "report" / "typematch_ab.process.json"
    stage = output / "stages" / "report" / attempt_id
    command = _report_command(
        root=root,
        function_data=function_data,
        manifest=manifest,
        merged=merged,
        backends=backends,
        scope_policy=scope_policy,
        regression_limit=regression_limit,
        report=stage / "report.json",
        markdown=stage / "report.md",
    )
    _validate_report_contents(
        report_path,
        backends,
        root=root,
        function_data=function_data,
        manifest=manifest,
        merged=merged,
        scope_policy=scope_policy,
    )
    try:
        raw_process = json.loads(process_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ShardedTypeMatchError(f"invalid report process record: {exc}") from exc
    process = _validate_process_payload(
        raw_process,
        coordinate=str(process_path),
        expected_attempt_id=attempt_id,
        expected_job="report",
        expected_command=command,
        require_completed_success=True,
    )
    return {
        "schema": REPORT_RECEIPT_SCHEMA,
        "attempt_id": attempt_id,
        "stage_directory": str(stage),
        "command": list(command),
        "backends": list(backends),
        "scope": {
            "name": scope_policy.get("name"),
            "fairness": scope_policy.get("fairness"),
        },
        "regression_limit": regression_limit,
        "merged": {
            mode: {
                "path": str(path),
                "sha256": file_sha256(path),
                "manifest_sha256": file_sha256(typematch_overlay_manifest_path(path)),
            }
            for mode, path in merged.items()
        },
        "report": {
            "path": str(report_path),
            "sha256": file_sha256(report_path),
            "size": report_path.stat().st_size,
        },
        "markdown": {
            "path": str(markdown_path),
            "sha256": file_sha256(markdown_path),
            "size": markdown_path.stat().st_size,
        },
        "stdout": {
            "path": str(stdout_path),
            "sha256": file_sha256(stdout_path),
            "size": stdout_path.stat().st_size,
        },
        "stderr": {
            "path": str(stderr_path),
            "sha256": file_sha256(stderr_path),
            "size": stderr_path.stat().st_size,
        },
        "process": {
            "path": str(process_path),
            "sha256": file_sha256(process_path),
            "payload": process,
        },
    }


def _validate_report_receipt(
    *,
    root: Path,
    function_data: Path,
    manifest: Path,
    output: Path,
    merged: Mapping[str, Path],
    backends: Sequence[str],
    scope_policy: Mapping[str, object],
    regression_limit: int,
) -> bool:
    receipt_path = output / "report" / "receipt.json"
    if not receipt_path.exists():
        return False
    try:
        receipt = json.loads(receipt_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ShardedTypeMatchError(f"invalid report receipt {receipt_path}: {exc}") from exc
    attempt_id = receipt.get("attempt_id") if isinstance(receipt, Mapping) else None
    if not isinstance(attempt_id, str) or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None:
        raise ShardedTypeMatchError(f"invalid report attempt token in {receipt_path}")
    expected = _report_receipt_payload(
        root=root,
        function_data=function_data,
        manifest=manifest,
        output=output,
        merged=merged,
        backends=backends,
        scope_policy=scope_policy,
        regression_limit=regression_limit,
        attempt_id=attempt_id,
    )
    if receipt != expected:
        raise ShardedTypeMatchError(f"report receipt content mismatch: {receipt_path}")
    return True


def _run_report(
    *,
    root: Path,
    function_data: Path,
    manifest: Path,
    output: Path,
    merged: Mapping[str, Path],
    backends: Sequence[str],
    scope_policy: Mapping[str, object],
    regression_limit: int,
    timeout: int,
) -> tuple[Path, Path]:
    report_path = output / "report" / "typematch_ab.json"
    markdown_path = output / "report" / "typematch_ab.md"
    stage_root = output / "stages" / "report"
    stale_stages = sorted(stage_root.iterdir()) if stage_root.is_dir() else []
    if _validate_report_receipt(
        root=root,
        function_data=function_data,
        manifest=manifest,
        output=output,
        merged=merged,
        backends=backends,
        scope_policy=scope_policy,
        regression_limit=regression_limit,
    ):
        if stale_stages:
            receipt_attempt = str(
                json.loads((output / "report" / "receipt.json").read_text())["attempt_id"]
            )
            for stale in stale_stages:
                if stale.name != receipt_attempt or not stale.is_dir():
                    raise ShardedTypeMatchError(
                        f"completed report has unexpected stale stage: {stale}"
                    )
                entries = list(stale.iterdir())
                if entries:
                    duplicate_process = stale / "process.json"
                    committed_process = output / "report" / "typematch_ab.process.json"
                    if (
                        entries != [duplicate_process]
                        or duplicate_process.read_bytes() != committed_process.read_bytes()
                    ):
                        raise ShardedTypeMatchError(
                            f"completed report has unexpected stale stage: {stale}"
                        )
                    duplicate_process.unlink()
                stale.rmdir()
        return report_path, markdown_path

    report_directory = output / "report"
    committed_process = report_directory / "typematch_ab.process.json"
    for stale in stale_stages:
        if not stale.is_dir() or any(stale.iterdir()):
            continue
        attempt_id = stale.name
        command = _report_command(
            root=root,
            function_data=function_data,
            manifest=manifest,
            merged=merged,
            backends=backends,
            scope_policy=scope_policy,
            regression_limit=regression_limit,
            report=stale / "report.json",
            markdown=stale / "report.md",
        )
        try:
            raw_process = json.loads(committed_process.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ShardedTypeMatchError(
                f"cannot prove empty report stage ownership at {stale}: {exc}"
            ) from exc
        _validate_process_payload(
            raw_process,
            coordinate=str(committed_process),
            expected_attempt_id=attempt_id,
            expected_job="report",
            expected_command=command,
            require_completed_success=True,
        )
        _terminate_recorded_process_group(committed_process)
        stale.rmdir()
    stale_stages = sorted(stage_root.iterdir()) if stage_root.is_dir() else []
    final_artifacts = [
        report_path,
        markdown_path,
        report_directory / "typematch_ab.stdout.log",
        report_directory / "typematch_ab.stderr.log",
        report_directory / "typematch_ab.process.json",
        *stale_stages,
    ]
    final_artifacts.extend(report_directory.glob(".receipt.json.*.tmp"))
    final_artifacts.extend(report_directory.glob(".typematch_ab.process.json.*.tmp"))
    quarantine = _quarantine_owned_artifacts(
        output=output,
        label="report",
        paths=final_artifacts,
        reason="report artifacts existed without a committed receipt",
        require_process_record_for_directories=True,
    )
    if quarantine is not None:
        print(f"[retry] report: preserved incomplete stage in {quarantine}")

    attempt_id = secrets.token_hex(16)
    stage = stage_root / attempt_id
    stage.mkdir(parents=True, exist_ok=False)
    temporary_report = stage / "report.json"
    temporary_markdown = stage / "report.md"
    command = _report_command(
        root=root,
        function_data=function_data,
        manifest=manifest,
        merged=merged,
        backends=backends,
        scope_policy=scope_policy,
        regression_limit=regression_limit,
        report=temporary_report,
        markdown=temporary_markdown,
    )
    outcome = _run_subprocess(
        command,
        cwd=_REPO_ROOT,
        timeout=timeout,
        process_record=stage / "process.json",
        process_identity={"attempt_id": attempt_id, "job": "report"},
    )
    _write_bytes_atomic(stage / "stdout.log", outcome.stdout.encode())
    _write_bytes_atomic(stage / "stderr.log", outcome.stderr.encode())
    if outcome.timed_out or outcome.returncode != 0 or outcome.stderr.strip():
        raise ShardedTypeMatchError(
            "TypeMatch A/B report failed closed: "
            f"exit={outcome.returncode}, timeout={outcome.timed_out}, "
            f"stderr={outcome.stderr!r}"
        )
    _validate_report_contents(
        temporary_report,
        backends,
        root=root,
        function_data=function_data,
        manifest=manifest,
        merged=merged,
        scope_policy=scope_policy,
    )
    expected_stdout = f"wrote {temporary_report}:"
    if not any(line.startswith(expected_stdout) for line in outcome.stdout.splitlines()):
        raise ShardedTypeMatchError("report stdout lacks the exact completion marker")
    report_directory.mkdir(parents=True, exist_ok=True)
    promotions = (
        (temporary_report, report_path),
        (temporary_markdown, markdown_path),
        (stage / "stdout.log", report_directory / "typematch_ab.stdout.log"),
        (stage / "stderr.log", report_directory / "typematch_ab.stderr.log"),
    )
    for source, target in promotions:
        os.replace(source, target)
    _write_bytes_atomic(
        report_directory / "typematch_ab.process.json",
        (stage / "process.json").read_bytes(),
    )
    receipt = _report_receipt_payload(
        root=root,
        function_data=function_data,
        manifest=manifest,
        output=output,
        merged=merged,
        backends=backends,
        scope_policy=scope_policy,
        regression_limit=regression_limit,
        attempt_id=attempt_id,
    )
    _write_json_atomic(report_directory / "receipt.json", receipt)
    (stage / "process.json").unlink()
    stage.rmdir()
    return report_path, markdown_path


def _final_receipt(
    *,
    plan_path: Path,
    jobs: Sequence[WorkerJob],
    merged: Mapping[str, Path],
    report: Path,
    markdown: Path,
    expected_by_backend: Mapping[str, set[ScoreKey]],
    scope_policy: Mapping[str, object],
    output: Path,
    completed_at: str | None = None,
) -> dict[str, object]:
    expected = set().union(*expected_by_backend.values())
    return {
        "schema": FINAL_RECEIPT_SCHEMA,
        "completed_at": completed_at or datetime.now(timezone.utc).isoformat(),
        "plan": {"path": str(plan_path), "sha256": file_sha256(plan_path)},
        "scope": {
            "name": scope_policy.get("name"),
            "fairness": scope_policy.get("fairness"),
        },
        "jobs": {
            "count": len(jobs),
            "receipt_sha256": _sha256_bytes(
                _json_bytes(
                    [
                        [str(job.receipt), file_sha256(job.receipt)]
                        for job in sorted(jobs, key=lambda item: item.label)
                    ],
                    pretty=False,
                )
            ),
        },
        "expected": {
            "entry_count_per_mode": len(expected),
            "score_key_sha256": _score_key_sha256(expected),
        },
        "merged": {
            mode: {
                "path": str(path),
                "sha256": file_sha256(path),
                "manifest_path": str(typematch_overlay_manifest_path(path)),
                "manifest_sha256": file_sha256(typematch_overlay_manifest_path(path)),
                "receipt": {
                    "path": str(path.with_suffix(".receipt.json")),
                    "sha256": file_sha256(path.with_suffix(".receipt.json")),
                },
            }
            for mode, path in merged.items()
        },
        "report": {
            "path": str(report),
            "sha256": file_sha256(report),
            "receipt": {
                "path": str(output / "report" / "receipt.json"),
                "sha256": file_sha256(output / "report" / "receipt.json"),
            },
        },
        "markdown": {"path": str(markdown), "sha256": file_sha256(markdown)},
        "quarantined_attempts": _optional_tree_inventory(output / "failed_attempts"),
        "canonical_outputs_touched": False,
    }


def _validate_completed_run(
    receipt_path: Path,
    *,
    root: Path,
    function_data: Path,
    manifest: Path,
    plan_path: Path,
    jobs: Sequence[WorkerJob],
    output: Path,
    backends: Sequence[str],
    expected_by_backend: Mapping[str, set[ScoreKey]],
    scope_policy: Mapping[str, object],
    regression_limit: int,
) -> bool:
    if not receipt_path.exists():
        return False
    try:
        receipt = json.loads(receipt_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ShardedTypeMatchError(f"invalid final receipt {receipt_path}: {exc}") from exc
    if receipt.get("schema") != FINAL_RECEIPT_SCHEMA:
        raise ShardedTypeMatchError(f"unsupported final receipt: {receipt_path}")

    expected = set().union(*expected_by_backend.values())
    merged: dict[str, Path] = {}
    for mode in MODES:
        path = output / "merged" / f"type_match_{mode.replace('+', '_plus_')}.json"
        _validate_overlay(path, mode=mode, expected=expected, backend=None)
        if not _validate_merge_receipt(
            receipt_path=path.with_suffix(".receipt.json"),
            mode=mode,
            target=path,
            expected=expected,
        ):
            raise ShardedTypeMatchError(f"completed run lacks merge receipt for mode {mode}")
        merged[mode] = path

    report_path = output / "report" / "typematch_ab.json"
    markdown_path = output / "report" / "typematch_ab.md"
    if not _validate_report_receipt(
        root=root,
        function_data=function_data,
        manifest=manifest,
        output=output,
        merged=merged,
        backends=backends,
        scope_policy=scope_policy,
        regression_limit=regression_limit,
    ):
        raise ShardedTypeMatchError("completed run lacks its report receipt")
    completed_at = receipt.get("completed_at")
    if not isinstance(completed_at, str):
        raise ShardedTypeMatchError("final receipt completion timestamp is invalid")
    try:
        datetime.fromisoformat(completed_at)
    except ValueError as exc:
        raise ShardedTypeMatchError("final receipt completion timestamp is invalid") from exc
    expected_receipt = _final_receipt(
        plan_path=plan_path,
        jobs=jobs,
        merged=merged,
        report=report_path,
        markdown=markdown_path,
        expected_by_backend=expected_by_backend,
        scope_policy=scope_policy,
        output=output,
        completed_at=completed_at,
    )
    if receipt != expected_receipt:
        raise ShardedTypeMatchError(f"final receipt content mismatch: {receipt_path}")
    return True


def _checkout_root(path: Path) -> Path | None:
    try:
        outcome = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ShardedTypeMatchError(f"could not inspect git checkout for {path}: {exc}") from exc
    if outcome.returncode != 0:
        return None
    rendered = outcome.stdout.strip()
    return Path(rendered).resolve() if rendered else None


def _linked_worktrees(checkout: Path) -> set[Path]:
    try:
        outcome = subprocess.run(
            ["git", "-C", str(checkout), "worktree", "list", "--porcelain"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ShardedTypeMatchError(
            f"could not enumerate protected git worktrees from {checkout}: {exc}"
        ) from exc
    if outcome.returncode != 0:
        raise ShardedTypeMatchError(
            f"could not enumerate protected git worktrees from {checkout}: "
            f"{outcome.stderr.strip()}"
        )
    roots = {
        Path(line.removeprefix("worktree ")).resolve()
        for line in outcome.stdout.splitlines()
        if line.startswith("worktree ")
    }
    roots.add(checkout.resolve())
    return roots


def _output_worktrees(root: Path) -> set[Path]:
    checkouts = {_REPO_ROOT.resolve()}
    results_checkout = _checkout_root(root)
    if results_checkout is not None:
        checkouts.add(results_checkout)
    worktrees: set[Path] = set()
    for checkout in checkouts:
        worktrees.update(_linked_worktrees(checkout))
    return {worktree.resolve() for worktree in worktrees}


def _protected_dataset_roots(worktrees: Iterable[Path]) -> set[Path]:
    candidates = {(path.parent / "decbench-dataset").resolve() for path in worktrees}
    protected = set(candidates)
    enumerated: set[Path] = set()
    for candidate in sorted(candidates):
        if not candidate.exists():
            continue
        checkout = _checkout_root(candidate)
        if checkout is None or checkout in enumerated:
            continue
        protected.update(_linked_worktrees(checkout))
        enumerated.add(checkout)
    return protected


def _assert_output_scope(
    root: Path,
    output: Path,
    *,
    function_data: Path | None = None,
    manifest: Path | None = None,
) -> None:
    if output == root or root in output.parents:
        raise ShardedTypeMatchError("output directory must be outside the evaluated results tree")
    if output in root.parents:
        raise ShardedTypeMatchError("output directory must not contain the results root")
    if function_data is not None:
        baseline = function_data.resolve(strict=True)
        baseline_root = baseline.parent
        if output == baseline_root or baseline_root in output.parents:
            raise ShardedTypeMatchError(
                "output directory must be outside the function-data baseline tree"
            )
        if output == baseline or output in baseline.parents:
            raise ShardedTypeMatchError("output directory must not contain function data")
    if manifest is not None:
        selected_manifest = manifest.resolve(strict=True)
        if output == selected_manifest or output in selected_manifest.parents:
            raise ShardedTypeMatchError("output directory must not contain the source manifest")
    worktrees = _output_worktrees(root)
    datasets = _protected_dataset_roots(worktrees)
    if any(output == dataset or dataset in output.parents for dataset in datasets):
        raise ShardedTypeMatchError(
            "output directory may not be inside a protected dataset checkout"
        )
    for worktree in worktrees:
        if output != worktree and worktree not in output.parents:
            continue
        results_tree = worktree / "results"
        if output == results_tree or results_tree not in output.parents:
            raise ShardedTypeMatchError(
                "output inside a linked source worktree must be below its results directory"
            )
    canonical = (root / "type_match_new.json").resolve()
    generated = [
        output / "merged" / f"type_match_{mode.replace('+', '_plus_')}.json" for mode in MODES
    ]
    for path in generated:
        try:
            aliases = path.resolve() == canonical or (
                path.exists() and canonical.exists() and os.path.samefile(path, canonical)
            )
        except OSError:
            aliases = False
        if aliases:
            raise ShardedTypeMatchError(f"analysis output aliases canonical overlay: {path}")


def _assert_no_symlink_ancestry(path: Path) -> None:
    if not path.is_absolute():
        raise ShardedTypeMatchError(f"analysis output must be absolute: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ShardedTypeMatchError(
                f"could not inspect analysis output ancestry at {current}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ShardedTypeMatchError(
                f"analysis output ancestry may not contain a symlink: {current}"
            )


def _recover_top_level_atomic_temporaries(output: Path) -> None:
    candidates: list[Path] = []
    for path in output.iterdir():
        owned_name = any(
            path.name.startswith(f".{target}.") and path.name.endswith(".tmp")
            for target in ("run_plan.json", "receipt.json")
        )
        if not owned_name:
            continue
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ShardedTypeMatchError(f"owned atomic temporary is unsafe: {path}")
        candidates.append(path)
    quarantine = _quarantine_owned_artifacts(
        output=output,
        label="top-level-atomic-write",
        paths=candidates,
        reason="top-level atomic write lacked a committed directory entry",
    )
    if quarantine is not None:
        print(f"[retry] preserved incomplete top-level atomic write in {quarantine}")


@contextmanager
def _output_lock(output: Path) -> Iterator[None]:
    if not output.is_absolute():
        raise ShardedTypeMatchError(f"analysis output must be absolute: {output}")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = os.open(os.sep, directory_flags)
    try:
        for part in output.parts[1:]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        lock_flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        lock_fd = os.open(".run.lock", lock_flags, 0o600, dir_fd=directory_fd)
    except OSError as exc:
        os.close(directory_fd)
        raise ShardedTypeMatchError(
            f"could not safely open analysis lock below {output}: {exc}"
        ) from exc

    try:
        lock_stat = os.fstat(lock_fd)
        entry_stat = os.stat(".run.lock", dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        os.close(directory_fd)
        os.close(lock_fd)
        raise ShardedTypeMatchError(
            f"could not validate analysis lock below {output}: {exc}"
        ) from exc
    os.close(directory_fd)
    if (
        not stat.S_ISREG(lock_stat.st_mode)
        or lock_stat.st_nlink != 1
        or (lock_stat.st_dev, lock_stat.st_ino) != (entry_stat.st_dev, entry_stat.st_ino)
    ):
        os.close(lock_fd)
        raise ShardedTypeMatchError(
            f"analysis lock must be a regular single-link file: {output / '.run.lock'}"
        )
    stream = os.fdopen(lock_fd, "a+b")
    try:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ShardedTypeMatchError(
                f"another TypeMatch A/B orchestrator holds {output / '.run.lock'}"
            ) from exc
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def _prepare_shards(
    manifest: Path,
    selected: set[FunctionKey],
    output: Path,
    count: int,
    timeout: int,
    *,
    dry_run: bool,
) -> tuple[
    Path,
    dict[str, Any],
    list[tuple[Path, set[FunctionKey], Mapping[str, Any]]],
    tempfile.TemporaryDirectory[str] | None,
]:
    if dry_run:
        temporary = tempfile.TemporaryDirectory(prefix="decbench-typematch-shards-")
        directory = Path(temporary.name) / "shards"
        _run_sharder(manifest, directory, count, timeout)
        index, rows = _load_shard_index(
            directory,
            source_manifest=manifest,
            source_keys=selected,
            shard_count=count,
        )
        return directory, index, rows, temporary

    directory = output / "shards"
    stage_root = output / "stages" / "shards"
    if stage_root.is_dir():
        for stage in sorted(stage_root.iterdir()):
            if stage.is_symlink() or not stage.is_dir():
                raise ShardedTypeMatchError(f"invalid shard-generation stage: {stage}")
            if not any(stage.iterdir()):
                stage.rmdir()
                continue
            quarantine = _quarantine_owned_artifacts(
                output=output,
                label="shard-generation",
                paths=[stage],
                reason="shard generation lacked a committed output directory",
                require_process_record_for_directories=True,
            )
            if quarantine is not None:
                print(f"[retry] preserved incomplete shard generation in {quarantine}")
        with contextlib.suppress(OSError):
            stage_root.rmdir()
        with contextlib.suppress(OSError):
            stage_root.parent.rmdir()
    if directory.exists():
        try:
            index, rows = _load_shard_index(
                directory,
                source_manifest=manifest,
                source_keys=selected,
                shard_count=count,
            )
        except ShardedTypeMatchError:
            if (output / "run_plan.json").exists():
                raise
            quarantine = _quarantine_owned_artifacts(
                output=output,
                label="shards",
                paths=[directory],
                reason="uncommitted shard directory was incomplete or invalid",
            )
            if quarantine is not None:
                print(f"[retry] preserved incomplete shard directory in {quarantine}")
        else:
            return directory, index, rows, None

    attempt_id = secrets.token_hex(16)
    stage = stage_root / attempt_id
    stage.mkdir(parents=True, exist_ok=False)
    generated = stage / "generated"
    process_record = stage / "process.json"
    _run_sharder(
        manifest,
        generated,
        count,
        timeout,
        process_record=process_record,
        attempt_id=attempt_id,
    )
    index, rows = _load_shard_index(
        generated,
        source_manifest=manifest,
        source_keys=selected,
        shard_count=count,
    )
    os.replace(generated, directory)
    process_record.unlink()
    stage.rmdir()
    stage_root.rmdir()
    with contextlib.suppress(OSError):
        stage_root.parent.rmdir()
    index, rows = _load_shard_index(
        directory,
        source_manifest=manifest,
        source_keys=selected,
        shard_count=count,
    )
    return directory, index, rows, None


def _run_locked(
    args: argparse.Namespace,
    *,
    root: Path,
    manifest: Path,
    function_data: Path,
    output: Path,
) -> int:
    manifest_record = _stable_file_record(manifest)
    function_data_record = _stable_file_record(function_data)
    _old, function_keys, measurable_keys = _function_data_scope(root, function_data)
    selected = load_manifest(manifest)
    if _stable_file_record(manifest) != manifest_record:
        raise ShardedTypeMatchError("manifest changed while the run scope was loaded")
    if _stable_file_record(function_data) != function_data_record:
        raise ShardedTypeMatchError(
            f"function data changed while its denominator loaded: {function_data}"
        )
    missing = sorted(selected - function_keys)
    if missing:
        raise ShardedTypeMatchError(
            f"manifest has {len(missing)} keys absent from function_results.json: "
            + ", ".join(key_text(key) for key in missing[:3])
        )
    if not (selected & measurable_keys):
        raise ShardedTypeMatchError("manifest has no functions in the fixed TypeMatch denominator")

    backends, checkpoints, expected_by_backend = _checkpoint_scope(
        root,
        selected,
        measurable_keys,
        args.backend,
    )
    scope_policy = _validate_run_scope(
        scope=args.scope,
        root=root,
        selected=selected,
        function_keys=function_keys,
        backends=backends,
        explicitly_requested=args.backend,
    )
    binaries, sources = _selected_source_inventory(root, selected)

    shard_dir, shard_index, shard_rows, shard_temporary = _prepare_shards(
        manifest,
        selected,
        output,
        args.shards,
        args.job_timeout,
        dry_run=args.dry_run,
    )
    plan = _build_plan(
        root=root,
        selected=selected,
        measurable=measurable_keys,
        backends=backends,
        expected_by_backend=expected_by_backend,
        checkpoints=checkpoints,
        binaries=binaries,
        sources=sources,
        shard_directory=shard_dir,
        recorded_shard_directory=output / "shards",
        shard_index=shard_index,
        shard_rows=shard_rows,
        manifest_record=manifest_record,
        function_data_record=function_data_record,
        scope_policy=scope_policy,
        regression_limit=args.regression_limit,
    )
    plan_bytes = _json_bytes(plan)
    plan_sha256 = _sha256_bytes(plan_bytes)
    if args.dry_run:
        summary = {
            "schema": RUN_PLAN_SCHEMA,
            "plan_sha256": plan_sha256,
            "selected_functions": len(selected),
            "measurable_functions": len(selected & measurable_keys),
            "backends": backends,
            "scope": args.scope,
            "modes": list(MODES),
            "shards": args.shards,
            "jobs": 4
            * sum(
                bool({key for key in expected_by_backend[backend] if key[:4] in shard_keys})
                for _path, shard_keys, _row in shard_rows
                for backend in backends
            ),
            "writes": False,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        if shard_temporary is not None:
            shard_temporary.cleanup()
        return 0

    plan_path = output / "run_plan.json"
    if plan_path.exists():
        if plan_path.read_bytes() != plan_bytes:
            raise ShardedTypeMatchError(
                "run plan differs from current inputs/code; use a new output directory"
            )
    else:
        existing = [
            path
            for path in output.iterdir()
            if path.name not in {".run.lock", "failed_attempts", "shards"}
        ]
        if existing:
            raise ShardedTypeMatchError("run artifacts exist without a binding run plan")
        _write_bytes_atomic(plan_path, plan_bytes)
    _validate_inventory(plan, root)

    jobs = _jobs(
        output=output,
        function_data=function_data,
        shards=shard_rows,
        backends=backends,
        expected_by_backend=expected_by_backend,
    )
    expected_job_count = 4 * sum(
        bool({key for key in expected_by_backend[backend] if key[:4] in shard_keys})
        for _path, shard_keys, _row in shard_rows
        for backend in backends
    )
    if len(jobs) != expected_job_count:
        raise ShardedTypeMatchError("internal job inventory mismatch")

    _execute_jobs(
        jobs,
        root=root,
        workers=args.workers,
        timeout=args.job_timeout,
        plan_sha256=plan_sha256,
    )
    _validate_inventory(plan, root)
    final_receipt_path = output / "receipt.json"
    if _validate_completed_run(
        final_receipt_path,
        root=root,
        function_data=function_data,
        manifest=manifest,
        plan_path=plan_path,
        jobs=jobs,
        output=output,
        backends=backends,
        expected_by_backend=expected_by_backend,
        scope_policy=scope_policy,
        regression_limit=args.regression_limit,
    ):
        print(f"[resume] completed run validated: {final_receipt_path}")
        return 0
    merged = _merge_modes(jobs, output=output, expected_by_backend=expected_by_backend)
    report, markdown = _run_report(
        root=root,
        function_data=function_data,
        manifest=manifest,
        output=output,
        merged=merged,
        backends=backends,
        scope_policy=scope_policy,
        regression_limit=args.regression_limit,
        timeout=args.job_timeout,
    )
    _validate_inventory(plan, root)
    receipt = _final_receipt(
        plan_path=plan_path,
        jobs=jobs,
        merged=merged,
        report=report,
        markdown=markdown,
        expected_by_backend=expected_by_backend,
        scope_policy=scope_policy,
        output=output,
    )
    _write_json_atomic(final_receipt_path, receipt)
    print(
        f"complete: {len(selected & measurable_keys)} fixed-denominator functions, "
        f"{len(backends)} backend(s), receipt={output / 'receipt.json'}"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.results_dir.resolve(strict=True)
    manifest = args.manifest.resolve(strict=True)
    function_data = (
        args.function_data.resolve(strict=True)
        if args.function_data is not None
        else (root / "function_results.json").resolve(strict=True)
    )
    requested_output = Path(os.path.abspath(args.output_dir.expanduser()))
    _assert_no_symlink_ancestry(requested_output)
    output = requested_output.resolve()
    if not root.is_dir():
        raise ShardedTypeMatchError(f"results root is not a directory: {root}")
    if not function_data.is_file():
        raise ShardedTypeMatchError(f"function data is not a regular file: {function_data}")
    _assert_output_scope(root, output, function_data=function_data, manifest=manifest)
    if args.dry_run:
        return _run_locked(
            args,
            root=root,
            manifest=manifest,
            function_data=function_data,
            output=output,
        )

    if output.exists() and not output.is_dir():
        raise ShardedTypeMatchError(f"output path is not a directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    with _output_lock(output):
        symlinks = sorted(path for path in output.rglob("*") if path.is_symlink())
        if symlinks:
            raise ShardedTypeMatchError(f"analysis directory contains a symlink: {symlinks[0]}")
        _recover_top_level_atomic_temporaries(output)
        allowed = {
            ".run.lock",
            "shards",
            "run_plan.json",
            "workers",
            "failed_attempts",
            "stages",
            "merged",
            "report",
            "receipt.json",
        }
        unknown = sorted(path.name for path in output.iterdir() if path.name not in allowed)
        if unknown:
            raise ShardedTypeMatchError(
                "output directory contains unrelated entries: " + ", ".join(unknown[:3])
            )
        return _run_locked(
            args,
            root=root,
            manifest=manifest,
            function_data=function_data,
            output=output,
        )


if __name__ == "__main__":
    raise SystemExit(main())
