#!/usr/bin/env python
"""Calibrate the local-variable matcher with debug-visible IDA/Ghidra names.

This is a *calibration* lane, not a realistic variable-recovery benchmark.
IDA/Ghidra analyze the unstripped, DWARF-bearing binaries so retained source
names can be used as a post-match oracle.  Before ``match_variables`` is
called, every source and decompiler variable name is replaced with an opaque
alias.  Original names are inspected only after matching.

The preferred input is the stable sample emitted by the stripped checkpoint
scorer.  Its JSONL records contain an address-bearing ``function`` object, so
the exact same functions are used for IDA and Ghidra without a redraw:

    python scripts/calibrate_local_variable_matcher.py \
      --results-root results/lved_coreutils \
      --sample-manifest \
        results/lved_coreutils/local_variable_distance_sample.jsonl \
      --backend ida --backend ghidra

When no sample manifest is supplied, the script ranks all attributable O2
functions by a stable SHA-256 hash, takes ``--sample-size`` (default 100), and
persists the resolved address-bearing manifest beside the report.

Outputs under ``--output-dir``:

* ``calibration_manifest.json``: the exact function/address set;
* ``calibration_pairs.jsonl``: one row per accepted matcher pair;
* ``calibration_functions.jsonl``: one row per function/backend, including
  extraction failures and abstention denominators;
* ``calibration_report.json``: per-stage micro/macro metrics, calibration bins,
  and deterministic function-cluster bootstrap intervals.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from decbench.caching import stable_hash
from decbench.experimental.local_variable_checkpoint import (
    ScoreConfig,
    SourceLineCache,
    discover_dwarf_function_universe,
    resolve_source_unit,
)
from decbench.experimental.local_variable_distance import (
    DistanceResult,
    FunctionEvidence,
    VariableEvidence,
    extract_decompiler_evidence,
    extract_source_evidence,
    instruction_addresses,
    match_variables,
)
from decbench.models.decompilation import FunctionDecompilation

SCHEMA_VERSION = 1
LANE = "debug-visible-blinded-name-calibration"
DEFAULT_SAMPLE_SEED = "coreutils-lved-v1"
SAMPLE_ALGORITHM = "sha256-rank-v1"
STAGES = ("argument", "stack", "overlap")
VERDICTS = ("correct", "incorrect", "unknown")
METRICS = (
    "precision",
    "decidable_error_rate",
    "recall",
    "coverage",
    "abstention",
    "unknown_rate",
    "error_rate_lower_bound",
    "error_rate_upper_bound",
    "oracle_retention_rate",
)
PARTITIONS = ("tuning", "held_out")

_C_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SYNTHETIC_NAME_PATTERNS = (
    # IDA's default argument/local names.
    re.compile(r"^(?:a|v)\d+$", re.IGNORECASE),
    re.compile(r"^(?:arg|var)_[0-9a-f]+$", re.IGNORECASE),
    # Ghidra's default arguments, locals, temporaries, and register names.
    re.compile(
        r"^(?:param|local|stack|temp|tmp|varnode|field|array|joined)_[0-9a-f]+$",
        re.IGNORECASE,
    ),
    re.compile(r"^[puicbsldf]*Var\d+$"),
    re.compile(r"^(?:unaff|extraout|in|out)_[A-Za-z0-9_]+$", re.IGNORECASE),
    # Compiler/debugger-generated identifiers.
    re.compile(r"^(?:D|iftmp|pretmp|profiler|__compound_literal)\.?\d+$"),
    re.compile(r"^__?(?:func|FUNCTION|PRETTY_FUNCTION)__$"),
)


@dataclass(frozen=True, order=True)
class CalibrationTarget:
    """One address-pinned source function shared by every backend."""

    project: str
    optimization: str
    binary: str
    address: int
    name: str
    partition: str | None = None

    def __post_init__(self) -> None:
        if self.partition is not None and self.partition not in PARTITIONS:
            raise ValueError(
                f"invalid calibration partition {self.partition!r}; "
                f"expected one of {PARTITIONS}"
            )

    @property
    def cluster_id(self) -> str:
        return (
            f"{self.project}::{self.optimization}::{self.binary}::"
            f"0x{self.address:x}::{self.name}"
        )

    def hash_parts(self) -> tuple[str, str, str, str]:
        """Return the scorer's exact hash domain (project is added separately)."""

        return (
            self.optimization,
            self.binary,
            f"0x{self.address:x}",
            self.name,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "optimization": self.optimization,
            "binary": self.binary,
            "address": f"0x{self.address:x}",
            "name": self.name,
        }

    def to_manifest_dict(self) -> dict[str, Any]:
        row = self.to_dict()
        row["partition"] = self.partition
        return row


@dataclass(frozen=True)
class CalibrationConfig:
    """Frozen matcher/report parameters recorded with every result."""

    min_overlap: float = 0.1
    ambiguity_margin: float = 0.03
    tuning_fraction: float = 0.25
    sample_seed: str = DEFAULT_SAMPLE_SEED
    bootstrap_iterations: int = 2000
    bootstrap_seed: str = "coreutils-lved-calibration-bootstrap-v1"

    def __post_init__(self) -> None:
        if self.min_overlap < 0:
            raise ValueError("min_overlap must be non-negative")
        if self.ambiguity_margin < 0:
            raise ValueError("ambiguity_margin must be non-negative")
        if not 0 <= self.tuning_fraction <= 1:
            raise ValueError("tuning_fraction must be between 0 and 1")
        if self.bootstrap_iterations < 0:
            raise ValueError("bootstrap_iterations must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_address(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _target_spec(row: dict[str, Any]) -> dict[str, Any]:
    function = row.get("function")
    return function if isinstance(function, dict) else row


def _read_manifest_rows(path: Path) -> list[dict[str, Any]]:
    """Read a scorer JSONL, standard subset JSON, or resolved calibration JSON."""

    if path.suffix.lower() == ".jsonl":
        rows = []
        for line_number, text in enumerate(path.read_text().splitlines(), start=1):
            if not text.strip():
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            rows.append(row)
        return rows
    payload = json.loads(path.read_text())
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected a JSON object or list")
    rows = payload.get("functions")
    if not isinstance(rows, list):
        raise ValueError(f"{path}: expected a 'functions' list")
    return rows


def _resolve_manifest_rows(
    rows: Iterable[dict[str, Any]],
    *,
    project: str,
    optimization: str,
    universe: Sequence[CalibrationTarget] | None = None,
) -> list[CalibrationTarget]:
    """Resolve manifest rows, using the DWARF universe only when addresses are absent."""

    by_name: dict[tuple[str, str, str, str], list[CalibrationTarget]] = defaultdict(list)
    if universe is not None:
        for target in universe:
            by_name[(target.project, target.optimization, target.binary, target.name)].append(
                target
            )

    resolved: list[CalibrationTarget] = []
    seen_targets: set[tuple[str, str, str, int, str]] = set()
    seen_sample_ids: set[str] = set()
    unresolved: list[tuple[str, str, str, str]] = []
    partition_presence: set[bool] = set()
    for raw in rows:
        spec = _target_spec(raw)
        row_project = str(spec.get("project", project))
        row_opt = str(spec.get("optimization", spec.get("opt", optimization)))
        row_binary = str(spec.get("binary", ""))
        row_name = str(spec.get("name", spec.get("function", "")))
        if row_project != project or row_opt != optimization:
            continue
        if not row_binary or not row_name:
            raise ValueError(f"manifest function is missing binary/name: {spec}")
        partition_value = raw.get("partition", spec.get("partition"))
        partition_presence.add(partition_value is not None)
        partition = str(partition_value) if partition_value is not None else None
        if partition is not None and partition not in PARTITIONS:
            raise ValueError(f"manifest function has invalid partition {partition!r}: {spec}")
        sample_id = raw.get("sample_id")
        if sample_id is not None:
            normalized_sample_id = str(sample_id)
            if normalized_sample_id in seen_sample_ids:
                raise ValueError(f"duplicate sample_id in manifest: {normalized_sample_id}")
            seen_sample_ids.add(normalized_sample_id)
        address = _parse_address(spec.get("address"))
        if address is None:
            key = (row_project, row_opt, row_binary, row_name)
            matches = by_name.get(key, [])
            if len(matches) != 1:
                unresolved.append(key)
                continue
            target = replace(matches[0], partition=partition)
        else:
            target = CalibrationTarget(
                row_project,
                row_opt,
                row_binary,
                address,
                row_name,
                partition,
            )
        key = (
            target.project,
            target.optimization,
            target.binary,
            target.address,
            target.name,
        )
        if key in seen_targets:
            raise ValueError("duplicate function target in manifest: " f"{target.cluster_id}")
        seen_targets.add(key)
        resolved.append(target)
    if unresolved:
        rendered = ", ".join("/".join(key) for key in unresolved[:5])
        extra = f" (+{len(unresolved) - 5} more)" if len(unresolved) > 5 else ""
        raise ValueError(
            "manifest rows without addresses did not resolve uniquely in DWARF: "
            f"{rendered}{extra}"
        )
    if not resolved:
        raise ValueError(f"manifest contains no {project}/{optimization} functions")
    if len(partition_presence) > 1:
        raise ValueError(
            "manifest mixes partitioned and unpartitioned rows; refusing an "
            "ambiguous tuning/held-out split"
        )
    return sorted(resolved)


def load_sample_manifest(
    path: Path,
    *,
    project: str,
    optimization: str,
    universe: Sequence[CalibrationTarget] | None = None,
) -> list[CalibrationTarget]:
    """Load the exact sample used by the stripped checkpoint scorer."""

    return _resolve_manifest_rows(
        _read_manifest_rows(path),
        project=project,
        optimization=optimization,
        universe=universe,
    )


def discover_targets(
    results_root: Path,
    *,
    project: str = "coreutils",
    optimization: str = "O2",
) -> list[CalibrationTarget]:
    """Discover the same strict, backend-independent source universe as the scorer."""

    universe, _diagnostics = discover_dwarf_function_universe(
        results_root,
        ScoreConfig(
            project=project,
            optimizations=(optimization,),
            decompiler_bases=(),
            sample_size=0,
            bootstrap_iterations=0,
        ),
        SourceLineCache(),
    )
    targets = [
        CalibrationTarget(
            project,
            row.key.optimization,
            row.key.binary,
            row.key.address,
            row.key.name,
        )
        for row in universe
    ]
    if not targets:
        raise ValueError(
            f"no strictly attributable DWARF functions found for " f"{project}/{optimization}"
        )
    return sorted(targets)


def deterministic_sample(
    targets: Sequence[CalibrationTarget],
    *,
    size: int = 100,
    seed: str = DEFAULT_SAMPLE_SEED,
) -> list[CalibrationTarget]:
    """Stable-hash rank a universe independently of filesystem/iteration order."""

    if size < 0:
        raise ValueError("sample size must be non-negative (0 means all)")
    ranked = sorted(
        targets,
        key=lambda target: (
            stable_hash(SAMPLE_ALGORITHM, seed, target.hash_parts()),
            target,
        ),
    )
    return ranked if size == 0 else ranked[:size]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def compiled_binary_hashes(
    results_root: Path,
    targets: Sequence[CalibrationTarget],
) -> list[dict[str, str]]:
    """Hash every sampled compiled artifact so address targets cannot go stale."""

    identities = sorted(
        {(target.project, target.optimization, target.binary) for target in targets}
    )
    rows = []
    for project, optimization, binary in identities:
        path = results_root / optimization / project / "compiled" / binary
        if not path.is_file():
            raise ValueError(f"sampled compiled binary is missing: {path}")
        rows.append(
            {
                "project": project,
                "optimization": optimization,
                "binary": binary,
                "sha256": _sha256_file(path),
            }
        )
    return rows


def calibration_implementation_hashes() -> dict[str, str]:
    """Hash the calibration, matcher, and source-resolution implementations."""

    repository = Path(__file__).resolve().parents[1]
    paths = (
        Path(__file__).resolve(),
        repository / "decbench/metrics/variable_match.py",
        repository / "decbench/metrics/variable_features.py",
        repository / "decbench/experimental/local_variable_checkpoint.py",
        repository / "decbench/decompilers/raw/ida_raw.py",
        repository / "decbench/decompilers/raw/ghidra_raw.py",
    )
    return {str(path.relative_to(repository)): _sha256_file(path) for path in paths}


def write_resolved_manifest(
    path: Path,
    targets: Sequence[CalibrationTarget],
    *,
    source_manifest: Path | None,
    config: CalibrationConfig,
    backends: Sequence[str],
    compiled_artifacts: Sequence[dict[str, str]],
    implementation_hashes: dict[str, str],
) -> None:
    """Persist all frozen inputs and refuse target/config/code drift."""

    targets = freeze_target_partitions(targets, config)
    target_ids = [target.cluster_id for target in targets]
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("resolved calibration targets contain duplicates")
    source_manifest_hash = (
        _sha256_file(source_manifest.resolve()) if source_manifest is not None else None
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "lane": LANE,
        "method": "external-manifest" if source_manifest else SAMPLE_ALGORITHM,
        "source_manifest": str(source_manifest.resolve()) if source_manifest else None,
        "source_manifest_sha256": source_manifest_hash,
        "frozen_config": config.to_dict(),
        "backends": list(backends),
        "compiled_artifacts": list(compiled_artifacts),
        "implementation_sha256": dict(sorted(implementation_hashes.items())),
        "functions": [target.to_manifest_dict() for target in sorted(targets)],
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if path.is_file() and path.read_text() != rendered:
        raise ValueError(
            f"resolved manifest would change {path}; remove it or choose a new output directory"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered)


def _debug_sections(path: Path) -> set[str]:
    from elftools.elf.elffile import ELFFile

    with path.open("rb") as stream:
        elf = ELFFile(stream)
        return {section.name for section in elf.iter_sections() if int(section["sh_size"]) > 0}


def verify_debug_visible_binary(path: Path) -> None:
    """Refuse a stripped or misplaced binary in the debug-visible lane."""

    if "stripped" in path.parts:
        raise ValueError(f"calibration input must not come from a stripped directory: {path}")
    sections = _debug_sections(path)
    if ".debug_info" not in sections or ".symtab" not in sections:
        raise ValueError(
            f"calibration requires .debug_info and .symtab in {path}; "
            f"present={sorted(sections & {'.debug_info', '.symtab', '.dynsym'})}"
        )


def resolve_binary(results_root: Path, target: CalibrationTarget) -> Path:
    path = (
        results_root / target.optimization / target.project / "compiled" / target.binary
    ).resolve()
    if not path.is_file():
        raise ValueError(f"sampled binary does not exist: {path}")
    verify_debug_visible_binary(path)
    return path


def _address_match(address: int, requested: int) -> bool:
    return address == requested or (address & ~1) == requested or address == (requested & ~1)


def _decompile_exact_ida(
    binary_path: Path,
    targets: Sequence[CalibrationTarget],
    backend_spec: str,
) -> tuple[dict[int, FunctionDecompilation], dict[int, str], str | None]:
    """Open one IDA database and invoke Hex-Rays only at sampled addresses."""

    import decbench.decompilers  # noqa: F401
    from decbench.decompilers.raw import common
    from decbench.decompilers.registry import DecompilerRegistry

    decompiler = DecompilerRegistry.get(backend_spec)
    if not decompiler.is_available():
        raise RuntimeError(f"Decompiler {backend_spec!r} is unavailable")

    import ida_hexrays
    import idapro

    elf_base = common.elf_min_vaddr(binary_path)
    text_range = common.elf_text_range(binary_path)
    output: dict[int, FunctionDecompilation] = {}
    errors: dict[int, str] = {}
    idapro.open_database(str(binary_path), run_auto_analysis=True)
    try:
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler is unavailable")
        enumerated = decompiler._enumerate(elf_base, text_range)
        for target in sorted(targets):
            matches = [
                (name, address)
                for name, address in enumerated
                if _address_match(address, target.address)
            ]
            if len(matches) != 1:
                errors[target.address] = (
                    f"IDA resolved {len(matches)} functions at 0x{target.address:x}"
                )
                continue
            tool_name, tool_address = matches[0]
            try:
                function = decompiler._decompile_one(tool_name, tool_address, elf_base)
            except Exception as exc:  # noqa: BLE001
                errors[target.address] = f"{type(exc).__name__}: {exc}"
                continue
            if function is None:
                errors[target.address] = "Hex-Rays returned no decompilation"
            else:
                output[target.address] = function
    finally:
        idapro.close_database(save=False)
    return output, errors, decompiler.get_version()


def _decompile_exact_ghidra(
    binary_path: Path,
    targets: Sequence[CalibrationTarget],
    backend_spec: str,
) -> tuple[dict[int, FunctionDecompilation], dict[int, str], str | None]:
    """Open one Ghidra program and decompile only address-resolved sampled functions."""

    import decbench.decompilers  # noqa: F401
    from decbench.decompilers.raw import common
    from decbench.decompilers.registry import DecompilerRegistry

    decompiler = DecompilerRegistry.get(backend_spec)
    if not decompiler.is_available():
        raise RuntimeError(f"Decompiler {backend_spec!r} is unavailable")
    launcher = decompiler._ensure_started()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    elf_base = common.elf_min_vaddr(binary_path)
    output: dict[int, FunctionDecompilation] = {}
    errors: dict[int, str] = {}
    with decompiler._open_program(launcher, binary_path) as flat:
        program = flat.getCurrentProgram()
        image_base = int(program.getImageBase().getOffset())
        by_address: dict[int, list[Any]] = defaultdict(list)
        for function in program.getFunctionManager().getFunctions(True):
            if function.isThunk() or function.isExternal():
                continue
            entry = int(function.getEntryPoint().getOffset())
            file_address = (entry - image_base) + elf_base
            by_address[file_address].append(function)

        interface = DecompInterface()
        interface.openProgram(program)
        monitor = ConsoleTaskMonitor()
        timeout = int(decompiler.config.function_timeout_seconds)
        try:
            for target in sorted(targets):
                matches = [
                    (address, function)
                    for address, functions in by_address.items()
                    if _address_match(address, target.address)
                    for function in functions
                ]
                if len(matches) != 1:
                    errors[target.address] = (
                        f"Ghidra resolved {len(matches)} functions at 0x{target.address:x}"
                    )
                    continue
                tool_address, function = matches[0]
                try:
                    result = decompiler._decompile_one(
                        interface,
                        function,
                        str(function.getName() or target.name),
                        tool_address,
                        elf_base,
                        image_base,
                        timeout,
                        monitor,
                    )
                except Exception as exc:  # noqa: BLE001
                    errors[target.address] = f"{type(exc).__name__}: {exc}"
                    continue
                if result is None:
                    errors[target.address] = "Ghidra returned no decompilation"
                else:
                    output[target.address] = result
        finally:
            interface.dispose()
    return output, errors, decompiler.get_version()


def decompile_sampled_addresses(
    binary_path: Path,
    targets: Sequence[CalibrationTarget],
    backend_spec: str,
) -> tuple[dict[int, FunctionDecompilation], dict[int, str], str | None]:
    """Dispatch an exact-address debug-visible run to a raw backend."""

    base = backend_spec.split("@", 1)[0]
    if base == "ida":
        return _decompile_exact_ida(binary_path, targets, backend_spec)
    if base == "ghidra":
        return _decompile_exact_ghidra(binary_path, targets, backend_spec)
    raise ValueError("calibration backend must be ida or ghidra")


def blind_variables(
    variables: Iterable[VariableEvidence],
    *,
    prefix: str,
) -> list[VariableEvidence]:
    """Replace every name without consulting or preserving its old value."""

    ordered = sorted(variables, key=lambda variable: variable.identity)
    aliases = {
        variable.identity: f"__blind_{prefix}_{index:04d}" for index, variable in enumerate(ordered)
    }
    return [replace(variable, name=aliases[variable.identity]) for variable in variables]


def _is_synthetic_name(name: str) -> bool:
    stripped = name.strip()
    if not stripped or not _C_IDENTIFIER.fullmatch(stripped):
        return True
    return any(pattern.fullmatch(stripped) for pattern in _SYNTHETIC_NAME_PATTERNS)


def _name_status(
    name: str,
    own_counts: Counter[str],
    other_counts: Counter[str],
) -> str:
    if _is_synthetic_name(name):
        return "synthetic"
    if own_counts[name] != 1:
        return "duplicate_lexical_name"
    if other_counts[name] == 0:
        return "not_retained_on_other_side"
    if other_counts[name] != 1:
        return "duplicate_on_other_side"
    return "eligible"


def build_name_oracle(
    source: Sequence[VariableEvidence],
    decompiled: Sequence[VariableEvidence],
) -> dict[str, Any]:
    """Build the conservative exact-name oracle after matching has completed."""

    source_counts = Counter(variable.name.strip() for variable in source)
    decompiled_counts = Counter(variable.name.strip() for variable in decompiled)
    source_status = {
        variable.identity: _name_status(
            variable.name.strip(),
            source_counts,
            decompiled_counts,
        )
        for variable in source
    }
    decompiled_status = {
        variable.identity: _name_status(
            variable.name.strip(),
            decompiled_counts,
            source_counts,
        )
        for variable in decompiled
    }
    eligible_names = sorted(
        name
        for name, count in source_counts.items()
        if count == 1 and decompiled_counts[name] == 1 and not _is_synthetic_name(name)
    )
    return {
        "eligible_names": eligible_names,
        "source_status": source_status,
        "decompiled_status": decompiled_status,
    }


def _computed_partition(
    target: CalibrationTarget,
    config: CalibrationConfig,
) -> str:
    digest = stable_hash(
        "lved-partition-v1",
        config.sample_seed,
        target.hash_parts(),
    )
    value = int(digest, 16) / (1 << 256)
    return "tuning" if value < config.tuning_fraction else "held_out"


def _partition(target: CalibrationTarget, config: CalibrationConfig) -> str:
    return target.partition or _computed_partition(target, config)


def freeze_target_partitions(
    targets: Sequence[CalibrationTarget],
    config: CalibrationConfig,
) -> list[CalibrationTarget]:
    """Freeze imported splits verbatim, or assign the scorer's split once."""

    frozen = []
    for target in targets:
        computed = _computed_partition(target, config)
        if target.partition is not None and target.partition != computed:
            raise ValueError(
                "imported scorer partition disagrees with the frozen seed/fraction "
                f"for {target.cluster_id}: imported={target.partition}, "
                f"computed={computed}"
            )
        frozen.append(replace(target, partition=target.partition or computed))
    return sorted(frozen)


def validate_imported_scorer_rows(
    rows: Sequence[dict[str, Any]],
    targets: Sequence[CalibrationTarget],
    config: CalibrationConfig,
) -> None:
    """Validate scorer IDs/ranks/thresholds without consulting match verdicts."""

    target_by_key = {
        (
            target.project,
            target.optimization,
            target.binary,
            target.address,
            target.name,
        ): target
        for target in targets
    }
    seen: set[tuple[str, str, str, int, str]] = set()
    address_bearing_rows = 0
    for raw in rows:
        spec = _target_spec(raw)
        try:
            key = (
                str(spec["project"]),
                str(spec.get("optimization", spec.get("opt"))),
                str(spec["binary"]),
                int(str(spec["address"]), 0),
                str(spec.get("name", spec.get("function"))),
            )
        except (KeyError, TypeError, ValueError):
            continue
        address_bearing_rows += 1
        target = target_by_key.get(key)
        if target is None:
            continue
        if key in seen:
            raise ValueError(f"duplicate imported scorer target: {target.cluster_id}")
        seen.add(key)

        expected_id = stable_hash(
            "lved-function-v1",
            target.project,
            target.hash_parts(),
        )
        if raw.get("sample_id") is not None and str(raw["sample_id"]) != expected_id:
            raise ValueError(f"stale sample_id for {target.cluster_id}")
        expected_rank = stable_hash(
            SAMPLE_ALGORITHM,
            config.sample_seed,
            target.hash_parts(),
        )
        if raw.get("sample_rank") is not None and str(raw["sample_rank"]) != expected_rank:
            raise ValueError(f"sample rank/seed drift for {target.cluster_id}")
        imported_partition = raw.get("partition", spec.get("partition"))
        if imported_partition is not None and str(imported_partition) != target.partition:
            raise ValueError(f"partition changed while resolving {target.cluster_id}")

        decompilers = raw.get("decompilers", {})
        if not isinstance(decompilers, dict):
            continue
        for backend, entry in decompilers.items():
            if not isinstance(entry, dict):
                continue
            thresholds = entry.get("matching", {}).get("thresholds")
            if not isinstance(thresholds, dict):
                continue
            observed = (
                float(thresholds.get("min_overlap")),
                float(thresholds.get("ambiguity_margin")),
            )
            expected = (config.min_overlap, config.ambiguity_margin)
            if observed != expected:
                raise ValueError(
                    "matcher threshold drift from scorer manifest for "
                    f"{target.cluster_id}/{backend}: observed={observed}, "
                    f"frozen={expected}"
                )
    if address_bearing_rows and seen != set(target_by_key):
        missing = sorted(
            target.cluster_id for key, target in target_by_key.items() if key not in seen
        )
        raise ValueError(
            "resolved targets are missing from imported scorer rows: " + ", ".join(missing[:5])
        )


def _runner_up_gaps(
    match: Any,
) -> dict[str, float | None]:
    source_gap = match.source_runner_up_gap
    decompiled_gap = match.decompiled_runner_up_gap
    finite = [gap for gap in (source_gap, decompiled_gap) if gap is not None]
    return {
        "source_runner_up_gap": source_gap,
        "decompiled_runner_up_gap": decompiled_gap,
        "minimum_runner_up_gap": min(finite) if finite else None,
    }


def _evidence_dict(variable: VariableEvidence) -> dict[str, Any]:
    return {
        "identity": variable.identity,
        "addresses": [f"0x{address:x}" for address in sorted(variable.addresses)],
        "stack_offsets": list(variable.stack_offsets),
        "size": variable.size,
        "kind": variable.kind,
        "arg_index": variable.arg_index,
        "decl_file": variable.decl_file,
        "decl_line": variable.decl_line,
        "lines": list(variable.lines),
    }


def _result_pair_signature(result: DistanceResult) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                match.source_id,
                match.decompiled_id,
                match.stage,
                match.score,
                match.intersection,
                match.source_runner_up_gap,
                match.decompiled_runner_up_gap,
            )
            for match in result.matches
        )
    )


def _calibration_controls(
    source: Sequence[VariableEvidence],
    decompiled: Sequence[VariableEvidence],
    result: DistanceResult,
    config: CalibrationConfig,
    *,
    instructions: frozenset[int] | None,
    dropped_decompiler_addresses: Sequence[int],
) -> dict[str, Any]:
    """Run the required name/address/determinism controls on blinded evidence."""

    renamed_source = [
        replace(variable, name=f"control_source_{index}")
        for index, variable in enumerate(reversed(source))
    ]
    renamed_decompiled = [
        replace(variable, name=f"control_decompiled_{index}")
        for index, variable in enumerate(reversed(decompiled))
    ]
    matcher_kwargs = {
        "min_overlap": config.min_overlap,
        "ambiguity_margin": config.ambiguity_margin,
    }
    renamed = match_variables(renamed_source, renamed_decompiled, **matcher_kwargs)
    repeated = match_variables(source, decompiled, **matcher_kwargs)
    address_only_source = [
        replace(variable, stack_offsets=(), arg_index=None) for variable in source
    ]
    observed_addresses = {
        address for variable in [*source, *decompiled] for address in variable.addresses
    }
    address_shift = (
        max(observed_addresses, default=0)
        - min(
            observed_addresses,
            default=0,
        )
        + 1
    )
    disjoint_decompiled = [
        replace(
            variable,
            addresses=frozenset(address + address_shift for address in variable.addresses),
            stack_offsets=(),
            arg_index=None,
        )
        for variable in decompiled
    ]
    disjoint = match_variables(
        address_only_source,
        disjoint_decompiled,
        **matcher_kwargs,
    )
    fake = VariableEvidence(
        identity="control:fake-local",
        name="__blind_control_fake",
    )
    with_fake = match_variables(source, [*decompiled, fake], **matcher_kwargs)

    invalid_addresses = (
        sorted(observed_addresses - instructions) if instructions is not None else []
    )
    address_passed = not invalid_addresses if instructions is not None else None
    return {
        "rename_invariance": {
            "passed": _result_pair_signature(renamed) == _result_pair_signature(result),
        },
        "disjoint_address_overlap_zero": {
            "passed": not any(match.stage == "overlap" for match in disjoint.matches),
        },
        "fake_local_increases_distance_by_one": {
            "passed": with_fake.distance == result.distance + 1,
            "baseline_distance": result.distance,
            "fake_distance": with_fake.distance,
        },
        "addresses_are_instructions": {
            "passed": address_passed,
            "scope": (
                "decoded instruction starts in the DWARF function range"
                if instructions is not None
                else "unchecked: no binary instruction set supplied"
            ),
            "invalid_addresses": [f"0x{address:x}" for address in invalid_addresses],
            "raw_decompiler_addresses_dropped": [
                f"0x{address:x}" for address in sorted(dropped_decompiler_addresses)
            ],
        },
        "repeated_pair_set_identical": {
            "passed": repeated.to_dict() == result.to_dict(),
        },
    }


def calibrate_function(
    target: CalibrationTarget,
    backend: str,
    source: FunctionEvidence,
    decompiled: FunctionEvidence,
    config: CalibrationConfig,
    *,
    matcher: Callable[..., DistanceResult] = match_variables,
    instructions: frozenset[int] | None = None,
    dropped_decompiler_addresses: Sequence[int] = (),
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Blind names, run the matcher, then apply the retained-name oracle."""

    # Nothing derived from an original variable name exists before this call.
    blinded_source = blind_variables(source.variables, prefix="source")
    blinded_decompiled = blind_variables(
        decompiled.variables,
        prefix="decompiled",
    )
    result = matcher(
        blinded_source,
        blinded_decompiled,
        min_overlap=config.min_overlap,
        ambiguity_margin=config.ambiguity_margin,
    )
    controls = _calibration_controls(
        blinded_source,
        blinded_decompiled,
        result,
        config,
        instructions=instructions,
        dropped_decompiler_addresses=dropped_decompiler_addresses,
    )

    # The name oracle is intentionally constructed only after matcher return.
    oracle = build_name_oracle(source.variables, decompiled.variables)
    source_by_id = {variable.identity: variable for variable in source.variables}
    decompiled_by_id = {variable.identity: variable for variable in decompiled.variables}
    observable_source = {
        variable.identity
        for variable in source.variables
        if variable.addresses or variable.stack_offsets or variable.arg_index is not None
    }
    eligible_source = {
        variable.identity
        for variable in source.variables
        if variable.identity in observable_source
        and oracle["source_status"][variable.identity] == "eligible"
    }
    eligible_source_names = sorted(
        source_by_id[identity].name.strip() for identity in eligible_source
    )

    pair_rows: list[dict[str, Any]] = []
    for match in result.matches:
        source_variable = source_by_id[match.source_id]
        decompiled_variable = decompiled_by_id[match.decompiled_id]
        source_status = oracle["source_status"][match.source_id]
        decompiled_status = oracle["decompiled_status"][match.decompiled_id]
        if source_status == decompiled_status == "eligible":
            verdict = (
                "correct"
                if source_variable.name.strip() == decompiled_variable.name.strip()
                else "incorrect"
            )
            unknown_reason = None
        else:
            verdict = "unknown"
            unknown_reason = {
                "source": source_status,
                "decompiled": decompiled_status,
            }
        pair_rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "lane": LANE,
                "function": target.to_dict(),
                "cluster_id": target.cluster_id,
                "partition": _partition(target, config),
                "decompiler": backend,
                "source_id": match.source_id,
                "decompiled_id": match.decompiled_id,
                "stage": match.stage,
                "score": match.score,
                "runner_up": _runner_up_gaps(match),
                "intersection": [f"0x{address:x}" for address in match.intersection],
                "oracle": {
                    "verdict": verdict,
                    "unknown_reason": unknown_reason,
                    "source_name": source_variable.name,
                    "decompiled_name": decompiled_variable.name,
                    "rule": (
                        "exact equality of a nonempty, nonsynthetic name "
                        "appearing exactly once on both sides"
                    ),
                },
                "source_evidence": _evidence_dict(source_variable),
                "decompiled_evidence": _evidence_dict(decompiled_variable),
            }
        )

    counts = Counter(row["oracle"]["verdict"] for row in pair_rows)
    function_row = {
        "schema_version": SCHEMA_VERSION,
        "lane": LANE,
        "status": "ok",
        "function": target.to_dict(),
        "cluster_id": target.cluster_id,
        "partition": _partition(target, config),
        "decompiler": backend,
        "source_observable": result.source_count,
        "decompiled_variables": result.decompiled_count,
        "accepted": len(result.matches),
        "correct": counts["correct"],
        "incorrect": counts["incorrect"],
        "unknown": counts["unknown"],
        "oracle_decidable_source": len(eligible_source),
        "unmatched_source": len(result.unmatched_source),
        "unmatched_decompiled": len(result.unmatched_decompiled),
        "unobservable_source": len(result.unobservable_source),
        "stack_shift": result.stack_shift,
        "accepted_by_stage": dict(sorted(Counter(row["stage"] for row in pair_rows).items())),
        "oracle_eligible_names": len(eligible_source_names),
        "oracle_eligible_name_values": eligible_source_names,
        "oracle_eligible_names_including_unobservable_source": len(oracle["eligible_names"]),
        "oracle_retention_rate": _ratio(
            len(eligible_source),
            result.source_count,
        ),
        "raw_decompiler_addresses_dropped": [
            f"0x{address:x}" for address in sorted(dropped_decompiler_addresses)
        ],
        "controls": controls,
        "blinding": {
            "matcher_received_only_opaque_names": True,
            "original_names_read_after_match": True,
            "matcher_input_source_names": [variable.name for variable in blinded_source],
            "matcher_input_decompiled_names": [variable.name for variable in blinded_decompiled],
        },
    }
    return pair_rows, function_row


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _mean(values: Iterable[float | None]) -> float | None:
    finite = [value for value in values if value is not None]
    return sum(finite) / len(finite) if finite else None


def _function_counts(
    function: dict[str, Any],
    pairs: Sequence[dict[str, Any]],
) -> dict[str, int]:
    verdicts = Counter(pair["oracle"]["verdict"] for pair in pairs)
    accepted = len(pairs)
    source_total = int(function["source_observable"] or 0)
    oracle_evaluated_source = source_total if function["status"] == "ok" else 0
    return {
        "accepted": accepted,
        "correct": verdicts["correct"],
        "incorrect": verdicts["incorrect"],
        "unknown": verdicts["unknown"],
        "oracle_source": int(function["oracle_decidable_source"]),
        "oracle_evaluated_source": oracle_evaluated_source,
        "source_observable": source_total,
        "abstained": max(0, source_total - accepted),
    }


def _metrics_from_counts(counts: dict[str, int]) -> dict[str, float | None]:
    decidable = counts["correct"] + counts["incorrect"]
    accepted = counts["accepted"]
    return {
        "precision": _ratio(counts["correct"], decidable),
        "decidable_error_rate": _ratio(counts["incorrect"], decidable),
        "recall": _ratio(counts["correct"], counts["oracle_source"]),
        "coverage": _ratio(counts["accepted"], counts["source_observable"]),
        "abstention": _ratio(counts["abstained"], counts["source_observable"]),
        "unknown_rate": _ratio(counts["unknown"], accepted),
        "error_rate_lower_bound": _ratio(counts["incorrect"], accepted),
        "error_rate_upper_bound": _ratio(
            counts["incorrect"] + counts["unknown"],
            accepted,
        ),
        "oracle_retention_rate": _ratio(
            counts["oracle_source"],
            counts["oracle_evaluated_source"],
        ),
    }


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot take a quantile of no values")
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _aggregate_estimates(
    functions: Sequence[dict[str, Any]],
    pairs_by_cluster: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, int], dict[str, float | None], dict[str, float | None]]:
    per_function_counts = [
        _function_counts(
            function,
            pairs_by_cluster.get(function["cluster_id"], []),
        )
        for function in functions
    ]
    totals = {
        name: sum(row[name] for row in per_function_counts)
        for name in (
            "accepted",
            "correct",
            "incorrect",
            "unknown",
            "oracle_source",
            "oracle_evaluated_source",
            "source_observable",
            "abstained",
        )
    }
    micro = _metrics_from_counts(totals)
    function_metrics = [_metrics_from_counts(row) for row in per_function_counts]
    macro = {metric: _mean(row[metric] for row in function_metrics) for metric in METRICS}
    return totals, micro, macro


def _bootstrap_intervals(
    functions: Sequence[dict[str, Any]],
    pairs_by_cluster: dict[str, list[dict[str, Any]]],
    config: CalibrationConfig,
    seed_parts: tuple[Any, ...],
) -> dict[str, Any]:
    output: dict[str, Any] = {
        "requested_replicates": config.bootstrap_iterations,
        "micro": {metric: {"interval_95": None, "valid_replicates": 0} for metric in METRICS},
        "macro_by_function": {
            metric: {"interval_95": None, "valid_replicates": 0} for metric in METRICS
        },
    }
    if not functions or config.bootstrap_iterations <= 0:
        return output
    rng = random.Random(int(stable_hash(config.bootstrap_seed, seed_parts, "overall"), 16))
    samples: dict[str, dict[str, list[float]]] = {
        "micro": {metric: [] for metric in METRICS},
        "macro_by_function": {metric: [] for metric in METRICS},
    }
    for _iteration in range(config.bootstrap_iterations):
        drawn = [rng.choice(functions) for _ in functions]
        _totals, micro, macro = _aggregate_estimates(
            drawn,
            pairs_by_cluster,
        )
        for metric in METRICS:
            if micro[metric] is not None:
                samples["micro"][metric].append(micro[metric])
            if macro[metric] is not None:
                samples["macro_by_function"][metric].append(macro[metric])
    for mode in samples:
        for metric, values in samples[mode].items():
            output[mode][metric]["valid_replicates"] = len(values)
            if values:
                output[mode][metric]["interval_95"] = [
                    _quantile(values, 0.025),
                    _quantile(values, 0.975),
                ]
    return output


def _bin_label(value: float | None, boundaries: Sequence[float]) -> str:
    if value is None:
        return "no_runner_up"
    lower = 0.0
    for upper in boundaries:
        if value < upper:
            return f"[{lower:g},{upper:g})"
        lower = upper
    return f"[{lower:g},inf)"


def _calibration_bins(
    pairs: Sequence[dict[str, Any]],
    field: str,
    boundaries: Sequence[float],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pair in pairs:
        value = (
            float(pair["score"]) if field == "score" else pair["runner_up"]["minimum_runner_up_gap"]
        )
        grouped[_bin_label(value, boundaries)].append(pair)
    rows = []
    for label, matches in sorted(grouped.items()):
        counts = Counter(match["oracle"]["verdict"] for match in matches)
        decidable = counts["correct"] + counts["incorrect"]
        rows.append(
            {
                "bin": label,
                "accepted": len(matches),
                "correct": counts["correct"],
                "incorrect": counts["incorrect"],
                "unknown": counts["unknown"],
                "precision": _ratio(counts["correct"], decidable),
            }
        )
    return rows


def _bootstrap_stage_precision(
    functions: Sequence[dict[str, Any]],
    pairs_by_cluster: dict[str, list[dict[str, Any]]],
    stage: str,
    config: CalibrationConfig,
    seed_parts: tuple[Any, ...],
) -> dict[str, Any]:
    output = {
        "requested_replicates": config.bootstrap_iterations,
        "micro_precision_decidable_accepted": {
            "interval_95": None,
            "valid_replicates": 0,
        },
        "macro_precision_by_function": {
            "interval_95": None,
            "valid_replicates": 0,
        },
    }
    if not functions or config.bootstrap_iterations <= 0:
        return output
    rng = random.Random(int(stable_hash(config.bootstrap_seed, seed_parts, stage), 16))
    micro_values: list[float] = []
    macro_values: list[float] = []
    for _iteration in range(config.bootstrap_iterations):
        drawn = [rng.choice(functions) for _ in functions]
        per_function: list[float] = []
        totals: Counter[str] = Counter()
        for function in drawn:
            selected = [
                pair
                for pair in pairs_by_cluster.get(function["cluster_id"], [])
                if pair["stage"] == stage
            ]
            verdicts = Counter(pair["oracle"]["verdict"] for pair in selected)
            totals.update(verdicts)
            precision = _ratio(
                verdicts["correct"],
                verdicts["correct"] + verdicts["incorrect"],
            )
            if precision is not None:
                per_function.append(precision)
        micro = _ratio(
            totals["correct"],
            totals["correct"] + totals["incorrect"],
        )
        if micro is not None:
            micro_values.append(micro)
        if per_function:
            macro_values.append(sum(per_function) / len(per_function))
    for key, values in (
        ("micro_precision_decidable_accepted", micro_values),
        ("macro_precision_by_function", macro_values),
    ):
        output[key]["valid_replicates"] = len(values)
        if values:
            output[key]["interval_95"] = [
                _quantile(values, 0.025),
                _quantile(values, 0.975),
            ]
    return output


def aggregate_group(
    functions: Sequence[dict[str, Any]],
    pairs: Sequence[dict[str, Any]],
    config: CalibrationConfig,
    *,
    dimensions: tuple[str, str, str],
) -> dict[str, Any]:
    """Aggregate one partition/optimization/decompiler slice."""

    ok_functions = [function for function in functions if function["status"] == "ok"]
    denominator_functions = [
        function for function in functions if function.get("source_observable") is not None
    ]
    pairs_by_cluster: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pair in pairs:
        pairs_by_cluster[pair["cluster_id"]].append(pair)

    def overall() -> dict[str, Any]:
        totals, micro, macro = _aggregate_estimates(
            denominator_functions,
            pairs_by_cluster,
        )
        ok_totals, _ok_micro, _ok_macro = _aggregate_estimates(
            ok_functions,
            pairs_by_cluster,
        )
        return {
            "accepted": totals["accepted"],
            "correct": totals["correct"],
            "incorrect": totals["incorrect"],
            "unknown": totals["unknown"],
            "denominators": {
                "decidable_accepted": totals["correct"] + totals["incorrect"],
                "oracle_decidable_source": totals["oracle_source"],
                "oracle_evaluated_observable_source": totals["oracle_evaluated_source"],
                "observable_source": totals["source_observable"],
                "source_extraction_failures_excluded": sum(
                    function.get("source_observable") is None for function in functions
                ),
                "backend_failure_observable_source_included": sum(
                    int(function.get("source_observable") or 0)
                    for function in denominator_functions
                    if function["status"] != "ok"
                ),
            },
            "micro": micro,
            "macro_by_function": macro,
            "conditional_on_successful_backend_extraction": {
                "observable_source": ok_totals["source_observable"],
                "accepted": ok_totals["accepted"],
                "coverage": _ratio(
                    ok_totals["accepted"],
                    ok_totals["source_observable"],
                ),
            },
            "bootstrap_95_function_cluster": _bootstrap_intervals(
                denominator_functions,
                pairs_by_cluster,
                config,
                dimensions,
            ),
            "score_calibration_bins": _calibration_bins(
                pairs,
                "score",
                (0.25, 0.5, 0.75, 0.9, 1.000001),
            ),
            "runner_up_gap_calibration_bins": _calibration_bins(
                pairs,
                "gap",
                (config.ambiguity_margin, 0.1, 0.25, 0.5, 1.000001),
            ),
        }

    overall_row = overall()

    def one_stage(stage: str) -> dict[str, Any]:
        selected = [pair for pair in pairs if pair["stage"] == stage]
        verdicts = Counter(pair["oracle"]["verdict"] for pair in selected)
        accepted = len(selected)
        decidable = verdicts["correct"] + verdicts["incorrect"]
        per_function_precision = []
        for function in ok_functions:
            rows = [
                pair
                for pair in pairs_by_cluster.get(function["cluster_id"], [])
                if pair["stage"] == stage
            ]
            counts = Counter(pair["oracle"]["verdict"] for pair in rows)
            precision = _ratio(
                counts["correct"],
                counts["correct"] + counts["incorrect"],
            )
            if precision is not None:
                per_function_precision.append(precision)
        return {
            "accepted": accepted,
            "correct": verdicts["correct"],
            "incorrect": verdicts["incorrect"],
            "unknown": verdicts["unknown"],
            "denominators": {
                "decidable_accepted_at_stage": decidable,
                "all_accepted_matches": overall_row["accepted"],
                "all_decidable_accepted_matches": (
                    overall_row["correct"] + overall_row["incorrect"]
                ),
            },
            "micro": {
                "precision_decidable_accepted": _ratio(
                    verdicts["correct"],
                    decidable,
                ),
                "decidable_error_rate": _ratio(
                    verdicts["incorrect"],
                    decidable,
                ),
                "unknown_rate_among_stage_accepted": _ratio(
                    verdicts["unknown"],
                    accepted,
                ),
                "accepted_contribution_to_all_accepted": _ratio(
                    accepted,
                    overall_row["accepted"],
                ),
                "correct_contribution_to_all_correct": _ratio(
                    verdicts["correct"],
                    overall_row["correct"],
                ),
                "recall": None,
                "coverage": None,
                "abstention": None,
            },
            "macro_precision_by_function": _mean(per_function_precision),
            "undefined_source_denominator_metrics": {
                "recall": ("undefined: an abstained source variable has no matching stage"),
                "coverage": ("undefined: source variables are not stage-eligible before matching"),
                "abstention": (
                    "undefined: source variables are not stage-eligible before matching"
                ),
            },
            "bootstrap_95_function_cluster": _bootstrap_stage_precision(
                ok_functions,
                pairs_by_cluster,
                stage,
                config,
                dimensions,
            ),
            "score_calibration_bins": _calibration_bins(
                selected,
                "score",
                (0.25, 0.5, 0.75, 0.9, 1.000001),
            ),
            "runner_up_gap_calibration_bins": _calibration_bins(
                selected,
                "gap",
                (config.ambiguity_margin, 0.1, 0.25, 0.5, 1.000001),
            ),
        }

    statuses = Counter(function["status"] for function in functions)
    controls: dict[str, Counter[str]] = defaultdict(Counter)
    for function in ok_functions:
        for name, control in function.get("controls", {}).items():
            passed = control.get("passed")
            controls[name][
                "passed" if passed is True else "failed" if passed is False else "unchecked"
            ] += 1
    return {
        "partition": dimensions[0],
        "optimization": dimensions[1],
        "decompiler": dimensions[2],
        "functions": len(functions),
        "function_statuses": dict(sorted(statuses.items())),
        "overall": overall_row,
        "by_stage": {stage: one_stage(stage) for stage in STAGES},
        "controls": {
            name: {bucket: counts[bucket] for bucket in ("passed", "failed", "unchecked")}
            for name, counts in sorted(controls.items())
        },
    }


def _common_retained_name_subset(
    function_rows: Sequence[dict[str, Any]],
    pair_rows: Sequence[dict[str, Any]],
    *,
    backends: Sequence[str],
    backend: str,
    optimization: str,
    partition: str,
) -> dict[str, Any]:
    """Evaluate each backend on names independently retained by every backend."""

    selected_functions = [
        row
        for row in function_rows
        if row["function"]["optimization"] == optimization
        and (partition == "all" or row["partition"] == partition)
    ]
    rows_by_cluster: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in selected_functions:
        rows_by_cluster[row["cluster_id"]][row["decompiler"]] = row

    common_by_cluster: dict[str, set[str]] = {}
    for cluster_id, rows in rows_by_cluster.items():
        if any(
            requested not in rows or rows[requested]["status"] != "ok" for requested in backends
        ):
            continue
        retained_sets = [
            set(rows[requested].get("oracle_eligible_name_values", [])) for requested in backends
        ]
        common_by_cluster[cluster_id] = set.intersection(*retained_sets) if retained_sets else set()

    selected_pairs = [
        row
        for row in pair_rows
        if row["decompiler"] == backend
        and row["function"]["optimization"] == optimization
        and (partition == "all" or row["partition"] == partition)
        and row["cluster_id"] in common_by_cluster
        and row["oracle"]["source_name"].strip() in common_by_cluster[row["cluster_id"]]
    ]
    verdicts = Counter(row["oracle"]["verdict"] for row in selected_pairs)
    source_total = sum(len(names) for names in common_by_cluster.values())
    accepted = len(selected_pairs)
    decidable = verdicts["correct"] + verdicts["incorrect"]
    return {
        "definition": (
            "unique nonsynthetic source names retained exactly once by every "
            "requested backend in the same function"
        ),
        "functions_with_all_backends_successful": len(common_by_cluster),
        "common_retained_source_names": source_total,
        "accepted": accepted,
        "correct": verdicts["correct"],
        "incorrect": verdicts["incorrect"],
        "unknown": verdicts["unknown"],
        "matcher_coverage_on_common_subset": _ratio(accepted, source_total),
        "precision_decidable_accepted": _ratio(verdicts["correct"], decidable),
        "decidable_error_rate": _ratio(verdicts["incorrect"], decidable),
        "error_rate_lower_bound": _ratio(verdicts["incorrect"], accepted),
        "error_rate_upper_bound": _ratio(
            verdicts["incorrect"] + verdicts["unknown"],
            accepted,
        ),
    }


def _validate_result_rows(
    function_rows: Sequence[dict[str, Any]],
    pair_rows: Sequence[dict[str, Any]],
    targets: Sequence[CalibrationTarget],
    backends: Sequence[str],
) -> None:
    if len(backends) != len(set(backends)):
        raise ValueError("duplicate calibration backends")
    if len(targets) != len({target.cluster_id for target in targets}):
        raise ValueError("duplicate calibration targets")
    partitions = {target.cluster_id: target.partition for target in targets}
    expected_functions = {
        (target.cluster_id, backend) for target in targets for backend in backends
    }
    seen_functions: set[tuple[str, str]] = set()
    function_statuses: dict[tuple[str, str], str] = {}
    for row in function_rows:
        key = (str(row["cluster_id"]), str(row["decompiler"]))
        if key in seen_functions:
            raise ValueError(f"duplicate calibration function result: {key}")
        if key not in expected_functions:
            raise ValueError(f"stale/unexpected calibration function result: {key}")
        if row.get("partition") != partitions[key[0]]:
            raise ValueError(f"partition drift in calibration function result: {key}")
        seen_functions.add(key)
        function_statuses[key] = str(row["status"])
    if seen_functions != expected_functions:
        missing = sorted(expected_functions - seen_functions)
        raise ValueError(
            "missing calibration function result(s): "
            + ", ".join(f"{cluster}/{backend}" for cluster, backend in missing[:5])
        )

    seen_pairs: set[tuple[str, str, str, str]] = set()
    for row in pair_rows:
        function_key = (str(row["cluster_id"]), str(row["decompiler"]))
        if function_key not in seen_functions:
            raise ValueError(f"pair references an unknown function result: {function_key}")
        if function_statuses[function_key] != "ok":
            raise ValueError(f"pair references a failed function result: {function_key}")
        if row.get("partition") != partitions[function_key[0]]:
            raise ValueError(f"partition drift in calibration pair: {function_key}")
        key = (
            function_key[0],
            function_key[1],
            str(row["source_id"]),
            str(row["decompiled_id"]),
        )
        if key in seen_pairs:
            raise ValueError(f"duplicate calibration pair: {key}")
        seen_pairs.add(key)


def build_report(
    function_rows: Sequence[dict[str, Any]],
    pair_rows: Sequence[dict[str, Any]],
    *,
    targets: Sequence[CalibrationTarget],
    backends: Sequence[str],
    config: CalibrationConfig,
    source_manifest: Path | None,
    source_cache: SourceLineCache | None = None,
    compiled_artifacts: Sequence[dict[str, str]] = (),
    implementation_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the labeled calibration report (never a recovery score report)."""

    targets = freeze_target_partitions(targets, config)
    _validate_result_rows(function_rows, pair_rows, targets, backends)
    optimization_values = sorted({target.optimization for target in targets})
    aggregate_rows = []
    for partition in ("all", "tuning", "held_out"):
        selected_functions = [
            row for row in function_rows if partition == "all" or row["partition"] == partition
        ]
        selected_pairs = [
            row for row in pair_rows if partition == "all" or row["partition"] == partition
        ]
        for optimization in optimization_values:
            for backend in backends:
                functions = [
                    row
                    for row in selected_functions
                    if row["function"]["optimization"] == optimization
                    and row["decompiler"] == backend
                ]
                pairs = [
                    row
                    for row in selected_pairs
                    if row["function"]["optimization"] == optimization
                    and row["decompiler"] == backend
                ]
                aggregate = aggregate_group(
                    functions,
                    pairs,
                    config,
                    dimensions=(partition, optimization, backend),
                )
                aggregate["common_retained_name_subset"] = _common_retained_name_subset(
                    function_rows,
                    pair_rows,
                    backends=backends,
                    backend=backend,
                    optimization=optimization,
                    partition=partition,
                )
                aggregate_rows.append(aggregate)
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment": "local-variable-matcher-calibration",
        "lane": LANE,
        "realistic_recovery_measurement": False,
        "disclaimer": (
            "Calibration only: IDA/Ghidra analyzed unstripped debug-visible binaries. "
            "Names were blinded from the matcher, then unique retained names were used "
            "as a conservative oracle. These numbers must not be reported as realistic "
            "decompiler variable-name recovery. The name oracle is selective and cannot "
            "validate non-retained or synthetic names; decidable error is conditional on "
            "retention, while lower/upper error bounds treat every unknown as respectively "
            "correct/wrong. It is not a storage-location oracle."
        ),
        "blinding": {
            "matcher_names": "deterministic opaque aliases",
            "oracle_timing": "original names inspected only after match_variables returned",
            "oracle_rule": (
                "unique, nonempty, nonsynthetic exact names occurring once on both sides"
            ),
            "duplicates_excluded": True,
            "synthetic_names_excluded": True,
            "unretained_decompiler_names_excluded": True,
            "nameless_evidenceful_decompiler_variables": (
                "included before blinding and necessarily oracle-unknown"
            ),
            "oracle_retention_rate": (
                "unique retained-name source denominator / observable source "
                "denominator on successful backend extractions"
            ),
            "unknown_bounded_error": (
                "lower=incorrect/all accepted; " "upper=(incorrect+unknown)/all accepted"
            ),
        },
        "sampling": {
            "algorithm": (
                "external-address-manifest" if source_manifest is not None else SAMPLE_ALGORITHM
            ),
            "source_manifest": (str(source_manifest.resolve()) if source_manifest else None),
            "seed": config.sample_seed,
            "selected_functions": len(targets),
            "function_ids": [target.cluster_id for target in sorted(targets)],
            "partition_counts": {
                partition: sum(target.partition == partition for target in targets)
                for partition in PARTITIONS
            },
            "partition_policy": (
                "imported scorer partitions are preserved exactly and validated "
                "against lved-partition-v1"
            ),
        },
        "frozen_config": config.to_dict(),
        "frozen_thresholds": {
            "min_overlap": config.min_overlap,
            "ambiguity_margin": config.ambiguity_margin,
            "warning": (
                "Thresholds were frozen before this calibration output. Do not "
                "alter them after inspecting matcher/oracle results; report "
                "held_out unchanged."
            ),
        },
        "bootstrap": {
            "method": "percentile, resampling whole functions with replacement",
            "iterations": config.bootstrap_iterations,
            "seed": config.bootstrap_seed,
            "valid_replicates": (
                "reported per metric because undefined-denominator replicates " "are omitted"
            ),
        },
        "failure_denominators": {
            "source_extraction_failure": (
                "reported separately and excluded because no observable-source "
                "denominator can be measured"
            ),
            "backend_or_calibration_failure_after_source_extraction": (
                "observable source denominator retained; contributes zero "
                "accepted matches and therefore zero end-to-end coverage"
            ),
        },
        "address_policy": {
            "matching_evidence": (
                "decoded instruction starts within the address-pinned DWARF " "function range"
            ),
            "out_of_range_or_noninstruction_backend_addresses": (
                "filtered before matching and counted per function"
            ),
        },
        "provenance": {
            "compiled_artifacts": list(compiled_artifacts),
            "implementation_sha256": dict(sorted((implementation_hashes or {}).items())),
        },
        "source_line_cache": source_cache.stats() if source_cache else None,
        "rows": aggregate_rows,
    }


def write_jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n")


def _observable_source_count(source: FunctionEvidence) -> int:
    return sum(
        bool(variable.addresses or variable.stack_offsets or variable.arg_index is not None)
        for variable in source.variables
    )


def _function_instruction_set(
    binary_path: Path,
    start: int,
    end: int,
) -> frozenset[int]:
    from elftools.elf.elffile import ELFFile

    with binary_path.open("rb") as stream:
        return frozenset(instruction_addresses(ELFFile(stream), start, end))


def _filter_to_instruction_starts(
    evidence: FunctionEvidence,
    instructions: frozenset[int],
) -> tuple[FunctionEvidence, tuple[int, ...]]:
    observed = {address for variable in evidence.variables for address in variable.addresses} | {
        address for addresses in evidence.line_addresses.values() for address in addresses
    }
    dropped = tuple(sorted(observed - instructions))
    return (
        replace(
            evidence,
            variables=[
                replace(
                    variable,
                    addresses=frozenset(variable.addresses & instructions),
                )
                for variable in evidence.variables
            ],
            line_addresses={
                line: frozenset(addresses & instructions)
                for line, addresses in evidence.line_addresses.items()
            },
        ),
        dropped,
    )


def _error_function_row(
    target: CalibrationTarget,
    backend: str,
    config: CalibrationConfig,
    error: str,
    *,
    status: str,
    source: FunctionEvidence | None,
) -> dict[str, Any]:
    source_observable = _observable_source_count(source) if source is not None else None
    return {
        "schema_version": SCHEMA_VERSION,
        "lane": LANE,
        "status": status,
        "error": error,
        "function": target.to_dict(),
        "cluster_id": target.cluster_id,
        "partition": _partition(target, config),
        "decompiler": backend,
        "source_observable": source_observable,
        "decompiled_variables": 0,
        "accepted": 0,
        "correct": 0,
        "incorrect": 0,
        "unknown": 0,
        "oracle_decidable_source": 0,
        "unmatched_source": source_observable or 0,
        "unmatched_decompiled": 0,
        "unobservable_source": (
            len(source.variables) - source_observable
            if source is not None and source_observable is not None
            else None
        ),
        "oracle_eligible_names": 0,
        "oracle_eligible_name_values": [],
        "oracle_retention_rate": None,
        "controls": {},
    }


def run_calibration(
    results_root: Path,
    targets: Sequence[CalibrationTarget],
    backends: Sequence[str],
    config: CalibrationConfig,
    *,
    source_cache: SourceLineCache | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str | None]]:
    """Extract source/debug-visible evidence and score every backend on one sample."""

    cache = source_cache or SourceLineCache()
    grouped: dict[tuple[str, str, str], list[CalibrationTarget]] = defaultdict(list)
    for target in targets:
        grouped[(target.project, target.optimization, target.binary)].append(target)

    pair_rows: list[dict[str, Any]] = []
    function_rows: list[dict[str, Any]] = []
    versions: dict[str, str | None] = {}
    for (_project, _optimization, _binary), binary_targets in sorted(grouped.items()):
        source_by_address: dict[int, FunctionEvidence] = {}
        instructions_by_address: dict[int, frozenset[int]] = {}
        source_errors: dict[int, str] = {}
        try:
            binary_path = resolve_binary(results_root, binary_targets[0])
        except Exception as exc:  # noqa: BLE001
            message = f"{type(exc).__name__}: {exc}"
            for target in binary_targets:
                source_errors[target.address] = message
            binary_path = None

        if binary_path is not None:
            for target in sorted(binary_targets):
                try:
                    source_path, preprocessed_path, _decl_file, _decl_line = resolve_source_unit(
                        binary_path,
                        target.name,
                        target.address,
                        cache,
                    )
                    source = extract_source_evidence(
                        binary_path,
                        source_path,
                        target.name,
                        preprocessed_path=preprocessed_path,
                        function_address=target.address,
                        source_lines=cache.lines(source_path, preprocessed_path),
                    )
                    instructions = _function_instruction_set(
                        binary_path,
                        source.start,
                        source.end,
                    )
                    source, dropped_source = _filter_to_instruction_starts(
                        source,
                        instructions,
                    )
                    if dropped_source:
                        raise ValueError(
                            "source extraction emitted noninstruction addresses: "
                            + ", ".join(f"0x{address:x}" for address in dropped_source[:5])
                        )
                    source_by_address[target.address] = source
                    instructions_by_address[target.address] = instructions
                except Exception as exc:  # noqa: BLE001
                    source_errors[target.address] = f"{type(exc).__name__}: {exc}"

        for backend in backends:
            eligible_targets = [
                target for target in binary_targets if target.address in source_by_address
            ]
            decompiled: dict[int, FunctionDecompilation] = {}
            decompiler_errors: dict[int, str] = {}
            if binary_path is not None and eligible_targets:
                try:
                    decompiled, decompiler_errors, version = decompile_sampled_addresses(
                        binary_path,
                        eligible_targets,
                        backend,
                    )
                    versions[backend] = version
                except Exception as exc:  # noqa: BLE001
                    message = f"{type(exc).__name__}: {exc}"
                    decompiler_errors.update(
                        {target.address: message for target in eligible_targets}
                    )
            for target in sorted(binary_targets):
                if target.address in source_errors:
                    function_rows.append(
                        _error_function_row(
                            target,
                            backend,
                            config,
                            "source extraction: " + source_errors[target.address],
                            status="source_error",
                            source=None,
                        )
                    )
                    continue
                function = decompiled.get(target.address)
                if function is None:
                    source = source_by_address[target.address]
                    function_rows.append(
                        _error_function_row(
                            target,
                            backend,
                            config,
                            "decompiler extraction: "
                            + decompiler_errors.get(
                                target.address,
                                "sampled address was not returned",
                            ),
                            status="backend_error",
                            source=source,
                        )
                    )
                    continue
                source = source_by_address[target.address]
                try:
                    evidence = extract_decompiler_evidence(
                        function,
                        backend=backend,
                        function_name=target.name,
                        function_end=source.end,
                        include_unnamed=True,
                    )
                    evidence, dropped_addresses = _filter_to_instruction_starts(
                        evidence,
                        instructions_by_address[target.address],
                    )
                    # Empty anonymous bookkeeping slots cannot participate in
                    # this matcher. Anonymous variables with valid address,
                    # stack, or argument evidence remain and become
                    # oracle-unknown only after the opaque-name match.
                    evidence = replace(
                        evidence,
                        variables=[
                            variable
                            for variable in evidence.variables
                            if (
                                variable.name
                                or variable.addresses
                                or variable.stack_offsets
                                or variable.arg_index is not None
                            )
                        ],
                    )
                    pairs, summary = calibrate_function(
                        target,
                        backend,
                        source,
                        evidence,
                        config,
                        instructions=instructions_by_address[target.address],
                        dropped_decompiler_addresses=dropped_addresses,
                    )
                    summary["controls"]["debug_visible_input_metadata_present"] = {
                        "passed": True,
                        "required_sections": [".debug_info", ".symtab"],
                    }
                    pair_rows.extend(pairs)
                    function_rows.append(summary)
                except Exception as exc:  # noqa: BLE001
                    function_rows.append(
                        _error_function_row(
                            target,
                            backend,
                            config,
                            f"calibration: {type(exc).__name__}: {exc}",
                            status="calibration_error",
                            source=source,
                        )
                    )
    pair_rows.sort(
        key=lambda row: (
            row["decompiler"],
            row["cluster_id"],
            row["stage"],
            row["source_id"],
            row["decompiled_id"],
        )
    )
    function_rows.sort(key=lambda row: (row["decompiler"], row["cluster_id"]))
    return pair_rows, function_rows, versions


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-root",
        type=Path,
        default=Path("results/lved_coreutils"),
    )
    parser.add_argument("--project", default="coreutils")
    parser.add_argument(
        "--optimization",
        default="O2",
        choices=["O2"],
        help="this calibration experiment is deliberately O2-only",
    )
    parser.add_argument(
        "--backend",
        action="append",
        help="ida, ghidra, or a versioned spec; repeat (default: ida and ghidra)",
    )
    parser.add_argument(
        "--sample-manifest",
        type=Path,
        help=(
            "address-bearing scorer JSONL or subset/calibration JSON; preferred "
            "to guarantee the same stripped/debug-visible sample"
        ),
    )
    parser.add_argument("--sample-size", type=int, default=100)
    parser.add_argument("--sample-seed", default=DEFAULT_SAMPLE_SEED)
    parser.add_argument("--tuning-fraction", type=float, default=0.25)
    parser.add_argument("--min-overlap", type=float, default=0.1)
    parser.add_argument("--ambiguity-margin", type=float, default=0.03)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument(
        "--bootstrap-seed",
        default="coreutils-lved-calibration-bootstrap-v1",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="default: <results-root>/local_variable_calibration",
    )
    parser.add_argument(
        "--fail-on-function-errors",
        action="store_true",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    backends = args.backend or ["ida", "ghidra"]
    if len(backends) != len(set(backends)):
        raise SystemExit(f"duplicate calibration backend(s): {backends}")
    invalid = [backend for backend in backends if backend.split("@", 1)[0] not in {"ida", "ghidra"}]
    if invalid:
        raise SystemExit(f"calibration only supports ida/ghidra, got {invalid}")
    config = CalibrationConfig(
        min_overlap=args.min_overlap,
        ambiguity_margin=args.ambiguity_margin,
        tuning_fraction=args.tuning_fraction,
        sample_seed=args.sample_seed,
        bootstrap_iterations=args.bootstrap_iterations,
        bootstrap_seed=args.bootstrap_seed,
    )
    output_dir = args.output_dir or args.results_root / "local_variable_calibration"
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved_manifest = output_dir / "calibration_manifest.json"

    source_manifest = args.sample_manifest
    imported_rows: list[dict[str, Any]] | None = None
    universe: list[CalibrationTarget] | None = None
    if source_manifest is not None:
        raw_rows = _read_manifest_rows(source_manifest)
        imported_rows = raw_rows
        needs_addresses = any(
            _parse_address(_target_spec(row).get("address")) is None
            for row in raw_rows
            if str(
                _target_spec(row).get(
                    "optimization",
                    _target_spec(row).get("opt", args.optimization),
                )
            )
            == args.optimization
            and str(_target_spec(row).get("project", args.project)) == args.project
        )
        if needs_addresses:
            universe = discover_targets(
                args.results_root,
                project=args.project,
                optimization=args.optimization,
            )
        targets = _resolve_manifest_rows(
            raw_rows,
            project=args.project,
            optimization=args.optimization,
            universe=universe,
        )
    elif resolved_manifest.is_file():
        existing_payload = json.loads(resolved_manifest.read_text())
        targets = load_sample_manifest(
            resolved_manifest,
            project=args.project,
            optimization=args.optimization,
        )
        recorded_source_manifest = existing_payload.get("source_manifest")
        source_manifest = (
            Path(str(recorded_source_manifest)) if recorded_source_manifest is not None else None
        )
        imported_rows = _read_manifest_rows(resolved_manifest)
    else:
        universe = discover_targets(
            args.results_root,
            project=args.project,
            optimization=args.optimization,
        )
        targets = deterministic_sample(
            universe,
            size=args.sample_size,
            seed=args.sample_seed,
        )

    targets = freeze_target_partitions(targets, config)
    if imported_rows is not None:
        validate_imported_scorer_rows(imported_rows, targets, config)
    compiled_artifacts = compiled_binary_hashes(args.results_root, targets)
    implementation_hashes = calibration_implementation_hashes()
    write_resolved_manifest(
        resolved_manifest,
        targets,
        source_manifest=source_manifest,
        config=config,
        backends=backends,
        compiled_artifacts=compiled_artifacts,
        implementation_hashes=implementation_hashes,
    )
    cache = SourceLineCache()
    pairs, functions, versions = run_calibration(
        args.results_root,
        targets,
        backends,
        config,
        source_cache=cache,
    )
    report = build_report(
        functions,
        pairs,
        targets=targets,
        backends=backends,
        config=config,
        source_manifest=source_manifest,
        source_cache=cache,
        compiled_artifacts=compiled_artifacts,
        implementation_hashes=implementation_hashes,
    )
    report["decompiler_versions"] = versions
    write_jsonl(output_dir / "calibration_pairs.jsonl", pairs)
    write_jsonl(output_dir / "calibration_functions.jsonl", functions)
    write_json(output_dir / "calibration_report.json", report)

    errors = sum(row["status"] != "ok" for row in functions)
    print(
        f"calibration: functions={len(targets)} backends={','.join(backends)} "
        f"pairs={len(pairs)} errors={errors}"
    )
    print(f"manifest: {resolved_manifest}")
    print(f"report:   {output_dir / 'calibration_report.json'}")
    if errors and args.fail_on_function_errors:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
