"""Score saved local-variable-distance evidence from a benchmark checkpoint.

The checkpoint is the only benchmark artifact that retains IDA/Ghidra variable
address evidence.  This module deliberately keeps variable names out of the
matcher and its JSON output: source and decompiler variables are renamed to
synthetic aliases before matching.  Oracle accuracy remains ``None`` until a
separate audit-label JSONL is supplied.
"""

from __future__ import annotations

import hashlib
import json
import math
import pickle
import random
import re
from collections import defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any

from decbench.caching import stable_hash
from decbench.experimental.local_variable_distance import (
    MATCHER_MODES,
    DistanceResult,
    FunctionEvidence,
    MatcherMode,
    VariableEvidence,
    extract_decompiler_evidence,
    extract_source_evidence,
    has_usage_context,
    instruction_addresses,
    preprocessed_line_marker_lines,
    source_file_lines,
)
from decbench.models.decompilation import DecompilationResult, FunctionDecompilation
from decbench.utils.langs import PREPROC_EXTS, SOURCE_EXTS, is_cxx_preprocessed

SCHEMA_VERSION = 2
SAMPLE_ALGORITHM = "sha256-rank-v1"
DEFAULT_SAMPLE_SEED = "coreutils-lved-v1"
STRICT_UNIVERSE_VERSION = "lved-strict-dwarf-cu-universe-v1"
SCORE_CONFIG_VERSION = "lved-score-config-v2"
RUN_BINDING_VERSION = "lved-run-binding-v1"
SCORER_JSONL_SERIALIZATION = "utf8-json-sort-keys-ensure-ascii-lf-v1"
VERDICTS = {"correct", "incorrect", "unknown"}
SOURCE_ORACLE_STATUSES = {"match", "missing", "unknown", "split", "merged"}


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Hash one JSON value using the scorer's documented canonical encoding."""

    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def file_sha256(path: Path) -> str:
    """Hash a file without loading the whole artifact into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _jsonl_line(row: dict[str, Any]) -> bytes:
    # Keep this byte-for-byte identical to ``write_jsonl``.  ASCII escaping
    # makes the bytes independent of the host's locale/default text encoding.
    return (json.dumps(row, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode(
        "ascii"
    )


def jsonl_sha256(rows: list[dict[str, Any]]) -> str:
    """Hash the exact bytes that :func:`write_jsonl` will emit."""

    digest = hashlib.sha256()
    for row in rows:
        digest.update(_jsonl_line(row))
    return digest.hexdigest()


@dataclass(frozen=True, order=True)
class FunctionKey:
    """Stable identity for a checkpoint function."""

    optimization: str
    binary: str
    address: int
    name: str

    def hash_parts(self) -> tuple[str, str, str, str]:
        return self.optimization, self.binary, f"0x{self.address:x}", self.name

    def to_dict(self, project: str) -> dict[str, Any]:
        return {
            "project": project,
            "optimization": self.optimization,
            "binary": self.binary,
            "address": f"0x{self.address:x}",
            "name": self.name,
        }


@dataclass
class CheckpointFunction:
    """One source function and every requested decompiler result for it."""

    key: FunctionKey
    functions: dict[str, FunctionDecompilation] = field(default_factory=dict)
    results: dict[str, DecompilationResult] = field(default_factory=dict)
    source: FunctionSource | None = None


@dataclass(frozen=True)
class FunctionSource:
    """Address-pinned DWARF source-unit resolution for one function."""

    binary_path: Path
    source_path: Path
    preprocessed_path: Path
    cu_path: str
    decl_file: str
    decl_line: int | None


@dataclass(frozen=True)
class ScoreConfig:
    project: str = "coreutils"
    optimizations: tuple[str, ...] = ("O0",)
    decompiler_bases: tuple[str, ...] = ("ida", "ghidra")
    sample_size: int = 100
    sample_seed: str = DEFAULT_SAMPLE_SEED
    tuning_fraction: float = 0.25
    min_overlap: float = 0.1
    ambiguity_margin: float = 0.03
    matcher_mode: MatcherMode = "address"
    min_usage_similarity: float = 0.1
    usage_ambiguity_margin: float = 0.03
    min_combined_similarity: float = 0.1
    address_weight: float = 0.5
    include_inlined: bool = False
    bootstrap_iterations: int = 2000

    def __post_init__(self) -> None:
        if self.sample_size < 0:
            raise ValueError("sample_size must be non-negative (0 means all functions)")
        if not 0 <= self.tuning_fraction <= 1:
            raise ValueError("tuning_fraction must be between 0 and 1")
        if self.min_overlap < 0:
            raise ValueError("min_overlap must be non-negative")
        if self.ambiguity_margin < 0:
            raise ValueError("ambiguity_margin must be non-negative")
        if self.matcher_mode not in MATCHER_MODES:
            raise ValueError(
                f"unknown matcher mode {self.matcher_mode!r}; expected one of {MATCHER_MODES}"
            )
        if self.min_usage_similarity < 0:
            raise ValueError("min_usage_similarity must be non-negative")
        if self.usage_ambiguity_margin < 0:
            raise ValueError("usage_ambiguity_margin must be non-negative")
        if self.min_combined_similarity < 0:
            raise ValueError("min_combined_similarity must be non-negative")
        if not 0 <= self.address_weight <= 1:
            raise ValueError("address_weight must be between 0 and 1")
        if self.bootstrap_iterations < 0:
            raise ValueError("bootstrap_iterations must be non-negative")


def score_config_payload(config: ScoreConfig) -> dict[str, Any]:
    """Return every effective scorer option in a stable, hashable form."""

    return {
        "version": SCORE_CONFIG_VERSION,
        "project": config.project,
        "optimizations": list(config.optimizations),
        "decompiler_bases": list(config.decompiler_bases),
        "sample_size": config.sample_size,
        "sample_seed": config.sample_seed,
        "tuning_fraction": config.tuning_fraction,
        "min_overlap": config.min_overlap,
        "ambiguity_margin": config.ambiguity_margin,
        "matcher_mode": config.matcher_mode,
        "min_usage_similarity": config.min_usage_similarity,
        "usage_ambiguity_margin": config.usage_ambiguity_margin,
        "min_combined_similarity": config.min_combined_similarity,
        "address_weight": config.address_weight,
        "include_inlined": config.include_inlined,
        "bootstrap_iterations": config.bootstrap_iterations,
    }


class SourceLineCache:
    """Cache source files and parsed ``.i`` line-marker maps by resolved path."""

    def __init__(self) -> None:
        self._sources: dict[Path, dict[tuple[str, int], str]] = {}
        self._source_text: dict[Path, str] = {}
        self._preprocessed: dict[Path, dict[tuple[str, int], str]] = {}
        self._preprocessed_text: dict[Path, str] = {}
        self._function_definitions: dict[Path, dict[str, tuple[str, ...]]] = {}
        self._primary_markers: dict[Path, str | None] = {}
        self._merged: dict[tuple[Path, Path], dict[tuple[str, int], str]] = {}
        self.requests = 0
        self.hits = 0

    @staticmethod
    def _key(path: Path) -> Path:
        return path.resolve()

    def preprocessed(self, path: Path) -> dict[tuple[str, int], str]:
        key = self._key(path)
        parsed = self._preprocessed.get(key)
        if parsed is None:
            parsed = preprocessed_line_marker_lines(key)
            self._preprocessed[key] = parsed
        return parsed

    def marker_basenames(self, path: Path) -> set[str]:
        return {filename for filename, _line in self.preprocessed(path)}

    def contains_identifier(self, path: Path, identifier: str) -> bool:
        """Whether a cached translation unit contains an identifier token."""

        key = self._key(path)
        text = self._preprocessed_text.get(key)
        if text is None:
            text = key.read_text(errors="replace")
            self._preprocessed_text[key] = text
        return re.search(r"\b" + re.escape(identifier) + r"\b", text) is not None

    def _text(self, path: Path, *, preprocessed: bool) -> str:
        key = self._key(path)
        cache = self._preprocessed_text if preprocessed else self._source_text
        text = cache.get(key)
        if text is None:
            text = key.read_text(errors="replace")
            cache[key] = text
        return text

    def function_code(
        self,
        source_path: Path,
        preprocessed_path: Path,
        function_name: str,
    ) -> str | None:
        """Find one function definition, preferring macro-expanded C."""

        if is_cxx_preprocessed(preprocessed_path):
            return ""

        from decbench.experimental.local_variable_features import index_c_functions

        for path, preprocessed in (
            (preprocessed_path, True),
            (source_path, False),
        ):
            key = self._key(path)
            definitions = self._function_definitions.get(key)
            if definitions is None:
                definitions = index_c_functions(self._text(key, preprocessed=preprocessed))
                self._function_definitions[key] = definitions
            exact = definitions.get(function_name, ())
            if len(exact) == 1:
                return exact[0]
        return None

    def primary_marker(self, path: Path) -> str | None:
        """Return the first real source path named by a preprocessor line marker."""

        key = self._key(path)
        if key in self._primary_markers:
            return self._primary_markers[key]
        text = self._preprocessed_text.get(key)
        if text is None:
            text = key.read_text(errors="replace")
            self._preprocessed_text[key] = text
        marker = re.compile(r'^\s*#\s+\d+\s+"([^"]+)"')
        primary = None
        for line in text.splitlines():
            match = marker.match(line)
            if not match:
                continue
            candidate = match.group(1)
            if candidate.startswith("<") and candidate.endswith(">"):
                continue
            if candidate.endswith("/") or candidate.endswith("//"):
                continue
            primary = candidate
            break
        self._primary_markers[key] = primary
        return primary

    def lines(
        self,
        source_path: Path,
        preprocessed_path: Path,
    ) -> dict[tuple[str, int], str]:
        self.requests += 1
        source_key = self._key(source_path)
        preprocessed_key = self._key(preprocessed_path)
        key = (source_key, preprocessed_key)
        cached = self._merged.get(key)
        if cached is not None:
            self.hits += 1
            return cached
        source = self._sources.get(source_key)
        if source is None:
            source = source_file_lines(source_key)
            self._sources[source_key] = source
        merged = dict(source)
        for location, text in self.preprocessed(preprocessed_key).items():
            merged.setdefault(location, text)
        self._merged[key] = merged
        return merged

    def stats(self) -> dict[str, int]:
        return {
            "requests": self.requests,
            "hits": self.hits,
            "misses": self.requests - self.hits,
            "source_files": len(self._sources),
            "preprocessed_units": len(self._preprocessed),
            "merged_maps": len(self._merged),
        }


def _optimization_name(value: Any) -> str:
    return str(getattr(value, "value", value))


def load_checkpoint_functions(
    checkpoint_path: Path,
    config: ScoreConfig,
) -> tuple[list[CheckpointFunction], list[str]]:
    """Load and normalize the checkpoint's nested decompilation dictionaries."""

    # Register modules referenced by older pickles before unpickling.
    import decbench.decompilers  # noqa: F401
    import decbench.metrics  # noqa: F401

    try:
        payload = pickle.loads(checkpoint_path.read_bytes())
    except FileNotFoundError as exc:
        raise ValueError(f"checkpoint does not exist: {checkpoint_path}") from exc
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"could not load checkpoint {checkpoint_path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("decompile"), dict):
        raise ValueError("checkpoint has no 'decompile' result dictionary")

    wanted_opts = set(config.optimizations)
    wanted_bases = set(config.decompiler_bases)
    grouped: dict[FunctionKey, CheckpointFunction] = {}
    seen_decompilers: set[str] = set()
    for optimization, binary_results in payload["decompile"].items():
        opt_name = _optimization_name(optimization)
        if wanted_opts and opt_name not in wanted_opts:
            continue
        if not isinstance(binary_results, dict):
            continue
        for binary_key, decompiler_results in binary_results.items():
            if not isinstance(decompiler_results, dict):
                continue
            for decompiler, result in decompiler_results.items():
                decompiler = str(decompiler)
                if decompiler.split("@", 1)[0] not in wanted_bases:
                    continue
                if not isinstance(result, DecompilationResult):
                    continue
                seen_decompilers.add(decompiler)
                for function in result.functions.values():
                    key = FunctionKey(
                        optimization=opt_name,
                        binary=str(binary_key),
                        address=int(function.address),
                        name=str(function.name),
                    )
                    candidate = grouped.setdefault(key, CheckpointFunction(key))
                    if decompiler in candidate.functions:
                        raise ValueError(
                            "duplicate checkpoint function for "
                            f"{opt_name}/{binary_key}::{function.name}@0x{function.address:x} "
                            f"({decompiler})"
                        )
                    candidate.functions[decompiler] = function
                    candidate.results[decompiler] = result
    if not grouped:
        raise ValueError(
            "checkpoint contains no matching functions for "
            f"optimizations={sorted(wanted_opts)} decompilers={sorted(wanted_bases)}"
        )
    return sorted(grouped.values(), key=lambda row: row.key), sorted(seen_decompilers)


def _sample_digest(key: FunctionKey, seed: str) -> str:
    return stable_hash(SAMPLE_ALGORITHM, seed, key.hash_parts())


def deterministic_sample(
    functions: list[CheckpointFunction],
    *,
    size: int,
    seed: str,
) -> list[CheckpointFunction]:
    """Take the lowest stable-hash ranks, independent of checkpoint iteration order."""

    ranked = sorted(functions, key=lambda row: (_sample_digest(row.key, seed), row.key))
    return ranked if size == 0 else ranked[:size]


def _partition(key: FunctionKey, seed: str, tuning_fraction: float) -> str:
    digest = stable_hash("lved-partition-v1", seed, key.hash_parts())
    fraction = int(digest, 16) / (1 << 256)
    return "tuning" if fraction < tuning_fraction else "held_out"


def _has_debug_info(path: Path) -> bool:
    try:
        from elftools.elf.elffile import ELFFile

        with path.open("rb") as stream:
            elf = ELFFile(stream)
            section = elf.get_section_by_name(".debug_info")
            return section is not None and int(section["sh_size"]) > 0
    except Exception:  # noqa: BLE001
        return False


def resolve_unstripped_binary(
    candidate: CheckpointFunction,
    results_root: Path,
    project: str,
) -> Path:
    """Resolve and verify the DWARF-bearing binary used as source ground truth."""

    compiled_dir = results_root / candidate.key.optimization / project / "compiled"
    choices: list[Path] = []
    for result in candidate.results.values():
        stored = Path(result.binary_path)
        choices.extend([stored, results_root / stored])
        choices.append(compiled_dir / stored.name)
        choices.append(compiled_dir / result.binary_name)
    choices.append(compiled_dir / candidate.key.binary)
    if compiled_dir.is_dir():
        choices.extend(
            path
            for path in sorted(compiled_dir.iterdir())
            if path.is_file() and path.stem == Path(candidate.key.binary).stem
        )

    unique: list[Path] = []
    seen: set[Path] = set()
    for path in choices:
        resolved = path.resolve()
        if resolved not in seen:
            unique.append(resolved)
            seen.add(resolved)
    valid = [path for path in unique if path.is_file() and _has_debug_info(path)]
    if not valid:
        existing = [str(path) for path in unique if path.is_file()]
        detail = f"; existing candidates without DWARF: {existing}" if existing else ""
        raise ValueError(
            f"could not resolve DWARF binary for "
            f"{candidate.key.optimization}/{candidate.key.binary}{detail}"
        )
    # Prefer the canonical compiled tree over an absolute path serialized on
    # another machine.  Equal paths collapse in ``unique`` above.
    valid.sort(key=lambda path: (path.parent != compiled_dir.resolve(), str(path)))
    return valid[0]


def _decode_path(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _normalized_source_path(path: str, comp_dir: str = "") -> str:
    """Normalize a DWARF/line-marker path and strip its compilation root."""

    raw = path.replace("\\", "/")
    normalized = PurePosixPath(raw).as_posix()
    comp = PurePosixPath(comp_dir.replace("\\", "/")).as_posix() if comp_dir else ""
    if comp and (normalized == comp or normalized.startswith(comp.rstrip("/") + "/")):
        normalized = normalized[len(comp.rstrip("/")) :].lstrip("/")
    return normalized.removeprefix("./")


def _line_file_path(line_program: Any, index: int, comp_dir: str) -> str:
    entries = line_program.header["file_entry"]
    if not 0 <= index < len(entries):
        return ""
    entry = entries[index]
    name = _decode_path(entry.name)
    if PurePosixPath(name).is_absolute():
        return _normalized_source_path(name, comp_dir)
    directory = ""
    dir_index = int(getattr(entry, "dir_index", 0))
    directories = line_program.header["include_directory"]
    version = int(line_program.header.get("version", 4))
    actual = dir_index if version >= 5 else dir_index - 1
    if 0 <= actual < len(directories):
        directory = _decode_path(directories[actual])
    joined = PurePosixPath(directory, name).as_posix() if directory else name
    return _normalized_source_path(joined, comp_dir)


def _cu_source_path(cu: Any, line_program: Any) -> tuple[str, str]:
    """Return ``(path-qualified primary source, comp_dir)`` for one CU."""

    top = cu.get_top_DIE()
    name_attr = top.attributes.get("DW_AT_name")
    comp_attr = top.attributes.get("DW_AT_comp_dir")
    comp_dir = _decode_path(comp_attr.value) if comp_attr is not None else ""
    dwarf_name = (
        _normalized_source_path(_decode_path(name_attr.value), comp_dir)
        if name_attr is not None
        else ""
    )
    line_name = _line_file_path(line_program, 0, comp_dir)
    candidates = [path for path in (dwarf_name, line_name) if path]
    qualified = [path for path in candidates if len(PurePosixPath(path).parts) >= 2]
    if not qualified:
        raise ValueError(
            f"CU primary source is not path-qualified: dwarf={dwarf_name!r} " f"line={line_name!r}"
        )
    # DW_AT_name names the actual compilation unit. The line-table primary
    # entry supplies its directory when producers emit only a basename.
    if dwarf_name and len(PurePosixPath(dwarf_name).parts) >= 2:
        return dwarf_name, comp_dir
    return qualified[0], comp_dir


def _path_has_suffix(candidate: str, suffix: str) -> bool:
    candidate_parts = PurePosixPath(_normalized_source_path(candidate)).parts
    suffix_parts = PurePosixPath(_normalized_source_path(suffix)).parts
    return bool(suffix_parts) and candidate_parts[-len(suffix_parts) :] == suffix_parts


def _select_preprocessed_unit(
    cu_path: str,
    binary_path: Path,
    units: list[Path],
    cache: SourceLineCache,
) -> Path:
    """Select only a ``.i`` whose primary marker matches the full CU path."""

    candidates = [
        unit
        for unit in units
        if (primary := cache.primary_marker(unit)) is not None
        and _path_has_suffix(primary, cu_path)
    ]
    if len(candidates) > 1:
        binary_stem = binary_path.stem
        cu_stem = PurePosixPath(cu_path).stem
        binary_prefixed = [
            path
            for path in candidates
            if path.stem
            in {
                f"{binary_stem}-{cu_stem}",
                f"{binary_stem}_{cu_stem}",
            }
            or path.stem.startswith(binary_stem + "-")
            and path.stem.endswith("-" + cu_stem)
        ]
        if len(binary_prefixed) == 1:
            candidates = binary_prefixed
    if len(candidates) > 1:
        cu_stem = PurePosixPath(cu_path).stem
        stem_exact = [path for path in candidates if path.stem == cu_stem]
        if len(stem_exact) == 1:
            candidates = stem_exact
    if len(candidates) != 1:
        markers = {path.name: cache.primary_marker(path) for path in candidates}
        raise ValueError(
            f"no unique path-qualified .i for CU {cu_path!r} in {binary_path.name}; "
            f"candidates={markers}"
        )
    return candidates[0]


def _source_path_for_unit(binary_path: Path, cu_path: str, unit: Path) -> Path:
    original = binary_path.parent / PurePosixPath(cu_path).name
    if original.is_file():
        return original
    without_preprocessed_suffix = unit.with_suffix("")
    if without_preprocessed_suffix.suffix in SOURCE_EXTS and without_preprocessed_suffix.is_file():
        return without_preprocessed_suffix
    c_source = unit.with_suffix(".c")
    return c_source if c_source.is_file() else unit


def resolve_source_unit(
    binary_path: Path,
    function_name: str,
    function_address: int,
    cache: SourceLineCache,
) -> tuple[Path, Path, str, int | None]:
    """Resolve an address-pinned function through its path-qualified DWARF CU.

    The return signature is retained for calibration callers, but unlike the
    historical implementation the declaration filename never selects the
    translation unit.
    """

    from elftools.elf.elffile import ELFFile

    from decbench.experimental.local_variable_distance import (
        _decl_location,
        _die_name,
        _die_ranges,
    )

    units = sorted(
        unit for extension in PREPROC_EXTS for unit in binary_path.parent.glob(f"*{extension}")
    )
    with binary_path.open("rb") as stream:
        dwarfinfo = ELFFile(stream).get_dwarf_info()
        for cu in dwarfinfo.iter_CUs():
            line_program = dwarfinfo.line_program_for_CU(cu)
            if line_program is None:
                continue
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or _die_name(die) != function_name:
                    continue
                if not any(
                    begin == function_address for begin, _end in _die_ranges(die, dwarfinfo)
                ):
                    continue
                cu_path, _comp_dir = _cu_source_path(cu, line_program)
                preprocessed_path = _select_preprocessed_unit(
                    cu_path,
                    binary_path,
                    units,
                    cache,
                )
                source_path = _source_path_for_unit(
                    binary_path,
                    cu_path,
                    preprocessed_path,
                )
                decl_file, decl_line = _decl_location(die, line_program)
                return (
                    source_path,
                    preprocessed_path,
                    decl_file or "",
                    decl_line,
                )
    raise ValueError(
        f"DWARF function {function_name!r} at 0x{function_address:x} "
        f"was not found in {binary_path}"
    )


def _discover_compiled_binaries(compiled_dir: Path) -> list[Path]:
    skipped_suffixes = {
        ".h",
        ".hh",
        ".hpp",
        ".o",
        ".s",
        ".a",
        ".json",
        ".toml",
        *PREPROC_EXTS,
        *SOURCE_EXTS,
    }
    return [
        path
        for path in sorted(compiled_dir.iterdir())
        if path.is_file()
        and not path.is_symlink()
        and path.suffix not in skipped_suffixes
        and _has_debug_info(path)
    ]


def discover_dwarf_function_universe(
    results_root: Path,
    config: ScoreConfig,
    cache: SourceLineCache,
) -> tuple[list[CheckpointFunction], dict[str, Any]]:
    """Discover source functions without consulting decompiler success."""

    from elftools.elf.elffile import ELFFile

    from decbench.experimental.local_variable_distance import _decl_location, _die_name

    universe: dict[FunctionKey, CheckpointFunction] = {}
    diagnostics: dict[str, Any] = {
        "compiled_binaries": 0,
        "cus_seen": 0,
        "cus_resolved": 0,
        "cus_rejected": 0,
        "defined_functions_all_cus": 0,
        "functions_seen_in_resolved_cus": 0,
        "functions_resolved": 0,
        "linked_lib_cus_excluded": 0,
        "linked_lib_functions_excluded": 0,
        "rejected_cu_reasons": {},
        "rejected_cu_examples": [],
    }
    rejected_reasons: dict[str, int] = defaultdict(int)
    rejected_cu_paths: dict[str, int] = defaultdict(int)
    units_by_opt: dict[str, list[Path]] = {}
    for optimization in config.optimizations:
        compiled_dir = results_root / optimization / config.project / "compiled"
        if not compiled_dir.is_dir():
            continue
        units = sorted(
            unit for extension in PREPROC_EXTS for unit in compiled_dir.glob(f"*{extension}")
        )
        units_by_opt[optimization] = units
        binaries = _discover_compiled_binaries(compiled_dir)
        diagnostics["compiled_binaries"] += len(binaries)
        for binary_path in binaries:
            with binary_path.open("rb") as stream:
                dwarfinfo = ELFFile(stream).get_dwarf_info()
                for cu in dwarfinfo.iter_CUs():
                    diagnostics["cus_seen"] += 1
                    line_program = dwarfinfo.line_program_for_CU(cu)
                    if line_program is None:
                        reason = "no_line_program"
                        rejected_reasons[reason] += 1
                        diagnostics["cus_rejected"] += 1
                        continue
                    try:
                        cu_path, _comp_dir = _cu_source_path(cu, line_program)
                    except ValueError as exc:
                        reason = "cu_source_not_path_qualified"
                        rejected_reasons[reason] += 1
                        diagnostics["cus_rejected"] += 1
                        if len(diagnostics["rejected_cu_examples"]) < 50:
                            diagnostics["rejected_cu_examples"].append(
                                {
                                    "optimization": optimization,
                                    "binary": binary_path.name,
                                    "reason": str(exc),
                                }
                            )
                        continue
                    defined_dies = [
                        die
                        for die in cu.iter_DIEs()
                        if die.tag == "DW_TAG_subprogram"
                        and die.attributes.get("DW_AT_low_pc") is not None
                        and bool(_die_name(die))
                    ]
                    diagnostics["defined_functions_all_cus"] += len(defined_dies)
                    try:
                        preprocessed_path = _select_preprocessed_unit(
                            cu_path,
                            binary_path,
                            units,
                            cache,
                        )
                    except ValueError as exc:
                        reason = "no_path_qualified_preprocessed_unit"
                        rejected_reasons[reason] += 1
                        rejected_cu_paths[cu_path] += 1
                        diagnostics["cus_rejected"] += 1
                        if cu_path.startswith("lib/"):
                            diagnostics["linked_lib_cus_excluded"] += 1
                            diagnostics["linked_lib_functions_excluded"] += len(defined_dies)
                        if len(diagnostics["rejected_cu_examples"]) < 50:
                            diagnostics["rejected_cu_examples"].append(
                                {
                                    "optimization": optimization,
                                    "binary": binary_path.name,
                                    "reason": str(exc),
                                }
                            )
                        continue
                    diagnostics["cus_resolved"] += 1
                    source_path = _source_path_for_unit(
                        binary_path,
                        cu_path,
                        preprocessed_path,
                    )
                    for die in defined_dies:
                        diagnostics["functions_seen_in_resolved_cus"] += 1
                        low_pc = die.attributes["DW_AT_low_pc"]
                        name = _die_name(die)
                        address = int(low_pc.value)
                        decl_file, decl_line = _decl_location(die, line_program)
                        key = FunctionKey(
                            optimization=optimization,
                            binary=binary_path.name,
                            address=address,
                            name=name,
                        )
                        source = FunctionSource(
                            binary_path=binary_path.resolve(),
                            source_path=source_path.resolve(),
                            preprocessed_path=preprocessed_path.resolve(),
                            cu_path=cu_path,
                            decl_file=decl_file or "",
                            decl_line=decl_line,
                        )
                        previous = universe.get(key)
                        if previous is not None and previous.source != source:
                            raise ValueError(
                                f"conflicting DWARF CUs for {optimization}/"
                                f"{binary_path.name}::{name}@0x{address:x}"
                            )
                        universe.setdefault(key, CheckpointFunction(key, source=source))
    diagnostics["functions_resolved"] = len(universe)
    diagnostics["rejected_cu_reasons"] = dict(sorted(rejected_reasons.items()))
    diagnostics["rejected_cu_paths"] = dict(sorted(rejected_cu_paths.items()))
    diagnostics["preprocessed_units"] = sum(len(units) for units in units_by_opt.values())
    universe_members = []
    for row in sorted(universe.values(), key=lambda candidate: candidate.key):
        if row.source is None:  # pragma: no cover - construction invariant
            raise ValueError(f"resolved universe member has no source: {row.key}")
        universe_members.append(
            {
                "function": row.key.to_dict(config.project),
                "source": {
                    "dwarf_cu_path": row.source.cu_path,
                    "dwarf_decl_file": row.source.decl_file,
                    "dwarf_decl_line": row.source.decl_line,
                    "source_file": row.source.source_path.name,
                    "preprocessed_file": row.source.preprocessed_path.name,
                    "preprocessed_primary_marker": cache.primary_marker(
                        row.source.preprocessed_path
                    ),
                },
            }
        )
    universe_payload = {
        "version": STRICT_UNIVERSE_VERSION,
        "project": config.project,
        "optimizations": list(config.optimizations),
        "members": universe_members,
    }
    diagnostics["strict_universe_digest"] = {
        "version": STRICT_UNIVERSE_VERSION,
        "sha256": canonical_sha256(universe_payload),
        "member_count": len(universe_members),
    }
    return sorted(universe.values(), key=lambda row: row.key), diagnostics


def build_scoring_universe(
    checkpoint_path: Path,
    results_root: Path,
    config: ScoreConfig,
    cache: SourceLineCache,
) -> tuple[list[CheckpointFunction], list[str], dict[str, Any]]:
    """Merge backend outputs into the independently discovered DWARF universe."""

    checkpoint_rows, decompilers = load_checkpoint_functions(checkpoint_path, config)
    source_rows, diagnostics = discover_dwarf_function_universe(
        results_root,
        config,
        cache,
    )
    checkpoint_by_key = {row.key: row for row in checkpoint_rows}
    source_by_key = {row.key: row for row in source_rows}
    for key, source_row in source_by_key.items():
        checkpoint_row = checkpoint_by_key.get(key)
        if checkpoint_row is None:
            continue
        source_row.functions.update(checkpoint_row.functions)
        source_row.results.update(checkpoint_row.results)

    checkpoint_only = sorted(set(checkpoint_by_key) - set(source_by_key))
    missing_counts: dict[str, int] = {}
    for decompiler in decompilers:
        missing_counts[decompiler] = sum(decompiler not in row.functions for row in source_rows)
    diagnostics["checkpoint_union_functions"] = len(checkpoint_rows)
    diagnostics["checkpoint_functions_merged"] = len(
        checkpoint_by_key.keys() & source_by_key.keys()
    )
    diagnostics["checkpoint_only_excluded"] = len(checkpoint_only)
    diagnostics["checkpoint_only_examples"] = [
        key.to_dict(config.project) for key in checkpoint_only[:50]
    ]
    diagnostics["backend_missing_functions"] = missing_counts
    diagnostics["missing_both_backends"] = sum(not row.functions for row in source_rows)
    return source_rows, decompilers, diagnostics


def _blind_evidence(evidence: FunctionEvidence, prefix: str) -> FunctionEvidence:
    ordered = sorted(evidence.variables, key=lambda variable: variable.identity)
    aliases = {variable.identity: f"{prefix}_{index:03d}" for index, variable in enumerate(ordered)}
    return replace(
        evidence,
        variables=[
            replace(variable, name=aliases[variable.identity]) for variable in evidence.variables
        ],
        # Decompiler C contains raw local names. Usage vectors are extracted
        # before blinding, so neither matcher mode needs the text afterward.
        code="",
    )


def _pairs(result: DistanceResult) -> list[tuple[str, str, str]]:
    return sorted((match.source_id, match.decompiled_id, match.stage) for match in result.matches)


def _match_confidence(
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


def _matching_dict(result: DistanceResult, config: ScoreConfig) -> dict[str, Any]:
    matches = []
    for match in result.matches:
        row = match.to_dict()
        row["confidence"] = _match_confidence(match)
        matches.append(row)
    return {
        "mode": config.matcher_mode,
        "thresholds": {
            "min_overlap": config.min_overlap,
            "ambiguity_margin": config.ambiguity_margin,
            "min_usage_similarity": config.min_usage_similarity,
            "usage_ambiguity_margin": config.usage_ambiguity_margin,
            "min_combined_similarity": config.min_combined_similarity,
            "address_weight": config.address_weight,
        },
        "source_observable_count": result.source_count,
        "decompiled_count": result.decompiled_count,
        "accepted_count": len(result.matches),
        "distance": result.distance,
        # This is the LVED recovery score, never matcher/oracle accuracy.
        "recovery_score": result.accuracy,
        "strict_distance": result.strict_distance,
        "stack_shift": result.stack_shift,
        "accepted_matches": matches,
        "unmatched_source": result.unmatched_source,
        "unmatched_decompiled": result.unmatched_decompiled,
        "unobservable_source": result.unobservable_source,
        "candidates": {
            source_id: [{"decompiled_id": target, "score": score} for target, score in rows]
            for source_id, rows in sorted(result.candidates.items())
        },
    }


def _metadata_sections(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"status": "missing", "passed": None, "path": str(path)}
    try:
        from elftools.elf.elffile import ELFFile

        with path.open("rb") as stream:
            elf = ELFFile(stream)
            forbidden = []
            for section in elf.iter_sections():
                name = section.name
                if (
                    name.startswith(".debug")
                    or name in {".symtab", ".strtab", ".gdb_index", ".gnu_debuglink"}
                ) and int(section["sh_size"]) > 0:
                    forbidden.append(name)
        return {
            "status": "checked",
            "passed": not forbidden,
            "path": str(path),
            "forbidden_sections": sorted(forbidden),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "passed": False,
            "path": str(path),
            "error": f"{type(exc).__name__}: {exc}",
        }


def _function_instruction_set(
    binary_path: Path,
    start: int,
    end: int,
) -> frozenset[int]:
    from elftools.elf.elffile import ELFFile

    with binary_path.open("rb") as stream:
        return frozenset(instruction_addresses(ELFFile(stream), start, end))


def _filter_to_function_instructions(
    evidence: FunctionEvidence,
    instructions: frozenset[int],
) -> tuple[FunctionEvidence, tuple[int, ...]]:
    """Drop backend spillover/padding addresses before they affect matching."""

    observed = {
        address for addresses in evidence.line_addresses.values() for address in addresses
    } | {address for variable in evidence.variables for address in variable.addresses}
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


def _match_with_config(
    source: list[VariableEvidence],
    decompiled: list[VariableEvidence],
    config: ScoreConfig,
) -> DistanceResult:
    from decbench.experimental.local_variable_distance import match_variables

    return match_variables(
        source,
        decompiled,
        mode=config.matcher_mode,
        min_overlap=config.min_overlap,
        ambiguity_margin=config.ambiguity_margin,
        min_usage_similarity=config.min_usage_similarity,
        usage_ambiguity_margin=config.usage_ambiguity_margin,
        min_combined_similarity=config.min_combined_similarity,
        address_weight=config.address_weight,
    )


def _controls(
    source: FunctionEvidence,
    decompiled: FunctionEvidence,
    result: DistanceResult,
    instructions: frozenset[int],
    dropped_decompiler_addresses: tuple[int, ...],
    stripped_path: Path,
    config: ScoreConfig,
) -> dict[str, Any]:
    renamed_source = [
        replace(variable, name=f"renamed_source_{index}")
        for index, variable in enumerate(reversed(source.variables))
    ]
    renamed_decompiled = [
        replace(variable, name=f"renamed_decompiled_{index}")
        for index, variable in enumerate(reversed(decompiled.variables))
    ]
    renamed = _match_with_config(
        renamed_source,
        renamed_decompiled,
        config,
    )
    repeated = _match_with_config(
        source.variables,
        decompiled.variables,
        config,
    )
    address_only_source = [
        replace(variable, stack_offsets=(), arg_index=None) for variable in source.variables
    ]
    address_shift = max(1, source.end - source.start + 1)
    disjoint_decompiled = [
        replace(
            variable,
            addresses=frozenset(address + address_shift for address in variable.addresses),
            stack_offsets=(),
            arg_index=None,
            usage_features=(),
        )
        for variable in decompiled.variables
    ]
    disjoint = _match_with_config(
        address_only_source,
        disjoint_decompiled,
        config,
    )
    fake = VariableEvidence(
        identity="control:fake-local",
        name="control_fake",
    )
    with_fake = _match_with_config(
        source.variables,
        [*decompiled.variables, fake],
        config,
    )

    evidence_addresses = {
        address
        for variable in [*source.variables, *decompiled.variables]
        for address in variable.addresses
    }
    bad_addresses = sorted(evidence_addresses - instructions)
    address_control: dict[str, Any] = {
        "passed": not bad_addresses,
        "invalid_addresses": [f"0x{address:x}" for address in bad_addresses],
        "raw_decompiler_addresses_dropped": [
            f"0x{address:x}" for address in dropped_decompiler_addresses
        ],
    }

    return {
        "rename_invariance": {
            "passed": _pairs(renamed) == _pairs(result),
        },
        "disjoint_address_overlap_zero": {
            "passed": not any(match.stage == "overlap" for match in disjoint.matches),
        },
        "fake_local_increases_distance_by_one": {
            "passed": with_fake.distance == result.distance + 1,
            "baseline_distance": result.distance,
            "fake_distance": with_fake.distance,
        },
        "addresses_are_instructions": address_control,
        "stripped_input_metadata_absent": _metadata_sections(stripped_path),
        "repeated_pair_set_identical": {
            "passed": _pairs(repeated) == _pairs(result),
        },
    }


def _variable_by_id(evidence: dict[str, Any], identity: str) -> dict[str, Any] | None:
    return next(
        (
            variable
            for variable in evidence.get("variables", [])
            if variable["identity"] == identity
        ),
        None,
    )


def score_function(
    candidate: CheckpointFunction,
    *,
    results_root: Path,
    decompilers: list[str],
    config: ScoreConfig,
    cache: SourceLineCache,
) -> dict[str, Any]:
    """Extract and match one sampled function, preserving errors as data."""

    sample_id = stable_hash("lved-function-v1", config.project, candidate.key.hash_parts())
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "sample_id": sample_id,
        "sample_rank": _sample_digest(candidate.key, config.sample_seed),
        "partition": _partition(
            candidate.key,
            config.sample_seed,
            config.tuning_fraction,
        ),
        "function": candidate.key.to_dict(config.project),
        "blinding": {
            "variable_names_blinded": True,
            "decompiled_code_omitted": True,
            "matcher_received_only_synthetic_names": True,
        },
        "source_status": "pending",
        "decompilers": {},
    }
    try:
        if candidate.source is None:
            raise ValueError("function is not in the resolved DWARF source universe")
        binary_path = candidate.source.binary_path
        source_path = candidate.source.source_path
        preprocessed_path = candidate.source.preprocessed_path
        primary_marker = cache.primary_marker(preprocessed_path)
        if primary_marker is None or not _path_has_suffix(
            primary_marker,
            candidate.source.cu_path,
        ):
            raise ValueError(
                f"resolved .i primary marker {primary_marker!r} does not match "
                f"CU {candidate.source.cu_path!r}"
            )
        source = extract_source_evidence(
            binary_path,
            source_path,
            candidate.key.name,
            preprocessed_path=preprocessed_path,
            include_inlined=config.include_inlined,
            function_address=candidate.key.address,
            source_lines=cache.lines(source_path, preprocessed_path),
            feature_code=cache.function_code(
                source_path,
                preprocessed_path,
                candidate.key.name,
            ),
        )
        source = _blind_evidence(source, "source")
        stripped_path = (
            results_root
            / candidate.key.optimization
            / config.project
            / "stripped"
            / binary_path.name
        )
        record["source_status"] = "ok"
        record["artifacts"] = {
            "binary": str(binary_path),
            "source": str(source_path),
            "preprocessed": str(preprocessed_path),
            "stripped_input": str(stripped_path),
            "dwarf_cu_path": candidate.source.cu_path,
            "dwarf_decl_file": candidate.source.decl_file,
            "dwarf_decl_line": candidate.source.decl_line,
            "resolution_policy": "address-pinned path-qualified DWARF CU",
        }
        record["source_controls"] = {
            "cu_primary_matches_preprocessed_marker": {
                "passed": True,
                "dwarf_cu_path": candidate.source.cu_path,
                "preprocessed_primary_marker": primary_marker,
            }
        }
        record["source_evidence"] = source.to_dict()
        instructions = _function_instruction_set(binary_path, source.start, source.end)
    except Exception as exc:  # noqa: BLE001
        record["source_status"] = "error"
        record["source_error"] = f"{type(exc).__name__}: {exc}"
        for decompiler in decompilers:
            record["decompilers"][decompiler] = {"status": "source_error"}
        return record

    from decbench.experimental.local_variable_distance import match_variables

    for decompiler in decompilers:
        function = candidate.functions.get(decompiler)
        if function is None:
            record["decompilers"][decompiler] = {"status": "missing"}
            continue
        try:
            decompiled = extract_decompiler_evidence(
                function,
                backend=decompiler,
                function_name=candidate.key.name,
                function_end=source.end,
            )
            decompiled = _blind_evidence(decompiled, "decompiled")
            decompiled, dropped_addresses = _filter_to_function_instructions(
                decompiled,
                instructions,
            )
            result = match_variables(
                source.variables,
                decompiled.variables,
                mode=config.matcher_mode,
                min_overlap=config.min_overlap,
                ambiguity_margin=config.ambiguity_margin,
                min_usage_similarity=config.min_usage_similarity,
                usage_ambiguity_margin=config.usage_ambiguity_margin,
                min_combined_similarity=config.min_combined_similarity,
                address_weight=config.address_weight,
            )
            record["decompilers"][decompiler] = {
                "status": "ok",
                "evidence": decompiled.to_dict(),
                "address_filter": {
                    "policy": "decoded instruction starts in the DWARF function range",
                    "boundary_merge_status": (
                        "out_of_range_or_noninstruction_evidence_filtered"
                        if dropped_addresses
                        else "none"
                    ),
                    "dropped_count": len(dropped_addresses),
                    "dropped_addresses": [f"0x{address:x}" for address in dropped_addresses],
                },
                "matching": _matching_dict(result, config),
                "controls": _controls(
                    source,
                    decompiled,
                    result,
                    instructions,
                    dropped_addresses,
                    stripped_path,
                    config,
                ),
            }
        except Exception as exc:  # noqa: BLE001
            record["decompilers"][decompiler] = {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }
    return record


def make_label_template(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a blinded, independently editable oracle-label template."""

    rows: list[dict[str, Any]] = []
    for record in records:
        if record.get("source_status") != "ok":
            continue
        source_ids = [
            variable["identity"]
            for variable in record["source_evidence"]["variables"]
            if (
                variable["addresses"]
                or variable["stack_offsets"]
                or variable["arg_index"] is not None
            )
        ]
        for decompiler, entry in sorted(record["decompilers"].items()):
            if entry.get("status") != "ok":
                continue
            rows.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "run_binding_sha256": record.get("run_binding_sha256"),
                    "sample_id": record["sample_id"],
                    "function": record["function"],
                    "partition": record["partition"],
                    "decompiler": decompiler,
                    "accepted_matches": [
                        {
                            "source_id": match["source_id"],
                            "decompiled_id": match["decompiled_id"],
                            "stage": match["stage"],
                            "verdict": None,
                            "notes": "",
                        }
                        for match in entry["matching"]["accepted_matches"]
                    ],
                    "source_oracle": [
                        {
                            "source_id": source_id,
                            "status": None,
                            "decompiled_id": None,
                            "notes": "",
                        }
                        for source_id in source_ids
                    ],
                    "notes": "",
                }
            )
    return rows


def load_audit_labels(path: Path | None) -> dict[tuple[str, str], dict[str, Any]]:
    """Load label JSONL, rejecting duplicates and unsupported label values."""

    if path is None:
        return {}
    labels: dict[tuple[str, str], dict[str, Any]] = {}
    for line_number, text in enumerate(path.read_text().splitlines(), start=1):
        if not text.strip():
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
        key = (str(row.get("sample_id", "")), str(row.get("decompiler", "")))
        if not all(key):
            raise ValueError(f"{path}:{line_number}: sample_id and decompiler are required")
        if key in labels:
            raise ValueError(f"{path}:{line_number}: duplicate label row for {key}")
        for match in row.get("accepted_matches", []):
            verdict = match.get("verdict")
            if verdict is not None and verdict not in VERDICTS:
                raise ValueError(
                    f"{path}:{line_number}: invalid accepted-match verdict {verdict!r}"
                )
        for source in row.get("source_oracle", []):
            status = source.get("status")
            if status is not None and status not in SOURCE_ORACLE_STATUSES:
                raise ValueError(f"{path}:{line_number}: invalid source oracle status {status!r}")
            if status == "match" and not source.get("decompiled_id"):
                raise ValueError(f"{path}:{line_number}: source status 'match' needs decompiled_id")
        labels[key] = row
    return labels


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot take a quantile of no values")
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _bootstrap_mean(
    values: list[float],
    *,
    iterations: int,
    seed_parts: tuple[Any, ...],
) -> list[float] | None:
    if not values or iterations <= 0:
        return None
    rng = random.Random(int(stable_hash("lved-bootstrap-v1", seed_parts), 16))
    estimates = [
        sum(rng.choice(values) for _ in values) / len(values) for _iteration in range(iterations)
    ]
    return [_quantile(estimates, 0.025), _quantile(estimates, 0.975)]


def _bootstrap_ratio(
    clusters: list[tuple[int, int]],
    *,
    iterations: int,
    seed_parts: tuple[Any, ...],
) -> list[float] | None:
    if not clusters or iterations <= 0 or sum(denominator for _num, denominator in clusters) == 0:
        return None
    rng = random.Random(int(stable_hash("lved-bootstrap-ratio-v1", seed_parts), 16))
    estimates: list[float] = []
    for _iteration in range(iterations):
        sampled = [rng.choice(clusters) for _ in clusters]
        numerator = sum(row[0] for row in sampled)
        denominator = sum(row[1] for row in sampled)
        if denominator:
            estimates.append(numerator / denominator)
    if not estimates:
        return None
    return [_quantile(estimates, 0.025), _quantile(estimates, 0.975)]


def _histogram(value: float | None, boundaries: tuple[float, ...]) -> str:
    if value is None:
        return "no_runner_up"
    lower = 0.0
    for upper in boundaries:
        if value < upper:
            return f"[{lower:g},{upper:g})"
        lower = upper
    return f"[{lower:g},inf)"


def _label_stats(
    rows: list[dict[str, Any]],
    decompiler: str,
    labels: dict[tuple[str, str], dict[str, Any]],
    iterations: int,
    seed_parts: tuple[Any, ...],
) -> dict[str, Any]:
    accepted = {"correct": 0, "incorrect": 0, "unknown": 0, "unlabeled": 0}
    stage_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"correct": 0, "incorrect": 0, "unknown": 0, "unlabeled": 0}
    )
    precision_clusters: list[tuple[int, int]] = []
    recall_clusters: list[tuple[int, int]] = []
    source_statuses: dict[str, int] = defaultdict(int)
    label_rows = 0
    for record in rows:
        entry = record["decompilers"].get(decompiler, {})
        if entry.get("status") != "ok":
            continue
        label = labels.get((record["sample_id"], decompiler))
        if label is not None:
            label_rows += 1
        verdicts = {
            (match.get("source_id"), match.get("decompiled_id")): match.get("verdict")
            for match in (label or {}).get("accepted_matches", [])
        }
        function_correct = 0
        function_decidable = 0
        accepted_pairs = set()
        for match in entry["matching"]["accepted_matches"]:
            pair = (match["source_id"], match["decompiled_id"])
            accepted_pairs.add(pair)
            verdict = verdicts.get(pair)
            bucket = verdict if verdict in VERDICTS else "unlabeled"
            accepted[bucket] += 1
            stage_counts[match["stage"]][bucket] += 1
            if bucket in {"correct", "incorrect"}:
                function_decidable += 1
                function_correct += int(bucket == "correct")
        precision_clusters.append((function_correct, function_decidable))

        recall_correct = 0
        recall_denom = 0
        for source in (label or {}).get("source_oracle", []):
            status = source.get("status")
            if status is None:
                source_statuses["unlabeled"] += 1
                continue
            source_statuses[status] += 1
            if status == "match":
                recall_denom += 1
                recall_correct += int(
                    (source.get("source_id"), source.get("decompiled_id")) in accepted_pairs
                )
        recall_clusters.append((recall_correct, recall_denom))

    precision_denom = accepted["correct"] + accepted["incorrect"]
    recall_num = sum(row[0] for row in recall_clusters)
    recall_denom = sum(row[1] for row in recall_clusters)
    if label_rows == 0:
        status = "unlabeled"
    elif accepted["unlabeled"] or source_statuses.get("unlabeled"):
        status = "partially_labeled"
    else:
        status = "labeled"
    return {
        "status": status,
        "label_rows": label_rows,
        "accepted": accepted,
        "correct": accepted["correct"] if label_rows else None,
        "incorrect": accepted["incorrect"] if label_rows else None,
        "oracle_unknown": accepted["unknown"] if label_rows else None,
        "precision_decidable_accepted": (
            accepted["correct"] / precision_denom if precision_denom else None
        ),
        "recall_oracle_matchable_source": (recall_num / recall_denom if recall_denom else None),
        "source_oracle_statuses": dict(sorted(source_statuses.items())),
        "bootstrap_95_clustered_by_function": {
            "precision": _bootstrap_ratio(
                precision_clusters,
                iterations=iterations,
                seed_parts=(*seed_parts, "precision"),
            ),
            "recall": _bootstrap_ratio(
                recall_clusters,
                iterations=iterations,
                seed_parts=(*seed_parts, "recall"),
            ),
        },
        "by_stage": {
            stage: {
                "accepted": sum(counts.values()),
                "correct": counts["correct"] if label_rows else None,
                "incorrect": counts["incorrect"] if label_rows else None,
                "oracle_unknown": counts["unknown"] if label_rows else None,
                "unlabeled": counts["unlabeled"],
                "precision_decidable_accepted": (
                    counts["correct"] / (counts["correct"] + counts["incorrect"])
                    if counts["correct"] + counts["incorrect"]
                    else None
                ),
                # An abstained source has no matching stage, so stage-specific
                # recall is undefined rather than fabricated.
                "recall": None,
            }
            for stage, counts in sorted(stage_counts.items())
        },
    }


def _calibration_output(
    bins: dict[str, dict[str, int]],
    *,
    labels_present: bool,
) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "accepted": sum(counts.values()),
            "correct": counts["correct"] if labels_present else None,
            "incorrect": counts["incorrect"] if labels_present else None,
            "oracle_unknown": counts["unknown"] if labels_present else None,
            "unlabeled": counts["unlabeled"],
            "precision_decidable_accepted": (
                counts["correct"] / (counts["correct"] + counts["incorrect"])
                if counts["correct"] + counts["incorrect"]
                else None
            ),
        }
        for name, counts in sorted(bins.items())
    }


def _record_source_observable_count(record: dict[str, Any], mode: MatcherMode) -> int:
    if record.get("source_status") != "ok":
        return 0
    count = 0
    for raw in record["source_evidence"]["variables"]:
        variable = VariableEvidence.from_dict(raw)
        address_observable = bool(
            variable.addresses or variable.stack_offsets or variable.arg_index is not None
        )
        usage_observable = has_usage_context(variable)
        if (
            (mode == "address" and address_observable)
            or (mode == "usage" and usage_observable)
            or (mode == "address+usage" and (address_observable or usage_observable))
        ):
            count += 1
    return count


def _aggregate_row(
    rows: list[dict[str, Any]],
    decompiler: str,
    labels: dict[tuple[str, str], dict[str, Any]],
    config: ScoreConfig,
    dimensions: tuple[str, str, str],
) -> dict[str, Any]:
    statuses: dict[str, int] = defaultdict(int)
    source_total = 0
    decompiled_total = 0
    accepted_total = 0
    unmatched_source = 0
    distances = 0
    conditioned_source_total = 0
    conditioned_decompiled_total = 0
    conditioned_accepted_total = 0
    conditioned_unmatched_source = 0
    dropped_decompiler_addresses = 0
    recovery_scores: list[float] = []
    coverages: list[float] = []
    stage_counts: dict[str, int] = defaultdict(int)
    boundary_statuses: dict[str, int] = defaultdict(int)
    score_bins: dict[str, dict[str, int]] = defaultdict(
        lambda: {"correct": 0, "incorrect": 0, "unknown": 0, "unlabeled": 0}
    )
    gap_bins: dict[str, dict[str, int]] = defaultdict(
        lambda: {"correct": 0, "incorrect": 0, "unknown": 0, "unlabeled": 0}
    )
    controls: dict[str, dict[str, int]] = defaultdict(
        lambda: {"passed": 0, "failed": 0, "unchecked": 0}
    )
    gap_margin = (
        config.ambiguity_margin
        if config.matcher_mode == "address"
        else config.usage_ambiguity_margin
    )
    for record in rows:
        entry = record["decompilers"].get(decompiler, {"status": "missing"})
        status = str(entry.get("status", "error"))
        statuses[status] += 1
        if record.get("source_status") != "ok":
            continue
        source_count = _record_source_observable_count(record, config.matcher_mode)
        source_total += source_count
        if status != "ok":
            unmatched_source += source_count
            distances += source_count
            recovery_scores.append(0.0 if source_count else 1.0)
            coverages.append(0.0 if source_count else 1.0)
            continue
        matching = entry["matching"]
        boundary_statuses[
            entry.get("address_filter", {}).get("boundary_merge_status", "unknown")
        ] += 1
        dropped_decompiler_addresses += int(entry.get("address_filter", {}).get("dropped_count", 0))
        if int(matching["source_observable_count"]) != source_count:
            raise ValueError(
                f"source observable count drift for {record['sample_id']}/{decompiler}"
            )
        decompiled_total += int(matching["decompiled_count"])
        accepted_total += int(matching["accepted_count"])
        unmatched_source += len(matching["unmatched_source"])
        distances += int(matching["distance"])
        conditioned_source_total += source_count
        conditioned_decompiled_total += int(matching["decompiled_count"])
        conditioned_accepted_total += int(matching["accepted_count"])
        conditioned_unmatched_source += len(matching["unmatched_source"])
        recovery_scores.append(float(matching["recovery_score"]))
        coverages.append(matching["accepted_count"] / source_count if source_count else 1.0)
        label = labels.get((record["sample_id"], decompiler), {})
        verdicts = {
            (match.get("source_id"), match.get("decompiled_id")): match.get("verdict")
            for match in label.get("accepted_matches", [])
        }
        for match in matching["accepted_matches"]:
            stage_counts[match["stage"]] += 1
            pair = (match["source_id"], match["decompiled_id"])
            verdict = verdicts.get(pair)
            bucket = verdict if verdict in VERDICTS else "unlabeled"
            score_bins[_histogram(float(match["score"]), (0.25, 0.5, 0.75))][bucket] += 1
            gap = match["confidence"]["minimum_runner_up_gap"]
            gap_bins[_histogram(gap, (gap_margin, 0.1, 0.25))][bucket] += 1
        for name, control in entry["controls"].items():
            passed = control.get("passed")
            bucket = "passed" if passed is True else "failed" if passed is False else "unchecked"
            controls[name][bucket] += 1

    recovery_denom = source_total + decompiled_total
    conditioned_recovery_denom = conditioned_source_total + conditioned_decompiled_total
    oracle = _label_stats(
        rows,
        decompiler,
        labels,
        config.bootstrap_iterations,
        dimensions,
    )
    return {
        "partition": dimensions[0],
        "optimization": dimensions[1],
        "decompiler": dimensions[2],
        "functions_sampled": len(rows),
        "function_statuses": dict(sorted(statuses.items())),
        "micro": {
            "source_observable": source_total,
            "decompiled_variables": decompiled_total,
            "accepted_matches": accepted_total,
            "unmatched_source": unmatched_source,
            "distance": distances,
            "raw_decompiler_addresses_outside_function_dropped": (dropped_decompiler_addresses),
            "matcher_coverage": accepted_total / source_total if source_total else None,
            "abstention_rate": unmatched_source / source_total if source_total else None,
            "recovery_score": (2 * accepted_total / recovery_denom if recovery_denom else None),
        },
        "success_conditioned_micro": {
            "source_observable": conditioned_source_total,
            "decompiled_variables": conditioned_decompiled_total,
            "accepted_matches": conditioned_accepted_total,
            "unmatched_source": conditioned_unmatched_source,
            "matcher_coverage": (
                conditioned_accepted_total / conditioned_source_total
                if conditioned_source_total
                else None
            ),
            "abstention_rate": (
                conditioned_unmatched_source / conditioned_source_total
                if conditioned_source_total
                else None
            ),
            "recovery_score": (
                2 * conditioned_accepted_total / conditioned_recovery_denom
                if conditioned_recovery_denom
                else None
            ),
        },
        "macro_by_function": {
            "recovery_score": (
                sum(recovery_scores) / len(recovery_scores) if recovery_scores else None
            ),
            "matcher_coverage": (sum(coverages) / len(coverages) if coverages else None),
            "bootstrap_95_clustered_by_function": {
                "recovery_score": _bootstrap_mean(
                    recovery_scores,
                    iterations=config.bootstrap_iterations,
                    seed_parts=(*dimensions, "recovery_score"),
                ),
                "matcher_coverage": _bootstrap_mean(
                    coverages,
                    iterations=config.bootstrap_iterations,
                    seed_parts=(*dimensions, "matcher_coverage"),
                ),
            },
        },
        "accepted_by_stage": dict(sorted(stage_counts.items())),
        "boundary_merge_statuses": dict(sorted(boundary_statuses.items())),
        "score_calibration_bins": _calibration_output(
            score_bins,
            labels_present=oracle["label_rows"] > 0,
        ),
        "runner_up_gap_calibration_bins": _calibration_output(
            gap_bins,
            labels_present=oracle["label_rows"] > 0,
        ),
        "controls": {name: counts for name, counts in sorted(controls.items())},
        "oracle_accuracy": oracle,
    }


def _audit_examples(
    records: list[dict[str, Any]],
    labels: dict[tuple[str, str], dict[str, Any]],
    limit: int = 10,
) -> dict[str, Any]:
    false_matches: list[dict[str, Any]] = []
    abstentions: list[dict[str, Any]] = []
    for record in records:
        if record.get("source_status") != "ok":
            continue
        for decompiler, entry in sorted(record["decompilers"].items()):
            if entry.get("status") != "ok":
                continue
            label = labels.get((record["sample_id"], decompiler), {})
            verdicts = {
                (row.get("source_id"), row.get("decompiled_id")): row.get("verdict")
                for row in label.get("accepted_matches", [])
            }
            for match in entry["matching"]["accepted_matches"]:
                pair = (match["source_id"], match["decompiled_id"])
                if verdicts.get(pair) != "incorrect" or len(false_matches) >= limit:
                    continue
                false_matches.append(
                    {
                        "sample_id": record["sample_id"],
                        "function": record["function"],
                        "decompiler": decompiler,
                        "match": match,
                        "source_evidence": _variable_by_id(
                            record["source_evidence"],
                            match["source_id"],
                        ),
                        "decompiler_evidence": _variable_by_id(
                            entry["evidence"],
                            match["decompiled_id"],
                        ),
                    }
                )
            for source_id in entry["matching"]["unmatched_source"]:
                if len(abstentions) >= limit:
                    break
                abstentions.append(
                    {
                        "sample_id": record["sample_id"],
                        "function": record["function"],
                        "decompiler": decompiler,
                        "source_evidence": _variable_by_id(
                            record["source_evidence"],
                            source_id,
                        ),
                        "candidates": entry["matching"]["candidates"].get(source_id, []),
                    }
                )
    return {
        "false_matches": false_matches,
        "false_matches_note": (
            "Only independently labeled incorrect pairs appear here."
            if labels
            else "No audit labels supplied; false matches are not inferred from overlap."
        ),
        "abstentions": abstentions,
    }


def aggregate_report(
    records: list[dict[str, Any]],
    *,
    checkpoint_path: Path,
    decompilers: list[str],
    config: ScoreConfig,
    cache: SourceLineCache,
    labels: dict[tuple[str, str], dict[str, Any]] | None = None,
    universe_diagnostics: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build structural metrics plus oracle fields that stay null when unlabeled."""

    labels = labels or {}
    aggregate_rows = []
    optimizations = sorted({record["function"]["optimization"] for record in records})
    for partition in ("all", "tuning", "held_out"):
        partition_rows = (
            records
            if partition == "all"
            else [record for record in records if record["partition"] == partition]
        )
        for optimization in optimizations:
            opt_rows = [
                record
                for record in partition_rows
                if record["function"]["optimization"] == optimization
            ]
            for decompiler in decompilers:
                aggregate_rows.append(
                    _aggregate_row(
                        opt_rows,
                        decompiler,
                        labels,
                        config,
                        (partition, optimization, decompiler),
                    )
                )
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment": "local-variable-edit-distance",
        "checkpoint": str(checkpoint_path.resolve()),
        "provenance": provenance or {},
        "project": config.project,
        "disclaimer": (
            "recovery_score is an LVED set-correspondence score, not matcher precision. "
            "Precision/recall remain null unless independent oracle labels are supplied."
        ),
        "blinding": {
            "variable_names_blinded": True,
            "matching_uses_synthetic_names": True,
        },
        "sampling": {
            "algorithm": SAMPLE_ALGORITHM,
            "seed": config.sample_seed,
            "requested_size": config.sample_size,
            "selected_size": len(records),
            "tuning_fraction": config.tuning_fraction,
            "partition_counts": {
                partition: sum(record["partition"] == partition for record in records)
                for partition in ("tuning", "held_out")
            },
            "sample_ids": [record["sample_id"] for record in records],
            "backend_status_counts": {
                decompiler: {
                    status: sum(
                        record["decompilers"].get(decompiler, {}).get("status") == status
                        for record in records
                    )
                    for status in sorted(
                        {
                            record["decompilers"]
                            .get(decompiler, {})
                            .get(
                                "status",
                                "missing",
                            )
                            for record in records
                        }
                    )
                }
                for decompiler in decompilers
            },
            "missing_both_functions": [
                record["function"]
                for record in records
                if record.get("source_status") == "ok"
                and all(
                    record["decompilers"].get(decompiler, {}).get("status") == "missing"
                    for decompiler in decompilers
                )
            ],
        },
        "frozen_thresholds": {
            "matcher_mode": config.matcher_mode,
            "min_overlap": config.min_overlap,
            "ambiguity_margin": config.ambiguity_margin,
            "min_usage_similarity": config.min_usage_similarity,
            "usage_ambiguity_margin": config.usage_ambiguity_margin,
            "min_combined_similarity": config.min_combined_similarity,
            "address_weight": config.address_weight,
            "warning": "Tune only on the tuning partition; report held_out unchanged.",
        },
        "source_line_cache": cache.stats(),
        "source_universe": universe_diagnostics or {},
        "source_statuses": dict(
            sorted(
                {
                    status: sum(record["source_status"] == status for record in records)
                    for status in {record["source_status"] for record in records}
                }.items()
            )
        ),
        "oracle_labels": {
            "path_supplied": bool(labels),
            "rows_loaded": len(labels),
        },
        "rows": aggregate_rows,
        "audit_examples": _audit_examples(records, labels),
    }


def score_checkpoint(
    checkpoint_path: Path,
    results_root: Path,
    config: ScoreConfig,
    *,
    labels: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    """Load, sample, extract, match, and aggregate one checkpoint."""

    checkpoint_digest = file_sha256(checkpoint_path)
    cache = SourceLineCache()
    functions, decompilers, universe_diagnostics = build_scoring_universe(
        checkpoint_path,
        results_root,
        config,
        cache,
    )
    selected = deterministic_sample(
        functions,
        size=config.sample_size,
        seed=config.sample_seed,
    )
    records = [
        score_function(
            candidate,
            results_root=results_root,
            decompilers=decompilers,
            config=config,
            cache=cache,
        )
        for candidate in selected
    ]
    config_payload = score_config_payload(config)
    config_digest = canonical_sha256(config_payload)
    selected_sample_payload = [
        {
            "sample_id": record["sample_id"],
            "sample_rank": record["sample_rank"],
            "partition": record["partition"],
            "function": record["function"],
        }
        for record in records
    ]
    selected_sample_digest = canonical_sha256(selected_sample_payload)
    strict_universe = universe_diagnostics.get("strict_universe_digest", {})
    strict_universe_digest = strict_universe.get("sha256")
    if not isinstance(strict_universe_digest, str):
        raise ValueError("strict source-universe digest was not produced")
    run_binding_inputs = {
        "version": RUN_BINDING_VERSION,
        "checkpoint_sha256": checkpoint_digest,
        "score_config_sha256": config_digest,
        "strict_universe_sha256": strict_universe_digest,
        "selected_sample_sha256": selected_sample_digest,
        "decompilers": decompilers,
    }
    run_binding_digest = canonical_sha256(run_binding_inputs)
    for record in records:
        record["run_binding_sha256"] = run_binding_digest
    scorer_digest = jsonl_sha256(records)
    # Refuse a race or accidental overwrite while the checkpoint is being
    # scored.  Otherwise the advertised digest might not name the bytes that
    # were actually unpickled above.
    if file_sha256(checkpoint_path) != checkpoint_digest:
        raise ValueError(f"checkpoint changed while scoring: {checkpoint_path}")
    provenance = {
        "hash_algorithm": "sha256",
        "checkpoint_sha256": checkpoint_digest,
        "score_config": config_payload,
        "score_config_sha256": config_digest,
        "strict_universe": strict_universe,
        "selected_sample_sha256": selected_sample_digest,
        "selected_sample_count": len(records),
        "decompilers": decompilers,
        "run_binding_version": RUN_BINDING_VERSION,
        "run_binding_sha256": run_binding_digest,
        "scorer_jsonl_serialization": SCORER_JSONL_SERIALIZATION,
        "scorer_jsonl_sha256": scorer_digest,
    }
    report = aggregate_report(
        records,
        checkpoint_path=checkpoint_path,
        decompilers=decompilers,
        config=config,
        cache=cache,
        labels=labels,
        universe_diagnostics=universe_diagnostics,
        provenance=provenance,
    )
    return records, report, make_label_template(records)


def validate_run_provenance(
    report: dict[str, Any],
    checkpoint_path: Path,
    records: list[dict[str, Any]],
) -> dict[str, str]:
    """Verify that a report, checkpoint, and scorer JSONL rows belong together.

    The semantic-audit builder performs the same checks before re-extracting
    pseudocode.  Keeping a small public validator here also makes stale or
    substituted artifacts directly testable by scorer callers.
    """

    provenance = report.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("aggregate report has no provenance object")

    expected_checkpoint = provenance.get("checkpoint_sha256")
    actual_checkpoint = file_sha256(checkpoint_path)
    if not isinstance(expected_checkpoint, str) or actual_checkpoint != expected_checkpoint:
        raise ValueError(
            "checkpoint SHA-256 mismatch: aggregate does not bind the supplied checkpoint"
        )

    config_payload = provenance.get("score_config")
    expected_config = provenance.get("score_config_sha256")
    if not isinstance(config_payload, dict) or canonical_sha256(config_payload) != expected_config:
        raise ValueError("score-config SHA-256 mismatch in aggregate provenance")

    strict_universe = provenance.get("strict_universe")
    if not isinstance(strict_universe, dict) or not isinstance(
        strict_universe.get("sha256"),
        str,
    ):
        raise ValueError("aggregate provenance has no strict-universe SHA-256")

    selected_payload = [
        {
            "sample_id": record.get("sample_id"),
            "sample_rank": record.get("sample_rank"),
            "partition": record.get("partition"),
            "function": record.get("function"),
        }
        for record in records
    ]
    selected_digest = canonical_sha256(selected_payload)
    if selected_digest != provenance.get("selected_sample_sha256"):
        raise ValueError("selected-sample SHA-256 mismatch in aggregate provenance")
    if len(records) != provenance.get("selected_sample_count"):
        raise ValueError("selected-sample count mismatch in aggregate provenance")

    binding_inputs = {
        "version": provenance.get("run_binding_version"),
        "checkpoint_sha256": expected_checkpoint,
        "score_config_sha256": expected_config,
        "strict_universe_sha256": strict_universe["sha256"],
        "selected_sample_sha256": selected_digest,
        "decompilers": provenance.get("decompilers"),
    }
    expected_binding = provenance.get("run_binding_sha256")
    if canonical_sha256(binding_inputs) != expected_binding:
        raise ValueError("run-binding SHA-256 mismatch in aggregate provenance")
    mismatched_rows = [
        str(record.get("sample_id"))
        for record in records
        if record.get("run_binding_sha256") != expected_binding
    ]
    if mismatched_rows:
        raise ValueError("scorer row run-binding mismatch; first sample is " + mismatched_rows[0])

    actual_scorer = jsonl_sha256(records)
    if actual_scorer != provenance.get("scorer_jsonl_sha256"):
        raise ValueError("scorer JSONL SHA-256 mismatch in aggregate provenance")
    if provenance.get("scorer_jsonl_serialization") != SCORER_JSONL_SERIALIZATION:
        raise ValueError("unsupported scorer JSONL serialization contract")
    return {
        "checkpoint_sha256": actual_checkpoint,
        "scorer_jsonl_sha256": actual_scorer,
        "run_binding_sha256": str(expected_binding),
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    """Atomically write strict JSONL."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        for row in rows:
            stream.write(_jsonl_line(row))
    temporary.replace(path)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write strict, human-readable JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n")
    temporary.replace(path)
