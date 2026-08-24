"""Validate native line and variable provenance stored in benchmark checkpoints."""

from __future__ import annotations

import hashlib
import json
import pickle
import struct
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from decbench.utils import binfmt
from decbench.utils.results_tree import compiled_dir

FunctionKey = tuple[str, str, str, str]
SliceKey = tuple[str, str, str]
FunctionRanges = tuple[tuple[int, int], ...]
FunctionIdentity = tuple[str, int]

REPORT_SCHEMA = "decbench-native-provenance-audit-v1"
SUPPORTED_FORMATS = frozenset({"elf", "pe"})
SUPPORTED_ARCHITECTURES = frozenset({"x86", "x86-64", "arm", "aarch64"})


@dataclass(frozen=True)
class SampleManifest:
    """Strict sample allowlist and its content identity."""

    path: Path
    sha256: str
    keys: frozenset[FunctionKey]

    @property
    def slices(self) -> frozenset[SliceKey]:
        return frozenset(key[:3] for key in self.keys)


@dataclass(frozen=True)
class FunctionCode:
    """Independent machine-code facts for one exact DWARF function."""

    binary_path: Path
    binary_format: str
    architecture: str
    thumb: bool
    ranges: tuple[tuple[int, int], ...]
    instruction_starts: frozenset[int]
    mclass: bool = False


@dataclass(frozen=True)
class BinaryCodeIndex:
    """Immutable machine-code and DWARF context shared within one binary slice."""

    binary_path: Path
    info: binfmt.BinInfo
    executable_regions: tuple[tuple[int, bytes], ...]
    arm_mclass: bool
    pe_machine: int | None
    ranges_by_identity: Mapping[FunctionIdentity, frozenset[FunctionRanges]] = field(repr=False)
    range_errors_by_name: Mapping[str, Exception] = field(repr=False)
    thumb_states_by_address: Mapping[int, frozenset[bool]] = field(repr=False)
    thumb_states_by_name: Mapping[str, tuple[bool, ...]] = field(repr=False)

    @classmethod
    def from_binary(cls, binary_path: Path) -> BinaryCodeIndex:
        """Parse one binary and build its exact function-identity index once."""

        binary_path = binary_path.resolve()
        info = binfmt.detect(binary_path)
        if info is None:
            raise ValueError("unrecognized binary format")
        if info.fmt not in SUPPORTED_FORMATS or info.arch not in SUPPORTED_ARCHITECTURES:
            raise ValueError(f"unsupported binary format/architecture {info.fmt}/{info.arch}")
        dwarfinfo = binfmt.dwarf_info(binary_path)
        if dwarfinfo is None:
            raise ValueError("binary has no readable DWARF")

        indexed_ranges: defaultdict[FunctionIdentity, set[FunctionRanges]] = defaultdict(set)
        range_errors: dict[str, Exception] = {}
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name = binfmt.die_str_attr(die, "DW_AT_name")
                if not name:
                    continue
                try:
                    raw_ranges = _die_ranges(die, dwarfinfo)
                except Exception:
                    continue
                try:
                    ranges = _normalize_ranges(raw_ranges, info.arch)
                    entry = _function_entry(die, raw_ranges, info.arch)
                except Exception as exc:  # noqa: BLE001
                    range_errors.setdefault(name, exc)
                    continue
                if (
                    ranges
                    and entry is not None
                    and any(begin <= entry < end for begin, end in ranges)
                ):
                    indexed_ranges[(name, entry)].add(ranges)

        thumb_by_address: Mapping[int, frozenset[bool]] = MappingProxyType({})
        thumb_by_name: Mapping[str, tuple[bool, ...]] = MappingProxyType({})
        if info.fmt == "elf" and info.arch == "arm":
            thumb_by_address, thumb_by_name = _elf_thumb_state_index(binary_path)
        arm_mclass = (
            info.fmt == "elf" and info.arch == "arm" and binfmt.elf_is_arm_mclass(binary_path)
        )
        pe_machine = _pe_machine(binary_path) if info.fmt == "pe" and info.arch == "arm" else None
        return cls(
            binary_path=binary_path,
            info=info,
            executable_regions=tuple(binfmt.executable_regions(binary_path)),
            arm_mclass=arm_mclass,
            pe_machine=pe_machine,
            ranges_by_identity=MappingProxyType(
                {identity: frozenset(ranges) for identity, ranges in indexed_ranges.items()}
            ),
            range_errors_by_name=MappingProxyType(range_errors),
            thumb_states_by_address=thumb_by_address,
            thumb_states_by_name=thumb_by_name,
        )

    def function_ranges(
        self,
        function_name: str,
        function_address: int,
    ) -> FunctionRanges:
        """Resolve one unambiguous DWARF definition by exact name and entry."""

        if function_name in self.range_errors_by_name:
            raise self.range_errors_by_name[function_name]
        expected = function_address & ~1 if self.info.arch == "arm" else function_address
        candidates = self.ranges_by_identity.get((function_name, expected), frozenset())
        if not candidates:
            raise ValueError(
                f"no DWARF function matches {function_name!r} at 0x{function_address:x}"
            )
        if len(candidates) != 1:
            raise ValueError(
                f"ambiguous DWARF function {function_name!r} at 0x{function_address:x}"
            )
        return next(iter(candidates))

    def uses_thumb(self, function_name: str, function_address: int) -> bool:
        """Select ARM or Thumb from cached authoritative binary metadata."""

        if self.info.arch != "arm":
            return False
        if function_address & 1:
            return True
        if self.info.fmt == "pe":
            return self.pe_machine in {0x1C2, 0x1C4}
        exact = self.thumb_states_by_address.get(function_address & ~1, frozenset())
        if exact:
            return next(iter(exact)) if len(exact) == 1 else False
        named = self.thumb_states_by_name.get(function_name, ())
        return named[0] if len(named) == 1 else False

    def resolve(self, function_name: str, function_address: int) -> FunctionCode:
        """Decode one exact function using the cached binary context."""

        ranges = self.function_ranges(function_name, function_address)
        thumb = self.uses_thumb(function_name, function_address)
        mclass = thumb and self.arm_mclass
        starts = decode_instruction_starts(
            self.info,
            ranges,
            self.executable_regions,
            thumb=thumb,
            mclass=mclass,
        )
        expected = function_address & ~1 if self.info.arch == "arm" else function_address
        if expected not in starts:
            raise ValueError(f"function entry 0x{expected:x} is not a decoded instruction start")
        return FunctionCode(
            binary_path=self.binary_path,
            binary_format=self.info.fmt,
            architecture=("thumb" if thumb else self.info.arch),
            thumb=thumb,
            ranges=ranges,
            instruction_starts=starts,
            mclass=mclass,
        )


@dataclass(frozen=True)
class Finding:
    """One provenance-contract violation."""

    code: str
    message: str
    project: str | None = None
    optimization: str | None = None
    binary: str | None = None
    backend: str | None = None
    function: str | None = None

    def to_dict(self) -> dict[str, str]:
        row = {"code": self.code, "message": self.message}
        for name in ("project", "optimization", "binary", "backend", "function"):
            value = getattr(self, name)
            if value is not None:
                row[name] = value
        return row


@dataclass
class BackendStats:
    """Mutable counters accumulated for one checkpoint backend."""

    functions_seen: int = 0
    functions_with_provenance: int = 0
    functions_validated: int = 0
    functions_without_provenance: int = 0
    functions_with_line_maps: int = 0
    functions_with_variable_lines: int = 0
    functions_with_variable_addresses: int = 0
    functions_with_direct_only_addresses: int = 0
    line_mapping_rows: int = 0
    mapped_addresses: int = 0
    variables: int = 0
    variables_with_lines: int = 0
    variables_with_addresses: int = 0
    errors: int = 0
    formats: Counter[str] = field(default_factory=Counter)
    architectures: Counter[str] = field(default_factory=Counter)
    observed_keys: set[FunctionKey] = field(default_factory=set)

    def to_dict(self, manifest: SampleManifest | None) -> dict[str, Any]:
        row: dict[str, Any] = {
            "functions_seen": self.functions_seen,
            "functions_with_provenance": self.functions_with_provenance,
            "functions_validated": self.functions_validated,
            "functions_without_provenance": self.functions_without_provenance,
            "functions_with_line_maps": self.functions_with_line_maps,
            "functions_with_variable_lines": self.functions_with_variable_lines,
            "functions_with_variable_addresses": self.functions_with_variable_addresses,
            "functions_with_direct_only_addresses": self.functions_with_direct_only_addresses,
            "line_mapping_rows": self.line_mapping_rows,
            "mapped_addresses": self.mapped_addresses,
            "variables": self.variables,
            "variables_with_lines": self.variables_with_lines,
            "variables_with_addresses": self.variables_with_addresses,
            "formats": dict(sorted(self.formats.items())),
            "architectures": dict(sorted(self.architectures.items())),
            "errors": self.errors,
        }
        if manifest is not None:
            present = self.observed_keys & manifest.keys
            row["manifest_functions_present"] = len(present)
            row["manifest_functions_missing"] = len(manifest.keys - present)
        return row


@dataclass
class AuditState:
    """Shared state for deterministic finding and summary construction."""

    max_findings: int
    backend_stats: defaultdict[str, BackendStats] = field(
        default_factory=lambda: defaultdict(BackendStats)
    )
    findings: list[Finding] = field(default_factory=list)
    finding_counts: Counter[str] = field(default_factory=Counter)

    def add(self, finding: Finding) -> None:
        self.finding_counts[finding.code] += 1
        if finding.backend is not None:
            self.backend_stats[finding.backend].errors += 1
        if len(self.findings) < self.max_findings:
            self.findings.append(finding)

    @property
    def error_count(self) -> int:
        return sum(self.finding_counts.values())


def load_manifest(path: Path) -> SampleManifest:
    """Load a non-empty, duplicate-free sample manifest."""

    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
        rows = payload["functions"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"invalid sample manifest {path}: {exc}") from exc
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"sample manifest has no functions: {path}")
    keys: list[FunctionKey] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError(f"invalid sample manifest row {index} in {path}")
        try:
            values = tuple(row[name] for name in ("project", "opt", "binary", "function"))
        except KeyError as exc:
            raise ValueError(f"invalid sample manifest row {index} in {path}: {exc}") from exc
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError(f"sample manifest row {index} has a non-string or empty field: {path}")
        key = tuple(value.strip() for value in values)
        keys.append((key[0], key[1], key[2], key[3]))
    if len(keys) != len(set(keys)):
        raise ValueError(f"sample manifest contains duplicate function keys: {path}")
    return SampleManifest(path.resolve(), hashlib.sha256(raw).hexdigest(), frozenset(keys))


def _die_ranges(die: Any, dwarfinfo: Any) -> tuple[tuple[int, int], ...]:
    """Resolve contiguous and range-list DWARF function extents."""

    from elftools.dwarf.descriptions import describe_form_class
    from elftools.dwarf.ranges import BaseAddressEntry

    low_attr = die.attributes.get("DW_AT_low_pc")
    high_attr = die.attributes.get("DW_AT_high_pc")
    if low_attr is not None and high_attr is not None:
        low = int(low_attr.value)
        high = int(high_attr.value)
        if describe_form_class(high_attr.form) != "address":
            high += low
        return ((low, high),) if high > low else ()
    ranges_attr = die.attributes.get("DW_AT_ranges")
    if ranges_attr is None:
        return ()
    entries = dwarfinfo.range_lists().get_range_list_at_offset(ranges_attr.value, die.cu)
    cu_low = die.cu.get_top_DIE().attributes.get("DW_AT_low_pc")
    base = int(cu_low.value) if cu_low is not None else 0
    ranges: list[tuple[int, int]] = []
    for entry in entries:
        if isinstance(entry, BaseAddressEntry):
            base = int(entry.base_address)
            continue
        begin = int(entry.begin_offset)
        end = int(entry.end_offset)
        if not entry.is_absolute:
            begin += base
            end += base
        if end > begin:
            ranges.append((begin, end))
    return tuple(ranges)


def _normalize_ranges(ranges: Sequence[tuple[int, int]], architecture: str) -> FunctionRanges:
    if architecture != "arm":
        return tuple(ranges)
    return tuple(((begin & ~1), (begin & ~1) + (end - begin)) for begin, end in ranges)


def _function_entry(
    die: Any,
    ranges: Sequence[tuple[int, int]],
    architecture: str,
) -> int | None:
    entry_attr = die.attributes.get("DW_AT_entry_pc")
    low_attr = die.attributes.get("DW_AT_low_pc")
    raw_entry = (
        int(entry_attr.value)
        if entry_attr is not None
        else (
            int(low_attr.value) if low_attr is not None else int(ranges[0][0]) if ranges else None
        )
    )
    if raw_entry is not None and architecture == "arm":
        return raw_entry & ~1
    return raw_entry


def _function_ranges(
    binary_path: Path,
    function_name: str,
    function_address: int,
    architecture: str,
) -> tuple[tuple[int, int], ...]:
    """Find one unambiguous DWARF definition by exact name and entry address."""

    dwarfinfo = binfmt.dwarf_info(binary_path)
    if dwarfinfo is None:
        raise ValueError("binary has no readable DWARF")
    expected = function_address & ~1 if architecture == "arm" else function_address
    candidates: set[tuple[tuple[int, int], ...]] = set()
    for cu in dwarfinfo.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram":
                continue
            if binfmt.die_str_attr(die, "DW_AT_name") != function_name:
                continue
            try:
                ranges = _die_ranges(die, dwarfinfo)
            except Exception:
                continue
            normalized = _normalize_ranges(ranges, architecture)
            entry = _function_entry(die, ranges, architecture)
            if (
                normalized
                and entry == expected
                and any(begin <= expected < end for begin, end in normalized)
            ):
                candidates.add(normalized)
    if not candidates:
        raise ValueError(f"no DWARF function matches {function_name!r} at 0x{function_address:x}")
    if len(candidates) != 1:
        raise ValueError(f"ambiguous DWARF function {function_name!r} at 0x{function_address:x}")
    return next(iter(candidates))


def _pe_machine(path: Path) -> int | None:
    """Read the COFF machine value from a PE image."""

    try:
        with path.open("rb") as stream:
            head = stream.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return None
            offset = struct.unpack_from("<I", head, 0x3C)[0]
            stream.seek(offset)
            if stream.read(4) != b"PE\x00\x00":
                return None
            raw = stream.read(2)
            return struct.unpack("<H", raw)[0] if len(raw) == 2 else None
    except (OSError, struct.error):
        return None


def _elf_thumb_state_index(
    binary_path: Path,
) -> tuple[Mapping[int, frozenset[bool]], Mapping[str, tuple[bool, ...]]]:
    """Index the same authoritative ARM symbol states as the one-shot resolver."""

    exact_states: defaultdict[int, set[bool]] = defaultdict(set)
    named_states: defaultdict[str, list[bool]] = defaultdict(list)
    try:
        from elftools.elf.elffile import ELFFile

        with binary_path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf.header["e_machine"] != "EM_ARM":
                return MappingProxyType({}), MappingProxyType({})
            symbol_table: Any = elf.get_section_by_name(".symtab")
            if symbol_table is None:
                return MappingProxyType({}), MappingProxyType({})
            for symbol in symbol_table.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC" or symbol["st_size"] <= 0:
                    continue
                raw_address = int(symbol["st_value"])
                state = bool(raw_address & 1)
                exact_states[raw_address & ~1].add(state)
                named_states[symbol.name].append(state)
    except Exception:
        return MappingProxyType({}), MappingProxyType({})
    return (
        MappingProxyType({address: frozenset(states) for address, states in exact_states.items()}),
        MappingProxyType({name: tuple(states) for name, states in named_states.items()}),
    )


def _uses_thumb(
    binary_path: Path,
    info: binfmt.BinInfo,
    function_name: str,
    function_address: int,
) -> bool:
    """Select ARM or Thumb without relying on decode success as a heuristic."""

    if info.arch != "arm":
        return False
    if function_address & 1:
        return True
    if info.fmt == "elf":
        return bool(binfmt.elf_function_is_thumb(binary_path, function_name, function_address))
    return _pe_machine(binary_path) in {0x1C2, 0x1C4}


def _build_binary_code_index(binary_path: Path) -> BinaryCodeIndex:
    """Build the auditor-private context for one resolved binary path."""

    return BinaryCodeIndex.from_binary(binary_path)


def decode_instruction_starts(
    info: binfmt.BinInfo,
    ranges: Sequence[tuple[int, int]],
    regions: Sequence[tuple[int, bytes]],
    *,
    thumb: bool,
    mclass: bool = False,
) -> frozenset[int]:
    """Decode every exact function extent and return real instruction starts."""

    from capstone import Cs

    arch_mode = binfmt.capstone_arch_mode(info, thumb=thumb, mclass=mclass)
    if arch_mode is None:
        raise ValueError(f"unsupported architecture {info.arch}")
    decoder = Cs(*arch_mode)
    decoder.skipdata = True
    starts: set[int] = set()
    for raw_start, raw_end in ranges:
        size = raw_end - raw_start
        start = raw_start & ~1 if info.arch == "arm" else raw_start
        end = start + size
        region = next(
            (
                (region_address, data)
                for region_address, data in regions
                if region_address <= start and end <= region_address + len(data)
            ),
            None,
        )
        if region is None:
            raise ValueError(f"function range 0x{start:x}-0x{end:x} is not executable")
        region_address, data = region
        offset = start - region_address
        code = data[offset : offset + size]
        starts.update(
            instruction.address
            for instruction in decoder.disasm(code, start)
            if instruction.id != 0
        )
    return frozenset(starts)


def resolve_function_code(
    binary_path: Path,
    function_name: str,
    function_address: int,
) -> FunctionCode:
    """Resolve and decode the exact linked function independently of a backend."""

    info = binfmt.detect(binary_path)
    if info is None:
        raise ValueError("unrecognized binary format")
    if info.fmt not in SUPPORTED_FORMATS or info.arch not in SUPPORTED_ARCHITECTURES:
        raise ValueError(f"unsupported binary format/architecture {info.fmt}/{info.arch}")
    ranges = _function_ranges(binary_path, function_name, function_address, info.arch)
    thumb = _uses_thumb(binary_path, info, function_name, function_address)
    mclass = thumb and info.fmt == "elf" and binfmt.elf_is_arm_mclass(binary_path)
    starts = decode_instruction_starts(
        info,
        ranges,
        binfmt.executable_regions(binary_path),
        thumb=thumb,
        mclass=mclass,
    )
    expected = function_address & ~1 if info.arch == "arm" else function_address
    if expected not in starts:
        raise ValueError(f"function entry 0x{expected:x} is not a decoded instruction start")
    return FunctionCode(
        binary_path=binary_path,
        binary_format=info.fmt,
        architecture=("thumb" if thumb else info.arch),
        thumb=thumb,
        ranges=tuple(ranges),
        instruction_starts=starts,
        mclass=mclass,
    )


def _field_sequence(owner: Any, name: str) -> Sequence[Any] | None:
    value = getattr(owner, name, None)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return None


def _field_has_evidence(owner: Any, name: str) -> bool:
    raw = getattr(owner, name, None)
    values = _field_sequence(owner, name)
    return (raw is not None and values is None) or bool(values)


def _strict_ints(values: Sequence[Any] | None) -> tuple[list[int], bool]:
    if values is None:
        return [], False
    output: list[int] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return [], False
        output.append(value)
    return output, True


def _function_context(key: FunctionKey, backend: str) -> dict[str, str]:
    return {
        "project": key[0],
        "optimization": key[1],
        "binary": key[2],
        "backend": backend,
        "function": key[3],
    }


def _add_function_finding(
    state: AuditState,
    key: FunctionKey,
    backend: str,
    code: str,
    message: str,
) -> None:
    state.add(Finding(code=code, message=message, **_function_context(key, backend)))


def _validate_address_list(
    state: AuditState,
    key: FunctionKey,
    backend: str,
    field_name: str,
    values: Sequence[Any] | None,
    instructions: frozenset[int],
) -> set[int]:
    addresses, valid = _strict_ints(values)
    if not valid:
        _add_function_finding(
            state,
            key,
            backend,
            "malformed_address_list",
            f"{field_name} must be a list of non-negative integer addresses",
        )
        return set()
    if len(addresses) != len(set(addresses)):
        _add_function_finding(
            state,
            key,
            backend,
            "duplicate_address",
            f"{field_name} contains duplicate addresses",
        )
    invalid = sorted(set(addresses) - instructions)
    if invalid:
        sample = ", ".join(f"0x{address:x}" for address in invalid[:5])
        _add_function_finding(
            state,
            key,
            backend,
            "noninstruction_address",
            f"{field_name} contains {len(invalid)} address(es) outside exact decoded "
            f"instruction starts: {sample}",
        )
    return set(addresses)


def audit_function(
    state: AuditState,
    key: FunctionKey,
    backend: str,
    function: Any,
    code: FunctionCode,
) -> None:
    """Validate one function's line and variable evidence against machine code."""

    stats = state.backend_stats[backend]
    source = getattr(function, "decompiled_code", None)
    if not isinstance(source, str):
        _add_function_finding(
            state, key, backend, "malformed_decompiled_code", "decompiled_code is not a string"
        )
        return
    line_count = source.count("\n") + 1 if source else 0
    mappings = _field_sequence(function, "line_mappings")
    variables = _field_sequence(function, "variables")
    if mappings is None or variables is None:
        _add_function_finding(
            state,
            key,
            backend,
            "malformed_provenance_fields",
            "line_mappings and variables must be lists",
        )
        return

    stats.formats[code.binary_format] += 1
    stats.architectures[code.architecture] += 1
    line_addresses: defaultdict[int, set[int]] = defaultdict(set)
    seen_mapping_lines: set[int] = set()
    for index, mapping in enumerate(mappings):
        line = getattr(mapping, "line_number", None)
        if isinstance(line, bool) or not isinstance(line, int) or not 1 <= line <= line_count:
            _add_function_finding(
                state,
                key,
                backend,
                "line_number_out_of_bounds",
                f"line_mappings[{index}].line_number={line!r} is outside 1..{line_count}",
            )
            continue
        if line in seen_mapping_lines:
            _add_function_finding(
                state,
                key,
                backend,
                "duplicate_line_mapping",
                f"decompiler line {line} has multiple LineMapping rows",
            )
        seen_mapping_lines.add(line)
        raw_addresses = _field_sequence(mapping, "addresses")
        addresses = _validate_address_list(
            state,
            key,
            backend,
            f"line_mappings[{index}].addresses",
            raw_addresses,
            code.instruction_starts,
        )
        if not addresses:
            _add_function_finding(
                state,
                key,
                backend,
                "empty_line_mapping",
                f"line_mappings[{index}] carries no valid addresses",
            )
        line_addresses[line].update(addresses)

    has_variable_lines = False
    has_variable_addresses = False
    for index, variable in enumerate(variables):
        raw_lines = _field_sequence(variable, "line_numbers")
        raw_addresses = _field_sequence(variable, "addresses")
        lines, lines_valid = _strict_ints(raw_lines)
        if not lines_valid:
            _add_function_finding(
                state,
                key,
                backend,
                "malformed_line_number_list",
                f"variables[{index}].line_numbers must be non-negative integers",
            )
            lines = []
        if len(lines) != len(set(lines)):
            _add_function_finding(
                state,
                key,
                backend,
                "duplicate_variable_line",
                f"variables[{index}].line_numbers contains duplicates",
            )
        bad_lines = sorted({line for line in lines if not 1 <= line <= line_count})
        if bad_lines:
            _add_function_finding(
                state,
                key,
                backend,
                "line_number_out_of_bounds",
                f"variables[{index}].line_numbers contains rows outside 1..{line_count}: "
                + ", ".join(str(line) for line in bad_lines[:5]),
            )
        usable_lines = {line for line in lines if 1 <= line <= line_count}
        addresses = _validate_address_list(
            state,
            key,
            backend,
            f"variables[{index}].addresses",
            raw_addresses,
            code.instruction_starts,
        )
        if usable_lines:
            has_variable_lines = True
            stats.variables_with_lines += 1
            if not mappings:
                _add_function_finding(
                    state,
                    key,
                    backend,
                    "variable_lines_without_map",
                    f"variables[{index}] carries line numbers but the function has no line map",
                )
            disagreeing_lines = sorted(
                line
                for line in usable_lines
                if line_addresses.get(line) and addresses and not (addresses & line_addresses[line])
            )
            if disagreeing_lines:
                _add_function_finding(
                    state,
                    key,
                    backend,
                    "variable_line_address_disagreement",
                    f"variables[{index}] has no direct address on mapped row(s): "
                    + ", ".join(str(line) for line in disagreeing_lines[:5]),
                )
        if addresses:
            has_variable_addresses = True
            stats.variables_with_addresses += 1

    stats.line_mapping_rows += len(mappings)
    stats.mapped_addresses += len(
        {address for addresses in line_addresses.values() for address in addresses}
    )
    stats.variables += len(variables)
    if mappings:
        stats.functions_with_line_maps += 1
    if has_variable_lines:
        stats.functions_with_variable_lines += 1
    if has_variable_addresses:
        stats.functions_with_variable_addresses += 1
    if has_variable_addresses and not mappings and not has_variable_lines:
        stats.functions_with_direct_only_addresses += 1


def _function_has_provenance(function: Any) -> bool:
    raw_mappings = getattr(function, "line_mappings", None)
    raw_variables = getattr(function, "variables", None)
    mappings = _field_sequence(function, "line_mappings")
    variables = _field_sequence(function, "variables")
    if (raw_mappings is not None and mappings is None) or (
        raw_variables is not None and variables is None
    ):
        return True
    if mappings:
        return True
    if variables is None:
        return getattr(function, "variables", None) is not None
    return any(
        _field_has_evidence(variable, "line_numbers") or _field_has_evidence(variable, "addresses")
        for variable in variables
    )


def _normalization_name(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw).strip()


def _checkpoint_paths(results_root: Path, requested: Sequence[Path] | None) -> list[Path]:
    paths = (
        [path.resolve() for path in requested]
        if requested
        else sorted((results_root / "checkpoints").glob("*.pkl"))
    )
    if not paths:
        raise ValueError(f"no checkpoint pickles found under {results_root / 'checkpoints'}")
    if len(paths) != len(set(paths)):
        raise ValueError("checkpoint path list contains duplicates")
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise ValueError(f"checkpoint does not exist: {missing[0]}")
    stems = [path.stem for path in paths]
    if len(stems) != len(set(stems)):
        raise ValueError("checkpoint path list contains duplicate project stems")
    return sorted(paths)


def _resolve_tree_binary(
    results_root: Path,
    optimization: str,
    project: str,
    binary_name: str,
) -> Path:
    """Resolve one unambiguous regular ELF/PE inside the audited result tree."""

    components = {
        "optimization": optimization,
        "project": project,
        "binary": binary_name,
    }
    for label, value in components.items():
        if not value or value in {".", ".."} or Path(value).name != value or "\\" in value:
            raise ValueError(f"invalid checkpoint {label} component {value!r}")

    current = results_root
    for component in (optimization, project, "compiled"):
        current /= component
        if current.is_symlink():
            raise ValueError(f"compiled path contains a symlink: {current}")
    directory = Path(compiled_dir(results_root, optimization, project))
    if not directory.is_dir():
        raise ValueError(f"compiled directory does not exist: {directory}")
    try:
        directory.resolve().relative_to(results_root)
    except ValueError as exc:
        raise ValueError(
            f"compiled directory escapes the audited result tree: {directory}"
        ) from exc

    candidates: list[Path] = sorted(
        path.resolve()
        for path in directory.iterdir()
        if path.is_file()
        and not path.is_symlink()
        and (path.name == binary_name or path.stem == binary_name)
        and binfmt.detect(path) is not None
    )
    if len(candidates) == 1:
        return candidates[0]
    identity = f"{project}/{optimization}/{binary_name}"
    if not candidates:
        raise ValueError(f"no compiled ELF/PE matches {identity} in {directory}")
    choices = ", ".join(path.name for path in candidates)
    raise ValueError(f"ambiguous compiled binary for {identity}: {choices}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_checkpoint(path: Path) -> tuple[Mapping[Any, Any], str]:
    import decbench.decompilers  # noqa: F401

    try:
        with path.open("rb") as stream:
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                digest.update(chunk)
            stream.seek(0)
            payload = pickle.load(stream)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"could not load checkpoint {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"checkpoint {path} is not a mapping")
    decompile = payload.get("decompile")
    if not isinstance(decompile, Mapping):
        raise ValueError(f"checkpoint {path} has no decompile mapping")
    return decompile, digest.hexdigest()


def audit_results_tree(
    results_root: Path,
    *,
    checkpoint_paths: Sequence[Path] | None = None,
    manifest_path: Path | None = None,
    requested_backends: Sequence[str] = (),
    max_findings: int = 200,
) -> dict[str, Any]:
    """Audit checkpointed native provenance without mutating the result tree."""

    if max_findings < 1:
        raise ValueError("max_findings must be positive")
    results_root = results_root.resolve()
    paths = _checkpoint_paths(results_root, checkpoint_paths)
    manifest = load_manifest(manifest_path) if manifest_path is not None else None
    backends = tuple(str(backend).strip() for backend in requested_backends)
    if any(not backend for backend in backends) or len(backends) != len(set(backends)):
        raise ValueError("requested backend list contains empty or duplicate entries")
    backend_filter = frozenset(backends)
    state = AuditState(max_findings=max_findings)
    observed_backends: set[str] = set()
    observed_slices: set[SliceKey] = set()
    observed_manifest_keys: set[FunctionKey] = set()
    checkpoint_rows: list[dict[str, str]] = []
    binary_rows: dict[SliceKey, dict[str, str]] = {}

    for checkpoint in paths:
        project = checkpoint.stem
        decompile, checkpoint_sha256 = _load_checkpoint(checkpoint)
        checkpoint_rows.append(
            {"project": project, "path": str(checkpoint), "sha256": checkpoint_sha256}
        )
        for raw_optimization, raw_binaries in sorted(
            decompile.items(), key=lambda item: _normalization_name(item[0])
        ):
            optimization = _normalization_name(raw_optimization)
            if not optimization or not isinstance(raw_binaries, Mapping):
                state.add(
                    Finding(
                        code="malformed_checkpoint_slice",
                        message="optimization entry is empty or not a binary mapping",
                        project=project,
                        optimization=optimization or None,
                    )
                )
                continue
            for raw_binary, raw_decompilers in sorted(
                raw_binaries.items(), key=lambda item: str(item[0])
            ):
                binary = str(raw_binary).strip()
                if not binary or not isinstance(raw_decompilers, Mapping):
                    state.add(
                        Finding(
                            code="malformed_checkpoint_slice",
                            message="binary entry is empty or not a decompiler mapping",
                            project=project,
                            optimization=optimization,
                            binary=binary or None,
                        )
                    )
                    continue
                slice_key = (project, optimization, binary)
                if slice_key in observed_slices:
                    state.add(
                        Finding(
                            code="duplicate_checkpoint_slice",
                            message=(
                                "checkpoint contains duplicate normalized "
                                "project/opt/binary slices"
                            ),
                            project=project,
                            optimization=optimization,
                            binary=binary,
                        )
                    )
                    continue
                observed_slices.add(slice_key)
                binary_path: Path | ValueError | None = None
                binary_index: BinaryCodeIndex | ValueError | None = None
                code_cache: dict[tuple[str, int], FunctionCode | ValueError] = {}
                for raw_backend, result in sorted(
                    raw_decompilers.items(), key=lambda item: str(item[0])
                ):
                    backend = str(raw_backend).strip()
                    if backend_filter and backend not in backend_filter:
                        continue
                    observed_backends.add(backend)
                    stats = state.backend_stats[backend]
                    functions = getattr(result, "functions", None)
                    if not backend or not isinstance(functions, Mapping):
                        state.add(
                            Finding(
                                code="malformed_decompilation_result",
                                message=(
                                    "decompiler id is empty or result.functions is not a mapping"
                                ),
                                project=project,
                                optimization=optimization,
                                binary=binary,
                                backend=backend or None,
                            )
                        )
                        continue
                    metadata = getattr(result, "decompiler", None)
                    metadata_backend = getattr(metadata, "decompiler_name", None)
                    if not isinstance(metadata_backend, str) or metadata_backend != backend:
                        state.add(
                            Finding(
                                code="backend_identity_mismatch",
                                message=(
                                    f"outer backend {backend!r} disagrees with metadata "
                                    f"decompiler_name={metadata_backend!r}"
                                ),
                                project=project,
                                optimization=optimization,
                                binary=binary,
                                backend=backend,
                            )
                        )
                    metadata_binary = getattr(result, "binary_name", None)
                    if not isinstance(metadata_binary, str) or metadata_binary != binary:
                        state.add(
                            Finding(
                                code="binary_identity_mismatch",
                                message=(
                                    f"outer binary {binary!r} disagrees with metadata "
                                    f"binary_name={metadata_binary!r}"
                                ),
                                project=project,
                                optimization=optimization,
                                binary=binary,
                                backend=backend,
                            )
                        )
                    for raw_function_name, function in sorted(
                        functions.items(), key=lambda item: str(item[0])
                    ):
                        mapping_name = str(raw_function_name).strip()
                        function_name = getattr(function, "name", None)
                        if not isinstance(function_name, str) or not function_name.strip():
                            key = (project, optimization, binary, mapping_name or "<invalid>")
                            _add_function_finding(
                                state,
                                key,
                                backend,
                                "malformed_function",
                                "function.name is empty or not a string",
                            )
                            continue
                        function_name = function_name.strip()
                        key = (project, optimization, binary, function_name)
                        if key in stats.observed_keys:
                            _add_function_finding(
                                state,
                                key,
                                backend,
                                "duplicate_checkpoint_function",
                                "backend contains the same normalized function key more than once",
                            )
                            continue
                        stats.functions_seen += 1
                        stats.observed_keys.add(key)
                        if mapping_name != function_name:
                            _add_function_finding(
                                state,
                                key,
                                backend,
                                "function_key_name_mismatch",
                                f"result key {mapping_name!r} differs from function.name",
                            )
                        if manifest is not None:
                            if key not in manifest.keys:
                                _add_function_finding(
                                    state,
                                    key,
                                    backend,
                                    "out_of_manifest_scope",
                                    "checkpoint function is outside the exact sample manifest",
                                )
                            else:
                                observed_manifest_keys.add(key)
                        if not _function_has_provenance(function):
                            stats.functions_without_provenance += 1
                            continue
                        stats.functions_with_provenance += 1
                        address = getattr(function, "address", None)
                        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
                            _add_function_finding(
                                state,
                                key,
                                backend,
                                "malformed_function_address",
                                f"function.address={address!r} is not a non-negative integer",
                            )
                            continue
                        if binary_path is None:
                            try:
                                binary_path = _resolve_tree_binary(
                                    results_root,
                                    optimization,
                                    project,
                                    binary,
                                )
                            except ValueError as exc:
                                binary_path = exc
                        if isinstance(binary_path, ValueError):
                            _add_function_finding(
                                state,
                                key,
                                backend,
                                "binary_resolution_failed",
                                str(binary_path),
                            )
                            continue
                        if slice_key not in binary_rows:
                            try:
                                binary_sha256 = _sha256_file(binary_path)
                            except OSError as exc:
                                binary_path = ValueError(
                                    f"could not hash compiled binary {binary_path}: {exc}"
                                )
                                _add_function_finding(
                                    state,
                                    key,
                                    backend,
                                    "binary_resolution_failed",
                                    str(binary_path),
                                )
                                continue
                            binary_rows[slice_key] = {
                                "project": project,
                                "optimization": optimization,
                                "binary": binary,
                                "path": str(binary_path),
                                "sha256": binary_sha256,
                            }
                        if binary_index is None:
                            try:
                                binary_index = _build_binary_code_index(binary_path)
                            except Exception as exc:  # noqa: BLE001
                                binary_index = ValueError(f"{type(exc).__name__}: {exc}")
                        if isinstance(binary_index, ValueError):
                            _add_function_finding(
                                state,
                                key,
                                backend,
                                "function_code_resolution_failed",
                                str(binary_index),
                            )
                            continue
                        cache_key = (function_name, address)
                        if cache_key not in code_cache:
                            try:
                                code_cache[cache_key] = binary_index.resolve(function_name, address)
                            except Exception as exc:  # noqa: BLE001
                                code_cache[cache_key] = ValueError(f"{type(exc).__name__}: {exc}")
                        code = code_cache[cache_key]
                        if isinstance(code, ValueError):
                            _add_function_finding(
                                state,
                                key,
                                backend,
                                "function_code_resolution_failed",
                                str(code),
                            )
                            continue
                        before = state.backend_stats[backend].errors
                        audit_function(state, key, backend, function, code)
                        if state.backend_stats[backend].errors == before:
                            stats.functions_validated += 1

    for backend in sorted(backend_filter - observed_backends):
        state.add(
            Finding(
                code="requested_backend_missing",
                message=f"requested backend {backend!r} was absent from all checkpoints",
                backend=backend,
            )
        )
    if not observed_backends:
        state.add(
            Finding(
                code="empty_backend_scope",
                message="no checkpoint backends were selected for audit",
            )
        )
    if manifest is not None:
        for project, optimization, binary in sorted(manifest.slices - observed_slices):
            state.add(
                Finding(
                    code="manifest_slice_missing",
                    message="sample manifest slice is absent from the selected checkpoints",
                    project=project,
                    optimization=optimization,
                    binary=binary,
                )
            )

    backend_rows = {
        backend: state.backend_stats[backend].to_dict(manifest)
        for backend in sorted(observed_backends | backend_filter)
    }
    totals = {
        name: sum(int(row[name]) for row in backend_rows.values())
        for name in (
            "functions_seen",
            "functions_with_provenance",
            "functions_validated",
            "functions_without_provenance",
            "functions_with_line_maps",
            "functions_with_variable_lines",
            "functions_with_variable_addresses",
            "functions_with_direct_only_addresses",
            "line_mapping_rows",
            "mapped_addresses",
            "variables",
            "variables_with_lines",
            "variables_with_addresses",
        )
    }
    scope: dict[str, Any] = {
        "checkpoint_projects": len(paths),
        "checkpoint_slices": len(observed_slices),
        "backends": sorted(observed_backends),
    }
    if manifest is not None:
        scope.update(
            {
                "manifest_functions": len(manifest.keys),
                "manifest_slices": len(manifest.slices),
                "manifest_functions_present_in_any_backend": len(observed_manifest_keys),
                "manifest_functions_missing_from_every_backend": len(
                    manifest.keys - observed_manifest_keys
                ),
            }
        )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "valid": state.error_count == 0,
        "inputs": {
            "results_root": str(results_root),
            "checkpoints": checkpoint_rows,
            "compiled_binaries": [binary_rows[key] for key in sorted(binary_rows)],
            "manifest": (
                {
                    "path": str(manifest.path),
                    "sha256": manifest.sha256,
                }
                if manifest is not None
                else None
            ),
            "requested_backends": list(backends),
        },
        "policy": {
            "manifest_scope": (
                "exact_allowlist" if manifest is not None else "all_checkpoint_functions"
            ),
            "function_identity": "exact DWARF name and linked entry address",
            "binary_identity": "unambiguous regular file inside the audited results tree",
            "address_validity": "decoded instruction starts inside exact DWARF function ranges",
            "arm_profile": "ELF ARM attributes select M-class decoding; PE is never inferred",
            "line_numbering": "1-based rows in FunctionDecompilation.decompiled_code",
            "direct_only_variables": "accepted without a line map after address validation",
            "supported_formats": sorted(SUPPORTED_FORMATS),
            "supported_architectures": ["x86", "x86-64", "arm", "thumb", "aarch64"],
        },
        "scope": scope,
        "totals": totals,
        "backends": backend_rows,
        "validation": {
            "error_count": state.error_count,
            "error_counts": dict(sorted(state.finding_counts.items())),
            "findings_emitted": len(state.findings),
            "findings_truncated": max(0, state.error_count - len(state.findings)),
        },
        "findings": [finding.to_dict() for finding in state.findings],
    }
    return report


def json_payload(report: Mapping[str, Any]) -> str:
    """Render a deterministic audit report."""

    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def summary_line(report: Mapping[str, Any]) -> str:
    """Render a compact human review line."""

    totals = report["totals"]
    validation = report["validation"]
    return (
        f"native provenance audit: valid={'yes' if report['valid'] else 'no'}, "
        f"backends={len(report['backends'])}, functions={totals['functions_seen']}, "
        f"provenance={totals['functions_with_provenance']}, "
        f"direct-only={totals['functions_with_direct_only_addresses']}, "
        f"errors={validation['error_count']}"
    )
