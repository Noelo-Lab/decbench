"""Exact function ranges and instruction starts for producer-side provenance."""

from __future__ import annotations

import struct
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from decbench.utils import binfmt

SUPPORTED_FORMATS = frozenset({"elf", "pe"})
SUPPORTED_ARCHITECTURES = frozenset({"x86", "x86-64", "arm", "aarch64"})


@dataclass(frozen=True)
class FunctionCode:
    """Machine-code facts for one exact DWARF function."""

    binary_path: Path
    binary_format: str
    architecture: str
    thumb: bool
    ranges: tuple[tuple[int, int], ...]
    instruction_starts: frozenset[int]
    mclass: bool = False


def die_ranges(die: Any, dwarfinfo: Any) -> tuple[tuple[int, int], ...]:
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


def _normalize_ranges(
    ranges: Sequence[tuple[int, int]], architecture: str
) -> tuple[tuple[int, int], ...]:
    if architecture != "arm":
        return tuple(ranges)
    return tuple(((begin & ~1), (begin & ~1) + (end - begin)) for begin, end in ranges)


def _die_entry(die: Any, ranges: Sequence[tuple[int, int]], architecture: str) -> int | None:
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


def function_ranges(
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
                raw_ranges = die_ranges(die, dwarfinfo)
            except Exception:
                continue
            normalized = _normalize_ranges(raw_ranges, architecture)
            entry = _die_entry(die, raw_ranges, architecture)
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


class NativeCodeResolver:
    """Resolve many functions against one parsed binary and DWARF index."""

    def __init__(self, binary_path: Path):
        self.binary_path = binary_path.resolve()
        info = binfmt.detect(self.binary_path)
        if info is None:
            raise ValueError("unrecognized binary format")
        if info.fmt not in SUPPORTED_FORMATS or info.arch not in SUPPORTED_ARCHITECTURES:
            raise ValueError(f"unsupported binary format/architecture {info.fmt}/{info.arch}")
        dwarfinfo = binfmt.dwarf_info(self.binary_path)
        if dwarfinfo is None:
            raise ValueError("binary has no readable DWARF")
        self.info = info
        self.regions = binfmt.executable_regions(self.binary_path)
        self.mclass = (
            info.fmt == "elf" and info.arch == "arm" and binfmt.elf_is_arm_mclass(self.binary_path)
        )
        self._thumb_by_address: defaultdict[int, set[bool]] = defaultdict(set)
        self._thumb_by_name: defaultdict[str, list[bool]] = defaultdict(list)
        if info.fmt == "elf" and info.arch == "arm":
            self._index_thumb_symbols()
        self._pe_machine = _pe_machine(self.binary_path) if info.fmt == "pe" else None
        self._ranges: defaultdict[tuple[str, int], set[tuple[tuple[int, int], ...]]] = defaultdict(
            set
        )
        self._resolved: dict[tuple[str, int], FunctionCode | str] = {}
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name = binfmt.die_str_attr(die, "DW_AT_name")
                if not name:
                    continue
                try:
                    raw_ranges = die_ranges(die, dwarfinfo)
                except Exception:
                    continue
                ranges = _normalize_ranges(raw_ranges, info.arch)
                entry = _die_entry(die, raw_ranges, info.arch)
                if (
                    ranges
                    and entry is not None
                    and any(begin <= entry < end for begin, end in ranges)
                ):
                    self._ranges[(name, entry)].add(ranges)

    def _index_thumb_symbols(self) -> None:
        from elftools.elf.elffile import ELFFile

        try:
            with self.binary_path.open("rb") as stream:
                symtab = ELFFile(stream).get_section_by_name(".symtab")
                if symtab is None:
                    return
                for symbol in symtab.iter_symbols():
                    if symbol["st_info"]["type"] != "STT_FUNC" or symbol["st_size"] <= 0:
                        continue
                    raw_address = int(symbol["st_value"])
                    state = bool(raw_address & 1)
                    self._thumb_by_address[raw_address & ~1].add(state)
                    self._thumb_by_name[symbol.name].append(state)
        except Exception:
            self._thumb_by_address.clear()
            self._thumb_by_name.clear()

    def _uses_thumb(self, function_name: str, function_address: int) -> bool:
        if self.info.arch != "arm":
            return False
        if function_address & 1:
            return True
        if self.info.fmt == "pe":
            if self._pe_machine in {0x1C2, 0x1C4}:
                return True
            if self._pe_machine == 0x1C0:
                return False
            raise ValueError("ARM instruction state is unavailable for the PE machine")
        exact = self._thumb_by_address.get(function_address & ~1, set())
        if exact:
            if len(exact) != 1:
                raise ValueError("ARM instruction state has conflicting exact ELF symbols")
            state = next(iter(exact))
            if self.mclass and not state:
                raise ValueError("ARM instruction state contradicts the ELF M-profile")
            return state
        named = self._thumb_by_name.get(function_name, [])
        if len(named) == 1:
            state = named[0]
            if self.mclass and not state:
                raise ValueError("ARM instruction state contradicts the ELF M-profile")
            return state
        if not named and self.mclass:
            return True
        raise ValueError(
            "ARM instruction state is unavailable without an exact or unique named ELF symbol"
        )

    def resolve(self, function_name: str, function_address: int) -> FunctionCode:
        """Resolve one exact function through the cached binary index."""

        cache_key = (function_name, function_address)
        cached = self._resolved.get(cache_key)
        if isinstance(cached, str):
            raise ValueError(cached)
        if cached is not None:
            return cached
        try:
            code = self._resolve_uncached(function_name, function_address)
        except Exception as exc:  # noqa: BLE001
            message = str(exc)
            self._resolved[cache_key] = message
            raise ValueError(message) from exc
        self._resolved[cache_key] = code
        return code

    def _resolve_uncached(self, function_name: str, function_address: int) -> FunctionCode:
        expected = function_address & ~1 if self.info.arch == "arm" else function_address
        candidates = self._ranges.get((function_name, expected), set())
        if not candidates:
            raise ValueError(
                f"no DWARF function matches {function_name!r} at 0x{function_address:x}"
            )
        if len(candidates) != 1:
            raise ValueError(
                f"ambiguous DWARF function {function_name!r} at 0x{function_address:x}"
            )
        ranges = next(iter(candidates))
        thumb = self._uses_thumb(function_name, function_address)
        mclass = thumb and self.mclass
        starts = decode_instruction_starts(
            self.info,
            ranges,
            self.regions,
            thumb=thumb,
            mclass=mclass,
        )
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


def resolve_function_code(
    binary_path: Path,
    function_name: str,
    function_address: int,
) -> FunctionCode:
    """Resolve and decode the exact linked function outside a backend adapter."""

    return NativeCodeResolver(binary_path).resolve(function_name, function_address)
