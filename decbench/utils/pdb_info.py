"""Bounded native PDB 7 transport for PE evaluation, independent of LLVM tools.

Only documented MSF/DBI/TPI/CodeView records are interpreted. Unsupported
types, storage pieces, ICF conflicts and unproven parameter classification
remain explicit exclusions. This is not a full PDB debugger or C++ type policy.
"""

from __future__ import annotations

import struct
import uuid
from bisect import bisect_left
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
_MAX_SIZE = 512 * 1024 * 1024
_PROC = {0x110F, 0x1110, 0x1146, 0x1147}
_REGISTERS = {
    **dict(
        enumerate(
            (
                "al",
                "cl",
                "dl",
                "bl",
                "ah",
                "ch",
                "dh",
                "bh",
                "ax",
                "cx",
                "dx",
                "bx",
                "sp",
                "bp",
                "si",
                "di",
                "eax",
                "ecx",
                "edx",
                "ebx",
                "esp",
                "ebp",
                "esi",
                "edi",
            ),
            1,
        )
    ),
    **dict(enumerate(("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"), 328)),
    **{336 + n: f"r{8+n}" for n in range(8)},
    **{344 + n: f"r{8+n}b" for n in range(8)},
    **{352 + n: f"r{8+n}w" for n in range(8)},
    **{360 + n: f"r{8+n}d" for n in range(8)},
    **{154 + n: f"xmm{n}" for n in range(8)},
}
_SIMPLE = {
    0x03: ("void", "void", 0),
    0x08: ("HRESULT", "int", 4),
    0x10: ("signed char", "signed char", 1),
    0x20: ("unsigned char", "unsigned char", 1),
    0x70: ("char", "char", 1),
    0x71: ("wchar_t", "unsigned short", 2),
    0x68: ("signed char", "signed char", 1),
    0x69: ("unsigned char", "unsigned char", 1),
    0x11: ("short", "short", 2),
    0x21: ("unsigned short", "unsigned short", 2),
    0x72: ("short", "short", 2),
    0x73: ("unsigned short", "unsigned short", 2),
    # Preserve LLP64 source spelling independently of the existing LP64 matcher.
    0x12: ("long", "int", 4),
    0x22: ("unsigned long", "unsigned int", 4),
    0x74: ("int", "int", 4),
    0x75: ("unsigned int", "unsigned int", 4),
    0x13: ("long long", "long long", 8),
    0x23: ("unsigned long long", "unsigned long long", 8),
    0x76: ("long long", "long long", 8),
    0x77: ("unsigned long long", "unsigned long long", 8),
    0x30: ("bool", "bool", 1),
    0x40: ("float", "float", 4),
    0x41: ("double", "double", 8),
}


def _unpack(fmt: str, data: bytes, offset: int = 0):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise ValueError("truncated PDB record")
    return struct.unpack_from(fmt, data, offset)


def _string(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\0", offset)
    if not 0 <= offset <= end:
        raise ValueError("unterminated PDB string")
    return data[offset:end].decode("utf-8", "replace"), end + 1


def _numeric(data: bytes, offset: int) -> tuple[int, int]:
    tag = _unpack("<H", data, offset)[0]
    if tag < 0x8000:
        return tag, offset + 2
    fmt = {
        0x8000: "<b",
        0x8001: "<h",
        0x8002: "<H",
        0x8003: "<i",
        0x8004: "<I",
        0x8009: "<q",
        0x800A: "<Q",
    }.get(tag)
    if fmt is None:
        raise ValueError(f"unsupported CodeView numeric leaf 0x{tag:x}")
    return _unpack(fmt, data, offset + 2)[0], offset + 2 + struct.calcsize(fmt)


def _records(data: bytes, start: int, end: int):
    if not 0 <= start <= end <= len(data):
        raise ValueError("PDB record stream exceeds its extent")
    offset = start
    while offset < end:
        length, kind = _unpack("<HH", data, offset)
        following = offset + 2 + length
        if length < 2 or following > end:
            raise ValueError("invalid CodeView record length")
        yield offset, kind, data[offset + 4 : following]
        offset = following


class _MSF:
    def __init__(self, path: Path):
        if path.stat().st_size > _MAX_SIZE:
            raise ValueError("PDB exceeds the supported 512 MiB reader bound")
        self.data = path.read_bytes()
        if self.data[:32] != _MAGIC:
            raise ValueError("not an MSF 7 PDB")
        self.block_size, _free, count, directory_size, _unknown, directory_map = _unpack(
            "<6I", self.data, 32
        )
        if (
            self.block_size not in {512, 1024, 2048, 4096}
            or len(self.data) != count * self.block_size
        ):
            raise ValueError("invalid MSF block geometry")
        n = (directory_size + self.block_size - 1) // self.block_size
        if n > self.block_size // 4 or directory_size > len(self.data):
            raise ValueError("unsupported MSF directory extent")
        blocks = _unpack(f"<{n}I", self.data, directory_map * self.block_size)
        directory = self._join(blocks, directory_size)
        nstreams = _unpack("<I", directory)[0]
        if 4 + 4 * nstreams > len(directory):
            raise ValueError("invalid MSF stream count")
        sizes = _unpack(f"<{nstreams}I", directory, 4)
        self.streams = []
        self.named_streams: dict[str, bytes] = {}
        offset = 4 + 4 * nstreams
        for size in sizes:
            if size == 0xFFFFFFFF:
                self.streams.append(None)
                continue
            if size > len(self.data):
                raise ValueError("invalid MSF stream size")
            nblocks = (size + self.block_size - 1) // self.block_size
            blocks = _unpack(f"<{nblocks}I", directory, offset)
            offset += nblocks * 4
            self.streams.append((blocks, size))

    def _join(self, blocks, size):
        if any(b * self.block_size + self.block_size > len(self.data) for b in blocks):
            raise ValueError("MSF block outside file")
        return b"".join(self.data[b * self.block_size : (b + 1) * self.block_size] for b in blocks)[
            :size
        ]

    def stream(self, index: int) -> bytes:
        if not 0 <= index < len(self.streams) or self.streams[index] is None:
            raise ValueError(f"missing PDB stream {index}")
        return self._join(*self.streams[index])


@dataclass(frozen=True)
class PdbType:
    source_name: str
    abi_name: str | None
    size: int | None


class _Types:
    def __init__(self, data: bytes):
        self.records: dict[int, tuple[int, bytes]] = {}
        self.cache: dict[int, PdbType | None] = {}
        if data:
            _version, header, first, last, size = _unpack("<5I", data)
            if header < 20 or first < 0x1000 or last < first:
                raise ValueError("invalid PDB type header")
            for index, (_, kind, payload) in enumerate(
                _records(data, header, header + size), first
            ):
                self.records[index] = kind, payload
            if len(self.records) != last - first:
                raise ValueError("PDB type index/record count mismatch")

    def resolve(self, index: int, depth: int = 0) -> PdbType | None:
        if depth > 32:
            return None
        if index in self.cache:
            return self.cache[index]
        if index < 0x1000:
            base = _SIMPLE.get(index & 0xFF)
            mode = (index >> 8) & 0xF
            if base is None:
                return None
            source, abi, size = base
            if mode:
                pointer_size = {4: 4, 6: 8}.get(mode)
                return PdbType(source + "*", abi + "*", pointer_size) if pointer_size else None
            return PdbType(source, abi, size)
        self.cache[index] = None  # cycles must never manufacture a type
        record = self.records.get(index)
        result = None
        if record:
            kind, p = record
            if kind == 0x1001:  # modifier
                base, flags = _unpack("<IH", p)
                t = self.resolve(base, depth + 1)
                if t and not flags & ~7:
                    qualifier = (
                        ("const " if flags & 1 else "")
                        + ("volatile " if flags & 2 else "")
                        + ("__unaligned " if flags & 4 else "")
                    )
                    result = PdbType(
                        qualifier + t.source_name,
                        qualifier + t.abi_name if t.abi_name else None,
                        t.size,
                    )
            elif kind == 0x1002:  # pointer / reference, never member pointers
                base, attrs = _unpack("<II", p)
                mode = (attrs >> 5) & 7
                t = self.resolve(base, depth + 1)
                size = (attrs >> 13) & 63 or {10: 4, 12: 8}.get(attrs & 31)
                if t and mode in {0, 1, 4} and size in {4, 8}:
                    suffix = {0: "*", 1: "&", 4: "&&"}[mode]
                    source_qualifiers = (" const" if attrs & 0x400 else "") + (
                        " volatile" if attrs & 0x200 else ""
                    )
                    result = PdbType(
                        t.source_name + suffix + source_qualifiers,
                        t.abi_name + "*" if t.abi_name else None,
                        size,
                    )
            elif kind in {0x1504, 0x1505, 0x1519, 0x1506}:  # named aggregate
                _count, flags = _unpack("<HH", p)
                size, name_offset = _numeric(p, 8 if kind == 0x1506 else 16)
                name, _ = _string(p, name_offset)
                result = PdbType(name, name, None if flags & 0x80 else size)
            elif kind == 0x1507:  # enum retains its source name, integer ABI
                base = _unpack("<I", p, 4)[0]
                name, _ = _string(p, 12)
                t = self.resolve(base, depth + 1)
                if t:
                    result = PdbType(name, t.abi_name, t.size)
            elif kind == 0x1503:
                base = _unpack("<I", p)[0]
                size, _ = _numeric(p, 8)
                t = self.resolve(base, depth + 1)
                if t and t.size and size >= 0 and size % t.size == 0:
                    suffix = f"[{size // t.size}]"
                    result = PdbType(
                        t.source_name + suffix, t.abi_name + suffix if t.abi_name else None, size
                    )
        self.cache[index] = result
        return result

    def parameter_count(self, index: int) -> int | None:
        record = self.records.get(index)
        if record is None:
            return None
        kind, p = record
        if kind == 0x1008:
            options = _unpack("<B", p, 5)[0]
            return _unpack("<H", p, 6)[0] + bool(options & 1)
        if kind == 0x1009:
            options = _unpack("<B", p, 13)[0]
            return _unpack("<H", p, 14)[0] + bool(_unpack("<I", p, 8)[0]) + bool(options & 1)
        return None


@dataclass(frozen=True)
class PdbStorage:
    register: int
    offset: int | None
    begin: int
    end: int


@dataclass
class PdbVariable:
    identity: str
    name: str
    type_index: int
    type: PdbType | None
    is_parameter: bool | None
    storage: list[PdbStorage] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    scope: tuple[int, ...] = ()


@dataclass
class PdbFunction:
    name: str
    address: int
    end: int
    module: str
    source_files: tuple[str, ...]
    debug_start: int
    debug_end: int
    variables: list[PdbVariable] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    source_file: str | None = None
    source_line: int = 0

    @property
    def measurable(self) -> bool:
        return not self.exclusions and all(not v.exclusions for v in self.variables)


@dataclass
class PdbInfo:
    path: Path
    guid: str
    age: int
    functions: tuple[PdbFunction, ...]
    _by_address: dict[int, PdbFunction | None] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self):
        for function in self.functions:
            if function.address in self._by_address:
                self._by_address[function.address] = None
            else:
                self._by_address[function.address] = function

    def at_address(self, address: int) -> PdbFunction | None:
        return self._by_address.get(address)


def _source_files(dbi: bytes, offset: int, size: int, nmodules: int) -> list[tuple[str, ...]]:
    p = dbi[offset : offset + size]
    count, _unused = _unpack("<HH", p)
    if count != nmodules:
        raise ValueError("PDB module/source count mismatch")
    counts = _unpack(f"<{count}H", p, 4 + count * 2)
    offsets = _unpack(f"<{sum(counts)}I", p, 4 + count * 4)
    names = 4 + count * 4 + sum(counts) * 4
    rows = []
    index = 0
    for n in counts:
        rows.append(tuple(_string(p, names + v)[0] for v in offsets[index : index + n]))
        index += n
    return rows


def _named_stream(msf: _MSF, name: str) -> bytes:
    if name in msf.named_streams:
        return msf.named_streams[name]
    info = msf.stream(1)
    length = _unpack("<I", info, 28)[0]
    strings = info[32 : 32 + length]
    offset = 32 + length
    count, capacity = _unpack("<II", info, offset)
    offset += 8
    present = []
    for vector in range(2):
        words = _unpack("<I", info, offset)[0]
        offset += 4
        if words * 32 > capacity + 31:
            raise ValueError("invalid PDB named-stream bit vector")
        values = _unpack(f"<{words}I", info, offset)
        offset += words * 4
        if vector == 0:
            present = [
                word * 32 + bit
                for word, value in enumerate(values)
                for bit in range(32)
                if value & (1 << bit)
            ]
    if len(present) != count or any(v >= capacity for v in present):
        raise ValueError("invalid PDB named-stream count")
    found = []
    for _ in present:
        key, index = _unpack("<II", info, offset)
        offset += 8
        if _string(strings, key)[0] == name:
            found.append(index)
    if len(found) != 1:
        raise ValueError("missing or ambiguous PDB string table")
    result = msf.stream(found[0])
    msf.named_streams[name] = result
    return result


def _module_lines(msf: _MSF, data: bytes, start: int, size: int, address):
    """C13 file/line provenance at native PCs, using the PDB /names stream."""
    if not size:
        return []
    if not 0 <= start <= start + size <= len(data):
        raise ValueError("PDB C13 extent outside module stream")
    subsections = []
    offset = start
    while offset < start + size:
        kind, length = _unpack("<II", data, offset)
        if offset + 8 + length > start + size:
            raise ValueError("PDB C13 subsection outside stream")
        subsections.append((kind, data[offset + 8 : offset + 8 + length]))
        offset = (offset + 8 + length + 3) & ~3
    checksums = {}
    for kind, p in subsections:
        if kind != 0xF4:
            continue
        pos = 0
        while pos < len(p):
            name, length, _kind = _unpack("<IBB", p, pos)
            if pos + 6 + length > len(p):
                raise ValueError("truncated PDB file checksum")
            checksums[pos] = name
            pos = (pos + 6 + length + 3) & ~3
    if not checksums:
        return []
    strings = _named_stream(msf, "/names")
    signature, version, length = _unpack("<III", strings)
    if signature != 0xEFFEEFFE or version not in {1, 2} or 12 + length > len(strings):
        raise ValueError("unsupported PDB string table")
    strings = strings[12 : 12 + length]
    rows = []
    for kind, p in subsections:
        if kind != 0xF2:
            continue
        base, segment, flags, size = _unpack("<IHHI", p)
        begin = address(segment, base, size)
        pos = 12
        while pos < len(p):
            file_id, count, block_size = _unpack("<III", p, pos)
            if block_size < 12 + count * (12 if flags & 1 else 8) or pos + block_size > len(p):
                raise ValueError("invalid PDB line block")
            if file_id not in checksums:
                raise ValueError("PDB line block has no file checksum")
            name = _string(strings, checksums[file_id])[0]
            for n in range(count):
                pc, line = _unpack("<II", p, pos + 12 + n * 8)
                if pc >= size:
                    raise ValueError("PDB source line PC outside code contribution")
                rows.append((begin + pc, name, line & 0xFFFFFF))
            pos += block_size
    return rows


def read_pdb(binary_path: Path, debug_path: Path | None = None) -> PdbInfo | None:
    """Read only a matching adjacent (or explicitly supplied) native PE PDB."""
    import lief

    binary = lief.PE.parse(str(binary_path))
    if binary is None:
        return None
    codeviews = [d for d in binary.debug if isinstance(d, lief.PE.CodeViewPDB)]
    if not codeviews:
        return None
    if len(codeviews) != 1:
        raise ValueError("ambiguous PE CodeView identity")
    cv = codeviews[0]
    path = (
        Path(debug_path)
        if debug_path is not None
        else binary_path.parent / PureWindowsPath(cv.filename).name
    )
    if not path.is_file():
        return None
    msf = _MSF(path)
    info = msf.stream(1)
    age = _unpack("<I", info, 8)[0]
    _unpack("<16s", info, 12)
    guid = str(uuid.UUID(bytes_le=info[12:28]))
    if guid.lower() != str(cv.guid).lower() or age != cv.age:
        raise ValueError("PE/PDB GUID or Age mismatch")
    dbi = msf.stream(3)
    machine = _unpack("<H", dbi, 58)[0]
    if _unpack("<I", dbi, 8)[0] != age or machine != int(binary.header.machine):
        raise ValueError("PE/PDB DBI Age or architecture mismatch")
    if machine not in {0x14C, 0x8664}:
        raise ValueError("native PDB storage supports x86/x86-64 only")
    sizes = _unpack("<5i", dbi, 24)
    optional, ec = _unpack("<2i", dbi, 48)
    if min(*sizes, optional, ec) < 0 or 64 + sum(sizes) + optional + ec > len(dbi):
        raise ValueError("invalid PDB DBI substream bounds")
    mod_size, contrib, secmap, files_size, _typeserver = sizes
    debug_header = 64 + sum(sizes) + ec
    indices = _unpack(f"<{optional // 2}H", dbi, debug_header)
    if len(indices) < 6 or indices[5] == 0xFFFF:
        raise ValueError("PDB has no section headers")
    if any(i != 0xFFFF and msf.stream(i) for i in indices[3:5]):
        raise ValueError("OMAP address translation is not supported")
    sections = msf.stream(indices[5])
    if len(sections) % 40 or len(sections) // 40 != len(binary.sections):
        raise ValueError("PE/PDB section count mismatch")
    for n, section in enumerate(binary.sections):
        name, vsize, rva, raw_size, raw_pointer = _unpack("<8s4I", sections, n * 40)
        if (name.rstrip(b"\0").decode(errors="replace"), vsize, rva, raw_size, raw_pointer) != (
            section.name,
            section.virtual_size,
            section.virtual_address,
            section.sizeof_raw_data,
            section.pointerto_raw_data,
        ):
            raise ValueError("PE/PDB section mapping mismatch")

    def address(segment: int, offset: int, size: int) -> int:
        if not 1 <= segment <= len(binary.sections):
            raise ValueError("CodeView section index outside image")
        section = binary.sections[segment - 1]
        if (
            offset < 0
            or size <= 0
            or offset + size > len(section.content)
            or not int(section.characteristics) & 0x20000000
        ):
            raise ValueError(
                f"CodeView range outside executable section {segment}: {offset}+{size}"
            )
        return int(binary.imagebase) + section.virtual_address + offset

    modules = []
    cursor = 64
    while cursor < 64 + mod_size:
        stream, sym_size, c11, c13 = _unpack("<HIII", dbi, cursor + 34)
        module, end = _string(dbi, cursor + 64)
        _obj, end = _string(dbi, end)
        cursor = (end + 3) & ~3
        if cursor > 64 + mod_size:
            raise ValueError("PDB module record outside module substream")
        modules.append((module, stream, sym_size, c11, c13))
    files = _source_files(dbi, 64 + mod_size + contrib + secmap, files_size, len(modules))
    types = _Types(msf.stream(2))
    ids = _Types(msf.stream(4)) if len(msf.streams) > 4 and msf.streams[4] else _Types(b"")
    functions = []
    for module_index, (module, stream, sym_size, _c11, _c13) in enumerate(modules):
        if stream == 0xFFFF or sym_size <= 4:
            continue
        data = msf.stream(stream)
        if _unpack("<I", data)[0] != 4:
            raise ValueError("unsupported CodeView symbol stream version")
        lines = sorted(_module_lines(msf, data, sym_size + _c11, _c13, address))
        line_pcs = [row[0] for row in lines]
        current = None
        end_offset = 0
        last_var = None
        frame_flags = 0
        inline_ends = []
        blocks = []
        block_extents = {}
        for position, kind, p in _records(data, 4, sym_size):
            inline_ends = [v for v in inline_ends if position < v]
            blocks = [v for v in blocks if position < v]
            if current is not None and position >= end_offset:
                current = None
                last_var = None
            if kind in _PROC:
                (
                    parent,
                    end_offset,
                    _next,
                    length,
                    dbg_start,
                    dbg_end,
                    signature,
                    offset,
                    segment,
                ) = _unpack("<8IH", p)
                name, _ = _string(p, 35)
                if parent or not position < end_offset < sym_size:
                    raise ValueError("unsupported or invalid procedure scope")
                begin = address(segment, offset, length)
                if not 0 <= dbg_start <= dbg_end <= length:
                    raise ValueError("invalid procedure debug bounds")
                if kind in {0x1146, 0x1147}:
                    id_record = ids.records.get(signature)
                    signature = (
                        _unpack("<I", id_record[1], 4)[0]
                        if id_record and id_record[0] in {0x1601, 0x1602}
                        else 0
                    )
                parameter_count = types.parameter_count(signature)
                current = PdbFunction(
                    name,
                    begin,
                    begin + length,
                    module,
                    files[module_index],
                    begin + dbg_start,
                    begin + dbg_end,
                )
                source_rows = lines[
                    bisect_left(line_pcs, begin) : bisect_left(line_pcs, begin + length)
                ]
                if source_rows:
                    first_pc = min(row[0] for row in source_rows)
                    first = {(row[1], row[2]) for row in source_rows if row[0] == first_pc}
                    if len(first) == 1:
                        current.source_file, current.source_line = next(iter(first))
                if parameter_count is None:
                    current.exclusions.append("unsupported procedure signature")
                functions.append(current)
                last_var = None
                frame_flags = 0
                inline_ends = []
                blocks = []
                block_extents = {}
                continue
            if current is None:
                continue
            if kind in {0x114D, 0x115D}:
                inline_ends.append(_unpack("<I", p, 4)[0])
                last_var = None
                continue
            if inline_ends:
                continue
            if kind == 0x1103:
                block_end = _unpack("<I", p, 4)[0]
                if not position < block_end <= end_offset:
                    raise ValueError("invalid CodeView block scope")
                blocks.append(block_end)
                code_size, code_offset, segment = _unpack("<IIH", p, 8)
                if code_size:
                    code_start = address(segment, code_offset, code_size)
                    if not current.address <= code_start < code_start + code_size <= current.end:
                        raise ValueError("CodeView block outside procedure")
                    block_extents[block_end] = (code_start, code_start + code_size)
                else:
                    block_extents[block_end] = (current.debug_start, current.debug_start)
                last_var = None
                continue
            if kind == 0x1012:
                frame_flags = _unpack("<I", p, 22)[0]
                if frame_flags & 1:
                    current.exclusions.append("dynamic stack frame")
                continue
            if kind in {0x113E, 0x1111, 0x110B, 0x1106}:
                if kind == 0x113E:
                    type_index, flags = _unpack("<IH", p)
                    name, _ = _string(p, 6)
                    is_parameter = bool(flags & 1)
                    location = None
                else:
                    if kind == 0x1106:
                        type_index, register = _unpack("<IH", p)
                        offset = None
                        name_pos = 6
                    else:
                        offset, type_index = _unpack("<iI", p)
                        register = (
                            _unpack("<H", p, 8)[0]
                            if kind == 0x1111
                            else (334 if machine == 0x8664 else 22)
                        )
                        name_pos = 10 if kind == 0x1111 else 8
                    name, _ = _string(p, name_pos)
                    is_parameter = None
                    begin = max([current.debug_start, *[block_extents[b][0] for b in blocks]])
                    end = min([current.debug_end, *[block_extents[b][1] for b in blocks]])
                    location = PdbStorage(register, offset, begin, end)
                t = types.resolve(type_index)
                if kind != 0x113E:
                    exact = [
                        v
                        for v in current.variables
                        if v.name == name
                        and v.type_index == type_index
                        and v.scope == tuple(blocks)
                        and v.is_parameter is not None
                    ]
                    if len(exact) == 1:
                        # MSVC emits legacy home copies alongside S_LOCAL. Attach
                        # only to one identical symbol in the same lexical scope.
                        exact[0].storage.append(location)
                        last_var = None
                        continue
                last_var = PdbVariable(
                    f"pdb:{module_index}:{position:x}", name, type_index, t, is_parameter
                )
                last_var.scope = tuple(blocks)
                if t is None or t.abi_name is None or t.size is None:
                    last_var.exclusions.append(f"unsupported type 0x{type_index:x}")
                if is_parameter is None:
                    last_var.exclusions.append("legacy symbol lacks parameter classification")
                if location is not None:
                    last_var.storage.append(location)
                    if location.register not in _REGISTERS:
                        last_var.exclusions.append("unsupported legacy storage register")
                current.variables.append(last_var)
                continue
            if kind in {0x1107, 0x110A, 0x110C, 0x1117, 0x112A, 0x1134, 0x1135}:
                current.exclusions.append(f"unsupported local symbol 0x{kind:x}")
                last_var = None
                continue
            if 0x113F <= kind <= 0x1145 and last_var is not None:
                register = None
                offset = None
                range_offset = None
                if kind == 0x1141:
                    register = _unpack("<H", p)[0]
                    range_offset = 4
                elif kind in {0x1142, 0x1144}:
                    offset = _unpack("<i", p)[0]
                    shift = 16 if last_var.is_parameter else 14
                    frame = (frame_flags >> shift) & 3
                    register = (
                        {1: 335, 2: 334}.get(frame)
                        if machine == 0x8664
                        else {1: 21, 2: 22}.get(frame)
                    )
                    range_offset = 4
                elif kind == 0x1145:
                    register, flags, offset = _unpack("<HHi", p)
                    if flags:
                        last_var.exclusions.append("partial register-relative storage")
                        continue
                    range_offset = 8
                else:
                    last_var.exclusions.append("unsupported storage piece")
                    continue
                if kind != 0x1144 and _unpack("<H", p, range_offset + 6)[0] == 0:
                    # Empty optimized lifetime is not an executable extent.
                    continue
                if register not in _REGISTERS:
                    last_var.exclusions.append("unsupported storage register")
                    continue
                if kind == 0x1144:
                    spans = [(current.debug_start, current.debug_end)]
                else:
                    start, section, length = _unpack("<IHH", p, range_offset)
                    begin = address(section, start, length)
                    end = begin + length
                    if not current.address <= begin < end <= current.end:
                        last_var.exclusions.append("storage range outside procedure")
                        continue
                    gaps = []
                    if (len(p) - range_offset - 8) % 4:
                        raise ValueError("invalid CodeView storage gaps")
                    for pos in range(range_offset + 8, len(p), 4):
                        gap, size = _unpack("<HH", p, pos)
                        if gap + size > length:
                            raise ValueError("CodeView gap outside storage range")
                        gaps.append((begin + gap, begin + gap + size))
                    spans = []
                    cursor = begin
                    for start, stop in sorted(gaps):
                        if start < cursor:
                            raise ValueError("overlapping CodeView storage gaps")
                        if cursor < start:
                            spans.append((cursor, start))
                        cursor = stop
                    if cursor < end:
                        spans.append((cursor, end))
                last_var.storage.extend(PdbStorage(register, offset, a, b) for a, b in spans)
                continue
            if kind not in {
                0x0006,
                0x000A,
                0x1101,
                0x1105,
                0x1108,
                0x1116,
                0x1124,
                0x1125,
                0x1127,
                0x1139,
                0x113A,
                0x113C,
                0x114C,
                0x114E,
                0x114F,
                0x115A,
                0x115B,
                0x115E,
                0x1168,
            }:
                current.exclusions.append(f"unsupported symbol in procedure 0x{kind:x}")
    return PdbInfo(path, guid, age, tuple(functions))


def reference_addresses(binary_path: Path, function: PdbFunction) -> dict[str, list[int]]:
    """Actual decoded operand references, never every PC in a live range."""
    import capstone

    from decbench.utils import binfmt

    info = binfmt.detect(binary_path)
    mode = binfmt.capstone_arch_mode(info)
    decoder = capstone.Cs(*mode)
    decoder.detail = True
    regions = binfmt.executable_regions(binary_path)
    region = next(
        (
            data[function.address - base : function.end - base]
            for base, data in regions
            if base <= function.address < function.end <= base + len(data)
        ),
        None,
    )
    if region is None:
        raise ValueError("PDB procedure is not file backed")
    result = {v.identity: [] for v in function.variables}
    for instruction in decoder.disasm(region, function.address):
        for variable in function.variables:
            for storage in variable.storage:
                if not storage.begin <= instruction.address < storage.end:
                    continue
                name = _REGISTERS.get(storage.register)
                if storage.offset is None:
                    read, written = instruction.regs_access()
                    matched = any(instruction.reg_name(reg) == name for reg in (*read, *written))
                else:
                    matched = any(
                        op.type == capstone.CS_OP_MEM
                        and instruction.reg_name(op.mem.base) == name
                        and not op.mem.index
                        and op.mem.disp == storage.offset
                        for op in instruction.operands
                    )
                if matched:
                    result[variable.identity].append(instruction.address)
                    break
    return {identity: sorted(set(addresses)) for identity, addresses in result.items()}


def ground_truth_variables(
    binary_path: Path, function: PdbFunction, *, include_addresses: bool = True
) -> list[dict[str, Any]]:
    if not function.measurable:
        return []
    references = reference_addresses(binary_path, function) if include_addresses else {}
    result = []
    for variable in function.variables:
        # Storage offsets with different bases cannot share a scalar calibration.
        bases = {s.register for s in variable.storage if s.offset is not None}
        # No stack-origin conversion has been proven between CodeView frame
        # bases and backend stack coordinates. Preserve bases in metadata only.
        offsets = []
        result.append(
            {
                "identity": variable.identity,
                "name": variable.name,
                "type": [variable.type.abi_name],
                "source_type": variable.type.source_name,
                "size": variable.type.size,
                "rbp_offset": offsets,
                "storage_base": sorted(bases),
                "addresses": references.get(variable.identity, []),
                "is_arg": variable.is_parameter,
                "arg_index": None,
                "debug_format": "pdb",
            }
        )
    return result
