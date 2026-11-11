"""Read primary CodeView procedure ranges in PDB section coordinates."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from decbench.utils.pdb_msf import PdbFormatError, PdbMsf

_DBI_STREAM = 3
_DBI_HEADER_SIZE = 64
_DBI_VERSIONS = {19990903, 20091201}  # V70, V110
_MODULE_HEADER_SIZE = 64
_NO_STREAM = 0xFFFF
_CV_SIGNATURE = 4
_SYMBOL_HEADER = struct.Struct("<HH")
_PROCEDURE = struct.Struct("<4xI4xI12xIHx")
_PROCEDURE_KINDS = {0x110F, 0x1110, 0x1146, 0x1147, 0x1155, 0x1156}
_PROCEDURE_ENDS = {0x0006, 0x114F}  # S_END, S_PROC_ID_END


@dataclass(frozen=True)
class PdbProcedure:
    name: str
    section: int
    section_offset: int
    code_size: int
    record_offset: int
    kind: int


@dataclass(frozen=True)
class PdbProcedureModule:
    index: int
    name: str
    object_file: str
    procedures: tuple[PdbProcedure, ...]


def read_procedure_modules(pdb: PdbMsf) -> tuple[PdbProcedureModule, ...]:
    """Read modules and supported ProcSym records in stream order.

    Records keep their original module and record coordinates. The range is
    the primary CodeView extent. Mapping to an image requires separately
    validated PE/PDB identity and section translation.
    """
    dbi = pdb.stream(_DBI_STREAM)
    if len(dbi) < _DBI_HEADER_SIZE:
        raise PdbFormatError("truncated PDB DBI header")
    signature, version, age = struct.unpack_from("<iII", dbi)
    if signature != -1 or version not in _DBI_VERSIONS or age != pdb.identity().age:
        raise PdbFormatError("unsupported or inconsistent PDB DBI header")
    sizes = struct.unpack_from("<5i4x2i", dbi, 24)
    if min(sizes) < 0 or _DBI_HEADER_SIZE + sum(sizes) != len(dbi):
        raise PdbFormatError("invalid PDB DBI substream extents")

    position = _DBI_HEADER_SIZE
    limit = position + sizes[0]
    modules: list[PdbProcedureModule] = []
    used_streams: set[int] = set()
    while position < limit:
        names = position + _MODULE_HEADER_SIZE
        if names >= limit:
            raise PdbFormatError("truncated PDB module descriptor")
        stream, symbol_size, c11_size, c13_size = struct.unpack_from("<HIII", dbi, position + 34)
        name, next_name = _read_string(dbi, names, limit)
        object_file, end = _read_string(dbi, next_name, limit)
        position = (end + 3) & ~3
        if not name or position > limit:
            raise PdbFormatError("invalid PDB module descriptor")
        procedures: tuple[PdbProcedure, ...]
        if stream == _NO_STREAM:
            if symbol_size or c11_size or c13_size:
                raise PdbFormatError("missing PDB module stream")
            procedures = ()
        else:
            if stream in used_streams:
                raise PdbFormatError("duplicate PDB module stream")
            used_streams.add(stream)
            data = pdb.stream(stream)
            if symbol_size < 4 or symbol_size + c11_size + c13_size > len(data):
                raise PdbFormatError("invalid PDB module substream extents")
            if struct.unpack_from("<I", data)[0] != _CV_SIGNATURE:
                raise PdbFormatError("unsupported PDB module symbol signature")
            procedures = _read_procedures(data, symbol_size)
        modules.append(PdbProcedureModule(len(modules), name, object_file, procedures))
    return tuple(modules)


def _read_procedures(data: bytes, limit: int) -> tuple[PdbProcedure, ...]:
    procedures = []
    procedure_ends: list[int] = []
    position = 4
    while position < limit:
        if position + _SYMBOL_HEADER.size > limit:
            raise PdbFormatError("truncated PDB module symbol header")
        length, kind = _SYMBOL_HEADER.unpack_from(data, position)
        end = position + 2 + length
        if length < 2 or end > limit:
            raise PdbFormatError("invalid PDB module symbol extent")
        if procedure_ends and position >= procedure_ends[-1]:
            if position != procedure_ends[-1] or kind not in _PROCEDURE_ENDS:
                raise PdbFormatError("invalid PDB procedure terminator")
            procedure_ends.pop()
        if kind in _PROCEDURE_KINDS:
            payload = position + _SYMBOL_HEADER.size
            name_offset = payload + _PROCEDURE.size
            if name_offset >= end:
                raise PdbFormatError("truncated CodeView procedure")
            scope_end, size, offset, section = _PROCEDURE.unpack_from(data, payload)
            if not end <= scope_end < limit or procedure_ends and scope_end >= procedure_ends[-1]:
                raise PdbFormatError("invalid PDB procedure scope")
            name, _ = _read_string(data, name_offset, end)
            if not name or not section or not size or offset + size > 1 << 32:
                raise PdbFormatError("invalid PDB procedure name or extent")
            procedure_ends.append(scope_end)
            procedures.append(PdbProcedure(name, section, offset, size, position, kind))
        position = end
    if procedure_ends:
        raise PdbFormatError("missing PDB procedure terminator")
    return tuple(procedures)


def _read_string(data: bytes, offset: int, limit: int) -> tuple[str, int]:
    end = data.find(b"\0", offset, limit)
    if end < 0:
        raise PdbFormatError("unterminated PDB module or procedure name")
    try:
        return data[offset:end].decode("utf-8"), end + 1
    except UnicodeDecodeError as exc:
        raise PdbFormatError("invalid PDB module or procedure name encoding") from exc
