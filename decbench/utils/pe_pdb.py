"""Match an explicitly supplied MSF PDB to a PE image's sole RSDS record."""

from __future__ import annotations

import os
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

from decbench.utils.pdb_msf import PdbFormatError, PdbMsf

_COFF_HEADER = struct.Struct("<HH12xH2x")
_DIRECTORY = struct.Struct("<II")
_SECTION = struct.Struct("<8xIIII16x")
_DEBUG_ENTRY = struct.Struct("<12xIIII")
_CODEVIEW = 2
_DEBUG_DIRECTORY = 6
_OPTIONAL_DIRECTORIES = {0x10B: 96, 0x20B: 112}
_MAX_DEBUG_ENTRIES = 4096
_MAX_RSDS_BYTES = 64 * 1024


@dataclass(frozen=True)
class PeCodeViewIdentity:
    guid: uuid.UUID
    age: int


def read_pe_codeview_identity(image: Path) -> PeCodeViewIdentity | None:
    """Read a unique, complete RSDS record or return None if CodeView is absent."""
    with image.open("rb") as stream:
        length = os.fstat(stream.fileno()).st_size

        def read(offset: int, size: int) -> bytes:
            if offset + size > length:
                raise PdbFormatError("PE structure extends beyond the file")
            stream.seek(offset)
            data = stream.read(size)
            if len(data) != size:
                raise PdbFormatError("truncated PE structure")
            return data

        dos = read(0, 64)
        pe_offset = struct.unpack_from("<I", dos, 60)[0]
        if dos[:2] != b"MZ" or pe_offset < len(dos) or read(pe_offset, 4) != b"PE\0\0":
            raise PdbFormatError("invalid PE image signature")
        _, section_count, optional_size = _COFF_HEADER.unpack(
            read(pe_offset + 4, _COFF_HEADER.size)
        )
        optional_offset = pe_offset + 4 + _COFF_HEADER.size
        optional = read(optional_offset, optional_size)
        magic = int.from_bytes(optional[:2], "little")
        directories = _OPTIONAL_DIRECTORIES.get(magic)
        if directories is None or len(optional) < directories:
            raise PdbFormatError("invalid PE optional header")
        directory_count = struct.unpack_from("<I", optional, directories - 4)[0]
        if directory_count > (len(optional) - directories) // _DIRECTORY.size:
            raise PdbFormatError("invalid PE data-directory count")
        if directory_count <= _DEBUG_DIRECTORY:
            return None
        debug_rva, debug_size = _DIRECTORY.unpack_from(
            optional, directories + _DEBUG_DIRECTORY * _DIRECTORY.size
        )
        if (debug_rva, debug_size) == (0, 0):
            return None
        if (
            not debug_rva
            or not debug_size
            or debug_size % _DEBUG_ENTRY.size
            or debug_size > _MAX_DEBUG_ENTRIES * _DEBUG_ENTRY.size
        ):
            raise PdbFormatError("invalid PE debug-directory extent")

        header_size = struct.unpack_from("<I", optional, 60)[0]
        section_offset = optional_offset + optional_size
        section_size = section_count * _SECTION.size
        if (
            not 0 < section_count <= 96
            or not section_offset + section_size <= header_size <= length
        ):
            raise PdbFormatError("invalid PE section table")
        mappings = [(0, header_size, header_size, 0)]
        for virtual_size, rva, raw_size, offset in _SECTION.iter_unpack(
            read(section_offset, section_size)
        ):
            if raw_size and (offset < header_size or offset + raw_size > length):
                raise PdbFormatError("invalid PE section file extent")
            mapped_size = virtual_size or raw_size
            if mapped_size:
                mappings.append((rva, rva + mapped_size, min(mapped_size, raw_size), offset))

        def file_offset(rva: int, size: int) -> int:
            end = rva + size
            matches = [mapping for mapping in mappings if mapping[0] < end and rva < mapping[1]]
            if len(matches) != 1:
                raise PdbFormatError("unmapped or ambiguous PE debug RVA")
            start, _, file_size, offset = matches[0]
            if not start <= rva < end <= start + file_size:
                raise PdbFormatError("PE debug RVA extends beyond file-backed bytes")
            return offset + rva - start

        directory_offset = file_offset(debug_rva, debug_size)
        codeviews = [
            (size, rva, offset)
            for kind, size, rva, offset in _DEBUG_ENTRY.iter_unpack(
                read(directory_offset, debug_size)
            )
            if kind == _CODEVIEW
        ]
        if not codeviews:
            return None
        if len(codeviews) != 1:
            raise PdbFormatError("ambiguous PE CodeView directory")
        size, rva, offset = codeviews[0]
        if not offset or not 25 <= size <= _MAX_RSDS_BYTES:
            raise PdbFormatError("invalid PE CodeView payload extent")
        if rva and file_offset(rva, size) != offset:
            raise PdbFormatError("PE CodeView RVA and file offset disagree")
        if offset < directory_offset + debug_size and directory_offset < offset + size:
            raise PdbFormatError("PE CodeView payload overlaps the debug directory")
        record = read(offset, size)
        if record[:4] != b"RSDS":
            raise PdbFormatError("unsupported PE CodeView signature")
        if not any(record[4:20]) or b"\0" not in record[24:]:
            raise PdbFormatError("invalid PE RSDS GUID or path terminator")
        return PeCodeViewIdentity(
            uuid.UUID(bytes_le=record[4:20]), struct.unpack_from("<I", record, 20)[0]
        )


def open_matching_pdb(image: Path, pdb_path: Path) -> PdbMsf:
    """Open a caller-selected PDB and require an exact PE GUID and age match."""
    codeview = read_pe_codeview_identity(image)
    if codeview is None:
        raise PdbFormatError("PE image has no CodeView identity")
    pdb = PdbMsf(pdb_path)
    identity = pdb.identity()
    if codeview.guid != identity.guid or codeview.age != identity.age:
        raise PdbFormatError("PE/PDB GUID or age mismatch")
    return pdb
