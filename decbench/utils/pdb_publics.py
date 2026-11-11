"""Read exact section-relative public function symbols from a PDB address map."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from decbench.utils.pdb_msf import PdbFormatError, PdbMsf

_DBI_STREAM = 3
_DBI_HEADER_SIZE = 64
_DBI_VERSIONS = {19990903, 20091201}  # V70, V110
_NO_STREAM = 0xFFFF
_PUBLIC_HEADER = struct.Struct("<III12xI")
_RECORD_HEADER = struct.Struct("<HH")
_PUBLIC_SYMBOL = struct.Struct("<IIH")
_S_PUB32 = 0x110E
_FUNCTION = 0x2


@dataclass(frozen=True)
class PdbPublicFunction:
    """Decorated name and location in PDB coordinates, before PE mapping."""

    name: str
    section: int
    section_offset: int
    record_offset: int


def read_public_functions(pdb: PdbMsf) -> tuple[PdbPublicFunction, ...]:
    """Return address-map function records, keeping aliases at the same location.

    The caller must verify the PE/PDB pair and map sections before using a
    record as native evidence. A public record alone gives no function extent.
    """
    dbi = pdb.stream(_DBI_STREAM)
    if len(dbi) < _DBI_HEADER_SIZE:
        raise PdbFormatError("truncated PDB DBI header")
    signature, version = struct.unpack_from("<iI", dbi)
    if signature != -1 or version not in _DBI_VERSIONS:
        raise PdbFormatError("unsupported PDB DBI header")
    public_stream, record_stream = struct.unpack_from("<H2xH", dbi, 16)
    if public_stream == _NO_STREAM:
        return ()

    publics = pdb.stream(public_stream)
    if len(publics) < _PUBLIC_HEADER.size:
        raise PdbFormatError("truncated PDB publics header")
    hash_size, map_size, thunks, sections = _PUBLIC_HEADER.unpack_from(publics)
    start = _PUBLIC_HEADER.size + hash_size
    end = start + map_size
    # A thunk map follows the address map. A section-offset map may follow it.
    trailing = len(publics) - end - 4 * thunks
    if map_size % 4 or trailing not in {0, 8 * sections}:
        raise PdbFormatError("invalid PDB public address map extent")
    offsets = {offset for (offset,) in struct.iter_unpack("<I", memoryview(publics)[start:end])}
    if len(offsets) != map_size // 4:
        raise PdbFormatError("duplicate PDB public record offset")
    if not offsets:
        return ()
    return _read_records(pdb.stream(record_stream), offsets)


def _read_records(data: bytes, offsets: set[int]) -> tuple[PdbPublicFunction, ...]:
    records = []
    position = 0
    while offsets and position + _RECORD_HEADER.size <= len(data):
        length, kind = _RECORD_HEADER.unpack_from(data, position)
        end = position + 2 + length  # CodeView length excludes its own 2 bytes.
        if length < 2 or end > len(data):
            raise PdbFormatError("invalid CodeView symbol record extent")
        if position in offsets:
            offsets.remove(position)
            payload = position + _RECORD_HEADER.size
            name_start = payload + _PUBLIC_SYMBOL.size
            if kind != _S_PUB32 or name_start >= end:
                raise PdbFormatError("PDB public address map must reference a complete S_PUB32")
            flags, section_offset, section = _PUBLIC_SYMBOL.unpack_from(data, payload)
            if flags & _FUNCTION:
                name_end = data.find(b"\0", name_start, end)
                if section == 0 or name_end <= name_start:
                    raise PdbFormatError("invalid PDB public function location or name")
                try:
                    name = data[name_start:name_end].decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise PdbFormatError("invalid PDB public function name encoding") from exc
                records.append(PdbPublicFunction(name, section, section_offset, position))
        position = end
    if offsets:
        raise PdbFormatError("PDB public address map references a non-record offset")
    return tuple(records)
