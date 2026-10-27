"""Bounded MSF 7 stream and PDB information transport.

This module does not find PDBs, match them to PE files or feed any metric.
Unsupported or invalid MSF encodings raise PdbFormatError; operating-system
read failures are left to the caller.
"""

from __future__ import annotations

import os
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
_MAX_BYTES = 512 * 1024 * 1024
_MAX_STREAMS = 1_000_000


class PdbFormatError(ValueError):
    """An invalid or unsupported MSF/PDB representation."""


def _unpack(fmt: str, data: bytes, offset: int = 0):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise PdbFormatError("truncated MSF structure")
    return struct.unpack_from(fmt, data, offset)


@dataclass(frozen=True)
class PdbIdentity:
    version: int
    signature: int
    age: int
    guid: uuid.UUID


class PdbMsf:
    """An in-memory bounded MSF 7 container, with no PE identity assertion."""

    def __init__(self, path: Path):
        with path.open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            if size > _MAX_BYTES:
                raise PdbFormatError("PDB exceeds the supported 512 MiB bound")
            self._data = stream.read(size + 1)
        if len(self._data) != size:
            raise PdbFormatError("PDB changed while being read")
        if self._data[:32] != _MAGIC:
            raise PdbFormatError("not an MSF 7 PDB")
        block_size, _, count, directory_size, _, directory_map = _unpack("<6I", self._data, 32)
        if block_size not in (512, 1024, 2048, 4096) or len(self._data) != count * block_size:
            raise PdbFormatError("invalid MSF block geometry")
        self._block_size = block_size
        directory_blocks = (directory_size + block_size - 1) // block_size
        # This bounded implementation supports one block-map block only.
        if directory_blocks > block_size // 4 or directory_size > len(self._data):
            raise PdbFormatError("unsupported MSF directory extent")
        blocks = _unpack(f"<{directory_blocks}I", self._data, directory_map * block_size)
        directory = self._read_blocks(blocks, directory_size)
        nstreams = _unpack("<I", directory)[0]
        if nstreams > _MAX_STREAMS or 4 + 4 * nstreams > len(directory):
            raise PdbFormatError("invalid MSF stream count")
        sizes = _unpack(f"<{nstreams}I", directory, 4)
        entries: list[tuple[tuple[int, ...], int] | None] = []
        offset = 4 + 4 * nstreams
        for size in sizes:
            if size == 0xFFFFFFFF:
                entries.append(None)
                continue
            if size > len(self._data):
                raise PdbFormatError("invalid MSF stream size")
            nblocks = (size + block_size - 1) // block_size
            blocks = _unpack(f"<{nblocks}I", directory, offset)
            offset += nblocks * 4
            if any(b >= count for b in blocks):
                raise PdbFormatError("MSF stream block outside file")
            entries.append((blocks, size))
        self._streams = tuple(entries)

    def _read_blocks(self, blocks: tuple[int, ...], size: int) -> bytes:
        if any((b + 1) * self._block_size > len(self._data) for b in blocks):
            raise PdbFormatError("MSF block outside file")
        return b"".join(
            self._data[b * self._block_size : (b + 1) * self._block_size] for b in blocks
        )[:size]

    @property
    def stream_count(self) -> int:
        return len(self._streams)

    def stream(self, index: int) -> bytes:
        if not 0 <= index < len(self._streams):
            raise PdbFormatError(f"missing PDB stream {index}")
        entry = self._streams[index]
        if entry is None:
            raise PdbFormatError(f"missing PDB stream {index}")
        blocks, size = entry
        return self._read_blocks(blocks, size)

    def identity(self) -> PdbIdentity:
        """Read the PDB information stream; the caller must match PE GUID/age."""
        data = self.stream(1)
        version, signature, age = _unpack("<III", data)
        if len(data) < 28 or not any(data[12:28]):
            raise PdbFormatError("invalid or missing PDB GUID")
        return PdbIdentity(version, signature, age, uuid.UUID(bytes_le=data[12:28]))
