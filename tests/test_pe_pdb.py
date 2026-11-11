"""PE/PDB identity tests, including ambiguous and damaged debug records."""

import re
import shutil
import struct
import subprocess
import uuid
from pathlib import Path

import pytest

from decbench.utils.pdb_msf import PdbFormatError
from decbench.utils.pe_pdb import PeCodeViewIdentity, open_matching_pdb, read_pe_codeview_identity
from tests.test_pdb_msf import _minimal_msf

_GUID = uuid.UUID("12345678-1234-5678-9abc-def012345678")
_OPTIONAL = 0x98
_DIRECTORY = 0x210
_RECORD = 0x290
_RSDS = b"RSDS" + _GUID.bytes_le + struct.pack("<I", 1) + b"other\\unused.pdb\0"


def _pe(bits: int = 64, *, mapped: bool = True) -> bytearray:
    data = bytearray(0x500)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    directory_start = 112 if bits == 64 else 96
    optional_size = directory_start + 16 * 8
    struct.pack_into("<HH12xH2x", data, 0x84, 0x8664 if bits == 64 else 0x14C, 1, optional_size)
    struct.pack_into("<H", data, _OPTIONAL, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<I", data, _OPTIONAL + 60, 0x200)
    struct.pack_into("<I", data, _OPTIONAL + directory_start - 4, 16)
    struct.pack_into("<II", data, _OPTIONAL + directory_start + 6 * 8, 0x1010, 28)
    struct.pack_into("<8xIIII16x", data, _OPTIONAL + optional_size, 0x200, 0x1000, 0x200, 0x200)
    offset = _RECORD if mapped else 0x410
    struct.pack_into("<IIII", data, _DIRECTORY + 12, 2, len(_RSDS), 0x1090 if mapped else 0, offset)
    data[offset : offset + len(_RSDS)] = _RSDS
    return data


@pytest.mark.parametrize(("bits", "mapped"), [(32, True), (64, True), (64, False)])
def test_matches_explicit_pdb_regardless_of_embedded_path(
    tmp_path: Path, bits: int, mapped: bool
) -> None:
    image, pdb = tmp_path / "a.exe", tmp_path / "different.pdb"
    image.write_bytes(_pe(bits, mapped=mapped))
    pdb.write_bytes(_minimal_msf())
    assert read_pe_codeview_identity(image) == PeCodeViewIdentity(_GUID, 1)
    assert open_matching_pdb(image, pdb).identity().guid == _GUID


@pytest.mark.parametrize("offset", [_OPTIONAL + 112 + 6 * 8, _DIRECTORY + 12])
def test_absent_codeview_does_not_open_pdb(tmp_path: Path, offset: int) -> None:
    image = tmp_path / "a.exe"
    data = _pe()
    if offset == _DIRECTORY + 12:
        struct.pack_into("<I", data, offset, 1)
    else:
        struct.pack_into("<II", data, offset, 0, 0)
    image.write_bytes(data)
    assert read_pe_codeview_identity(image) is None
    with pytest.raises(PdbFormatError, match="no CodeView identity"):
        open_matching_pdb(image, tmp_path / "missing.pdb")


@pytest.mark.parametrize("offset", [_RECORD + 4, _RECORD + 20])
def test_both_guid_and_age_must_match(tmp_path: Path, offset: int) -> None:
    image, pdb = tmp_path / "a.exe", tmp_path / "unused.pdb"
    data = _pe()
    data[offset] ^= 2
    image.write_bytes(data)
    pdb.write_bytes(_minimal_msf())
    with pytest.raises(PdbFormatError, match="GUID or age mismatch"):
        open_matching_pdb(image, pdb)


def test_rejects_second_codeview_even_if_incomplete(tmp_path: Path) -> None:
    image = tmp_path / "a.exe"
    data = _pe()
    struct.pack_into("<I", data, _OPTIONAL + 112 + 6 * 8 + 4, 56)
    struct.pack_into("<I", data, _DIRECTORY + 28 + 12, 2)
    image.write_bytes(data)
    with pytest.raises(PdbFormatError, match="ambiguous PE CodeView"):
        read_pe_codeview_identity(image)


@pytest.mark.parametrize(
    ("offset", "value", "reason"),
    [
        (_OPTIONAL + 108, 17, "data-directory count"),
        (_OPTIONAL + 112 + 6 * 8, 0x11F8, "debug RVA"),
        (_OPTIONAL + 112 + 6 * 8 + 4, 27, "debug-directory extent"),
        (_OPTIONAL + 112 + 6 * 8 + 4, 28 * 4097, "debug-directory extent"),
        (_DIRECTORY + 16, 24, "payload extent"),
        (_DIRECTORY + 24, 0x291, "RVA and file offset disagree"),
        (_RECORD, int.from_bytes(b"NB10", "little"), "CodeView signature"),
        (_RECORD + len(_RSDS) - 1, 0xFFFFFFFF, "path terminator"),
    ],
)
def test_rejects_malformed_debug_layout(
    tmp_path: Path, offset: int, value: int, reason: str
) -> None:
    image = tmp_path / "a.exe"
    data = _pe()
    struct.pack_into("<I", data, offset, value)
    image.write_bytes(data)
    with pytest.raises(PdbFormatError, match=reason):
        read_pe_codeview_identity(image)


@pytest.mark.parametrize("raw_size", [0, 16])
def test_rejects_overlapping_rva_mappings(tmp_path: Path, raw_size: int) -> None:
    image = tmp_path / "a.exe"
    data = _pe()
    struct.pack_into("<H", data, 0x86, 2)
    struct.pack_into("<8xIIII16x", data, _OPTIONAL + 240 + 40, 16, 0x1020, raw_size, 0x400)
    image.write_bytes(data)
    with pytest.raises(PdbFormatError, match="ambiguous PE debug RVA"):
        read_pe_codeview_identity(image)


@pytest.mark.parametrize("target", ["i686", "x86_64", "aarch64"])
def test_compiler_pair_matches_llvm(tmp_path: Path, target: str) -> None:
    compiler, linker, inspector = (
        shutil.which(name) for name in ("clang-cl", "lld-link", "llvm-readobj")
    )
    if not all((compiler, linker, inspector)):
        pytest.skip("clang-cl, lld-link and llvm-readobj are required")
    source, obj, pdb, image = (
        tmp_path / name for name in ("main.c", "main.obj", "main.pdb", "main.exe")
    )
    source.write_text("int main(void) { return 0; }\n")
    subprocess.run(
        [
            compiler,
            f"--target={target}-pc-windows-msvc",
            "/c",
            "/Z7",
            "/Od",
            "/GS-",
            str(source),
            f"/Fo{obj}",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            linker,
            "/entry:main",
            "/nodefaultlib",
            "/subsystem:console",
            "/debug:full",
            f"/pdb:{pdb}",
            f"/out:{image}",
            str(obj),
        ],
        check=True,
        capture_output=True,
    )
    output = subprocess.check_output([inspector, "--coff-debug-directory", str(image)], text=True)
    guid = re.search(r"PDBGUID:\s*\{([0-9A-Fa-f-]+)\}", output)
    age = re.search(r"PDBAge:\s*(\d+)", output)
    assert guid and age
    expected = PeCodeViewIdentity(uuid.UUID(guid.group(1)), int(age.group(1)))
    assert read_pe_codeview_identity(image) == expected
    identity = open_matching_pdb(image, pdb).identity()
    assert (identity.guid, identity.age) == (expected.guid, expected.age)
