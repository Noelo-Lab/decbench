"""PDB stream extraction only; this does not qualify a PE/PDB pair."""

import re
import shutil
import struct
import subprocess
import uuid
from pathlib import Path

import pytest

from decbench.utils import pdb_msf


def _minimal_msf() -> bytes:
    block_size = 512
    data = bytearray(5 * block_size)
    data[:32] = pdb_msf._MAGIC
    # block 1 maps block 2, the directory; info stream occupies block 3.
    struct.pack_into("<6I", data, 32, block_size, 0, 5, 16, 0, 1)
    struct.pack_into("<I", data, block_size, 2)
    struct.pack_into("<IIII", data, 2 * block_size, 2, 0, 28, 3)
    guid = uuid.UUID("12345678-1234-5678-9abc-def012345678")
    struct.pack_into("<III", data, 3 * block_size, 20000404, 19, 1)
    data[3 * block_size + 12 : 3 * block_size + 28] = guid.bytes_le
    return bytes(data)


def test_minimal_streams_and_identity(tmp_path: Path) -> None:
    path = tmp_path / "x.pdb"
    path.write_bytes(_minimal_msf())
    msf = pdb_msf.PdbMsf(path)
    assert msf.stream_count == 2
    assert msf.stream(0) == b""
    assert str(msf.identity().guid) == "12345678-1234-5678-9abc-def012345678"
    assert msf.identity().age == 1
    with pytest.raises(pdb_msf.PdbFormatError):
        msf.stream(2)


def test_rejects_bad_geometry_truncation_and_out_of_bounds(tmp_path: Path) -> None:
    path = tmp_path / "x.pdb"
    original = _minimal_msf()
    for mutated in (b"", original[:-1], b"bad" + original[3:]):
        path.write_bytes(mutated)
        with pytest.raises(pdb_msf.PdbFormatError):
            pdb_msf.PdbMsf(path)
    for offset, value in ((32, 123), (40, 10), (52, 99), (512, 99), (1036, 99)):
        data = bytearray(original)
        struct.pack_into("<I", data, offset, value)
        path.write_bytes(data)
        with pytest.raises(pdb_msf.PdbFormatError):
            pdb_msf.PdbMsf(path)


def test_rejects_oversized_and_zero_guid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "x.pdb"
    data = bytearray(_minimal_msf())
    path.write_bytes(data)
    monkeypatch.setattr(pdb_msf, "_MAX_BYTES", 50)
    with pytest.raises(pdb_msf.PdbFormatError):
        pdb_msf.PdbMsf(path)
    monkeypatch.setattr(pdb_msf, "_MAX_BYTES", len(data))
    data[3 * 512 + 12 : 3 * 512 + 28] = bytes(16)
    path.write_bytes(data)
    with pytest.raises(pdb_msf.PdbFormatError):
        pdb_msf.PdbMsf(path).identity()


def test_generated_pdb_matches_llvm_pdbutil(tmp_path: Path) -> None:
    compiler, linker, inspector = (
        shutil.which(name) for name in ("clang-cl", "lld-link", "llvm-pdbutil")
    )
    if not all((compiler, linker, inspector)):
        pytest.skip("clang-cl, lld-link and llvm-pdbutil are required")
    source, obj, pdb, exe = (
        tmp_path / name for name in ("main.c", "main.obj", "main.pdb", "main.exe")
    )
    source.write_text("int main(void) { return 0; }\n")
    subprocess.run(
        [compiler, "/c", "/Z7", "/Od", "/GS-", str(source), f"/Fo{obj}"],
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
            f"/out:{exe}",
            str(obj),
        ],
        check=True,
        capture_output=True,
    )
    summary = subprocess.check_output([inspector, "dump", "-summary", str(pdb)], text=True)
    guid = re.search(r"GUID:\s*\{([0-9A-Fa-f-]+)\}", summary)
    age = re.search(r"Age:\s*(\d+)", summary)
    streams = re.search(r"Number of streams:\s*(\d+)", summary)
    assert guid and age and streams
    msf = pdb_msf.PdbMsf(pdb)
    assert msf.identity().guid == uuid.UUID(guid.group(1))
    assert msf.identity().age == int(age.group(1))
    assert msf.stream_count == int(streams.group(1))
