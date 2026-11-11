"""Exact PDB public function coordinates without PE or metric integration."""

import re
import shutil
import struct
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from decbench.utils.pdb_msf import PdbFormatError, PdbMsf
from decbench.utils.pdb_publics import PdbPublicFunction, read_public_functions


def _symbol(
    name: bytes,
    *,
    flags: int = 2,
    offset: int = 32,
    section: int = 1,
    kind: int = 0x110E,
) -> bytes:
    payload = struct.pack("<HIIH", kind, flags, offset, section) + name + b"\0"
    return struct.pack("<H", len(payload)) + payload


def _streams(
    records: bytes, offsets: list[int], *, map_size: int | None = None, public: int = 4
) -> Mock:
    table = b"".join(struct.pack("<I", offset) for offset in offsets)
    dbi = bytearray(64)
    struct.pack_into("<iI", dbi, 0, -1, 19990903)
    struct.pack_into("<H2xH", dbi, 16, public, 5)
    size = len(table) if map_size is None else map_size
    header = struct.pack("<IIIIH2xII", 4, size, 0, 0, 0, 0, 0)
    msf = Mock(spec=PdbMsf)
    msf.stream.side_effect = {
        3: bytes(dbi),
        4: header + b"hash" + table,
        5: records,
    }.__getitem__
    return msf


def test_returns_indexed_functions_and_preserves_aliases() -> None:
    first = _symbol(b"first")
    alias = _symbol(b"alias")
    data = _symbol(b"data", flags=0, section=2)
    records = first + alias + data + _symbol(b"unindexed", offset=64)
    msf = _streams(records, [len(first) + len(alias), len(first), 0])
    assert read_public_functions(msf) == (
        PdbPublicFunction("first", 1, 32, 0),
        PdbPublicFunction("alias", 1, 32, len(first)),
    )


def test_absent_public_stream_has_no_public_functions() -> None:
    msf = _streams(b"", [], public=0xFFFF)
    assert read_public_functions(msf) == ()
    msf.stream.assert_called_once_with(3)


@pytest.mark.parametrize(
    ("record", "offsets", "map_size", "error"),
    [
        (_symbol(b"f"), [1], None, "non-record offset"),
        (_symbol(b"f"), [0, 0], None, "duplicate"),
        (_symbol(b"f"), [0], 5, "address map extent"),
        (_symbol(b"f"), [0], 8, "address map extent"),
        (_symbol(b"f")[:-1], [0], None, "symbol record extent"),
        (_symbol(b"f", kind=0x1110), [0], None, "complete S_PUB32"),
        (_symbol(b"f", section=0), [0], None, "location or name"),
        (_symbol(b""), [0], None, "location or name"),
        (_symbol(b"\xff"), [0], None, "name encoding"),
    ],
)
def test_rejects_malformed_public_evidence(record, offsets, map_size, error) -> None:
    with pytest.raises(PdbFormatError, match=error):
        read_public_functions(_streams(record, offsets, map_size=map_size))


def test_linked_template_publics_agree_with_llvm_pdbutil(tmp_path: Path) -> None:
    compiler, linker, inspector = (
        shutil.which(name) for name in ("clang-cl", "lld-link", "llvm-pdbutil")
    )
    if not all((compiler, linker, inspector)):
        pytest.skip("clang-cl, lld-link and llvm-pdbutil are required")
    source, obj, pdb, exe = (
        tmp_path / name for name in ("input.cpp", "input.obj", "input.pdb", "input.exe")
    )
    source.write_text(
        "template<int N> __declspec(noinline) int choose() { return N; }\n"
        "int data = 3;\n"
        'extern "C" int entry() { return choose<1>() + choose<2>() + data; }\n'
    )
    subprocess.run(
        [
            compiler,
            "--target=x86_64-pc-windows-msvc",
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
            "/entry:entry",
            "/subsystem:console",
            "/nodefaultlib",
            "/debug:full",
            "/opt:noicf",
            f"/pdb:{pdb}",
            f"/out:{exe}",
            str(obj),
        ],
        check=True,
        capture_output=True,
    )
    dump = subprocess.check_output([inspector, "dump", "--publics", str(pdb)], text=True)
    expected = {
        (name, int(section), int(offset), int(position))
        for position, name, flags, section, offset in re.findall(
            r"(\d+) \| S_PUB32 \[.*?\] `([^`]+)`\n\s*flags = ([^,]+), addr = (\d+):(\d+)",
            dump,
        )
        if re.search(r"\bfunction\b", flags, re.IGNORECASE)
    }
    assert len(expected) == 3
    symbols = read_public_functions(PdbMsf(pdb))
    assert {(s.name, s.section, s.section_offset, s.record_offset) for s in symbols} == expected
    specializations = [s for s in symbols if s.name.startswith("??$choose@")]
    assert len(specializations) == 2
    assert len({(s.section, s.section_offset) for s in specializations}) == 2
