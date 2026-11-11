"""DBI and procedure transport, independent of register and type recovery."""

import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from decbench.utils.pdb_msf import PdbFormatError, PdbMsf
from decbench.utils.pdb_procedures import PdbProcedure, read_procedure_modules
from tests.test_pdb_msf import _minimal_msf


def _module(stream: int, symbols: int, names: bytes = b"unit\0unit.obj\0") -> bytes:
    header = bytearray(64)
    struct.pack_into("<HIII", header, 34, stream, symbols, 0, 0)
    data = bytes(header) + names
    return data + bytes(-len(data) % 4)


def _pdb(dbi_modules: bytes, symbols: bytes, *, age: int = 1) -> bytes:
    data = bytearray(_minimal_msf() + bytes(512))
    dbi = bytearray(64)
    struct.pack_into("<iII", dbi, 0, -1, 19990903, age)
    struct.pack_into("<I", dbi, 24, len(dbi_modules))
    dbi.extend(dbi_modules)
    assert len(dbi) <= 512 and len(symbols) <= 512
    struct.pack_into("<II", data, 40, 6, 36)
    struct.pack_into("<9I", data, 1024, 5, 0, 28, 0, len(dbi), len(symbols), 3, 4, 5)
    data[2048 : 2048 + len(dbi)] = dbi
    data[2560 : 2560 + len(symbols)] = symbols
    return bytes(data)


def _record(kind: int, payload: bytes = b"") -> bytes:
    payload += bytes(-len(payload) % 4)
    return struct.pack("<HH", 2 + len(payload), kind) + payload


def _procedure(
    position: int, kind: int, name: bytes, *, scope_delta: int = 0, size: int = 8, section: int = 2
) -> bytes:
    payload = bytearray(struct.pack("<8IHB", 0, 0, 0, size, 0, 0, 1, 32, section, 0) + name)
    scope_end = position + len(_record(kind, payload))
    struct.pack_into("<I", payload, 4, scope_end + scope_delta)
    return _record(kind, payload) + _record(0x114F if kind in {0x1146, 0x1147} else 6)


def _read(tmp_path: Path, modules: bytes, symbols: bytes, *, age: int = 1):
    path = tmp_path / "a.pdb"
    path.write_bytes(_pdb(modules, symbols, age=age))
    return read_procedure_modules(PdbMsf(path))


def test_retains_same_address_records_and_empty_module(tmp_path: Path) -> None:
    first = _procedure(4, 0x1110, b"f\0")
    offset = 4 + len(first)
    second = _procedure(offset, 0x1146, b"f_alias\0")
    symbols = struct.pack("<I", 4) + first + second
    empty = _module(0xFFFF, 0, b"empty\0\0")
    absent, module = _read(tmp_path, empty + _module(4, len(symbols)), symbols)
    assert (absent.index, absent.name, absent.procedures) == (0, "empty", ())
    assert (module.index, module.name, module.object_file) == (1, "unit", "unit.obj")
    assert module.procedures == (
        PdbProcedure("f", 2, 32, 8, 4, 0x1110),
        PdbProcedure("f_alias", 2, 32, 8, offset, 0x1146),
    )


@pytest.mark.parametrize(
    ("symbol", "reason"),
    [
        (_record(0x1110), "truncated CodeView procedure"),
        (_procedure(4, 0x1110, b"f\0", scope_delta=-2), "procedure scope"),
        (_procedure(4, 0x1110, b"f\0", size=0), "name or extent"),
        (_procedure(4, 0x1110, b"f\0", section=0), "name or extent"),
        (_procedure(4, 0x1110, b"\xff\0"), "name encoding"),
        (_procedure(4, 0x1110, b"f\0")[:-2] + struct.pack("<H", 0x1101), "terminator"),
        (struct.pack("<HH", 64, 6), "module symbol extent"),
    ],
)
def test_rejects_malformed_symbol_evidence(tmp_path: Path, symbol: bytes, reason: str) -> None:
    symbols = struct.pack("<I", 4) + symbol
    with pytest.raises(PdbFormatError, match=reason):
        _read(tmp_path, _module(4, len(symbols)), symbols)


@pytest.mark.parametrize(
    ("modules", "age", "reason"),
    [
        (_module(4, 4), 2, "inconsistent PDB DBI header"),
        (bytes(64), 1, "truncated PDB module descriptor"),
        (_module(4, 4, b"ABCD"), 1, "unterminated PDB module"),
        (_module(0xFFFF, 4), 1, "missing PDB module stream"),
        (_module(4, 5), 1, "module substream extents"),
        (_module(4, 4) * 2, 1, "duplicate PDB module stream"),
    ],
)
def test_rejects_malformed_module_evidence(
    tmp_path: Path, modules: bytes, age: int, reason: str
) -> None:
    with pytest.raises(PdbFormatError, match=reason):
        _read(tmp_path, modules, struct.pack("<I", 4), age=age)


@pytest.mark.parametrize("target", ["i686", "x86_64", "aarch64"])
def test_compiler_procedures_match_llvm(tmp_path: Path, target: str) -> None:
    compiler, linker, inspector = (
        shutil.which(name) for name in ("clang-cl", "lld-link", "llvm-pdbutil")
    )
    if not all((compiler, linker, inspector)):
        pytest.skip("clang-cl, lld-link and llvm-pdbutil are required")
    source, obj, pdb, exe = (
        tmp_path / name for name in ("main.cpp", "main.obj", "main.pdb", "main.exe")
    )
    source.write_text(
        "namespace example {\n"
        "__declspec(noinline) int read(int value) { return value + 3; }\n"
        "__declspec(noinline) int read(short value) { return value + 5; }\n"
        "}\n"
        "int main() { return example::read(1) + example::read(static_cast<short>(1)); }\n"
    )
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
            f"/out:{exe}",
            str(obj),
        ],
        check=True,
        capture_output=True,
    )
    output = subprocess.check_output([inspector, "dump", "--symbols", str(pdb)], text=True)
    pattern = (
        r"(\d+) \| S_[GL]PROC32(?:_ID)? \[size = \d+\] `([^\n]+)`\n"
        r"\s*parent = \d+, end = \d+, addr = (\d+):(\d+), code size = (\d+)"
    )
    expected = [
        (int(position), name, int(section), int(offset), int(size))
        for position, name, section, offset, size in re.findall(pattern, output)
    ]
    rows = [row for module in read_procedure_modules(PdbMsf(pdb)) for row in module.procedures]
    assert len(expected) == 3
    assert [
        (r.record_offset, r.name, r.section, r.section_offset, r.code_size) for r in rows
    ] == expected
    assert rows[0].section_offset != rows[1].section_offset
