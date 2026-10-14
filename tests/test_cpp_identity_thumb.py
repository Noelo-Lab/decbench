"""ARM/Thumb canonical C++ identity validation."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.function_identity import dwarf_function_identities

pytestmark = pytest.mark.skipif(
    shutil.which("arm-none-eabi-g++") is None,
    reason="arm-none-eabi-g++ required",
)

SRC = r"""
namespace alpha { __attribute__((noinline)) int same(int x) { return x + 1; } }
namespace beta  { __attribute__((noinline)) int same(int x) { return x + 2; } }
extern "C" int thumb_entry(void) {
    volatile int x = 1;
    return alpha::same(x) + beta::same(x);
}
"""


def _driver():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_benchmark.py"
    spec = importlib.util.spec_from_file_location("thumb_identity_driver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_thumb_bit_normalizes_to_dwarf_low_pc(tmp_path: Path) -> None:
    source = tmp_path / "thumb.cpp"
    obj = tmp_path / "thumb.o"
    elf = tmp_path / "thumb.elf"
    source.write_text(SRC)
    common = [
        "-mcpu=cortex-m4",
        "-mthumb",
        "-O0",
        "-g",
        "-fno-exceptions",
        "-fno-rtti",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
    ]
    subprocess.run(
        ["arm-none-eabi-g++", *common, "-c", str(source), "-o", str(obj)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "arm-none-eabi-g++",
            *common,
            "-nostdlib",
            "-Wl,--entry=thumb_entry",
            "-Wl,-Ttext=0x08000000",
            str(obj),
            "-o",
            str(elf),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    identities = [row for row in dwarf_function_identities(elf) if row.name == "same"]
    assert len({row.address for row in identities}) == 2
    assert all(row.linkage_name for row in identities)

    with elf.open("rb") as stream:
        symtab = ELFFile(stream).get_section_by_name(".symtab")
        assert symtab is not None
        symbols = {symbol.name: int(symbol["st_value"]) for symbol in symtab.iter_symbols()}

    raw_addresses = []
    for row in identities:
        assert row.linkage_name is not None
        raw = symbols[row.linkage_name]
        assert raw & 1 == 1, (row.linkage_name, hex(raw))
        assert raw & ~1 == row.address
        raw_addresses.append(raw)

    result = DecompilationResult(
        binary_path=elf,
        binary_name=elf.stem,
        decompiler=DecompilerMetadata(decompiler_name="thumb-fixture"),
        functions={
            f"raw-{index}": FunctionDecompilation(
                name=f"FUN_{raw:x}",
                address=raw,
                decompiled_code=f"int FUN_{raw:x}(void) {{ return 0; }}",
            )
            for index, raw in enumerate(raw_addresses)
        },
    )
    addr2name = {row.address: row.name for row in identities}
    _driver()._relabel_to_dwarf(result, addr2name, elf)

    expected = {f"same@0x{address:x}" for address in addr2name}
    assert set(result.functions) == expected
    assert {fd.address for fd in result.functions.values()} == set(addr2name)
    assert all(fd.address & 1 == 0 for fd in result.functions.values())
    assert result.decompiler.failed_functions == []
