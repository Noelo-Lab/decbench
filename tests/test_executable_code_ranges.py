"""Executable-section filtering shared by decompiler backends."""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from decbench.decompilers import llm_dec
from decbench.decompilers.declib_dec import DeclibDecompiler
from decbench.decompilers.dockerized import elf_function_symbols
from decbench.decompilers.raw import common
from decbench.decompilers.raw.binja_raw import RawBinjaDecompiler


@pytest.fixture(scope="module")
def split_text_elf(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("a C compiler is required")
    directory = tmp_path_factory.mktemp("split_text_elf")
    source = directory / "split.c"
    source.write_text("""
__attribute__((section(".text.worker"), noinline)) int worker(void) {
    return 7;
}

int marker = 3;

int main(void) {
    return worker() + marker;
}
""")
    binary = directory / "split"
    process = subprocess.run(
        [
            compiler,
            "-g",
            "-O0",
            "-fno-inline",
            "-ffunction-sections",
            "-Wl,--unique=.text.worker",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        pytest.skip(f"linker does not support unique executable sections: {process.stderr}")
    return binary


def _elf_section_range(binary: Path, name: str) -> tuple[int, int]:
    from elftools.elf.elffile import ELFFile

    with binary.open("rb") as stream:
        section = ELFFile(stream).get_section_by_name(name)
        if section is None:
            raise AssertionError(f"missing section {name}")
        start = int(section["sh_addr"])
        return start, start + int(section["sh_size"])


def _elf_symbol_address(binary: Path, name: str) -> int:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    with binary.open("rb") as stream:
        for section in ELFFile(stream).iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol.name == name and symbol["st_value"]:
                    return int(symbol["st_value"])
    raise AssertionError(f"missing symbol {name}")


def _write_minimal_pe(path: Path) -> None:
    image_base = 0x400000
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 3, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x5000)
    struct.pack_into("<I", data, optional + 28, image_base)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x6000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 92, 16)
    sections = (
        (b".text", 0x1000, 0x200, 0x60000020),
        (b".xcode", 0x3000, 0x400, 0x60000020),
        (b".data", 0x5000, 0x600, 0xC0000040),
    )
    for index, (name, virtual_address, file_offset, characteristics) in enumerate(sections):
        header = 0x178 + index * 40
        data[header : header + 8] = name.ljust(8, b"\x00")
        struct.pack_into(
            "<IIIIIIHHI",
            data,
            header + 8,
            0x10,
            virtual_address,
            0x200,
            file_offset,
            0,
            0,
            0,
            0,
            characteristics,
        )
        data[file_offset : file_offset + 0x10] = bytes((0x90 + index,)) * 0x10
    path.write_bytes(data)


def test_elf_split_text_sections_are_included_without_spanning_data(
    split_text_elf: Path,
) -> None:
    ranges = common.executable_code_ranges(split_text_elf)
    text_start, text_end = _elf_section_range(split_text_elf, ".text")
    worker_start, worker_end = _elf_section_range(split_text_elf, ".text.worker")
    plt_start, _plt_end = _elf_section_range(split_text_elf, ".plt")
    worker = _elf_symbol_address(split_text_elf, "worker")
    marker = _elf_symbol_address(split_text_elf, "marker")

    assert common.elf_text_range(split_text_elf) == (text_start, text_end)
    assert text_start < text_end <= worker_start < worker_end
    assert not text_start <= worker < text_end
    assert common.in_executable_code(worker, ranges)
    assert not common.in_executable_code(plt_start, ranges)
    assert not common.in_executable_code(marker, ranges)
    assert dict(elf_function_symbols(split_text_elf))["worker"] == worker
    assert not common.in_executable_code(worker_end, ranges)


def test_llm_disassembly_hint_reads_split_executable_section(split_text_elf: Path) -> None:
    worker = _elf_symbol_address(split_text_elf, "worker")

    hint = llm_dec._disasm_hint(split_text_elf, worker)

    assert f"0x{worker:x}" in hint


def test_pe_executable_sections_are_disjoint_and_data_is_rejected(tmp_path: Path) -> None:
    binary = tmp_path / "split.exe"
    _write_minimal_pe(binary)

    ranges = common.executable_code_ranges(binary)

    assert ranges == ((0x401000, 0x401010), (0x403000, 0x403010))
    assert not common.should_skip_function("first", 0x401000, ranges)
    assert not common.should_skip_function("second", 0x403000, ranges)
    assert common.should_skip_function("gap", 0x402000, ranges)
    assert common.should_skip_function("data", 0x405000, ranges)


def test_unreadable_code_ranges_fail_closed(tmp_path: Path) -> None:
    binary = tmp_path / "not-a-binary"
    binary.write_text("not a binary")

    ranges = common.executable_code_ranges(binary)

    assert ranges == ()
    assert common.should_skip_function("candidate", 0x1000, ranges)


def test_binja_enumerates_functions_from_each_executable_range_only() -> None:
    binary_view = SimpleNamespace(
        start=0,
        functions=[
            SimpleNamespace(name="literal_text", start=0x100, is_thunk=False),
            SimpleNamespace(name="split_text", start=0x4500, is_thunk=False),
            SimpleNamespace(name="gap", start=0x2000, is_thunk=False),
            SimpleNamespace(name="data", start=0x20000000, is_thunk=False),
            SimpleNamespace(name="thunk", start=0x4504, is_thunk=True),
        ],
    )
    ranges = ((0x78, 0xBEF), (0x44F0, 0x4518))

    functions = RawBinjaDecompiler()._enumerate(binary_view, 0, ranges)

    assert functions == [("literal_text", 0x100), ("split_text", 0x4500)]


def test_declib_enumerates_functions_from_each_executable_range_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "program"
    ranges = ((0x78, 0xBEF), (0x44F0, 0x4518))
    monkeypatch.setattr(common, "executable_code_ranges", lambda _path: ranges)
    decompiler = SimpleNamespace(
        functions={
            0x100: SimpleNamespace(name="literal_text"),
            0x4500: SimpleNamespace(name="split_text"),
            0x2000: SimpleNamespace(name="gap"),
            0x20000000: SimpleNamespace(name="data"),
        }
    )

    functions = DeclibDecompiler()._enumerate_functions(decompiler, binary, 0)

    assert functions == [("literal_text", 0x100), ("split_text", 0x4500)]
