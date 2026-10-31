"""Recompiled-object function extraction for byte_match.

byte_match recompiles one decompiled function and compares its bytes against the
original. The recompiled bytes must be that function's own symbol extent from
the section the symbol lives in: GCC emits ``main`` into ``.text.startup`` at
``-O2``, so slicing ``.text`` scored a neighboring helper's bytes, or nothing.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from decbench.utils import binfmt

pytestmark = pytest.mark.skipif(
    shutil.which("gcc") is None or platform.machine() not in ("x86_64", "AMD64"),
    reason="needs a host x86-64 gcc",
)

_SRC = "int helper(void) { return 7; }\nint main(void) { return 42; }\n"
_MOV_7 = bytes.fromhex("b807000000")
_MOV_42 = bytes.fromhex("b82a000000")


def _compile(tmp_path: Path, *flags: str, compiler: str = "gcc") -> Path:
    source = tmp_path / "sections.c"
    obj = tmp_path / "sections.o"
    source.write_text(_SRC)
    subprocess.run([compiler, *flags, "-c", str(source), "-o", str(obj)], check=True)
    return obj


def _symbol_section(obj: Path, name: str) -> str:
    from elftools.elf.elffile import ELFFile

    with obj.open("rb") as f:
        elf = ELFFile(f)
        symbol = next(
            s for s in elf.get_section_by_name(".symtab").iter_symbols() if s.name == name
        )
        return str(elf.get_section(symbol["st_shndx"]).name)


def test_main_is_read_from_text_startup(tmp_path: Path) -> None:
    obj = _compile(tmp_path, "-O2")
    assert _symbol_section(obj, "main") == ".text.startup"

    main = binfmt.object_text_bytes(obj, "main")
    helper = binfmt.object_text_bytes(obj, "helper")

    assert main is not None and _MOV_42 in main and _MOV_7 not in main
    assert helper is not None and _MOV_7 in helper and _MOV_42 not in helper


def test_function_sections_are_read_per_symbol(tmp_path: Path) -> None:
    obj = _compile(tmp_path, "-O0", "-ffunction-sections")
    assert _symbol_section(obj, "helper") == ".text.helper"

    main = binfmt.object_text_bytes(obj, "main")
    helper = binfmt.object_text_bytes(obj, "helper")

    assert main is not None and _MOV_42 in main and _MOV_7 not in main
    assert helper is not None and _MOV_7 in helper and _MOV_42 not in helper


def test_neighbors_in_plain_text_keep_their_own_extent(tmp_path: Path) -> None:
    obj = _compile(tmp_path, "-O0")
    assert _symbol_section(obj, "main") == ".text"

    main = binfmt.object_text_bytes(obj, "main")
    helper = binfmt.object_text_bytes(obj, "helper")

    assert main is not None and _MOV_42 in main and _MOV_7 not in main
    assert helper is not None and _MOV_7 in helper and _MOV_42 not in helper


def test_missing_symbol_does_not_fall_back_to_text(tmp_path: Path) -> None:
    obj = _compile(tmp_path, "-O0")

    assert binfmt.object_text_bytes(obj, "absent") is None


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not available")
def test_coff_function_is_bounded_by_the_next_symbol(tmp_path: Path) -> None:
    obj = _compile(tmp_path, "-O2", "--target=i686-w64-windows-gnu", compiler="clang")

    main = binfmt.object_text_bytes(obj, "main")
    helper = binfmt.object_text_bytes(obj, "helper")

    assert main is not None and _MOV_42 in main and _MOV_7 not in main
    assert helper is not None and _MOV_7 in helper and _MOV_42 not in helper
