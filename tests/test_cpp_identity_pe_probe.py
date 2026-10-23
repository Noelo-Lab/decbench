"""Validate canonical C++ identity on a real MinGW PE+DWARF binary."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from decbench.decompilers.raw import common
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils import binfmt
from decbench.utils.function_identity import dwarf_function_identities, identities_by_name

pytestmark = pytest.mark.skipif(
    shutil.which("x86_64-w64-mingw32-g++") is None,
    reason="MinGW x86_64 C++ compiler required",
)

SRC = r"""
namespace alpha { __attribute__((noinline)) int same(int x) { return x + 1; } }
namespace beta  { __attribute__((noinline)) int same(int x) { return x + 2; } }
volatile int seed = 1;
int main() { int x = seed; return alpha::same(x) + beta::same(x); }
"""


def _driver() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_benchmark.py"
    spec = importlib.util.spec_from_file_location("pe_identity_driver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_real_pe_rva_relabels_to_dwarf_low_pc(tmp_path: Path) -> None:
    source = tmp_path / "fixture.cpp"
    binary = tmp_path / "fixture.exe"
    source.write_text(SRC)
    subprocess.run(
        [
            "x86_64-w64-mingw32-g++",
            "-std=c++17",
            "-O0",
            "-g",
            "-fno-builtin",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    info = binfmt.detect(binary)
    assert info is not None and info.fmt == "pe" and info.arch == "x86-64"
    image_base = common.elf_min_vaddr(binary)
    assert image_base > 0

    grouped = identities_by_name(dwarf_function_identities(binary))
    rows = grouped.get("same", [])
    assert len({row.address for row in rows}) == 2
    assert all(row.address > image_base for row in rows)

    addr2name = {row.address: row.name for row in rows}
    result = DecompilationResult(
        binary_path=binary,
        binary_name=binary.stem,
        decompiler=DecompilerMetadata(decompiler_name="pe-rva-fixture"),
        functions={
            f"rva-{index}": FunctionDecompilation(
                name=f"sub_{row.address - image_base:x}",
                address=row.address - image_base,
                decompiled_code="int sub(void) { return 0; }",
            )
            for index, row in enumerate(rows)
        },
    )

    _driver()._relabel_to_dwarf(result, addr2name, binary)

    assert set(result.functions) == {f"same@0x{address:x}" for address in addr2name}
    assert {fd.address for fd in result.functions.values()} == set(addr2name)
    assert result.decompiler.failed_functions == []
    assert result.decompiler.extra["function_identity"] == "dwarf-low-pc"
