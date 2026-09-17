"""Validate function identity with real optimized/inlined C++ DWARF."""

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
from decbench.utils.function_identity import dwarf_function_identities, identities_by_name

pytestmark = pytest.mark.skipif(shutil.which("g++") is None, reason="g++ required")

SRC = r"""
namespace alpha { int same(int x) { return x + 1; } }
namespace beta  { int same(int x) { return x + 2; } }
inline int inline_helper(int x) { return x * 7 + 3; }
volatile int seed = 1;
int (*volatile alpha_ptr)(int) = &alpha::same;
int (*volatile beta_ptr)(int) = &beta::same;
int main() {
    int x = seed;
    return alpha_ptr(x) + beta_ptr(x) + inline_helper(x);
}
"""


def _driver():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_benchmark.py"
    spec = importlib.util.spec_from_file_location("optimized_identity_driver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_o2_inlined_dwarf_does_not_confuse_concrete_same_name_identity(tmp_path: Path) -> None:
    source = tmp_path / "optimized.cpp"
    binary = tmp_path / "optimized"
    source.write_text(SRC)
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-g", "-fno-builtin", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )

    with binary.open("rb") as stream:
        dwarf = ELFFile(stream).get_dwarf_info()
        inlined = 0
        referenced = 0
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_inlined_subroutine":
                    inlined += 1
                if (
                    "DW_AT_abstract_origin" in die.attributes
                    or "DW_AT_specification" in die.attributes
                ):
                    referenced += 1
    assert inlined > 0
    assert referenced > 0

    grouped = identities_by_name(dwarf_function_identities(binary))
    rows = grouped.get("same", [])
    assert len({row.address for row in rows}) == 2
    addr2name = {row.address: row.name for row in rows}

    result = DecompilationResult(
        binary_path=binary,
        binary_name=binary.stem,
        decompiler=DecompilerMetadata(decompiler_name="optimized-fixture"),
        functions={
            f"raw-{index}": FunctionDecompilation(
                name=f"sub_{row.address:x}",
                address=row.address,
                decompiled_code="int sub(void) { return 0; }",
            )
            for index, row in enumerate(rows)
        },
    )
    _driver()._relabel_to_dwarf(result, addr2name, binary)

    assert set(result.functions) == {f"same@0x{address:x}" for address in addr2name}
    assert {fd.address for fd in result.functions.values()} == set(addr2name)
