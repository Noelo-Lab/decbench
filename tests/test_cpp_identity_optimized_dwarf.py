"""Validate function identity with real optimized/inlined C++ DWARF."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from decbench.metrics.type_match import extract_ground_truth_types_by_address
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.function_identity import dwarf_function_identities, identities_by_name


def _emits_elf() -> bool:
    """Whether the local ``g++`` links ELF, which pyelftools needs to read DWARF.

    Presence of ``g++`` is not enough: on macOS it is a clang driver that emits
    Mach-O, so every DWARF assertion in this module raised ``ELFError`` instead
    of skipping. Probe the linker output once and skip honestly off Linux.
    """
    if shutil.which("g++") is None:
        return False
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "probe.cpp"
        binary = Path(directory) / "probe"
        source.write_text("int main() { return 0; }\n")
        try:
            subprocess.run(
                ["g++", "-g", str(source), "-o", str(binary)],
                check=True,
                capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return False
        return binary.read_bytes()[:4] == b"\x7fELF"


pytestmark = pytest.mark.skipif(
    not _emits_elf(),
    reason="an ELF-producing g++ is required (pyelftools cannot read Mach-O)",
)

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


def test_namespace_scoped_overloads_reach_the_address_keyed_ground_truth(tmp_path: Path) -> None:
    """TypeMatch's address map must see subprograms nested in a C++ scope.

    ``alpha::same`` and ``beta::same`` are ``DW_TAG_subprogram`` DIEs inside a
    ``DW_TAG_namespace``, so a walk over the compile unit's *direct children*
    never reaches them. Identity extraction already walks the whole DIE tree; if
    the ground-truth walk is shallower, an overload is correctly named
    ``same@0x...`` and then has no entry at its address, so it drops out of the
    metric silently instead of scoring.

    The assertion is on the address being *present*: at O2 a parameter may be
    optimized away, and an empty-but-present list is the authoritative answer
    this extractor is designed to give.
    """
    source = tmp_path / "scoped.cpp"
    binary = tmp_path / "scoped"
    source.write_text(SRC)
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-g", "-fno-builtin", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )

    rows = identities_by_name(dwarf_function_identities(binary)).get("same", [])
    addresses = {row.address for row in rows}
    assert len(addresses) == 2, "fixture must produce two distinct concrete overloads"

    by_address = extract_ground_truth_types_by_address(binary)

    missing = addresses - set(by_address)
    assert not missing, (
        "namespace-scoped overloads are absent from the address-keyed ground "
        f"truth: {sorted(hex(address) for address in missing)}"
    )
