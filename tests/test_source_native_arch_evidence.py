"""Cross-format instruction addresses for source-side variable evidence."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from decbench.metrics.type_evidence import PreprocessedSourceContext, build_source_evidence
from decbench.metrics.type_match import extract_ground_truth_type_index
from decbench.metrics.variable_match import (
    SourceBinaryEvidenceContext,
    _decl_location,
    _line_program_rows,
    instruction_addresses,
    open_source_binary_context,
)
from decbench.utils import binfmt


def _synthetic_context(
    info: binfmt.BinInfo,
    address: int,
    code: bytes,
) -> SourceBinaryEvidenceContext:
    return SourceBinaryEvidenceContext(
        stream=None,
        elf=None,
        dwarfinfo=None,
        functions={},
        machine=info.arch,
        text_address=None,
        text_data=None,
        binary_info=info,
        code_regions=((address, code),),
    )


@pytest.mark.parametrize(
    ("info", "address", "code", "expected"),
    [
        (
            binfmt.BinInfo("pe", "x86", 32),
            0x401000,
            bytes.fromhex("5589e5c3"),
            [0x401000, 0x401001, 0x401003],
        ),
        (
            binfmt.BinInfo("elf", "aarch64", 64),
            0x400800,
            bytes.fromhex("000080d2c0035fd6"),
            [0x400800, 0x400804],
        ),
    ],
)
def test_instruction_addresses_use_binary_format_architecture(
    info: binfmt.BinInfo,
    address: int,
    code: bytes,
    expected: list[int],
) -> None:
    context = _synthetic_context(info, address, code)

    assert instruction_addresses(None, address, address + len(code), context) == expected


def test_instruction_addresses_decode_thumb_at_canonical_addresses() -> None:
    address = 0x08001000
    code = bytes.fromhex("084400eb40007047")
    context = _synthetic_context(binfmt.BinInfo("elf", "arm", 32), address, code)

    addresses = instruction_addresses(None, address | 1, address + len(code), context)

    assert addresses == [address, address + 2, address + 6]


def test_instruction_addresses_decode_cortex_m_system_registers() -> None:
    address = 0x08001000
    code = bytes.fromhex("eff31183 83f31188")
    context = _synthetic_context(binfmt.BinInfo("elf", "arm", 32), address, code)
    context.arm_mclass = True

    addresses = instruction_addresses(None, address | 1, address + len(code), context)

    assert addresses == [address, address + 4]


def test_line_table_version_controls_pre_dwarf5_file_indexes() -> None:
    source = SimpleNamespace(name=b"source.c")
    header = {"version": 3, "file_entry": [source, SimpleNamespace(name=b"header.h")]}
    line_program = SimpleNamespace(
        header=header,
        get_entries=lambda: [
            SimpleNamespace(
                state=SimpleNamespace(
                    file=1,
                    line=7,
                    address=0x1000,
                    end_sequence=False,
                )
            )
        ],
    )
    cu = {"version": 5}
    die = SimpleNamespace(
        cu=cu,
        attributes={
            "DW_AT_decl_file": SimpleNamespace(value=1),
            "DW_AT_decl_line": SimpleNamespace(value=7),
        },
    )

    assert _line_program_rows(cu, line_program) == ((0x1000,), (("source.c", 7),))
    assert _decl_location(die, line_program) == ("source.c", 7)


@pytest.mark.skipif(
    shutil.which("i686-w64-mingw32-gcc") is None,
    reason="i686-w64-mingw32-gcc is required",
)
def test_pe_source_variables_receive_native_addresses(tmp_path: Path) -> None:
    compiler = "i686-w64-mingw32-gcc"
    source = tmp_path / "fixture.c"
    preprocessed = tmp_path / "fixture.i"
    binary = tmp_path / "fixture.exe"
    source.write_text(
        "int target(int value) {\n"
        "    int local = value + 7;\n"
        "    return local * 3;\n"
        "}\n"
        "int main(void) { return target(1); }\n"
    )
    subprocess.run(
        [compiler, "-E", str(source), "-o", str(preprocessed)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [compiler, "-g", "-O0", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    ground_truth = extract_ground_truth_type_index(binary)
    address = next(
        function_address
        for function_address, functions in ground_truth.items()
        if "target" in functions
    )
    variables: list[dict[str, Any]] = ground_truth[address]["target"]
    context = PreprocessedSourceContext([preprocessed], binary.name)

    result = build_source_evidence(binary, "target", address, variables, context)

    assert result.error is None
    assert result.native_address_variables > 0
    assert all(
        address <= instruction
        for variable in result.variables
        for instruction in variable.addresses
    )
    binary_context = open_source_binary_context(binary)
    try:
        assert binary_context.binary_info == binfmt.BinInfo("pe", "x86", 32)
        assert binary_context.code_regions
    finally:
        binary_context.close()
