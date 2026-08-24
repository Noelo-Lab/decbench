"""ARM/Thumb function extraction and disassembly mode.

The ARM ELF ABI encodes Thumb state in bit 0 of an ``STT_FUNC`` symbol value:
a function recorded at ``0x08000001`` begins at ``0x08000000``. Ignoring the
marker caused final binaries and relocatable objects to be sliced one byte late,
then decoded in A32 mode. Capstone can return plausible wrong instructions or an
empty listing for that input.

The production byte-match metric does not award an automatic perfect score to
two empty listings: it falls back to raw-byte similarity. The defect is still
metric-unsound because the intended normalized instruction comparison silently
becomes a comparison of misaligned bytes or wrong-mode instructions.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from decbench.metrics.byte_match import _disassemble_bytes
from decbench.utils import binfmt

pytestmark = pytest.mark.skipif(
    shutil.which("arm-none-eabi-gcc") is None,
    reason="arm-none-eabi-gcc not available",
)

_SRC = """
int lcd_add(int a, int b) { int t = a + b; return t * 3; }
int lcd_sub(int a, int b) { return a - b; }
"""

_TEXT_BASE = 0x08000000
_EXPECTED = {
    "lcd_add": (
        bytes.fromhex("084400eb40007047"),
        ["add r0, r1", "add.w r0, r0, r0, lsl #1", "bx lr"],
    ),
    "lcd_sub": (bytes.fromhex("401a7047"), ["subs r0, r0, r1", "bx lr"]),
}


@pytest.fixture(scope="module")
def thumb_artifacts(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """An unstripped Cortex-M4 Thumb object and linked ELF."""
    directory = tmp_path_factory.mktemp("thumb")
    source = directory / "fixture.c"
    obj = directory / "fixture.o"
    elf = directory / "fixture.elf"
    source.write_text(_SRC)
    subprocess.run(
        [
            "arm-none-eabi-gcc",
            "-mcpu=cortex-m4",
            "-mthumb",
            "-g",
            "-O1",
            "-c",
            str(source),
            "-o",
            str(obj),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "arm-none-eabi-gcc",
            "-nostdlib",
            "-Wl,--entry=lcd_add",
            f"-Wl,-Ttext={_TEXT_BASE:#x}",
            str(obj),
            "-o",
            str(elf),
        ],
        check=True,
        capture_output=True,
    )
    return obj, elf


@pytest.fixture(scope="module")
def arm_elf(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A real A32 negative control for Thumb-state detection."""
    directory = tmp_path_factory.mktemp("arm")
    source = directory / "fixture.c"
    elf = directory / "fixture.elf"
    source.write_text(_SRC)
    subprocess.run(
        [
            "arm-none-eabi-gcc",
            "-march=armv7-a",
            "-marm",
            "-g",
            "-O1",
            "-nostdlib",
            "-Wl,--entry=lcd_add",
            f"-Wl,-Ttext={_TEXT_BASE:#x}",
            str(source),
            "-o",
            str(elf),
        ],
        check=True,
        capture_output=True,
    )
    return elf


def test_symbols_really_carry_the_thumb_bit(thumb_artifacts: tuple[Path, Path]) -> None:
    """Guard the ABI premise against a toolchain behavior change."""
    from elftools.elf.elffile import ELFFile

    _, elf_path = thumb_artifacts
    with elf_path.open("rb") as stream:
        symtab = ELFFile(stream).get_section_by_name(".symtab")
        assert symtab is not None
        values = {
            symbol.name: symbol["st_value"]
            for symbol in symtab.iter_symbols()
            if symbol.name in _EXPECTED
        }

    assert values
    assert all(value & 1 for value in values.values()), values


@pytest.mark.parametrize("name", sorted(_EXPECTED))
def test_final_elf_extraction_masks_the_thumb_bit(
    thumb_artifacts: tuple[Path, Path], name: str
) -> None:
    expected_bytes, _ = _EXPECTED[name]
    address = _TEXT_BASE + (0 if name == "lcd_add" else 8)

    got = binfmt.function_bytes(thumb_artifacts[1], name, address)

    assert got == expected_bytes


@pytest.mark.parametrize("name", sorted(_EXPECTED))
def test_relocatable_object_extraction_masks_the_thumb_bit(
    thumb_artifacts: tuple[Path, Path], name: str
) -> None:
    expected_bytes, _ = _EXPECTED[name]

    got = binfmt.object_text_bytes(thumb_artifacts[0], name)

    assert got == expected_bytes


@pytest.mark.parametrize("name", sorted(_EXPECTED))
def test_thumb_functions_decode_in_thumb_mode(
    thumb_artifacts: tuple[Path, Path], name: str
) -> None:
    expected_bytes, expected_asm = _EXPECTED[name]
    address = _TEXT_BASE + (0 if name == "lcd_add" else 8)
    elf_path = thumb_artifacts[1]

    assert binfmt.elf_function_is_thumb(elf_path, name, address) is True
    info = binfmt.detect(elf_path)
    assert info is not None
    arch_mode = binfmt.capstone_arch_mode(info, thumb=True)

    assert _disassemble_bytes(expected_bytes, address, arch_mode) == expected_asm


def test_a32_function_is_not_classified_as_thumb(arm_elf: Path) -> None:
    assert binfmt.elf_function_is_thumb(arm_elf, "lcd_add", _TEXT_BASE) is False


def test_arm_elf_attributes_select_mclass_only_for_cortex_m(
    thumb_artifacts: tuple[Path, Path], arm_elf: Path
) -> None:
    assert binfmt.elf_is_arm_mclass(thumb_artifacts[1]) is True
    assert binfmt.elf_is_arm_mclass(arm_elf) is False


@pytest.mark.parametrize("name", sorted(_EXPECTED))
def test_source_instruction_addresses_select_thumb_mode(
    thumb_artifacts: tuple[Path, Path],
    name: str,
) -> None:
    from decbench.metrics.variable_match import (
        _die_ranges,
        instruction_addresses,
        open_source_binary_context,
    )

    elf_path = thumb_artifacts[1]
    context = open_source_binary_context(elf_path)
    try:
        ((_identity, (_cu, die)),) = [
            item for item in context.functions.items() if item[0][0] == name
        ]
        ranges = _die_ranges(die, context.dwarfinfo)
        start = min(begin for begin, _end in ranges)
        end = max(finish for _begin, finish in ranges)

        addresses = instruction_addresses(
            context.elf,
            start,
            end,
            context,
            function_name=name,
        )
    finally:
        context.close()

    expected_bytes, _expected_asm = _EXPECTED[name]
    assert addresses[0] == start
    assert addresses[-1] < end
    assert len(addresses) == len(
        _disassemble_bytes(
            expected_bytes,
            start,
            binfmt.capstone_arch_mode(binfmt.BinInfo("elf", "arm", 32), thumb=True),
        )
    )


def test_wrong_mode_is_silently_not_instruction_equivalent(
    thumb_artifacts: tuple[Path, Path],
) -> None:
    elf_path = thumb_artifacts[1]
    info = binfmt.detect(elf_path)
    assert info is not None
    arm_mode = binfmt.capstone_arch_mode(info, thumb=False)
    sub_bytes, sub_asm = _EXPECTED["lcd_sub"]

    assert _disassemble_bytes(sub_bytes, _TEXT_BASE + 8, arm_mode) != sub_asm
