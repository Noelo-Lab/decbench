"""Tests for the shared executable-section / DWARF-target function filter.

Every backend (raw, declib, dockerized r2dec) routes its "is this function
benchmarkable?" question through ``raw.common.should_skip_function``. These
tests pin the section layouts that broke it: the single-``.text`` binary that
must stay unchanged, u-boot's ``.text`` + ``.text_rest`` split, freertos'
``-ffunction-sections`` fan-out, and a degenerate zero-size ``.text``.

The range reader is :func:`common.executable_code_ranges`, which accepts every
file-backed ``SHF_EXECINSTR`` section except the linkage scaffolding
(``.init``/``.fini``/``.iplt``/``.plt*``). It is fail-closed: an unreadable or
unsupported binary yields an EMPTY range collection that rejects every address,
and the DWARF-target exemption is what keeps that from zeroing a run.

The ELFs are built byte-by-byte here rather than taken from the results tree so
the tests are hermetic. Sections carry real file-backed content because the
range reader measures a section by the bytes it actually has.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from decbench.decompilers.raw import common

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_NOBITS = 8

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
AX = SHF_ALLOC | SHF_EXECINSTR


def _write_elf(
    path: Path,
    sections: list[tuple[str, int, int, int, int]],
    *,
    with_section_headers: bool = True,
) -> Path:
    """Write a minimal ELF64 whose section table lists ``sections``.

    Each entry is ``(name, sh_addr, sh_size, sh_flags, sh_type)``. Every
    non-NOBITS section gets ``sh_size`` real bytes at a real ``sh_offset`` so
    the reader measures the size the caller asked for.
    """
    names = [""] + [s[0] for s in sections] + [".shstrtab"]
    shstrtab = b"\x00".join(n.encode() for n in names) + b"\x00"
    name_off: dict[str, int] = {}
    off = 0
    for n in names:
        name_off[n] = off
        off += len(n) + 1

    ehsize = 64
    shentsize = 64
    shstrtab_off = ehsize

    body = bytearray()
    body_off = shstrtab_off + len(shstrtab)
    data_offsets: dict[int, int] = {}
    for index, (_nm, _addr, size, _flags, stype) in enumerate(sections):
        if stype == SHT_NOBITS or size <= 0:
            data_offsets[index] = 0
            continue
        data_offsets[index] = body_off + len(body)
        body += bytes(size)
    shoff = body_off + len(body)

    shdrs = [(b"", 0, 0, 0, 0, SHT_NULL, 0)]
    for index, (nm, addr, size, flags, stype) in enumerate(sections):
        shdrs.append((nm.encode(), name_off[nm], addr, size, flags, stype, data_offsets[index]))
    shdrs.append(
        (b".shstrtab", name_off[".shstrtab"], 0, len(shstrtab), 0, SHT_STRTAB, shstrtab_off)
    )

    shnum = len(shdrs)
    shstrndx = shnum - 1

    ehdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    ehdr += struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type = ET_EXEC
        0x3E,  # e_machine = x86-64
        1,  # e_version
        0,  # e_entry
        0,  # e_phoff
        shoff,
        0,  # e_flags
        ehsize,
        56,  # e_phentsize
        0,  # e_phnum
        shentsize,
        shnum if with_section_headers else 0,
        shstrndx if with_section_headers else 0,
    )
    assert len(ehdr) == ehsize

    table = b""
    for _nm, noff, addr, size, flags, stype, data_off in shdrs:
        table += struct.pack(
            "<IIQQQQIIQQ",
            noff,
            stype,
            flags,
            addr,
            data_off,
            size,
            0,  # sh_link
            0,  # sh_info
            1,  # sh_addralign
            0,  # sh_entsize
        )

    path.write_bytes(ehdr + shstrtab + bytes(body) + table)
    return path


# --------------------------------------------------------------------- layouts
def _single_text(tmp_path: Path) -> Path:
    """An ordinary x86-64 binary: one .text, plus .init/.plt/.fini around it."""
    return _write_elf(
        tmp_path / "single.elf",
        [
            (".init", 0x1000, 0x20, AX, SHT_PROGBITS),
            (".plt", 0x1020, 0x60, AX, SHT_PROGBITS),
            (".plt.sec", 0x1080, 0x40, AX, SHT_PROGBITS),
            (".text", 0x1100, 0x800, AX, SHT_PROGBITS),
            (".fini", 0x1900, 0x10, AX, SHT_PROGBITS),
            (".rodata", 0x2000, 0x100, SHF_ALLOC, SHT_PROGBITS),
        ],
    )


def _uboot_like(tmp_path: Path) -> Path:
    """u-boot: a 936-byte .text, then .efi_runtime, then a 486 KB .text_rest."""
    return _write_elf(
        tmp_path / "uboot.elf",
        [
            (".text", 0x60800000, 936, AX, SHT_PROGBITS),
            (".efi_runtime", 0x608003A8, 4984, AX, SHT_PROGBITS),
            (".text_rest", 0x60801720, 486208, AX, SHT_PROGBITS),
        ],
    )


def _function_sections(tmp_path: Path) -> Path:
    """freertos: -ffunction-sections, .text holds only newlib."""
    secs = [(".text", 0x78, 2935, AX, SHT_PROGBITS)]
    addr = 0xBF0
    for i in range(40):
        secs.append((f".text.fn{i}", addr, 0x40, AX, SHT_PROGBITS))
        addr += 0x40
    return _write_elf(tmp_path / "ffunc.elf", secs)


def _zero_size_text(tmp_path: Path) -> Path:
    return _write_elf(
        tmp_path / "zero.elf",
        [
            (".text", 0x14000000, 0, AX, SHT_PROGBITS),
            ("ER_ROM1", 0x14000000, 0x983C, AX, SHT_PROGBITS),
        ],
    )


# ----------------------------------------------------------------------- tests
def test_single_text_binary_is_unchanged(tmp_path: Path) -> None:
    """The common case must behave exactly as it did before multi-section support."""
    elf = _single_text(tmp_path)
    ranges = common.executable_code_ranges(elf)
    assert ranges == ((0x1100, 0x1900),)

    assert not common.should_skip_function("do_work", 0x1200, ranges)
    # PLT stubs / .init / .fini stay scaffolding and stay dropped.
    assert common.should_skip_function("puts", 0x1030, ranges)
    assert common.should_skip_function("frame_dummy", 0x1005, ranges)
    assert common.should_skip_function("_fini", 0x1900, ranges)
    # ...and so does anything in .rodata.
    assert common.should_skip_function("table", 0x2010, ranges)


def test_single_text_name_filter_still_off_inside_text(tmp_path: Path) -> None:
    """A user function called ``j_compress`` inside .text is not a thunk."""
    ranges = common.executable_code_ranges(_single_text(tmp_path))
    assert not common.should_skip_function("j_compress", 0x1200, ranges)
    assert common.should_skip_function("_start", 0x1200, ranges)


def test_text_rest_split_is_covered(tmp_path: Path) -> None:
    """u-boot's 486 KB .text_rest is code, not a data section."""
    elf = _uboot_like(tmp_path)
    ranges = common.executable_code_ranges(elf)
    # .text, .efi_runtime and .text_rest abut, so they coalesce into one span.
    assert ranges == ((0x60800000, 0x60801720 + 486208),)

    assert not common.should_skip_function("board_init", 0x60801720, ranges)
    assert not common.should_skip_function("do_bootm", 0x60870000, ranges)
    # .efi_runtime is executable u-boot code, so it is benchmarkable too.
    assert not common.should_skip_function("efi_reset_system", 0x608003A8, ranges)
    # Anything past the last executable section is still rejected.
    assert common.should_skip_function("blob", 0x60801720 + 486208, ranges)


def test_function_sections_are_covered(tmp_path: Path) -> None:
    """-ffunction-sections spreads code over one .text.<fn> per function."""
    elf = _function_sections(tmp_path)
    ranges = common.executable_code_ranges(elf)
    # Adjacent .text.fnN sections coalesce into one span next to .text.
    assert ranges == ((0x78, 0x78 + 2935), (0xBF0, 0xBF0 + 40 * 0x40))
    assert common.in_executable_code(0x78, ranges)
    for i in range(40):
        assert common.in_executable_code(0xBF0 + i * 0x40, ranges), f"fn{i}"
        assert not common.should_skip_function(f"fn{i}", 0xBF0 + i * 0x40, ranges)
    assert not common.in_executable_code(0xBF0 + 40 * 0x40, ranges)


def test_zero_size_text_does_not_hide_the_real_rom_section(tmp_path: Path) -> None:
    """A degenerate empty .text must not shadow the section that holds the code."""
    ranges = common.executable_code_ranges(_zero_size_text(tmp_path))
    assert ranges == ((0x14000000, 0x14000000 + 0x983C),)
    assert not common.should_skip_function("SWD_Sequence", 0x14001000, ranges)
    # CRT names are still dropped by name wherever they sit.
    assert common.should_skip_function("_start", 0x14001000, ranges)


def test_non_text_named_code_section(tmp_path: Path) -> None:
    """A firmware ROM region is code even though it is not called ``.text``."""
    elf = _write_elf(tmp_path / "norom.elf", [("ER_ROM1", 0x14000000, 0x100, AX, SHT_PROGBITS)])
    assert common.executable_code_ranges(elf) == ((0x14000000, 0x14000100),)


def test_no_section_headers_is_fail_closed(tmp_path: Path) -> None:
    """No section table => empty ranges => every non-target address is rejected."""
    elf = _write_elf(
        tmp_path / "noshdr.elf",
        [(".text", 0x1000, 0x100, AX, SHT_PROGBITS)],
        with_section_headers=False,
    )
    ranges = common.executable_code_ranges(elf)
    assert ranges == ()
    assert common.should_skip_function("do_work", 0x1000, ranges)
    # The DWARF-target exemption is what keeps fail-closed from zeroing a run.
    assert not common.should_skip_function("do_work", 0x1000, ranges, {0x1000})


def test_non_elf_inputs_are_fail_closed(tmp_path: Path) -> None:
    """Mach-O / garbage / missing files yield empty ranges, and must not crash."""
    macho = tmp_path / "a.dylib"
    macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
    assert common.executable_code_ranges(macho) == ()

    assert common.executable_code_ranges(tmp_path / "does-not-exist") == ()


def test_data_and_nobits_sections_are_ignored(tmp_path: Path) -> None:
    """A non-executable or NOBITS section contributes no range."""
    elf = _write_elf(
        tmp_path / "odd.elf",
        [
            (".text", 0x1000, 0x100, AX, SHT_PROGBITS),
            (".text.data", 0x2000, 0x100, SHF_ALLOC, SHT_PROGBITS),
            (".text.bss", 0x3000, 0x100, AX, SHT_NOBITS),
        ],
    )
    assert common.executable_code_ranges(elf) == ((0x1000, 0x1100),)


def test_overlapping_sections_merge(tmp_path: Path) -> None:
    elf = _write_elf(
        tmp_path / "dup.elf",
        [
            (".text", 0x1000, 0x200, AX, SHT_PROGBITS),
            (".text.dup", 0x1000, 0x200, AX, SHT_PROGBITS),
            (".text.overlap", 0x1100, 0x300, AX, SHT_PROGBITS),
            (".text.gap", 0x9000, 0x100, AX, SHT_PROGBITS),
        ],
    )
    ranges = common.executable_code_ranges(elf)
    assert ranges == ((0x1000, 0x1400), (0x9000, 0x9100))
    assert common.in_executable_code(0x13FF, ranges)
    assert not common.in_executable_code(0x1400, ranges)
    assert not common.in_executable_code(0x8FFF, ranges)
    assert common.in_executable_code(0x9000, ranges)


def test_dwarf_target_exemption_beats_the_section_rule(tmp_path: Path) -> None:
    ranges = common.executable_code_ranges(_single_text(tmp_path))
    far_away = 0x50000
    assert common.should_skip_function("mystery", far_away, ranges)
    assert not common.should_skip_function("mystery", far_away, ranges, {far_away})
    # A non-target at the same place is still dropped.
    assert common.should_skip_function("mystery", far_away, ranges, {0x1234})


def test_dwarf_target_exemption_tolerates_the_thumb_bit(tmp_path: Path) -> None:
    """DWARF low_pc is even; ARM tools report a Thumb entry with the LSB set."""
    ranges = common.executable_code_ranges(_single_text(tmp_path))
    assert not common.should_skip_function("thumb_fn", 0x40001, ranges, {0x40000})
    assert not common.should_skip_function("thumb_fn", 0x40000, ranges, {0x40001})


@pytest.mark.parametrize("targets", [None, set(), {0x1234}])
def test_no_targets_keeps_the_old_behaviour(tmp_path: Path, targets) -> None:
    ranges = common.executable_code_ranges(_single_text(tmp_path))
    assert common.should_skip_function("puts", 0x1030, ranges, targets)
    assert not common.should_skip_function("do_work", 0x1200, ranges, targets)


def test_unknown_ranges_still_fall_back_to_the_name_filter() -> None:
    """``None`` (not ``()``) is the legacy "ranges unknown" signal."""
    assert common.in_executable_code(0x1200, None)
    assert not common.should_skip_function("SWD_Sequence", 0x14001000, None)
    assert common.should_skip_function("thunk_memcpy", 0x14001000, None)


def test_in_executable_code_accepts_a_legacy_single_range() -> None:
    assert common.in_executable_code(0x1200, (0x1100, 0x1900))
    assert not common.in_executable_code(0x1000, (0x1100, 0x1900))
    assert common.in_text(0x1200, (0x1100, 0x1900))


def test_addr_targets_of_keeps_only_ints() -> None:
    assert common.addr_targets_of(None) == set()
    assert common.addr_targets_of(set()) == set()
    assert common.addr_targets_of({1, 2}) == {1, 2}
    assert common.addr_targets_of({"main", "helper"}) == set()
    assert common.addr_targets_of({True, False}) == set()


def test_every_backend_shares_one_rule() -> None:
    """r2dec's exemption and the raw path resolve to the same shared filter."""
    from decbench.decompilers import dockerized

    assert dockerized._addr_targets_of is common.addr_targets_of
    # r2dec's wrapper forwards straight through to the shared filter, exemption
    # and all, so the two paths cannot drift apart again.
    assert dockerized._skip_r2_function("puts", 0x1030, ((0x1100, 0x1900),))
    assert not dockerized._skip_r2_function("puts", 0x1030, ((0x1100, 0x1900),), {0x1030})
    assert common.in_text is not None
