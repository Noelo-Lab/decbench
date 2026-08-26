"""Tests for the shared ``.text``-family / DWARF-target function filter.

Every backend (raw, declib, dockerized r2dec) routes its "is this function
benchmarkable?" question through ``raw.common.should_skip_function``. These
tests pin the section layouts that broke it: the single-``.text`` binary that
must stay unchanged, u-boot's ``.text`` + ``.text_rest`` split, freertos'
``-ffunction-sections`` fan-out, and a degenerate zero-size ``.text``.

The ELFs are built byte-by-byte here rather than taken from the results tree so
the tests are hermetic.
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

    Each entry is ``(name, sh_addr, sh_size, sh_flags, sh_type)``. Only the
    section header table is meaningful — no program headers, no real content —
    which is all the filter reads.
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
    body_off = shstrtab_off + len(shstrtab)
    shoff = body_off

    shdrs = [(b"", 0, 0, 0, 0, SHT_NULL)]
    for nm, addr, size, flags, stype in sections:
        shdrs.append((nm.encode(), name_off[nm], addr, size, flags, stype))
    shdrs.append((b".shstrtab", name_off[".shstrtab"], 0, len(shstrtab), 0, SHT_STRTAB))

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
    for _nm, noff, addr, size, flags, stype in shdrs:
        data_off = shstrtab_off if stype == SHT_STRTAB else 0
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

    path.write_bytes(ehdr + shstrtab + table)
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
    ranges = common.elf_text_ranges(elf)
    assert ranges == [(0x1100, 0x1900)]

    assert not common.should_skip_function("do_work", 0x1200, ranges)
    # PLT stubs / .init / .fini stay outside the family and stay dropped.
    assert common.should_skip_function("puts", 0x1030, ranges)
    assert common.should_skip_function("frame_dummy", 0x1005, ranges)
    assert common.should_skip_function("_fini", 0x1900, ranges)
    # ...and so does anything in .rodata.
    assert common.should_skip_function("table", 0x2010, ranges)


def test_single_text_name_filter_still_off_inside_text(tmp_path: Path) -> None:
    """A user function called ``j_compress`` inside .text is not a thunk."""
    ranges = common.elf_text_ranges(_single_text(tmp_path))
    assert not common.should_skip_function("j_compress", 0x1200, ranges)
    assert common.should_skip_function("_start", 0x1200, ranges)


def test_text_rest_split_is_covered(tmp_path: Path) -> None:
    """u-boot's 486 KB .text_rest is code, not a data section."""
    elf = _uboot_like(tmp_path)
    ranges = common.elf_text_ranges(elf)
    assert ranges == [(0x60800000, 0x608003A8), (0x60801720, 0x60801720 + 486208)]

    assert not common.should_skip_function("board_init", 0x60801720, ranges)
    assert not common.should_skip_function("do_bootm", 0x60870000, ranges)
    # .efi_runtime is not in the .text family, so the section rule still drops it,
    # ...
    assert common.should_skip_function("efi_reset_system", 0x608003A8, ranges)
    # ...unless the driver asked for that exact address.
    assert not common.should_skip_function("efi_reset_system", 0x608003A8, ranges, {0x608003A8})


def test_function_sections_are_covered(tmp_path: Path) -> None:
    """-ffunction-sections spreads code over one .text.<fn> per function."""
    elf = _function_sections(tmp_path)
    ranges = common.elf_text_ranges(elf)
    # Adjacent .text.fnN sections coalesce into one span next to .text.
    assert ranges is not None
    assert common.in_text(0x78, ranges)
    for i in range(40):
        assert common.in_text(0xBF0 + i * 0x40, ranges), f"fn{i}"
        assert not common.should_skip_function(f"fn{i}", 0xBF0 + i * 0x40, ranges)
    assert not common.in_text(0xBF0 + 40 * 0x40, ranges)


def test_zero_size_text_is_treated_as_unknown(tmp_path: Path) -> None:
    """A degenerate empty .text must not become an empty range that drops all."""
    ranges = common.elf_text_ranges(_zero_size_text(tmp_path))
    assert ranges is None
    # Falls back to the name filter: real functions kept, thunks dropped.
    assert not common.should_skip_function("SWD_Sequence", 0x14001000, ranges)
    assert common.should_skip_function("thunk_memcpy", 0x14001000, ranges)


def test_no_text_family_section(tmp_path: Path) -> None:
    elf = _write_elf(tmp_path / "norom.elf", [("ER_ROM1", 0x14000000, 0x100, AX, SHT_PROGBITS)])
    assert common.elf_text_ranges(elf) is None


def test_no_section_headers(tmp_path: Path) -> None:
    elf = _write_elf(
        tmp_path / "noshdr.elf",
        [(".text", 0x1000, 0x100, AX, SHT_PROGBITS)],
        with_section_headers=False,
    )
    assert common.elf_text_ranges(elf) is None


def test_non_elf_inputs(tmp_path: Path) -> None:
    """PE / Mach-O / garbage must degrade to the name filter, not crash."""
    pe = tmp_path / "a.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 128)
    assert common.elf_text_ranges(pe) is None

    macho = tmp_path / "a.dylib"
    macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
    assert common.elf_text_ranges(macho) is None

    assert common.elf_text_ranges(tmp_path / "does-not-exist") is None


def test_data_and_nobits_text_sections_are_ignored(tmp_path: Path) -> None:
    """A non-executable or NOBITS ``.text*`` section contributes no range."""
    elf = _write_elf(
        tmp_path / "odd.elf",
        [
            (".text", 0x1000, 0x100, AX, SHT_PROGBITS),
            (".text.data", 0x2000, 0x100, SHF_ALLOC, SHT_PROGBITS),
            (".text.bss", 0x3000, 0x100, AX, SHT_NOBITS),
        ],
    )
    assert common.elf_text_ranges(elf) == [(0x1000, 0x1100)]


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
    assert common.elf_text_ranges(elf) == [(0x1000, 0x1400), (0x9000, 0x9100)]
    ranges = common.elf_text_ranges(elf)
    assert common.in_text(0x13FF, ranges)
    assert not common.in_text(0x1400, ranges)
    assert not common.in_text(0x8FFF, ranges)
    assert common.in_text(0x9000, ranges)


def test_dwarf_target_exemption_beats_the_section_rule(tmp_path: Path) -> None:
    ranges = common.elf_text_ranges(_single_text(tmp_path))
    far_away = 0x50000
    assert common.should_skip_function("mystery", far_away, ranges)
    assert not common.should_skip_function("mystery", far_away, ranges, {far_away})
    # A non-target at the same place is still dropped.
    assert common.should_skip_function("mystery", far_away, ranges, {0x1234})


def test_dwarf_target_exemption_tolerates_the_thumb_bit(tmp_path: Path) -> None:
    """DWARF low_pc is even; ARM tools report a Thumb entry with the LSB set."""
    ranges = common.elf_text_ranges(_single_text(tmp_path))
    assert not common.should_skip_function("thumb_fn", 0x40001, ranges, {0x40000})
    assert not common.should_skip_function("thumb_fn", 0x40000, ranges, {0x40001})


@pytest.mark.parametrize("targets", [None, set(), {0x1234}])
def test_no_targets_keeps_the_old_behaviour(tmp_path: Path, targets) -> None:
    ranges = common.elf_text_ranges(_single_text(tmp_path))
    assert common.should_skip_function("puts", 0x1030, ranges, targets)
    assert not common.should_skip_function("do_work", 0x1200, ranges, targets)


def test_in_text_accepts_a_legacy_single_range() -> None:
    assert common.in_text(0x1200, (0x1100, 0x1900))
    assert not common.in_text(0x1000, (0x1100, 0x1900))
    assert common.in_text(0x1200, None)


def test_addr_targets_of_keeps_only_ints() -> None:
    assert common.addr_targets_of(None) == set()
    assert common.addr_targets_of(set()) == set()
    assert common.addr_targets_of({1, 2}) == {1, 2}
    assert common.addr_targets_of({"main", "helper"}) == set()
    assert common.addr_targets_of({True, False}) == set()


def test_every_backend_shares_one_rule() -> None:
    """r2dec's exemption and the raw path are literally the same function now."""
    from decbench.decompilers import declib_dec, dockerized

    assert dockerized._skip_r2_function is common.should_skip_function
    assert dockerized._addr_targets_of is common.addr_targets_of
    assert dockerized._elf_text_range is common.elf_text_ranges
    assert declib_dec._elf_text_range is common.elf_text_ranges
    assert common.elf_text_range is common.elf_text_ranges
