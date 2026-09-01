"""Binary-format helpers shared by the type_match and byte_match metrics.

Lets the metrics work on **PE** (MinGW-built Windows malware) as well as **ELF**,
and — critically for byte_match — recompile the decompiled code *the same way the
source was compiled*: with the toolchain and arch/opt flags that match the
original binary's own format and architecture.

What's here:
  * :func:`detect` — format (elf/pe/coff) + arch of a binary.
  * :func:`recompiler_for` / :func:`producer_flags` — the matching compiler and
    the original `-m*/-O*` flags (from the DWARF producer), so a recompile is
    "the same way as source"; :func:`tool_available` gates on it being installed.
  * :func:`capstone_arch_mode` — the right capstone arch for disassembly.
  * :func:`dwarf_info` / :func:`pe_dwarf_info` — a pyelftools ``DWARFInfo`` for an
    ELF *or* a PE (PE: read the `.debug_*` sections via objdump file offsets and
    build the DWARFInfo by hand — LIEF's community build has no DWARF reader and
    PE COFF long section names defeat name lookups).
  * :func:`function_bytes` / :func:`object_text_bytes` — original function bytes
    from a final ELF/PE, and the `.text` of a single-function recompiled object
    (ELF or COFF), for byte_match.
  * :func:`die_attr` / :func:`die_str_attr` / :func:`die_attr_owner` — read a DIE
    attribute through ``DW_AT_specification`` (and, in a C++ unit only,
    ``DW_AT_abstract_origin``), which is where C++ out-of-line definitions keep
    their name and decl file; :func:`cu_file_table` resolves the
    ``DW_AT_decl_file`` index, :func:`source_function_owners` maps function
    addresses to their defining translation units, and :func:`cu_is_cxx` reports
    the unit's language.
"""

from __future__ import annotations

import io
import platform
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

_ELF_MACHINES = {
    0x28: "arm",
    0xB7: "aarch64",
    0x3E: "x86-64",
    0x03: "x86",
    0xF3: "riscv",
    0x08: "mips",
    0x14: "ppc",
    0x15: "ppc64",
}
_PE_MACHINES = {
    0x14C: "x86",
    0x8664: "x86-64",
    0xAA64: "aarch64",
    0x1C0: "arm",
    0x1C2: "arm",
    0x1C4: "arm",
}


@dataclass
class BinInfo:
    fmt: str
    arch: str
    bits: int


def detect(path: Path) -> BinInfo | None:
    """Detect (format, arch, bits) of a linked binary, or None if unrecognized."""
    try:
        with open(path, "rb") as f:
            head = f.read(2)
            if head == b"\x7fE":
                f.seek(0)
                if f.read(4) != b"\x7fELF":
                    return None
                f.seek(18)
                arch = _ELF_MACHINES.get(struct.unpack("<H", f.read(2))[0], "other")
                bits = 64 if arch in ("x86-64", "aarch64", "ppc64") else 32
                return BinInfo("elf", arch, bits)
            if head == b"MZ":
                f.seek(0x3C)
                pe_off = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_off)
                if f.read(4) != b"PE\x00\x00":
                    return None
                arch = _PE_MACHINES.get(struct.unpack("<H", f.read(2))[0], "other")
                bits = 64 if arch in ("x86-64", "aarch64") else 32
                return BinInfo("pe", arch, bits)
    except (OSError, struct.error):
        return None
    return None


_HOST_NATIVE_ARCHES = {
    "x86_64": ("x86-64", "x86"),
    "amd64": ("x86-64", "x86"),
    "i386": ("x86",),
    "i486": ("x86",),
    "i586": ("x86",),
    "i686": ("x86",),
    "aarch64": ("aarch64",),
    "arm64": ("aarch64",),
}

_CROSS_ELF_GCC = {
    "x86-64": "x86_64-linux-gnu-gcc",
    "x86": "i686-linux-gnu-gcc",
    "arm": "arm-none-eabi-gcc",
    "aarch64": "aarch64-linux-gnu-gcc",
}


def recompiler_for(info: BinInfo) -> str | None:
    """The compiler that builds for this binary's format+arch (the 'same way').

    Returns the compiler executable name, or None for arch/format we can't
    recompile to. Callers should also check :func:`tool_available`.

    Bare ``gcc`` is the answer only where the host builds that architecture
    natively. Elsewhere it is the cross triplet, so a corpus built for a
    different architecture than the host abstains (no toolchain) instead of
    recompiling every function with the host's own ``-march``.
    """
    if info.fmt == "elf":
        if info.arch in _HOST_NATIVE_ARCHES.get(platform.machine().lower(), ()):
            return "gcc"
        return _CROSS_ELF_GCC.get(info.arch)
    if info.fmt == "pe":
        return {
            "x86": "i686-w64-mingw32-gcc",
            "x86-64": "x86_64-w64-mingw32-gcc",
        }.get(info.arch)
    return None


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# Codegen-relevant flags carried over from the original build (never -g). Only
# codegen-only, header-independent flags: dropping them made byte_match
# unwinnable for whole projects (e.g. -fzero-call-used-regs, -fomit-frame-pointer).
_FLAG_RE = re.compile(
    r"(?:^|\s)(-m(?:arch|tune|cpu|thumb|float-abi|fpu|abi)?=?\S*|-O[0-3sgz]?"
    r"|-f(?:no-)?(?:omit-frame-pointer|zero-call-used-regs=\S+|trapv|wrapv"
    r"|stack-protector(?:-strong|-all|-explicit)?|cf-protection(?:=\S+)?"
    r"|PIC|PIE|pic|pie|plt|common|short-enums|signed-char|unsigned-char"
    r"|strict-aliasing|jump-tables|delete-null-pointer-checks|stack-clash-protection"
    r"|optimize-sibling-calls|reorder-blocks(?:-and-partition)?|tree-vectorize"
    r"|unroll-loops|finite-math-only|fast-math|math-errno|trapping-math"
    r"|signed-zeros|associative-math|reciprocal-math|unsafe-math-optimizations"
    r"|single-precision-constant|float-store|excess-precision=\S+)(?=\s|$))"
)


def producer_flags(path: Path) -> list[str]:
    """Extract the original codegen flags (-m*/-march/-O*) from the DWARF producer.

    These let byte_match recompile the same way the source was compiled.
    """
    try:
        di = dwarf_info(path)
        if di is None:
            return []
        for cu in di.iter_CUs():
            prod = cu.get_top_DIE().attributes.get("DW_AT_producer")
            if not prod:
                continue
            text = prod.value.decode() if isinstance(prod.value, bytes) else str(prod.value)
            flags = [m.group(1).strip() for m in _FLAG_RE.finditer(text)]
            return [f for f in flags if f and not f.startswith("-masm")]
    except Exception:
        pass
    return []


def capstone_arch_mode(
    info: BinInfo, thumb: bool = False, mclass: bool = False
) -> tuple[int, int] | None:
    """Return (capstone_arch, capstone_mode) for this binary, or None."""
    import capstone

    if info.arch in ("x86", "x86-64"):
        mode = capstone.CS_MODE_64 if info.bits == 64 else capstone.CS_MODE_32
        return capstone.CS_ARCH_X86, mode
    if info.arch == "arm":
        mode = capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM
        if thumb and mclass:
            mode |= capstone.CS_MODE_MCLASS
        return capstone.CS_ARCH_ARM, mode
    if info.arch == "aarch64":
        return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
    return None


def executable_regions(path: Path) -> tuple[tuple[int, bytes], ...]:
    """Return executable virtual-address regions from an ELF or PE binary."""
    info = detect(path)
    if info is None:
        return ()
    if info.fmt == "elf":
        try:
            from elftools.elf.elffile import ELFFile

            with path.open("rb") as stream:
                elf = ELFFile(stream)
                regions = [
                    (int(section["sh_addr"]), section.data())
                    for section in elf.iter_sections()
                    if int(section["sh_flags"]) & 0x4 and int(section["sh_size"]) > 0
                ]
            return tuple(sorted(regions))
        except Exception:
            return ()
    if info.fmt == "pe":
        try:
            import lief

            binary = lief.parse(str(path))
            if binary is None:
                return ()
            image_base = int(binary.optional_header.imagebase)
            regions = [
                (image_base + int(section.virtual_address), bytes(section.content))
                for section in binary.sections
                if int(section.characteristics) & 0x20000000 and section.content
            ]
            return tuple(sorted(regions))
        except Exception:
            return ()
    return ()


def elf_function_is_thumb(path: Path, func_name: str, address: int) -> bool:
    """Return whether an ARM ELF function symbol selects Thumb encoding.

    ARM ``STT_FUNC`` symbol values carry the Thumb-state marker in bit zero.
    Capstone accepts the same bytes in A32 mode without necessarily failing, so
    the symbol table is the authoritative mode source rather than a decoding
    heuristic.
    """
    try:
        from elftools.elf.elffile import ELFFile

        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf.header["e_machine"] != "EM_ARM":
                return False
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                return False
            symbol_table = cast(Any, symtab)
            exact_states: list[bool] = []
            named_states: list[bool] = []
            expected = address & ~1
            for symbol in symbol_table.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC" or symbol["st_size"] <= 0:
                    continue
                raw_address = int(symbol["st_value"])
                state = bool(raw_address & 1)
                if (raw_address & ~1) == expected:
                    exact_states.append(state)
                if symbol.name == func_name:
                    named_states.append(state)
            if exact_states:
                return exact_states[0] if len(set(exact_states)) == 1 else False
            if len(named_states) == 1:
                return named_states[0]
    except Exception:
        pass
    return False


def elf_is_arm_mclass(path: Path) -> bool:
    """Return whether an ARM ELF declares the microcontroller architecture profile."""
    try:
        from elftools.elf.elffile import ELFFile

        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf.header["e_machine"] != "EM_ARM":
                return False
            section = elf.get_section_by_name(".ARM.attributes")
            if section is None or not hasattr(section, "iter_subsections"):
                return False
            profiles = {
                int(attribute.value)
                for subsection in section.iter_subsections()
                if subsection.header.vendor_name == "aeabi"
                for scope in subsection.iter_subsubsections()
                for attribute in scope.iter_attributes()
                if attribute.tag == "TAG_CPU_ARCH_PROFILE"
            }
            return profiles == {ord("M")}
    except Exception:
        return False


_DWARF_SECS = (
    ".debug_info",
    ".debug_aranges",
    ".debug_abbrev",
    ".debug_frame",
    ".debug_str",
    ".debug_loc",
    ".debug_ranges",
    ".debug_line",
    ".debug_addr",
    ".debug_str_offsets",
    ".debug_line_str",
    ".debug_loclists",
    ".debug_rnglists",
    ".debug_types",
)


def _build_dwarfinfo(secs: dict[str, bytes], little_endian: bool, addr_size: int, march: str):
    from elftools.dwarf.dwarfinfo import DebugSectionDescriptor, DwarfConfig, DWARFInfo

    def mk(name: str):
        data = secs.get(name)
        return DebugSectionDescriptor(io.BytesIO(data), name, None, len(data), 0) if data else None

    return DWARFInfo(
        config=DwarfConfig(
            little_endian=little_endian, default_address_size=addr_size, machine_arch=march
        ),
        debug_info_sec=mk(".debug_info"),
        debug_aranges_sec=mk(".debug_aranges"),
        debug_abbrev_sec=mk(".debug_abbrev"),
        debug_frame_sec=mk(".debug_frame"),
        eh_frame_sec=None,
        debug_str_sec=mk(".debug_str"),
        debug_loc_sec=mk(".debug_loc"),
        debug_ranges_sec=mk(".debug_ranges"),
        debug_line_sec=mk(".debug_line"),
        debug_addr_sec=mk(".debug_addr"),
        debug_str_offsets_sec=mk(".debug_str_offsets"),
        debug_line_str_sec=mk(".debug_line_str"),
        debug_pubtypes_sec=None,
        debug_pubnames_sec=None,
        debug_loclists_sec=mk(".debug_loclists"),
        debug_rnglists_sec=mk(".debug_rnglists"),
        debug_sup_sec=None,
        gnu_debugaltlink_sec=None,
        debug_types_sec=mk(".debug_types"),
    )


def pe_dwarf_info(path: Path):
    """Build a self-contained pyelftools DWARFInfo from a PE's DWARF sections.

    PE COFF truncates section names to 8 chars (``.debug_info`` -> a string-table
    ref like ``/29``), so we get the real names + file offsets from ``objdump -h``
    and read the bytes straight out of the file.
    """
    objdump = shutil.which("objdump") or shutil.which("x86_64-w64-mingw32-objdump")
    if objdump is None:
        return None
    out = subprocess.run([objdump, "-h", str(path)], capture_output=True, text=True).stdout
    secs: dict[str, bytes] = {}
    raw = Path(path).read_bytes()
    for line in out.splitlines():
        m = re.match(
            r"\s*\d+\s+(\.debug[\w.]*)\s+([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)", line
        )
        if m:
            name, size, foff = m.group(1), int(m.group(2), 16), int(m.group(3), 16)
            secs[name] = raw[foff : foff + size]
    if ".debug_info" not in secs:
        return None
    info = detect(path)
    addr_size = 8 if (info and info.bits == 64) else 4
    march = {
        "x86": "x86",
        "x86-64": "x64",
        "arm": "ARM",
        "aarch64": "AArch64",
    }.get(info.arch if info is not None else "", "x64" if addr_size == 8 else "x86")
    return _build_dwarfinfo(secs, little_endian=True, addr_size=addr_size, march=march)


def dwarf_info(path: Path):
    """Return a pyelftools DWARFInfo for an ELF or PE binary, or None.

    For ELF, sections are read into memory so the result is self-contained
    (no dependence on an open file handle).
    """
    info = detect(path)
    if info is None:
        return None
    if info.fmt == "pe":
        return pe_dwarf_info(path)
    try:
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as f:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return None
            secs = {}
            for name in _DWARF_SECS:
                s = elf.get_section_by_name(name)
                if s is not None:
                    secs[name] = s.data()
            if ".debug_info" not in secs:
                return None
            addr_size = 8 if info.bits == 64 else 4
            march = {"x86-64": "x64", "x86": "x86", "arm": "ARM", "aarch64": "AArch64"}.get(
                info.arch, "x64"
            )
            return _build_dwarfinfo(secs, elf.little_endian, addr_size, march)
    except Exception:
        return None


_DIE_REF_MAX_HOPS = 4

# DW_LANG_C_plus_plus and its dated successors (03/11/14/17/20/23).
_CXX_LANGS = frozenset({0x04, 0x19, 0x1A, 0x21, 0x2A, 0x2B, 0x33})

_SPEC_ONLY = ("DW_AT_specification",)
_SPEC_AND_ORIGIN = ("DW_AT_specification", "DW_AT_abstract_origin")


def cu_is_cxx(cu) -> bool:
    """True when the compilation unit's ``DW_AT_language`` is a C++ dialect."""
    try:
        attr = cu.get_top_DIE().attributes.get("DW_AT_language")
    except Exception:
        return False
    return attr is not None and attr.value in _CXX_LANGS


def die_attr_owner(die, name: str):
    """``(attribute, owning DIE)`` for ``name``, following DIE reference chains.

    gcc splits an out-of-line C++ member definition in two: the defining DIE
    carries ``DW_AT_low_pc`` but NO ``DW_AT_name``/``DW_AT_decl_file``, which
    live on the in-class declaration it points at via ``DW_AT_specification``
    (and that declaration may itself forward once more, e.g. a template
    instantiation). Following the chain is what makes a C++ binary's functions
    visible at all.

    ``DW_AT_specification`` is a C++-only construct, so following it can never
    change a C result. ``DW_AT_abstract_origin`` is NOT — in C, gcc uses it for
    the out-of-line copy it keeps of a function it also inlined, and following
    it would newly surface ~10-20% more functions in the existing C corpus
    (measured: grep at O2 goes 262 -> 314). That hop is therefore taken only in
    a C++ compilation unit, which leaves every C binary bit-identical.

    The owning DIE is returned because a CU-relative attribute value such as
    ``DW_AT_decl_file`` must be read against ITS CU's line program, not the
    starting DIE's.
    """
    cur = die
    refs = _SPEC_AND_ORIGIN if cu_is_cxx(die.cu) else _SPEC_ONLY
    for _ in range(_DIE_REF_MAX_HOPS + 1):
        attr = cur.attributes.get(name)
        if attr is not None:
            return attr, cur
        nxt = None
        for ref in refs:
            if ref in cur.attributes:
                try:
                    nxt = cur.get_DIE_from_attribute(ref)
                except Exception:
                    nxt = None
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def die_attr(die, name: str):
    """The attribute ``name``, following DIE reference chains (:func:`die_attr_owner`)."""
    return die_attr_owner(die, name)[0]


def die_str_attr(die, name: str) -> str | None:
    """:func:`die_attr` decoded to ``str``, or None when absent."""
    attr = die_attr(die, name)
    if attr is None:
        return None
    val = attr.value
    return val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)


def cu_file_table(dwarfinfo, cu, cache: dict[int, list] | None = None) -> list:
    """A CU's ``DW_AT_decl_file`` index table, optionally memoized by CU offset.

    DW_AT_decl_file is 1-based pre-DWARF5 and 0-based in DWARF5; the leading
    placeholder entry makes the index line up either way.
    """
    if cache is not None:
        cached = cache.get(cu.cu_offset)
        if cached is not None:
            return cached
    lp = dwarfinfo.line_program_for_CU(cu)
    version = 4
    if lp is not None:
        version = lp.header.get("version", cu.header.get("version", 4))
    files: list = [] if version >= 5 else [None]
    if lp is not None:
        for fe in lp["file_entry"]:
            nm = fe.name
            files.append(nm.decode("utf-8", "replace") if isinstance(nm, bytes) else nm)
    if cache is not None:
        cache[cu.cu_offset] = files
    return files


def source_function_owners(path: Path, source_stems: set[str]) -> dict[int, tuple[str, str]]:
    """Map DWARF function addresses to ``(name, defining source-TU stem)``.

    Only definitions whose ``DW_AT_decl_file`` matches one of ``source_stems``
    are returned. Object-prefixed preprocessed stems such as ``program-main``
    match a declaration file named ``main.c``.
    """
    if not source_stems:
        return {}

    from decbench.utils.langs import build_stem_index, strip_source_ext

    try:
        dw = dwarf_info(path)
    except Exception:  # noqa: BLE001
        return {}
    if dw is None:
        return {}

    owners: dict[int, tuple[str, str]] = {}
    file_tables: dict[int, list] = {}
    stem_index = build_stem_index(source_stems)
    try:
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                    continue
                name = die_str_attr(die, "DW_AT_name")
                if name is None:
                    continue
                fi, owner = die_attr_owner(die, "DW_AT_decl_file")
                if fi is None:
                    continue
                files = cu_file_table(dw, owner.cu, file_tables)
                if not (0 <= fi.value < len(files)) or files[fi.value] is None:
                    continue
                decl_stem = strip_source_ext(Path(files[fi.value]).name)
                matched = stem_index.get(decl_stem)
                if matched is None:
                    suffix_matches = [
                        original
                        for normalized, original in stem_index.items()
                        if normalized.endswith("-" + decl_stem)
                        or normalized.endswith("_" + decl_stem)
                    ]
                    matched = suffix_matches[0] if len(suffix_matches) == 1 else None
                if matched is not None:
                    owners[int(die.attributes["DW_AT_low_pc"].value)] = (name, matched)
    except Exception:  # noqa: BLE001
        return {}
    return owners


def _dwarf_function_range(path: Path, func_name: str) -> tuple[int, int] | None:
    """(low_pc, high_pc) absolute VA for a function, from DWARF."""
    di = dwarf_info(path)
    if di is None:
        return None
    for cu in di.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                continue
            nm = die.attributes.get("DW_AT_name")
            name = nm.value.decode() if nm and isinstance(nm.value, bytes) else None
            if name != func_name:
                continue
            lo = die.attributes["DW_AT_low_pc"].value
            hi_at = die.attributes.get("DW_AT_high_pc")
            if hi_at is None:
                return None
            hi = lo + hi_at.value if hi_at.form != "DW_FORM_addr" else hi_at.value
            return (lo, hi)
    return None


def function_bytes(path: Path, func_name: str, address: int) -> bytes | None:
    """Extract a function's machine-code bytes from a final ELF or PE binary."""
    info = detect(path)
    if info is None:
        return None
    if info.fmt == "elf":
        b = _elf_function_bytes(path, func_name, address)
        if b is not None:
            return b
    rng = _dwarf_function_range(path, func_name)
    if rng is None:
        return None
    lo, hi = rng
    if hi <= lo:
        return None
    try:
        import lief

        binary = lief.parse(str(path))
        data = binary.get_content_from_virtual_address(lo, hi - lo)
        return bytes(data) if data else None
    except Exception:
        return None


def _elf_function_bytes(path: Path, func_name: str, address: int) -> bytes | None:
    """Original ELF symtab-based extraction (kept for the ELF fast path)."""
    try:
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                return None
            is_arm = elf.header["e_machine"] == "EM_ARM"
            for sym in symtab.iter_symbols():
                raw_address = sym["st_value"]
                symbol_address = raw_address & ~1 if is_arm else raw_address
                if (
                    sym.name == func_name or symbol_address == address or raw_address == address
                ) and sym["st_size"] > 0:
                    addr, size = symbol_address, sym["st_size"]
                    for section in elf.iter_sections():
                        sa, ss = section["sh_addr"], section["sh_size"]
                        if sa <= addr < sa + ss:
                            return section.data()[addr - sa : addr - sa + size]
    except Exception:
        pass
    return None


def object_text_bytes(obj_path: Path, func_name: str) -> bytes | None:
    """`.text` of a recompiled single-function object (ELF .o or COFF .o).

    byte_match compiles one function, so the object's ``.text`` is essentially
    that function (alignment padding is dropped by the disassembler's nop skip).
    """
    info = detect(obj_path)
    if info is not None and info.fmt == "elf":
        b = _elf_object_function(obj_path, func_name)
        if b is not None:
            return b
    try:
        import lief

        binary = lief.parse(str(obj_path))
        if binary is None:
            return None
        for sec in binary.sections:
            if sec.name == ".text" or sec.name.startswith(".text"):
                return bytes(sec.content)
    except Exception:
        pass
    return None


def _elf_object_function(obj_path: Path, func_name: str) -> bytes | None:
    try:
        from elftools.elf.elffile import ELFFile

        with open(obj_path, "rb") as f:
            elf = ELFFile(f)
            text = elf.get_section_by_name(".text")
            symtab = elf.get_section_by_name(".symtab")
            if text is None or symtab is None:
                return None
            is_arm = elf.header["e_machine"] == "EM_ARM"
            for sym in symtab.iter_symbols():
                if sym.name == func_name and sym["st_size"] > 0:
                    off = sym["st_value"]
                    if is_arm:
                        off &= ~1
                    return text.data()[off : off + sym["st_size"]]
    except Exception:
        pass
    return None
