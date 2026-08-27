"""Shared helpers for the raw (declib-free) decompiler backends.

This module re-implements the ELF / address bookkeeping that
``decbench.decompilers.declib_dec`` performs, so the raw backends can match
its output contract exactly *without* depending on declib:

* ``elf_min_vaddr`` — lowest ``PT_LOAD`` virtual address; adding it to a
  decompiler's lifted (0-based / image-base-relative) address yields the
  ELF-file-space address that DWARF uses.
* ``executable_code_ranges`` — the disjoint file-backed executable section
  ranges in an ELF or PE binary (``.text``, the ``.text.<fn>`` fan-out from
  ``-ffunction-sections``, ``.text_rest``, ``ER_ROM1`` …), with the linkage
  scaffolding (``.init``, ``.fini``, ``.iplt``, ``.plt*``) excluded.
* ``SKIP_NAMES`` / ``SKIP_PREFIXES`` — CRT/compiler-generated functions and
  thunk/import name prefixes that are never benchmarked.
* ``should_skip_function`` / ``in_executable_code`` — the shared name and
  executable-section filter, with the DWARF-target exemption that keeps a
  function the driver explicitly asked for whatever section it landed in.
  Address comparisons tolerate the ARM Thumb T-bit (DWARF ``low_pc`` is even;
  angr reports Thumb entries odd).
* ``addr_targets_of`` — the int (address) half of the driver's function filter.
* ``narrow_to_source`` — the optional ``function_names`` restriction, applied
  fail-closed so an address mismatch cannot broaden a requested subset.
* ``dump_progress`` — the atomic partial-result pickle used by the run driver
  to recover a process that is killed by a hard timeout.
* ``extract_metrics`` — the gotos/bools structure counts.

Addresses everywhere in DecBench results are **ELF-file-space**
(``lifted + elf_base``); these helpers centralise that translation.
"""

from __future__ import annotations

import logging
import pickle
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeAlias, cast

from decbench.utils import binfmt

if TYPE_CHECKING:
    from decbench.models.decompilation import DecompilationResult

_l = logging.getLogger(__name__)
_PROGRESS_DUMP_TIMES: dict[Path, float] = {}

AddressRange: TypeAlias = tuple[int, int]
ExecutableCodeRanges: TypeAlias = tuple[AddressRange, ...]
CodeRangeFilter: TypeAlias = ExecutableCodeRanges | AddressRange | None

_NON_SOURCE_ELF_EXECUTABLE_SECTIONS = frozenset({".init", ".fini", ".iplt"})

SKIP_NAMES = frozenset(
    {
        "_start",
        "__libc_start_main",
        "__libc_csu_init",
        "__libc_csu_fini",
        "_init",
        "_fini",
        "__do_global_dtors_aux",
        "register_tm_clones",
        "deregister_tm_clones",
        "frame_dummy",
        "__libc_start_call_main",
        "_dl_relocate_static_pie",
        "__gmon_start__",
        "__stack_chk_fail",
    }
)

SKIP_PREFIXES = ("thunk_", "j_", "__imp_", ".plt", "_dl_")


def _pe_image_base(binary_path: Path) -> int | None:
    """Read the ImageBase (linked load VA) from a PE's Optional Header.

    Returns ``None`` for non-PE files. DWARF ``low_pc`` in a PE is the linked
    virtual address (``ImageBase + RVA``), but the decompilers load the image at
    its ImageBase and report ``ImageBase + RVA`` too, so their ``tool_addr -
    load_base`` yields the bare RVA. Feeding this ImageBase back as the "min
    vaddr" makes ``(tool_addr - load_base) + base`` reconstruct the full VA that
    matches DWARF (exactly as ``elf_min_vaddr`` does for ELF).
    """
    try:
        with open(binary_path, "rb") as f:
            head = f.read(0x40)
            if head[:2] != b"MZ":
                return None
            pe_off = int.from_bytes(head[0x3C:0x40], "little")
            f.seek(pe_off)
            sig = f.read(4)
            if sig != b"PE\x00\x00":
                return None
            opt = pe_off + 4 + 20
            f.seek(opt)
            magic = int.from_bytes(f.read(2), "little")
            if magic == 0x10B:
                f.seek(opt + 28)
                return int.from_bytes(f.read(4), "little")
            if magic == 0x20B:
                f.seek(opt + 24)
                return int.from_bytes(f.read(8), "little")
            return None
    except Exception as e:  # noqa: BLE001
        _l.debug("Failed to read PE ImageBase for %s: %s", binary_path, e)
        return None


def elf_min_vaddr(binary_path: Path) -> int:
    """Get the base virtual address to lift a decompiler's addresses into.

    For an ELF this is the lowest ``PT_LOAD`` virtual address; for a PE it is the
    ImageBase. Adding this to a decompiler's lifted (load-base-relative)
    addresses yields addresses in the binary's own link/file address space,
    matching DWARF debug info regardless of where the decompiler loaded it.
    (Named ``elf_*`` historically; it is format-aware — a PE returns its
    ImageBase, not 0, so PE function addresses line up with DWARF ``low_pc``.)
    """
    try:
        from elftools.elf.elffile import ELFFile

        with open(binary_path, "rb") as f:
            magic = f.read(4)
        if magic[:2] == b"MZ":
            base = _pe_image_base(binary_path)
            if base is not None:
                return base
            return 0
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            vaddrs = [seg["p_vaddr"] for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD"]
            return min(vaddrs) if vaddrs else 0
    except Exception as e:  # noqa: BLE001
        _l.debug("Failed to read min vaddr for %s: %s", binary_path, e)
        return 0


def executable_code_ranges(binary_path: Path) -> ExecutableCodeRanges:
    """Return the disjoint file-backed executable ranges of an ELF or PE binary.

    ELF linkage scaffolding (``.init``, ``.fini``, and ``.plt*``) is excluded,
    preserving the old literal-``.text`` filter's treatment of those sections
    while accepting real code layouts such as ``.text.*``, ``.text_rest``,
    ``ER_ROM1``, and ``.efi_runtime``.

    An empty result is fail-closed: callers must not treat an unreadable or
    unsupported binary as though every address were code.
    """

    info = binfmt.detect(binary_path)
    if info is not None and info.fmt == "elf":
        try:
            from elftools.elf.elffile import ELFFile

            with binary_path.open("rb") as stream:
                elf = ELFFile(stream)
                regions = tuple(
                    (int(section["sh_addr"]), section.data())
                    for section in elf.iter_sections()
                    if int(section["sh_flags"]) & 0x4
                    and section.header["sh_type"] != "SHT_NOBITS"
                    and int(section["sh_size"]) > 0
                    and section.name not in _NON_SOURCE_ELF_EXECUTABLE_SECTIONS
                    and not section.name.startswith(".plt")
                )
        except Exception:  # noqa: BLE001
            regions = ()
    else:
        regions = binfmt.executable_regions(binary_path)

    ranges = sorted((start, start + len(data)) for start, data in regions if data)
    merged: list[AddressRange] = []
    for start, end in ranges:
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def elf_text_range(binary_path: Path) -> AddressRange | None:
    """Return the literal ELF ``.text`` range for compatibility.

    New backend code must use :func:`executable_code_ranges`; this helper keeps
    the old return shape for callers that have not migrated yet.
    """

    try:
        from elftools.elf.elffile import ELFFile

        with binary_path.open("rb") as stream:
            section = ELFFile(stream).get_section_by_name(".text")
            if section is None:
                return None
            start = int(section["sh_addr"])
            return start, start + int(section["sh_size"])
    except Exception as error:  # noqa: BLE001
        _l.debug("Failed to read .text range for %s: %s", binary_path, error)
        return None


def _coerce_code_ranges(code_ranges: CodeRangeFilter) -> ExecutableCodeRanges | None:
    if code_ranges is None:
        return None
    if len(code_ranges) == 2 and all(type(value) is int for value in code_ranges):
        return (cast(AddressRange, code_ranges),)
    return cast(ExecutableCodeRanges, code_ranges)


def in_executable_code(file_addr: int, code_ranges: CodeRangeFilter) -> bool:
    """Whether a linked address belongs to one exact executable section range.

    ``None`` retains the legacy unknown-range behavior for compatibility. The
    new range reader returns an empty collection on failure, which rejects every
    address.
    """

    ranges = _coerce_code_ranges(code_ranges)
    if ranges is None:
        return True
    return any(start <= file_addr < end for start, end in ranges)


def in_text(file_addr: int, text_range: CodeRangeFilter) -> bool:
    """Compatibility name for :func:`in_executable_code`."""

    return in_executable_code(file_addr, text_range)


def should_skip_function(
    name: str,
    file_addr: int,
    code_ranges: CodeRangeFilter,
    addr_targets: set[int] | None = None,
) -> bool:
    """Replicate ``declib_dec._enumerate_functions`` filtering for one function.

    A function whose address is one of ``addr_targets`` (the DWARF ``low_pc``
    source functions the benchmark driver asked for) is a VERIFIED real function
    and is always kept, whatever section it landed in. This is the rule
    ``dockerized._skip_r2_function`` has always applied on the r2dec path and
    ``raw/dewolf_driver`` on the dewolf path; it now applies everywhere, so a
    binary whose code sits outside the section filter's reach no longer scores 0
    on some backends and not others. It is also what keeps the fail-closed empty
    range (an unreadable or unsupported binary) from dropping every function.

    Args:
        name: function name (already non-empty checks happen here too).
        file_addr: function start address in ELF-file space
            (``lifted + elf_base``).
        code_ranges: Executable section ranges, one legacy single range, or
            ``None`` for the legacy name-prefix fallback.
        addr_targets: the driver's DWARF ``low_pc`` set, if any.

    Returns:
        ``True`` if the function should be excluded from benchmarking.
    """
    if addr_targets and _addr_matches(file_addr, addr_targets):
        return False
    if not name or name in SKIP_NAMES:
        return True
    if code_ranges is not None:
        if not in_executable_code(file_addr, code_ranges):
            return True
    elif name.startswith(SKIP_PREFIXES):
        return True
    return False


def addr_targets_of(function_names: set[int] | set[str] | None) -> set[int]:
    """The int (ELF-file-space) addresses in the driver's function filter.

    The driver passes DWARF ``low_pc`` ints for a stripped binary and names for
    the legacy non-stripped path; only the ints can exempt by address.
    """
    if not function_names:
        return set()
    return {int(x) for x in function_names if isinstance(x, int) and not isinstance(x, bool)}


def narrow_to_source(
    target_funcs: list[tuple[str, int]],
    target_addrs: set[int] | None,
    *,
    backend: str,
    binary_name: str,
) -> list[tuple[str, int]]:
    """Restrict to the project's own source functions BY ADDRESS.

    The decompiler is given a fully-stripped binary (no symbols), so it knows
    functions only by address; ``target_addrs`` is the set of DWARF low_pc
    addresses (ELF-file space) for the project's source functions. We keep the
    enumerated functions whose address is in that set. An explicit filter is a
    hard scope boundary: if nothing matches, return an empty list rather than
    silently decompiling unrelated functions.
    """
    if not target_addrs:
        return target_funcs
    filtered = [(n, a) for (n, a) in target_funcs if _addr_matches(a, target_addrs)]
    if filtered:
        _l.debug(
            "raw/%s: filtered %d/%d functions to source set for %s",
            backend,
            len(filtered),
            len(target_funcs),
            binary_name,
        )
    else:
        _l.warning(
            "raw/%s: no enumerated address matched the requested source set for %s",
            backend,
            binary_name,
        )
    return filtered


def _addr_matches(addr: int, target_addrs: set[int]) -> bool:
    """Whether ``addr`` corresponds to a DWARF target, tolerating the ARM Thumb
    T-bit. DWARF ``low_pc`` is even; angr reports a Thumb function's entry
    with the LSB set (odd). Match the address as-is or with the Thumb bit cleared
    (and set, for the rare inverse) so Thumb functions narrow correctly instead
    of falling through to "decompile everything" and polluting the result with
    non-source ``sub_*`` bodies."""
    return addr in target_addrs or (addr & ~1) in target_addrs or (addr | 1) in target_addrs


def extract_metrics(code: str) -> dict[str, Any]:
    """Extract basic structure metrics (matches ``declib_dec._extract_metrics``)."""
    return {
        "gotos": code.count("goto "),
        "bools": code.count(" && ") + code.count(" || "),
    }


def dump_progress(
    progress_path: Path | None,
    result: DecompilationResult,
    *,
    min_interval_seconds: float = 5.0,
    force: bool = False,
) -> None:
    """Atomically pickle a partial :class:`DecompilationResult` to disk.

    Writes to a ``.tmp`` sibling and ``os.replace``s it into place so a reader
    (or a killed-then-restarted run) never sees a half-written file. Repeated
    calls are throttled because serializing a growing multi-thousand-function
    result after every function is quadratic in output size. Best effort: any
    failure is swallowed so it never breaks decompilation.
    """
    if progress_path is None:
        return
    now = time.monotonic()
    last_dump = _PROGRESS_DUMP_TIMES.get(progress_path)
    if (
        not force
        and last_dump is not None
        and min_interval_seconds > 0
        and now - last_dump < min_interval_seconds
    ):
        return
    try:
        tmp = progress_path.with_suffix(progress_path.suffix + ".tmp")
        tmp.write_bytes(pickle.dumps(result))
        tmp.replace(progress_path)
        _PROGRESS_DUMP_TIMES[progress_path] = now
    except Exception:  # noqa: BLE001 - progress dump is best-effort
        pass


def line_starts(text: str) -> list[int]:
    """Return the 0-based character offset at which each line of ``text`` starts.

    ``line_starts(text)[i]`` is the offset of line ``i`` (0-based). Used to turn
    a character position (as angr's ``map_pos_to_addr`` reports) into a 1-based
    line number.
    """
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def pos_to_line(pos: int, starts: list[int]) -> int:
    """Convert a 0-based character position into a 1-based line number."""
    import bisect

    idx = bisect.bisect_right(starts, pos) - 1
    if idx < 0:
        idx = 0
    return idx + 1


def merge_line_addresses(
    line_to_addrs: dict[int, set[int]],
) -> list:
    """Build a sorted ``list[LineMapping]`` from ``{line_number: {addrs}}``."""
    from decbench.models.decompilation import LineMapping

    out = []
    for line_num in sorted(line_to_addrs):
        addrs = line_to_addrs[line_num]
        if not addrs:
            continue
        out.append(LineMapping(line_number=int(line_num), addresses=sorted(int(a) for a in addrs)))
    return out
