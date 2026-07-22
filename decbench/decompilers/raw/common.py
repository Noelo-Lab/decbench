"""Shared helpers for the raw (declib-free) decompiler backends.

This module re-implements the ELF / address bookkeeping that
``decbench.decompilers.declib_dec`` performs, so the raw backends can match
its output contract exactly *without* depending on declib:

* ``elf_min_vaddr`` — lowest ``PT_LOAD`` virtual address; adding it to a
  decompiler's lifted (0-based / image-base-relative) address yields the
  ELF-file-space address that DWARF uses.
* ``elf_text_range`` — ``[start, end)`` of the ``.text`` section, used to
  drop PLT stubs / import thunks that live in their own sections.
* ``SKIP_NAMES`` / ``SKIP_PREFIXES`` — CRT/compiler-generated functions and
  thunk/import name prefixes that are never benchmarked.
* ``should_skip_function`` / ``in_text`` — the name + section filter that
  ``declib_dec._enumerate_functions`` applies.
* ``narrow_to_source`` — the optional ``function_names`` restriction (with the
  same "fall back to everything if nothing matched" behaviour as declib_dec).
* ``dump_progress`` — the atomic partial-result pickle used by the run driver
  to recover a process that is killed by a hard timeout.
* ``extract_metrics`` — the gotos/bools structure counts.

Addresses everywhere in DecBench results are **ELF-file-space**
(``lifted + elf_base``); these helpers centralise that translation.
"""

from __future__ import annotations

import logging
import pickle
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from decbench.models.decompilation import DecompilationResult

_l = logging.getLogger(__name__)

# CRT/compiler-generated functions that are not user code. Copied verbatim
# from declib_dec so the raw backends discover the same benchmarkable set.
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

# Name prefixes for thunks/imports that should not be benchmarked.
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
            # COFF header is 20 bytes; the Optional Header magic follows it.
            opt = pe_off + 4 + 20
            f.seek(opt)
            magic = int.from_bytes(f.read(2), "little")
            if magic == 0x10B:  # PE32: ImageBase is a u32 at opt+28
                f.seek(opt + 28)
                return int.from_bytes(f.read(4), "little")
            if magic == 0x20B:  # PE32+: ImageBase is a u64 at opt+24
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


def elf_text_range(binary_path: Path) -> tuple[int, int] | None:
    """Get the ``[start, end)`` virtual-address range of the ``.text`` section.

    Used to exclude PLT stubs and import thunks, which live in their own
    sections (``.plt`` / ``.plt.sec``) outside ``.text``.
    """
    try:
        from elftools.elf.elffile import ELFFile

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            text = elf.get_section_by_name(".text")
            if text is None:
                return None
            start = text["sh_addr"]
            return (start, start + text["sh_size"])
    except Exception as e:  # noqa: BLE001
        _l.debug("Failed to read .text range for %s: %s", binary_path, e)
        return None


def in_text(file_addr: int, text_range: tuple[int, int] | None) -> bool:
    """Whether an ELF-file-space address falls inside ``.text``.

    When the ``.text`` range is unknown, everything is treated as "in text"
    (the name-prefix filter is the fallback in that case).
    """
    if text_range is None:
        return True
    return text_range[0] <= file_addr < text_range[1]


def should_skip_function(
    name: str,
    file_addr: int,
    text_range: tuple[int, int] | None,
) -> bool:
    """Replicate ``declib_dec._enumerate_functions`` filtering for one function.

    Args:
        name: function name (already non-empty checks happen here too).
        file_addr: function start address in ELF-file space
            (``lifted + elf_base``).
        text_range: ``.text`` ``[start, end)`` or ``None``.

    Returns:
        ``True`` if the function should be excluded from benchmarking.
    """
    if not name or name in SKIP_NAMES:
        return True
    if text_range is not None:
        # PLT stubs / import thunks live outside .text. Inside .text we trust
        # the section filter and never drop by name prefix (a user function may
        # legitimately be called e.g. "j_compress").
        if not in_text(file_addr, text_range):
            return True
    elif name.startswith(SKIP_PREFIXES):
        return True
    return False


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
    enumerated functions whose address is in that set. If nothing matches (an
    unexpected address-space mismatch) we fall back to the full list rather than
    silently producing an empty result.
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
        return filtered
    return target_funcs


def _addr_matches(addr: int, target_addrs: set[int]) -> bool:
    """Whether ``addr`` corresponds to a DWARF target, tolerating the ARM Thumb
    T-bit. DWARF ``low_pc`` is even; angr/phoenix report a Thumb function's entry
    with the LSB set (odd). Match the address as-is or with the Thumb bit cleared
    (and set, for the rare inverse) so Thumb functions narrow correctly instead
    of falling through to "decompile everything" and polluting the result with
    non-source ``sub_*`` bodies."""
    return addr in target_addrs or (addr & ~1) in target_addrs or (addr | 1) in target_addrs


def missing_targets(
    enumerated_addrs: Iterable[int],
    target_addrs: set[int] | None,
    text_range: tuple[int, int] | None,
) -> list[int]:
    """DWARF target addresses that a backend's auto-analysis did NOT discover.

    Used by the raw backends to *force-create* functions at addresses the tool
    missed on stripped firmware (vector/pointer-table functions), so DecBench
    measures decompilation quality rather than boundary discovery. Covered
    addresses are compared with Thumb even/odd normalization; results are the
    canonical (DWARF, even) target addresses, filtered to ``.text`` and to
    plausible code (drops a bogus ``low_pc`` of 0 seen in some DWARF).
    """
    if not target_addrs:
        return []
    covered: set[int] = set()
    for a in enumerated_addrs:
        covered.add(a)
        covered.add(a & ~1)
        covered.add(a | 1)
    out: list[int] = []
    for t in sorted(target_addrs):
        if t == 0:
            continue
        if t in covered or (t & ~1) in covered:
            continue
        if not in_text(t, text_range):
            continue
        out.append(t)
    return out


def extract_metrics(code: str) -> dict[str, Any]:
    """Extract basic structure metrics (matches ``declib_dec._extract_metrics``)."""
    return {
        "gotos": code.count("goto "),
        "bools": code.count(" && ") + code.count(" || "),
    }


def dump_progress(
    progress_path: Path | None,
    result: DecompilationResult,
) -> None:
    """Atomically pickle a partial :class:`DecompilationResult` to disk.

    Writes to a ``.tmp`` sibling and ``os.replace``s it into place so a reader
    (or a killed-then-restarted run) never sees a half-written file. Best
    effort: any failure is swallowed so it never breaks decompilation.
    """
    if progress_path is None:
        return
    try:
        tmp = progress_path.with_suffix(progress_path.suffix + ".tmp")
        tmp.write_bytes(pickle.dumps(result))
        tmp.replace(progress_path)
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
    # Binary search for the last line start <= pos.
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


def iter_unique(items: Iterable[Any]) -> list[Any]:
    """Stable de-duplication helper (preserves first-seen order)."""
    seen: set[Any] = set()
    out: list[Any] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out
