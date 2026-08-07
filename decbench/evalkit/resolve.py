"""Name <-> address resolution against a results tree's DWARF ground truth.

Mirrors the run driver's bookkeeping so the eval-kit speaks the exact same
address space as the rest of DecBench:

* :func:`name_to_addr` follows ``project_source_functions``
  (``scripts/run_benchmark.py``): DWARF ``DW_TAG_subprogram`` entries with a
  ``low_pc``, optionally filtered to the project's own translation units via
  ``DW_AT_decl_file`` stems (the compiled ``.i``/``.ii`` stems).
* :class:`AddrLookup` follows ``_relabel_to_dwarf``'s tolerance rules when
  mapping a reported address back to a DWARF name: exact, Thumb ``addr & ~1``,
  PE ``addr + min_vaddr`` (ImageBase), and both combined.
* :func:`discover_binary` follows ``PipelineExecutor._discover_existing_binaries``:
  only real linked ELF/PE files count (``compiled/`` also holds ``.i`` files and
  IDA leftovers like ``bash.id0``).

Addresses everywhere are "ELF-file-space": DWARF ``low_pc`` ints, i.e. the
virtual addresses encoded in the binary's own headers (ELF program-header
vaddrs; PE ``ImageBase + RVA``).
"""

from __future__ import annotations

import logging
import os
import struct
from pathlib import Path

from decbench.utils.langs import PREPROC_EXTS, build_stem_index, strip_source_ext

_l = logging.getLogger(__name__)


def source_stems(tree: Path, opt: str, project: str) -> set[str]:
    """Stems of the project's preprocessed (``.i``/``.ii``) units at ``opt``.

    These are the ``DW_AT_decl_file`` filter used to keep only functions defined
    in the project's own sources (excluding bundled gnulib etc.). An empty set
    means the tree has no preprocessed files for this slice (caller decides
    whether to fall back to an unfiltered walk).
    """
    compiled = Path(tree) / opt / project / "compiled"
    return {f.stem for ext in PREPROC_EXTS for f in compiled.glob(f"*{ext}")}


def _dwarf_addr_to_name(binary: Path, stems: set[str] | None) -> dict[int, str]:
    """DWARF subprogram walk: ``low_pc -> DW_AT_name`` (decl-file-filtered).

    Mirrors ``project_source_functions`` (scripts/run_benchmark.py) including its
    DWARF v4/v5 ``decl_file`` index handling, the ``DW_AT_specification`` chase
    that finds C++ out-of-line definitions, the source-extension-agnostic stem
    comparison, and the object-prefixed stem match (``mydoom-main.i`` <-> decl
    ``main.c``). When ``stems`` is None the decl-file filter is skipped and every
    named subprogram with a ``low_pc`` is kept. Returns an empty map when the
    binary has no usable DWARF.
    """
    from decbench.utils import binfmt

    try:
        dw = binfmt.dwarf_info(binary)
    except Exception as e:  # noqa: BLE001
        _l.warning("DWARF read failed for %s: %s", binary, e)
        return {}
    if dw is None:
        return {}
    addr2name: dict[int, str] = {}
    file_tables: dict[int, list[str | None]] = {}
    stem_index = build_stem_index(stems or ())
    try:
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                    continue
                name = binfmt.die_str_attr(die, "DW_AT_name")
                if name is None:
                    continue
                if stems is not None:
                    fi, owner = binfmt.die_attr_owner(die, "DW_AT_decl_file")
                    if fi is None:
                        continue
                    files = binfmt.cu_file_table(dw, owner.cu, file_tables)
                    if not (0 <= fi.value < len(files)) or files[fi.value] is None:
                        continue
                    stem = strip_source_ext(os.path.basename(files[fi.value]))  # type: ignore[arg-type]
                    if stem not in stem_index and not any(
                        s.endswith("-" + stem) or s.endswith("_" + stem) for s in stem_index
                    ):
                        continue
                addr2name[int(die.attributes["DW_AT_low_pc"].value)] = name
    except Exception as e:  # noqa: BLE001
        _l.warning("DWARF walk failed for %s: %s", binary, e)
        return {}
    return addr2name


def name_to_addr(
    binary: Path,
    names: set[str] | None = None,
    stems: set[str] | None = None,
) -> dict[str, int]:
    """Map function names to their DWARF ``low_pc`` addresses.

    ``stems`` restricts the walk to functions declared in those translation
    units (see :func:`_dwarf_addr_to_name`); ``names`` restricts the result to
    just those functions. An ambiguous name (several distinct addresses) keeps
    the lowest address and logs a warning.
    """
    addr2name = _dwarf_addr_to_name(Path(binary), stems)
    by_name: dict[str, list[int]] = {}
    for addr, nm in addr2name.items():
        if names is not None and nm not in names:
            continue
        by_name.setdefault(nm, []).append(addr)
    out: dict[str, int] = {}
    for nm, addrs in by_name.items():
        if len(addrs) > 1:
            _l.warning(
                "%s: name %r is ambiguous in DWARF (%s); keeping the lowest address",
                Path(binary).name,
                nm,
                ", ".join(hex(a) for a in sorted(addrs)),
            )
        out[nm] = min(addrs)
    return out


class AddrLookup:
    """Address -> DWARF-name lookup with ``_relabel_to_dwarf``'s tolerances.

    ``name_for`` tries, in order: the exact address, the Thumb-cleared address
    (``addr & ~1`` — ARM tools report Thumb entry points with the LSB set), the
    rebased address (``addr + min_vaddr`` — PE submissions that report bare RVAs
    reach the DWARF ``ImageBase + RVA`` VA), and the rebased Thumb-cleared form.
    """

    def __init__(self, addr_to_name: dict[int, str], min_vaddr: int = 0) -> None:
        self._map = {int(a): n for a, n in addr_to_name.items()}
        self.min_vaddr = int(min_vaddr)

    @classmethod
    def for_binary(cls, binary: Path, stems: set[str] | None = None) -> AddrLookup:
        """Build a lookup from a binary's DWARF (decl-file-filtered when ``stems``)."""
        from decbench.decompilers.raw import common

        binary = Path(binary)
        return cls(_dwarf_addr_to_name(binary, stems), common.elf_min_vaddr(binary))

    def name_for(self, addr: int) -> str | None:
        """The DWARF name at ``addr``, or None when no tolerance rule matches."""
        a = int(addr)
        return (
            self._map.get(a)
            or self._map.get(a & ~1)
            or self._map.get(a + self.min_vaddr)
            or self._map.get((a + self.min_vaddr) & ~1)
        )


def _is_linked_elf(path: Path) -> bool:
    """A linked ELF (executable or shared object) — mirrors the executor's check."""
    try:
        with open(path, "rb") as f:
            if f.read(4) != b"\x7fELF":
                return False
            f.seek(16)
            e_type = struct.unpack("<H", f.read(2))[0]
            return e_type in (2, 3)
    except (OSError, struct.error):
        return False


def discover_binary(tree: Path, opt: str, project: str, stem_or_file: str) -> Path:
    """Locate a compiled binary in ``<tree>/<opt>/<project>/compiled/``.

    ``stem_or_file`` may be a full filename (e.g. ``libacl.so.1.1.2301``) or the
    file stem used by manifests/checkpoints (``Path(file).stem``). Only real
    linked ELF/PE files are considered — ``compiled/`` also holds ``.i`` files
    and decompiler leftovers. Raises :class:`FileNotFoundError` with context
    when nothing matches.
    """
    from decbench.utils import binfmt

    compiled = Path(tree) / opt / project / "compiled"
    if not compiled.is_dir():
        raise FileNotFoundError(f"no compiled directory for {project}/{opt} (looked in {compiled})")
    candidates: list[Path] = []
    for entry in sorted(compiled.iterdir()):
        if not entry.is_file() or entry.is_symlink():
            continue
        if _is_linked_elf(entry):
            candidates.append(entry)
            continue
        info = binfmt.detect(entry)
        if info is not None and info.fmt == "pe":
            candidates.append(entry)
    exact = [c for c in candidates if c.name == stem_or_file]
    if exact:
        return exact[0]
    by_stem = [c for c in candidates if c.stem == stem_or_file]
    if len(by_stem) > 1:
        _l.warning(
            "%s/%s: stem %r matches several binaries (%s); using %s",
            project,
            opt,
            stem_or_file,
            ", ".join(c.name for c in by_stem),
            by_stem[0].name,
        )
    if by_stem:
        return by_stem[0]
    raise FileNotFoundError(
        f"binary {stem_or_file!r} not found for {project}/{opt} in {compiled} "
        f"(ELF/PE candidates: {', '.join(c.name for c in candidates) or 'none'})"
    )
