"""Read thin Mach-O DWARF without changing the benchmark's existing metrics.

The binary and its companion are supplied by the evaluator, never the producer.
Universal binaries and ambiguous/missing debug companions are not resolved.
"""

import struct
from pathlib import Path

from decbench.utils.binfmt import _DWARF_SECS, _build_dwarfinfo

_MAGICS = {
    b"\xce\xfa\xed\xfe": ("<", 32),
    b"\xcf\xfa\xed\xfe": ("<", 64),
    b"\xfe\xed\xfa\xce": (">", 32),
    b"\xfe\xed\xfa\xcf": (">", 64),
}
_MACHINES = {
    7: "x86",
    0x1000007: "x64",
    12: "ARM",
    0x100000C: "AArch64",
    18: "PowerPC",
    0x1000012: "PowerPC64",
}


def _thin_header(path: Path):
    """Return endian, address size, and machine only for a known thin header."""
    try:
        with path.open("rb") as stream:
            header = stream.read(16)
        if len(header) != 16 or header[:4] not in _MAGICS:
            return None
        endian, bits = _MAGICS[header[:4]]
        cpu, subtype, file_type = struct.unpack(endian + "III", header[4:16])
        machine = _MACHINES.get(cpu)
        if machine is None or bool(cpu & 0x01000000) != (bits == 64):
            return None
        return endian, bits // 8, machine, cpu, subtype, file_type
    except (OSError, struct.error):
        return None


def _image(path: Path):
    if _thin_header(path) is None:
        return None
    try:
        import lief

        images = lief.MachO.parse(str(path))
        return images[0] if images is not None and len(images) == 1 else None
    except (OSError, RuntimeError, ValueError, TypeError):
        return None


def _sections(image):
    sections = {}
    for section in image.sections:
        if section.segment_name != "__DWARF" or not section.name.startswith("__debug_"):
            continue
        name = "." + section.name[2:]
        if name == ".debug_str_offs":
            name = ".debug_str_offsets"
        if name in _DWARF_SECS:
            # Duplicate sections cannot safely be assigned a unique oracle.
            if name in sections:
                return None
            sections[name] = bytes(section.content)
    return sections


def _has_units(sections):
    return bool(sections and sections.get(".debug_info") and sections.get(".debug_abbrev"))


def macho_dwarf_info(path: Path, *, debug_path: Path | None = None):
    """Read embedded DWARF or a thin UUID/architecture-matched dSYM.

    Explicit ``debug_path`` selects a companion and is never silently ignored.
    Otherwise embedded DWARF is preferred and the canonical adjacent dSYM is
    used only if embedded sections are absent. Returns None when unsupported or
    identity cannot be established. Does not affect ``binfmt.dwarf_info``.
    """
    header = _thin_header(path)
    image = _image(path)
    if header is None or header[-1] not in (2, 6, 8) or image is None:
        return None
    sections = _sections(image) if debug_path is None else {}
    if sections is None:
        return None
    if not _has_units(sections):
        companion = debug_path if debug_path is not None else path.with_name(path.name + ".dSYM")
        if companion.is_dir():
            companion = companion / "Contents" / "Resources" / "DWARF" / path.name
        companion_header = _thin_header(companion)
        if (
            companion_header is None
            or companion_header[:-1] != header[:-1]
            or companion_header[-1] != 10
        ):
            return None
        debug = _image(companion)
        if debug is None or not image.has_uuid or not debug.has_uuid:
            return None
        image_uuid = bytes(image.uuid.uuid)
        debug_uuid = bytes(debug.uuid.uuid)
        if len(image_uuid) != 16 or not any(image_uuid) or image_uuid != debug_uuid:
            return None
        sections = _sections(debug)
    if not _has_units(sections):
        return None
    endian, address_size, machine, _, _, _ = header
    return _build_dwarfinfo(
        sections, little_endian=endian == "<", addr_size=address_size, march=machine
    )
