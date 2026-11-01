"""Tests for the unconnected thin Mach-O debug-reader building block."""

import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from decbench.utils import binfmt, macho_dwarf


def test_rejects_truncated_universal_and_unknown_mach_headers(tmp_path: Path) -> None:
    path = tmp_path / "input"
    for data in (
        b"",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe" + b"\0" * 16,
        b"\xcf\xfa\xed\xfe" + struct.pack("<II", 0x1234, 0),
    ):
        path.write_bytes(data)
        assert macho_dwarf.macho_dwarf_info(path) is None


def test_duplicate_dwarf_sections_abstain() -> None:
    section = SimpleNamespace(segment_name="__DWARF", name="__debug_info", content=[1])
    assert macho_dwarf._sections(SimpleNamespace(sections=[section, section])) is None


def test_rejects_missing_or_mismatched_uuid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "input"
    debug = tmp_path / "debug"
    # Sufficient for the local header gate; _image is replaced with controlled objects.
    header = b"\xcf\xfa\xed\xfe" + struct.pack("<III", 0x100000C, 0, 2)
    image.write_bytes(header)
    debug.write_bytes(b"\xcf\xfa\xed\xfe" + struct.pack("<III", 0x100000C, 0, 10))
    sections = [
        SimpleNamespace(segment_name="__DWARF", name=name, content=[1])
        for name in ("__debug_info", "__debug_abbrev")
    ]
    main = SimpleNamespace(sections=[], has_uuid=True, uuid=SimpleNamespace(uuid=bytes(range(16))))
    companion = SimpleNamespace(
        sections=sections, has_uuid=True, uuid=SimpleNamespace(uuid=bytes(reversed(range(16))))
    )
    monkeypatch.setattr(macho_dwarf, "_image", lambda path: main if path == image else companion)
    assert macho_dwarf.macho_dwarf_info(image, debug_path=debug) is None
    companion.has_uuid = False
    assert macho_dwarf.macho_dwarf_info(image, debug_path=debug) is None
    companion.has_uuid = True
    main.uuid.uuid = bytes(16)
    companion.uuid.uuid = bytes(16)
    assert macho_dwarf.macho_dwarf_info(image, debug_path=debug) is None


def test_rejects_architecture_or_subtype_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "input"
    debug = tmp_path / "debug"
    image.write_bytes(b"\xcf\xfa\xed\xfe" + struct.pack("<III", 0x100000C, 0, 2))
    obj = SimpleNamespace(sections=[], has_uuid=True, uuid=SimpleNamespace(uuid=bytes(range(16))))
    monkeypatch.setattr(macho_dwarf, "_image", lambda path: obj)
    for cpu, subtype in ((0x1000007, 0), (0x100000C, 2)):
        debug.write_bytes(b"\xcf\xfa\xed\xfe" + struct.pack("<III", cpu, subtype, 10))
        assert macho_dwarf.macho_dwarf_info(image, debug_path=debug) is None


def test_companion_must_be_dsym_and_source_must_be_linked_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image, companion = tmp_path / "image", tmp_path / "debug"
    uuid = bytes(range(16))

    def section(name):
        return SimpleNamespace(segment_name="__DWARF", name=name, content=[1])

    main = SimpleNamespace(sections=[], has_uuid=True, uuid=SimpleNamespace(uuid=uuid))
    debug = SimpleNamespace(
        sections=[section("__debug_info"), section("__debug_abbrev")],
        has_uuid=True,
        uuid=SimpleNamespace(uuid=uuid),
    )
    monkeypatch.setattr(macho_dwarf, "_image", lambda path: main if path == image else debug)

    def header(file_type):
        return b"\xcf\xfa\xed\xfe" + struct.pack("<III", 0x100000C, 0, file_type)

    image.write_bytes(header(2))
    companion.write_bytes(header(2))  # Matching UUID and architecture, wrong file kind.
    assert macho_dwarf.macho_dwarf_info(image, debug_path=companion) is None
    companion.write_bytes(header(10))
    image.write_bytes(header(1))  # Relocatable object is not a linked image.
    assert macho_dwarf.macho_dwarf_info(image, debug_path=companion) is None


@pytest.mark.skipif(sys.platform != "darwin", reason="requires Darwin compiler and dSYM tools")
def test_native_dsym_is_uuid_matched_and_self_contained(tmp_path: Path) -> None:
    cc = shutil.which("clang")
    dsymutil = shutil.which("dsymutil")
    strip = shutil.which("strip")
    if not all((cc, dsymutil, strip)):
        pytest.skip("clang, dsymutil and strip are required")
    source = tmp_path / "unit.c"
    source.write_text("int value(int x) { return x + 3; }\nint main(void) { return value(1); }\n")
    obj, image = tmp_path / "unit.o", tmp_path / "unit"
    subprocess.run(
        [cc, "-g", "-O0", "-gdwarf-4", "-c", str(source), "-o", str(obj)],
        check=True,
        capture_output=True,
    )
    subprocess.run([cc, str(obj), "-o", str(image)], check=True, capture_output=True)
    bundle = tmp_path / "unit.dSYM"
    subprocess.run([dsymutil, str(image), "-o", str(bundle)], check=True, capture_output=True)
    # A real dSYM from a different linked image must never be used as oracle.
    other_source, other_object, other_image = (
        tmp_path / "other.c",
        tmp_path / "other.o",
        tmp_path / "other",
    )
    other_source.write_text(
        "int value(int x) { return x + 4; }\nint main(void) { return value(2); }\n"
    )
    subprocess.run(
        [cc, "-g", "-O0", "-gdwarf-4", "-c", str(other_source), "-o", str(other_object)],
        check=True,
        capture_output=True,
    )
    subprocess.run([cc, str(other_object), "-o", str(other_image)], check=True, capture_output=True)
    assert (
        macho_dwarf.macho_dwarf_info(
            other_image, debug_path=bundle / "Contents" / "Resources" / "DWARF" / "unit"
        )
        is None
    )
    stripped = tmp_path / "stripped"
    subprocess.run([strip, "-S", "-o", str(stripped), str(image)], check=True, capture_output=True)
    stripped.replace(image)
    dwarf = macho_dwarf.macho_dwarf_info(image)
    assert dwarf is not None
    shutil.rmtree(bundle)
    names = {
        die.attributes["DW_AT_name"].value
        for cu in dwarf.iter_CUs()
        for die in cu.iter_DIEs()
        if "DW_AT_name" in die.attributes
    }
    assert b"value" in names
    assert macho_dwarf.macho_dwarf_info(image) is None
    # The existing evaluation entry point has not been wired to the new reader.
    assert binfmt.dwarf_info(image) is None
