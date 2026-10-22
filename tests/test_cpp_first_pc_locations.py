"""Multiple native first-PC rows must converge without picking a convenient line."""

from pathlib import Path

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.cfg_identity import CfgJoin, NativeSource, SourceCfgIndex, SourceLocation


def _resolve(text: str, locations: tuple[SourceLocation, ...], name: str = "f") -> CfgJoin:
    index = SourceCfgIndex()
    index.add(text, "unit.ii")
    result = DecompilationResult(
        binary_path=Path("unused"),
        binary_name="fixture",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    result.add_function(FunctionDecompilation(name=name, address=16, decompiled_code=""))
    record = NativeSource(
        16, name, ("/src/unit.cpp",), None, "native:16", candidate_locations=locations
    )
    return index.resolve(result, {16: [record]})


def test_all_first_pc_rows_must_prove_the_same_definition() -> None:
    rows = (SourceLocation("/src/unit.cpp", 1), SourceLocation("/src/unit.cpp", 2))
    joined = _resolve('# 1 "/src/unit.cpp"\nint f(int x) {\nreturn x + 1;\n}\n', rows)
    assert set(joined.cfgs) == {"f"}
    assert joined.evidence["f"]["native_location_candidates"] == [
        {"path": row.path, "line": row.line} for row in rows
    ]
    assert joined.evidence["f"]["native_location_policy"] == (
        "all_first_pc_locations_same_definition"
    )


@pytest.mark.parametrize(
    "text,locations",
    [
        (
            '# 1 "/src/unit.cpp"\nint f(){return 1;}\nint g(){return 2;}\n',
            (SourceLocation("/src/unit.cpp", 1), SourceLocation("/src/unit.cpp", 2)),
        ),
        (
            '# 1 "/src/unit.cpp"\nint f(){return 1;}\n',
            (SourceLocation("/src/unit.cpp", 1), SourceLocation("/src/unit.cpp", 20)),
        ),
        (
            '# 1 "/src/unit.cpp"\nint f(){return 1;}\n',
            (SourceLocation("/src/unit.cpp", 1), SourceLocation("/other/unit.cpp", 1)),
        ),
        (
            '# 1 "/src/unit.cpp"\nint f(int x){return x;} int f(double x){return 1;}\n',
            (SourceLocation("/src/unit.cpp", 1), SourceLocation("/src/unit.cpp", 1)),
        ),
    ],
)
def test_unmapped_or_conflicting_candidates_remain_ambiguous(
    text: str, locations: tuple[SourceLocation, ...]
) -> None:
    joined = _resolve(text, locations)
    assert not joined.cfgs
    assert joined.evidence["f"]["status"] == "ambiguous_native_source_location"


@pytest.mark.parametrize(
    "text,name,status",
    [
        (
            '# 1 "/src/unit.cpp"\ntemplate<class T> int f(T x){\nreturn x;\n}\n',
            "f",
            "unsupported_template_specialization",
        ),
        (
            '# 1 "/src/unit.cpp"\nint g(int x){\nreturn x;\n}\n',
            "f",
            "source_name_mismatch",
        ),
    ],
)
def test_convergence_does_not_bypass_other_qualification(text: str, name: str, status: str) -> None:
    joined = _resolve(
        text, (SourceLocation("/src/unit.cpp", 1), SourceLocation("/src/unit.cpp", 2)), name
    )
    assert not joined.cfgs
    assert joined.evidence[name]["status"] == status


def test_zero_line_is_not_removed_to_make_other_locations_converge() -> None:
    joined = _resolve(
        '# 1 "/src/unit.cpp"\nint f(){return 1;}\n',
        (SourceLocation("/src/unit.cpp", 0), SourceLocation("/src/unit.cpp", 1)),
    )
    assert not joined.cfgs


def test_singular_native_location_keeps_its_legacy_contract() -> None:
    record = NativeSource(
        16, "f", ("/src/unit.cpp",), SourceLocation("/src/unit.cpp", 1), "native:16"
    )
    assert record.locations == (record.location,)


def test_native_transport_keeps_candidates_separate_from_legacy_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from decbench.utils import binfmt
    from decbench.utils.cfg_identity import native_sources
    from decbench.utils.pdb_info import PdbFunction, PdbInfo

    image = tmp_path / "native.exe"
    image.write_bytes(b"native identity fixture")
    function = PdbFunction(
        "f",
        16,
        24,
        "unit.obj",
        ("/src/unit.cpp",),
        16,
        24,
        first_source_locations=(("/src/unit.cpp", 1), ("/src/unit.cpp", 2)),
    )
    info = PdbInfo(tmp_path / "native.pdb", "fixture", 1, (function,))
    monkeypatch.setattr(binfmt, "dwarf_info", lambda path: None)
    monkeypatch.setattr(binfmt, "pdb_info", lambda path: info)
    monkeypatch.setattr(binfmt, "native_debug_paths", lambda path: ())
    native = native_sources(image, {16})[16][0]
    assert native.location is None
    assert native.locations == (
        SourceLocation("/src/unit.cpp", 1),
        SourceLocation("/src/unit.cpp", 2),
    )
    assert function.source_file is None and function.source_line == 0


def test_c13_retains_distinct_source_rows_at_identical_native_pc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import struct

    from decbench.utils import pdb_info

    name = b"/src/unit.cpp\0"
    strings = struct.pack("<III", 0xEFFEEFFE, 1, len(name)) + name
    monkeypatch.setattr(pdb_info, "_named_stream", lambda msf, stream: strings)
    checksums = struct.pack("<IBB", 0, 0, 0) + b"\0\0"
    lines = struct.pack("<IHHI", 0, 1, 0, 4)
    lines += struct.pack("<III", 0, 2, 28)
    lines += struct.pack("<IIII", 0, 1, 0, 2)
    data = struct.pack("<II", 0xF4, len(checksums)) + checksums
    data += struct.pack("<II", 0xF2, len(lines)) + lines
    assert pdb_info._module_lines(None, data, 0, len(data), lambda seg, off, size: 16) == [
        (16, "/src/unit.cpp", 1),
        (16, "/src/unit.cpp", 2),
    ]
