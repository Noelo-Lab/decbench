"""Compilation-directory and recorded object/source unit provenance."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from decbench.utils.compilation_units import compilation_path, saved_temp_units


def _command(source: str = "/src/a.cpp", optimization: str = "-O0") -> dict:
    return {
        "directory": "/build",
        "file": source,
        "arguments": [
            "clang++",
            optimization,
            "-g",
            "-save-temps=obj",
            "-o",
            "obj/a.cpp.o",
            "-c",
            source,
        ],
    }


def test_saved_temps_require_exact_output_and_original_input(tmp_path: Path) -> None:
    database = tmp_path / "compile_commands.json"
    database.write_text(json.dumps([_command()]))
    bindings = saved_temp_units(database)
    assert set(bindings) == {"/build/obj/a.cpp"}
    assert bindings["/build/obj/a.cpp"].source_file == "/src/a.cpp"
    assert "/different/obj/a.cpp" not in bindings
    assert "/build/other/a.cpp" not in bindings
    assert compilation_path("src/a.cpp", "/build") == "/build/src/a.cpp"
    assert compilation_path("src/a.cpp") == "src/a.cpp"


def test_conflicting_commands_at_reused_object_output_abstain(tmp_path: Path) -> None:
    database = tmp_path / "compile_commands.json"
    database.write_text(json.dumps([_command(), _command(optimization="-O2")]))
    assert saved_temp_units(database) == {}
    database.write_text(json.dumps([_command(), _command()]))
    assert len(saved_temp_units(database)) == 1
    database.write_text(json.dumps([_command(), _command(source="/other/a.cpp")]))
    assert saved_temp_units(database) == {}


def test_missing_flags_and_inconsistent_source_are_not_guessed(tmp_path: Path) -> None:
    database = tmp_path / "compile_commands.json"
    entry = _command()
    entry["arguments"].remove("-save-temps=obj")
    database.write_text(json.dumps([entry]))
    assert saved_temp_units(database) == {}
    entry = _command()
    entry["file"] = "/different/a.cpp"
    database.write_text(json.dumps([entry]))
    with pytest.raises(ValueError, match="absent from recorded arguments"):
        saved_temp_units(database)


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ required")
@pytest.mark.parametrize("optimization", ["-O0", "-O2"])
def test_real_saved_temps_and_relative_markers_join(tmp_path: Path, optimization: str) -> None:
    from decbench.models.decompilation import (
        DecompilationResult,
        DecompilerMetadata,
        FunctionDecompilation,
    )
    from decbench.pipeline.cpp_ged import evaluate_cpp_ged
    from decbench.utils.cfg_identity import native_sources
    from decbench.utils.function_identity import dwarf_function_identities

    compiler = shutil.which("clang++")
    assert compiler is not None
    source = tmp_path / "unit.cpp"
    source.write_text("namespace n { int f(int x){return x+1;} }\nint main(){return n::f(0);}\n")
    obj = tmp_path / "objects/unit.cpp.o"
    obj.parent.mkdir()
    arguments = [
        compiler,
        optimization,
        "-g",
        "-save-temps=obj",
        "-o",
        "objects/unit.cpp.o",
        "-c",
        "unit.cpp",
    ]
    subprocess.run(arguments, cwd=tmp_path, check=True, capture_output=True)
    binary = tmp_path / "unit"
    subprocess.run([compiler, str(obj), "-o", str(binary)], check=True, capture_output=True)
    if binary.read_bytes()[:4] != b"\x7fELF":
        subprocess.run(["dsymutil", str(binary)], check=True, capture_output=True)
    preprocessed = tmp_path / "objects/unit.ii"
    assert preprocessed.exists()
    database = tmp_path / "compile_commands.json"
    database.write_text(
        json.dumps([{"directory": str(tmp_path), "file": "unit.cpp", "arguments": arguments}])
    )
    identity = next(row for row in dwarf_function_identities(binary) if row.name == "f")
    result = DecompilationResult(
        binary_path=binary,
        binary_name="unit",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    result.add_function(
        FunctionDecompilation(
            name="f", address=identity.address, decompiled_code="int sub_10(int x){return x+1;}"
        )
    )
    report = evaluate_cpp_ged(result, [preprocessed], compilation_database=database)
    assert (
        report.source_eligible == report.paired == report.metric.perfect_count == 1
    ), report.model_dump()
    assert report.compilation_database_sha256
    index = native_sources(binary, {identity.address})
    if index[identity.address][0].physical_unit != str(source):
        unbound = evaluate_cpp_ged(result, [preprocessed], native_index=index)
        assert unbound.source_eligible == 0


def test_relative_origin_uses_native_comp_dir_only() -> None:
    from decbench.models.decompilation import (
        DecompilationResult,
        DecompilerMetadata,
        FunctionDecompilation,
    )
    from decbench.utils.cfg_identity import NativeSource, SourceCfgIndex, SourceLocation

    index = SourceCfgIndex()
    index.add('# 1 "src/a.cpp"\nint f(){return 1;}\n', "locally-renamed.ii")
    result = DecompilationResult(
        binary_path=Path("unused"),
        binary_name="unit",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    result.add_function(
        FunctionDecompilation(name="f", address=16, decompiled_code="int f(){return 1;}")
    )
    record = NativeSource(
        16,
        "f",
        ("/build/src/a.cpp",),
        SourceLocation("/build/src/a.cpp", 1),
        "fixture",
        compilation_directory="/build",
    )
    assert index.resolve(result, {16: [record]}).evidence["f"]["status"] == "matched"
    record = NativeSource(
        16,
        "f",
        ("/other/src/a.cpp",),
        SourceLocation("/other/src/a.cpp", 1),
        "fixture",
        compilation_directory="/build",
    )
    assert not index.resolve(result, {16: [record]}).cfgs


def test_recorded_command_requires_native_directory_and_rejects_mutation(tmp_path: Path) -> None:
    from decbench.utils.cfg_identity import NativeSource, NativeSourceIndex

    binary = tmp_path / "fixture"
    binary.write_bytes(b"synthetic debug")
    database = tmp_path / "compile_commands.json"
    database.write_text(json.dumps([_command()]))
    record = NativeSource(
        16,
        "f",
        ("/build/obj/a.cpp",),
        None,
        "fixture",
        compilation_directory="/different",
        physical_unit="/build/obj/a.cpp",
    )
    index = NativeSourceIndex(binary, {16: [record]}).with_compilation_database(database)
    assert index[16][0].unit_binding is None
    database.write_text("[]")
    with pytest.raises(ValueError, match="compilation database changed"):
        index.validate(binary)
