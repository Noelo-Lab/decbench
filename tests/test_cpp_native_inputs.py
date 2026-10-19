"""C++ oracle preparation must track the image and separate debug inputs."""

from pathlib import Path

import pytest

from decbench.metrics.cpp_type_match import CppOracleContext
from decbench.utils import binfmt
from decbench.utils.cfg_identity import NativeSourceIndex


@pytest.mark.parametrize("owner", ["ged", "types"])
@pytest.mark.parametrize("mutation", ["replace", "remove", "appear"])
def test_reused_context_rejects_changed_debug_companion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner: str, mutation: str
) -> None:
    image = tmp_path / "image"
    image.write_bytes(b"unchanged native image")
    debug = tmp_path / "image.debug"
    if mutation != "appear":
        debug.write_bytes(b"original debug")
    monkeypatch.setattr(binfmt, "native_debug_paths", lambda path: (debug,), raising=False)
    if owner == "types":
        monkeypatch.setattr(binfmt, "dwarf_info", lambda path: None)
        monkeypatch.setattr(binfmt, "pdb_info", lambda path: None)
        context = CppOracleContext(image)
    else:
        context = NativeSourceIndex(image, {})
    context.validate(image)
    if mutation == "remove":
        debug.unlink()
    elif mutation == "replace":
        replacement = tmp_path / "new"
        replacement.write_bytes(b"replacement debug")
        replacement.replace(debug)
    else:
        debug.write_bytes(b"newly available debug")
    with pytest.raises(ValueError, match="debug inputs changed"):
        context.validate(image)


def test_compile_database_binding_preserves_debug_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "image"
    image.write_bytes(b"image")
    debug = tmp_path / "debug"
    debug.write_bytes(b"debug")
    monkeypatch.setattr(binfmt, "native_debug_paths", lambda path: (debug,), raising=False)
    index = NativeSourceIndex(image, {})
    database = tmp_path / "compile_commands.json"
    database.write_text("[]")
    bound = index.with_compilation_database(database)
    debug.unlink()
    with pytest.raises(ValueError, match="debug inputs changed"):
        bound.validate(image)


@pytest.mark.parametrize("target", ["native", "windows"])
def test_real_companion_mutation_invalidates_both_owners(tmp_path: Path, target: str) -> None:
    import shutil
    import subprocess

    from decbench.utils.cfg_identity import native_sources

    compiler = shutil.which("clang++")
    if compiler is None:
        pytest.skip("clang++ required")
    source = tmp_path / "unit.cpp"
    source.write_text('int f(int x){return x+1;} extern "C" int entry(){return f(0);}')
    binary = tmp_path / ("unit.exe" if target == "windows" else "unit")
    if target == "windows":
        cc, link = shutil.which("clang-cl"), shutil.which("lld-link")
        if cc is None or link is None:
            pytest.skip("clang-cl/lld-link required")
        obj = tmp_path / "unit.obj"
        subprocess.run(
            [
                cc,
                "--target=x86_64-pc-windows-msvc",
                "/c",
                "/Z7",
                "/Od",
                "/GS-",
                str(source),
                f"/Fo{obj}",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                link,
                str(obj),
                "/entry:entry",
                "/nodefaultlib",
                "/subsystem:console",
                "/debug:full",
                f"/pdb:{tmp_path/'unit.pdb'}",
                f"/out:{binary}",
            ],
            check=True,
            capture_output=True,
        )
    else:
        import sys

        if sys.platform != "darwin" or shutil.which("dsymutil") is None:
            pytest.skip("native dSYM fixture requires Darwin")
        subprocess.run(
            [compiler, "-g", str(source), "-Wl,-e,_entry", "-nostartfiles", "-o", str(binary)],
            check=True,
            capture_output=True,
        )
        subprocess.run(["dsymutil", str(binary)], check=True, capture_output=True)
    paths = binfmt.native_debug_paths(binary)
    assert len(paths) == 1 and paths[0].is_file()
    contexts = [native_sources(binary, set()), CppOracleContext(binary)]
    for context in contexts:
        context.validate(binary)
    paths[0].write_bytes(paths[0].read_bytes() + b"changed")
    for context in contexts:
        with pytest.raises(ValueError, match="debug inputs changed"):
            context.validate(binary)


def test_missing_location_keeps_exact_native_unit_for_recollection() -> None:
    from decbench.models.decompilation import (
        DecompilationResult,
        DecompilerMetadata,
        FunctionDecompilation,
    )
    from decbench.utils.cfg_identity import NativeSource, SourceCfgIndex

    result = DecompilationResult(
        binary_path=Path("unused"),
        binary_name="fixture",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    result.add_function(
        FunctionDecompilation(name="f", address=16, decompiled_code="int f(){return 1;}")
    )
    native = NativeSource(
        16,
        "f",
        ("/src/a.cpp",),
        None,
        "native:16",
        physical_unit="/build/a.o",
        compilation_directory="/build",
    )
    joined = SourceCfgIndex().resolve(result, {16: [native]})
    evidence = joined.evidence["f"]
    assert evidence["status"] == "missing_native_source_location"
    assert evidence["native_units"] == ["/src/a.cpp"]
    assert evidence["physical_unit"] == "/build/a.o"
    assert not joined.cfgs


def test_source_index_hashes_exact_prepared_text() -> None:
    import hashlib

    from decbench.utils.cfg_identity import SourceCfgIndex

    text = '# 1 "/src/a.cpp"\nint f(){return 1;}\n'
    index = SourceCfgIndex()
    index.add(text, "unit.ii")
    assert index.inputs[0]["text_sha256"] == hashlib.sha256(text.encode()).hexdigest()


def test_debug_change_during_native_preparation_is_not_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from decbench.utils.cfg_identity import native_sources

    image = tmp_path / "image"
    image.write_bytes(b"image")
    debug = tmp_path / "debug"
    debug.write_bytes(b"original")
    monkeypatch.setattr(binfmt, "native_debug_paths", lambda path: (debug,))

    def dwarf(path: Path) -> None:
        debug.write_bytes(b"changed during preparation")

    monkeypatch.setattr(binfmt, "dwarf_info", dwarf)
    monkeypatch.setattr(binfmt, "pdb_info", lambda path: None)
    with pytest.raises(ValueError, match="debug inputs changed"):
        native_sources(image, set())
    debug.write_bytes(b"reset")
    with pytest.raises(ValueError, match="debug inputs changed"):
        CppOracleContext(image)


def test_native_index_tracks_companion_beside_requested_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from decbench.utils.cfg_identity import native_sources

    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.mkdir()
    image = actual / "image"
    image.write_bytes(b"image")
    requested = alias / "image"
    requested.symlink_to(image)
    debug = alias / "debug"
    debug.write_bytes(b"debug")
    monkeypatch.setattr(binfmt, "native_debug_paths", lambda path: (path.parent / "debug",))
    monkeypatch.setattr(binfmt, "dwarf_info", lambda path: None)
    monkeypatch.setattr(binfmt, "pdb_info", lambda path: None)
    context = native_sources(requested, set())
    debug.write_bytes(b"changed")
    with pytest.raises(ValueError, match="debug inputs changed"):
        context.validate(requested)


def test_embedded_pe_dwarf_does_not_require_unused_pdb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import decbench.utils.pdb_info as pdb_module

    monkeypatch.setattr(binfmt, "detect", lambda path: binfmt.BinInfo("pe", "x86-64", 64))
    monkeypatch.setattr(binfmt, "pe_dwarf_info", lambda path: object())

    def forbidden(path: Path) -> None:
        raise AssertionError("embedded DWARF must not consult a PDB")

    monkeypatch.setattr(pdb_module, "pdb_path", forbidden)
    assert binfmt.native_debug_paths(tmp_path / "image.exe") == ()


def test_embedded_macho_dwarf_does_not_watch_unused_dsym(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(binfmt, "detect", lambda path: binfmt.BinInfo("macho", "aarch64", 64))
    image = SimpleNamespace(
        sections=[SimpleNamespace(segment_name="__DWARF", name="__debug_info", content=b"info")]
    )
    monkeypatch.setattr(binfmt, "_mach_o_binary", lambda path: image)
    assert binfmt.native_debug_paths(tmp_path / "image") == ()
