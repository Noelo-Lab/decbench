"""Unit tests for the manifold backend's binary resolution + TU splitting.

The real decompilation shells out to the ``manifold`` executable (a Rust
binary), so these tests exercise the parts that do NOT need it installed:
executable resolution, availability gating, splitting one whole-program
translation unit into per-function definitions, and the address mapping --
the last through a fake ``manifold`` that emits a canned translation unit.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import decbench.decompilers  # noqa: F401  (registers the raw backends)
from decbench.decompilers.raw.manifold_raw import (
    ManifoldDecompiler,
    parse_translation_unit,
    split_functions,
)
from decbench.decompilers.registry import DecompilerRegistry

TINY_C_SOURCE = """
int add_nums(int a, int b) {
    return a + b;
}

int main(void) {
    return add_nums(1, 2);
}
"""

# A translation unit in manifold's own shape: preprocessor lines, a struct, file
# scope globals, prototypes, then Allman-braced definitions.
SAMPLE_TU = """#include <stdint.h>

struct struct_1 {
    long f_0;
    struct struct_2 *f_8;
};

struct struct_2 {
    int f_0;
};

long L_1f27b;
extern unsigned char __TMC_END__;

long FUN_401136(void *p0, long p1);
int FUN_4011a0(struct struct_1 *p0);

long FUN_401136(void *p0, long p1)
{
    /* a comment with an unbalanced brace { */
    char *var_0 = "a string with } and { braces";
    return p1;
}

int FUN_4011a0(struct struct_1 *p0)
{
    return (int)(p0->f_0 + L_1f27b);
}
"""


def test_manifold_is_registered() -> None:
    dec = DecompilerRegistry.get("manifold")
    assert isinstance(dec, ManifoldDecompiler)
    assert dec.id == "manifold"
    assert dec.display_name == "Manifold"
    # is_available must never raise, whether or not the tool is installed.
    assert isinstance(dec.is_available(), bool)


def test_unavailable_without_binary(monkeypatch) -> None:
    monkeypatch.setenv("MANIFOLD_BIN", "/nonexistent/manifold")
    assert ManifoldDecompiler().is_available() is False


def test_env_override_wins(monkeypatch, tmp_path: Path) -> None:
    exe = tmp_path / "manifold"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(exe))
    assert ManifoldDecompiler().is_available() is True


def test_split_functions_finds_definitions_not_prototypes() -> None:
    funcs = dict(split_functions(SAMPLE_TU))
    assert sorted(funcs) == ["FUN_401136", "FUN_4011a0"]


def test_split_functions_ignores_braces_in_strings_and_comments() -> None:
    funcs = dict(split_functions(SAMPLE_TU))
    body = funcs["FUN_401136"]
    # The definition must be complete: a brace inside the string literal or the
    # comment must not have closed the body early.
    assert body.rstrip().endswith("}")
    assert "return p1;" in body


def test_each_function_carries_the_file_scope_it_references() -> None:
    funcs = dict(split_functions(SAMPLE_TU))
    # FUN_4011a0 dereferences struct_1 and reads L_1f27b, so both must ride along
    # -- and struct_1 names struct_2, so the preamble is transitive.
    a0 = funcs["FUN_4011a0"]
    assert "struct struct_1 {" in a0
    assert "struct struct_2 {" in a0
    assert "long L_1f27b;" in a0
    # ... but not the unrelated global.
    assert "__TMC_END__" not in a0
    # Preprocessor lines ride along with every function.
    assert "#include <stdint.h>" in a0


def test_parse_translation_unit_classifies_entities() -> None:
    entities = parse_translation_unit(SAMPLE_TU)
    functions = [e for e in entities if e.is_function]
    assert len(functions) == 2
    # struct definitions and prototypes are not functions
    assert any("struct struct_1" in e.text and not e.is_function for e in entities)


@pytest.fixture(scope="module")
def tiny_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler available")
    build_dir = tmp_path_factory.mktemp("manifold_bin")
    src = build_dir / "tiny.c"
    src.write_text(TINY_C_SOURCE)
    binary = build_dir / "tiny"
    subprocess.run([cc, "-g", "-O0", "-fno-inline", "-o", str(binary), str(src)], check=True)
    return binary


def _func_address(binary: Path, name: str) -> int:
    """The ELF-file-space entry address of ``name`` from the symbol table."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    with open(binary, "rb") as f:
        for sec in ELFFile(f).iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym.name == name and sym["st_value"]:
                        return int(sym["st_value"])
    raise AssertionError(f"no symbol {name} in {binary}")


def test_decompile_binary_maps_fun_names_to_addresses(
    monkeypatch, tiny_binary: Path, tmp_path: Path
) -> None:
    """A fake manifold emits a TU; the backend must key it by ELF-space address."""
    # Use the fixture's own function addresses so the .text-range filter (which
    # correctly drops anything outside .text) sees real targets.
    add_nums = _func_address(tiny_binary, "add_nums")
    main = _func_address(tiny_binary, "main")
    tu = SAMPLE_TU.replace("FUN_401136", f"FUN_{add_nums:x}").replace("FUN_4011a0", f"FUN_{main:x}")

    fake = tmp_path / "manifold"
    out_tu = tmp_path / "tu.c"
    out_tu.write_text(tu)
    # manifold's CLI is `manifold <input> <output.c>`; copy the canned TU there.
    fake.write_text(f'#!/bin/sh\ncat "{out_tu}" > "$2"\n')
    fake.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(fake))

    dec = ManifoldDecompiler()
    result = dec.decompile_binary(tiny_binary, output_dir=tmp_path)

    assert result.decompiler.decompiler_name == "manifold"
    assert sorted(result.functions) == sorted([f"FUN_{add_nums:x}", f"FUN_{main:x}"])
    # FUN_<hex> is manifold's name for the function entering at that vaddr, and
    # manifold reports the ELF's own addresses -- so no rebasing is applied.
    assert result.functions[f"FUN_{add_nums:x}"].address == add_nums
    assert result.functions[f"FUN_{main:x}"].address == main
    assert result.functions[f"FUN_{add_nums:x}"].decompiled_code.strip()
    assert (tmp_path / f"manifold_{tiny_binary.stem}.c").exists()


def test_decompile_binary_narrows_to_requested_addresses(
    monkeypatch, tiny_binary: Path, tmp_path: Path
) -> None:
    """``function_names`` carries target ADDRESSES; only those survive."""
    add_nums = _func_address(tiny_binary, "add_nums")
    main = _func_address(tiny_binary, "main")
    tu = SAMPLE_TU.replace("FUN_401136", f"FUN_{add_nums:x}").replace("FUN_4011a0", f"FUN_{main:x}")
    fake = tmp_path / "manifold"
    out_tu = tmp_path / "tu.c"
    out_tu.write_text(tu)
    fake.write_text(f'#!/bin/sh\ncat "{out_tu}" > "$2"\n')
    fake.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(fake))

    result = ManifoldDecompiler().decompile_binary(tiny_binary, function_names={add_nums})

    assert sorted(result.functions) == [f"FUN_{add_nums:x}"]


def test_decompile_binary_reports_failure_without_output(
    monkeypatch, tiny_binary: Path, tmp_path: Path
) -> None:
    fake = tmp_path / "manifold-fail"
    fake.write_text('#!/bin/sh\necho "unsupported architecture" >&2\nexit 1\n')
    fake.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(fake))

    result = ManifoldDecompiler().decompile_binary(tiny_binary)

    assert result.functions == {}
    assert result.decompiler.failed_functions == ["all"]
    assert "unsupported architecture" in result.decompiler.extra["error"]
