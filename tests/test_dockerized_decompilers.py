"""Tests for the dockerized / external-tool decompiler backends.

These tests are designed to run anywhere: anything needing a built image or an
installed tool **skips cleanly** when it is absent. The pure-Python helpers
(C-function splitting, ELF symbol enumeration) and the registration / is_available
semantics are always exercised.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from decbench.decompilers.dockerized import (
    DockerizedDecompiler,
    R2DecDecompiler,
    RekoDecompiler,
    RetDecDecompiler,
    elf_function_symbols,
    split_c_functions,
)
from decbench.decompilers.registry import DecompilerRegistry

# A tiny real binary used for the (skippable) native/ELF tests.
_GZIP = Path("results/sailr_full/O0/gzip/compiled/gzip")


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #

def test_backends_register() -> None:
    """Importing the module registers reko/retdec/r2dec."""
    import decbench.decompilers.dockerized  # noqa: F401

    registered = set(DecompilerRegistry.list_registered())
    assert {"reko", "retdec", "r2dec"} <= registered


@pytest.mark.parametrize(
    "spec,cls",
    [("reko", RekoDecompiler), ("retdec", RetDecDecompiler), ("r2dec", R2DecDecompiler)],
)
def test_registry_get_returns_correct_class(spec: str, cls: type) -> None:
    import decbench.decompilers.dockerized  # noqa: F401

    dec = DecompilerRegistry.get(spec)
    assert isinstance(dec, cls)
    assert dec.id == spec


# --------------------------------------------------------------------------- #
# is_available() semantics
# --------------------------------------------------------------------------- #

def test_docker_backends_unavailable_without_image() -> None:
    """retdec/reko report available iff their image exists; never auto-build."""
    for cls in (RetDecDecompiler, RekoDecompiler):
        dec = cls()
        expected = DockerizedDecompiler._image_present(cls.image)
        assert dec.is_available() == expected


def test_is_available_false_when_no_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    """With docker absent, image-only backends are unavailable."""
    monkeypatch.setattr(
        "decbench.decompilers.dockerized.shutil.which", lambda _name: None
    )
    assert RetDecDecompiler().is_available() is False
    assert RekoDecompiler().is_available() is False


def test_r2dec_available_when_native_present() -> None:
    """r2dec is available if native radare2+r2pipe exist (even w/o image)."""
    dec = R2DecDecompiler()
    native = R2DecDecompiler._native_available()
    if native:
        assert dec.is_available() is True
    else:
        # Falls back to image presence.
        assert dec.is_available() == DockerizedDecompiler._image_present(dec.image)


def test_get_version_proxies_image_tag() -> None:
    assert RetDecDecompiler().get_version() == "latest"
    assert RekoDecompiler().get_version() == "latest"


# --------------------------------------------------------------------------- #
# C-function splitting (pure, always runs)
# --------------------------------------------------------------------------- #

_FAKE_C = """
#include <stdint.h>

int32_t add(int32_t a, int32_t b) {
    if (a > b) {
        return a + b;
    }
    const char *s = "a } brace } in a string";
    char c = '}';
    return a - b;
}

void noop(void) {
}

uint64_t entrypoint(int argc, char **argv) {
    int x = add(argc, 1);
    noop();
    return (uint64_t)x;
}
"""


def test_split_c_functions_finds_all() -> None:
    parts = split_c_functions(_FAKE_C)
    assert set(parts) == {"add", "noop", "entrypoint"}


def test_split_c_functions_balances_braces_with_literals() -> None:
    parts = split_c_functions(_FAKE_C)
    # The literal '}' must not prematurely end add(); both returns must be in it.
    assert "return a + b;" in parts["add"]
    assert "return a - b;" in parts["add"]
    # entrypoint body should not leak into add.
    assert "entrypoint" not in parts["add"]
    assert "return (uint64_t)x;" in parts["entrypoint"]


def test_split_c_functions_empty_input() -> None:
    assert split_c_functions("") == {}
    assert split_c_functions("// just a comment\nint x;\n") == {}


def test_split_keeps_first_definition_of_duplicate_name() -> None:
    src = "int f(void) { return 1; }\nint f(void) { return 2; }\n"
    parts = split_c_functions(src)
    assert "return 1;" in parts["f"]
    assert "return 2;" not in parts["f"]


# --------------------------------------------------------------------------- #
# ELF symbol enumeration (needs the sample binary)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not _GZIP.is_file(), reason="sample gzip binary not present")
def test_elf_function_symbols_elf_space() -> None:
    syms = elf_function_symbols(_GZIP)
    assert syms, "expected function symbols from gzip"
    names = {n for n, _ in syms}
    # A known user function in gzip's deflate.c.
    assert "rsync_roll" in names
    # Addresses are sorted and look like ELF .text addresses (non-zero).
    addrs = [a for _, a in syms]
    assert all(a > 0 for a in addrs)
    assert addrs == sorted(addrs)
    # CRT helpers are filtered out.
    assert "_start" not in names
    assert "frame_dummy" not in names


# --------------------------------------------------------------------------- #
# _build_result mapping (no container; fake combined C)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not _GZIP.is_file(), reason="sample gzip binary not present")
def test_build_result_maps_snippets_to_elf_addresses() -> None:
    dec = RetDecDecompiler()
    # Pretend the container emitted C for one real gzip function.
    combined = "void rsync_roll(unsigned int a, unsigned int b) {\n    return;\n}\n"
    result = dec._build_result(
        binary_path=_GZIP,
        combined_c=combined,
        functions=None,
        function_names={"rsync_roll"},
        elapsed=0.1,
        timed_out=False,
        error=None,
        output_dir=None,
    )
    assert "rsync_roll" in result.functions
    fn = result.functions["rsync_roll"]
    # Address comes from the ELF symbol table (ELF file space).
    assert fn.address == 0x4567
    assert "rsync_roll" in fn.decompiled_code
    assert fn.variables == []
    assert fn.line_mappings == []
    assert result.decompiler.decompiler_name == "retdec"


# --------------------------------------------------------------------------- #
# r2dec native smoke (skips if radare2/r2pipe missing)
# --------------------------------------------------------------------------- #

def _native_r2dec_ready() -> bool:
    if shutil.which("r2") is None and shutil.which("radare2") is None:
        return False
    try:
        import r2pipe  # noqa: F401
    except Exception:
        return False
    return _GZIP.is_file()


@pytest.mark.skipif(
    not _native_r2dec_ready(), reason="native radare2/r2pipe or sample binary absent"
)
def test_r2dec_native_decompiles_one_function() -> None:
    dec = R2DecDecompiler()
    result = dec.decompile_binary(_GZIP, function_names={"rsync_roll"})
    assert result.decompiler.extra.get("via") == "native"
    assert "rsync_roll" in result.functions
    fn = result.functions["rsync_roll"]
    assert fn.address == 0x4567
    assert fn.decompiled_code.strip()  # non-empty pseudo-C
    assert result.decompiler.decompiler_name == "r2dec"


# --------------------------------------------------------------------------- #
# Docker-image decompile smoke (skips when image absent)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cls", [RetDecDecompiler, RekoDecompiler])
def test_docker_decompile_skips_when_image_absent(cls: type) -> None:
    dec = cls()
    if not dec.is_available():
        pytest.skip(f"{cls.__name__} image not built")
    if not _GZIP.is_file():
        pytest.skip("sample binary absent")
    result = dec.decompile_binary(_GZIP, function_names={"rsync_roll"})
    # When the image is present, we at least get a well-formed result.
    assert result.decompiler.decompiler_name == cls.name
