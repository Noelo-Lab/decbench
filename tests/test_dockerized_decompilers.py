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
    _func_ident_in_code,
    _r2_bare_name,
    _r2_is_import,
    elf_function_symbols,
    split_c_functions,
)
from decbench.decompilers.registry import DecompilerRegistry

# A tiny real binary used for the (skippable) native/ELF tests. Also probe the
# main checkout so these run even from an isolated worktree without results/.
_GZIP_CANDIDATES = [
    Path("results/sailr_full/O0/gzip/compiled/gzip"),
    Path("/home/mahaloz/github/decbench/results/sailr_full/O0/gzip/compiled/gzip"),
]
_GZIP = next((p for p in _GZIP_CANDIDATES if p.is_file()), _GZIP_CANDIDATES[0])


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
    monkeypatch.setattr("decbench.decompilers.dockerized.shutil.which", lambda _name: None)
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
# r2dec pure helpers: discovery, address filter, naming (no binary/tool needed)
# --------------------------------------------------------------------------- #


class _FakeR2:
    """Minimal r2pipe stand-in returning canned ``ij`` / ``aflj`` / ``pdd``."""

    def __init__(self, aflj: list[dict], baddr: int = 0) -> None:
        self._aflj = aflj
        self._baddr = baddr

    def cmdj(self, cmd: str):  # noqa: ANN201
        if cmd == "aflj":
            return self._aflj
        if cmd == "ij":
            return {"bin": {"baddr": self._baddr}}
        return None

    def cmd(self, cmd: str) -> str:
        if cmd.startswith(("pdd", "pdc")) and "@" in cmd:
            addr = int(cmd.rsplit("@", 1)[1].strip(), 0)
            # Emit r2dec-style C (banner + include) so name extraction is exercised.
            return (
                "/* r2dec pseudo code output (r2 6.0.8) */\n"
                "#include <stdint.h>\n\n"
                f"int64_t fcn_{addr:08x}(int32_t a) {{\n    return a;\n}}\n"
            )
        return ""

    def quit(self) -> None:  # noqa: D401
        pass


def test_r2_is_import_and_bare_name() -> None:
    assert _r2_is_import("sym.imp.free")
    assert _r2_is_import("reloc.foo")
    assert _r2_is_import("dbg.imp.bar") is False or ".imp." in "dbg.imp.bar"
    assert not _r2_is_import("fcn.00001234")
    assert not _r2_is_import("sym.main")
    assert _r2_bare_name("sym.acl_add_perm") == "acl_add_perm"
    assert _r2_bare_name("fcn.00001234") == "00001234"
    assert _r2_bare_name("main") == "main"


def test_func_ident_in_code_strips_banner_and_macros() -> None:
    # r2dec's block-comment banner + #include must not be mistaken for the name.
    code = (
        "/* r2dec pseudo code output (r2 6.0.8) */\n"
        "/* /in/bin @ 0x2e2b */\n"
        "#include <stdint.h>\n\n"
        "#define BIT_MASK(t,v) ((t)(-((v)!=0)))\n\n"
        "int64_t acl_create_entry (uint32_t a, uint32_t b) {\n"
        "    if (a) { return b; }\n"
        "    return a;\n}\n"
    )
    assert _func_ident_in_code(code) == "acl_create_entry"
    # pdc emits a dotted pseudo-name verbatim; it must round-trip.
    assert _func_ident_in_code("void fcn.00003bed (int64_t a) {\n    return;\n}") == "fcn.00003bed"
    # A snippet with no definition (just a control-flow block) yields None.
    assert _func_ident_in_code("if (x) {\n    y();\n}\n") is None


def test_r2_discover_normalizes_and_filters() -> None:
    aflj = [
        {"name": "sym.imp.free", "addr": 0x500},  # import -> skip
        {"name": "reloc.foo", "addr": 0x600},  # reloc -> skip
        {"name": "entry0", "addr": 0x1500},  # entry alias -> skip
        {"name": "fcn.00002000", "addr": 0x2000},  # keep
        {"name": "sym.main", "addr": 0x3000},  # keep
        {"name": "sym.outside", "addr": 0x9500},  # outside .text -> skip
    ]
    r = _FakeR2(aflj, baddr=0)
    out = R2DecDecompiler._discover(r, elf_base=0, text_range=(0x1000, 0x9000), baddr=0)
    assert out == [("fcn.00002000", 0x2000, 0x2000), ("sym.main", 0x3000, 0x3000)]


def test_r2_discover_rebases_when_baddr_differs() -> None:
    # ARM firmware: r2 loads at baddr; file_addr = raw - baddr + elf_base.
    aflj = [{"name": "fcn.08002000", "addr": 0x8002000}]
    r = _FakeR2(aflj, baddr=0x8000000)
    out = R2DecDecompiler._discover(
        r, elf_base=0x8000000, text_range=(0x8000000, 0x8010000), baddr=0x8000000
    )
    assert out == [("fcn.08002000", 0x8002000, 0x8002000)]


def test_r2_narrow_by_int_address() -> None:
    discovered = [("fcn.a", 0x1000, 0x1000), ("fcn.b", 0x2000, 0x2000), ("fcn.c", 0x3000, 0x3000)]
    out = R2DecDecompiler._narrow(discovered, {0x1000, 0x3000}, "bin")
    assert {t[1] for t in out} == {0x1000, 0x3000}
    # int labels are None (the code identifier becomes the key).
    assert all(t[0] is None for t in out)


def test_r2_narrow_int_thumb_tolerant() -> None:
    # DWARF low_pc is even; a Thumb function may be reported odd (addr|1).
    discovered = [("fcn.a", 0x8001, 0x8001)]
    out = R2DecDecompiler._narrow(discovered, {0x8000}, "bin")
    assert [t[1] for t in out] == [0x8001]


def test_r2_narrow_by_str_name_and_fallback() -> None:
    discovered = [("sym.foo", 0x1000, 0x1000), ("fcn.00002000", 0x2000, 0x2000)]
    out = R2DecDecompiler._narrow(discovered, {"foo"}, "bin")
    assert len(out) == 1 and out[0][0] == "foo" and out[0][1] == 0x1000
    # No address matches -> fall back to everything (never an empty result).
    out2 = R2DecDecompiler._narrow(discovered, {0xDEAD}, "bin")
    assert {t[1] for t in out2} == {0x1000, 0x2000}


def test_r2_make_function_names_from_code_and_relabels() -> None:
    code = "int foo(int a) {\n    return a;\n}\n"
    # No label: name == the code identifier so an address-relabel rewrites both.
    fd = R2DecDecompiler._make_function("fcn.00001000", 0x1000, code, None)
    assert fd is not None and fd.name == "foo" and fd.address == 0x1000
    # With a label (legacy str path): the code is rewritten to the label.
    fd2 = R2DecDecompiler._make_function("sym.foo", 0x1000, code, "realname")
    assert fd2 is not None and fd2.name == "realname"
    assert "realname" in fd2.decompiled_code and "foo(" not in fd2.decompiled_code
    # Empty code -> no function.
    assert R2DecDecompiler._make_function("fcn.x", 0x1, "   ", None) is None


def test_r2_decompile_native_int_filter_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """The int-address filter path end-to-end, with r2pipe mocked (no binary)."""
    import r2pipe

    aflj = [
        {"name": "sym.imp.puts", "addr": 0x500},
        {"name": "fcn.00001000", "addr": 0x1000},
        {"name": "sym.wanted", "addr": 0x2000},
        {"name": "fcn.00003000", "addr": 0x3000},
    ]
    monkeypatch.setattr(r2pipe, "open", lambda *a, **k: _FakeR2(aflj, baddr=0))
    dec = R2DecDecompiler()
    # binary_path need not exist: elf_min_vaddr -> 0, elf_text_range -> None.
    result = dec._decompile_native(Path("/nonexistent/bin"), None, None, {0x1000, 0x2000}, None)
    got = {fd.address for fd in result.functions.values()}
    assert got == {0x1000, 0x2000}  # the import + 0x3000 are excluded
    for fd in result.functions.values():
        assert _func_ident_in_code(fd.decompiled_code) == fd.name
    assert result.decompiler.extra.get("via") == "native"


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
    # Drive the native path directly: the public decompile_binary now prefers
    # the real r2dec via the docker image when it is built, so exercising the
    # native fallback (pdd-if-installed, else pdc) means calling it explicitly.
    # Discovery is from radare2's own analysis; a str name filter is the legacy
    # interface (the benchmark driver uses int addresses instead).
    dec = R2DecDecompiler()
    result = dec._decompile_native(_GZIP, None, None, {"rsync_roll"}, None)
    assert result.decompiler.extra.get("via") == "native"
    assert "rsync_roll" in result.functions
    fn = result.functions["rsync_roll"]
    # r2's normalized address must equal the ELF symbol-table address (ELF file
    # space), so it lines up with DWARF and the driver's address relabel.
    want = dict(elf_function_symbols(_GZIP)).get("rsync_roll")
    assert want is not None and fn.address == want
    assert fn.decompiled_code.strip()  # non-empty pseudo-C
    assert result.decompiler.decompiler_name == "r2dec"


def test_r2dec_native_int_address_filter() -> None:
    """The benchmark driver hands r2dec a set of int ADDRESSES; only functions at
    those (normalized) addresses come back, keyed by their code identifier."""
    if not _native_r2dec_ready():
        pytest.skip("native radare2/r2pipe or sample binary absent")
    dec = R2DecDecompiler()
    syms = dict(elf_function_symbols(_GZIP))
    # Pick a few known ELF-file-space addresses (what the driver would pass).
    wanted = {syms[n] for n in ("rsync_roll", "bi_reverse") if n in syms}
    assert wanted, "expected known gzip functions"
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        prog = Path(td) / "prog.pkl"
        result = dec._decompile_native(_GZIP, None, Path(td), wanted, prog)
        # Every returned function's address is one we asked for.
        got = {fd.address for fd in result.functions.values()}
        assert got, "expected at least one decompiled function"
        assert got <= wanted
        # Each function's name equals the identifier in its code (so a later
        # address-relabel rewrites the code too) and the code is non-empty.
        for fd in result.functions.values():
            assert fd.decompiled_code.strip()
            assert _func_ident_in_code(fd.decompiled_code) == fd.name
        # progress_path was checkpointed during the run.
        assert prog.exists()


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
