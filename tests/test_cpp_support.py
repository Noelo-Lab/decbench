"""C++ project support: preprocessed-unit naming, Joern frontend selection, DWARF chases.

The DWARF tests compile a tiny C and C++ pair so the C-vs-C++ asymmetry in
``binfmt.die_attr`` (``DW_AT_specification`` always followed,
``DW_AT_abstract_origin`` only in a C++ unit) is checked against real gcc
output rather than a hand-built fixture.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from decbench.compilers.gcc import find_preprocessed
from decbench.utils import binfmt
from decbench.utils.cfg import temp_parse_suffix
from decbench.utils.langs import preprocessed_ext, strip_source_ext
from decbench.utils.source_extract import _dwarf_decl

CXX_SRC = """
namespace demo {
class Widget {
 public:
  int Get(int x);
  inline int Inlined(int x) { return x + 1; }
};
int Widget::Get(int x) { return Inlined(x) * 2; }
}  // namespace demo

int main() {
  demo::Widget w;
  return w.Get(1);
}
"""

C_SRC = """
static int helper(int x) { return x + 1; }
int main(void) { return helper(1) + helper(2); }
"""


def test_preprocessed_ext_follows_the_language() -> None:
    assert preprocessed_ext(Path("db_impl.cc")) == ".ii"
    assert preprocessed_ext(Path("db_impl.cpp")) == ".ii"
    assert preprocessed_ext(Path("grep.c")) == ".i"


def test_temp_parse_suffix_picks_joerns_frontend() -> None:
    # Joern's C frontend returns zero functions for C++, so a .ii must be
    # handed over as .cpp.
    assert temp_parse_suffix(Path("db_impl.cc.ii")) == ".cpp"
    assert temp_parse_suffix(Path("grep.i")) == ".c"
    assert temp_parse_suffix(Path("decompiled.c")) == ".c"


def test_strip_source_ext_only_strips_source_extensions() -> None:
    # A C unit's preprocessed stem is "grep" but a C++ one is "db_impl.cc";
    # both sides of the DWARF decl-file match are normalized through this.
    assert strip_source_ext("db_impl.cc") == "db_impl"
    assert strip_source_ext("grep") == "grep"
    assert strip_source_ext("main.c") == "main"
    # Headers stay unstripped so header-defined functions remain outside the
    # "project's own translation units" filter.
    assert strip_source_ext("stl_vector.h") == "stl_vector.h"


def test_find_preprocessed_tries_both_extensions(tmp_path: Path) -> None:
    assert find_preprocessed(tmp_path / "grep.o") is None
    (tmp_path / "grep.i").write_text("")
    assert find_preprocessed(tmp_path / "grep.o") == tmp_path / "grep.i"
    (tmp_path / "db_impl.cc.ii").write_text("")
    assert find_preprocessed(tmp_path / "db_impl.cc.o") == tmp_path / "db_impl.cc.ii"


needs_gcc = pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("g++") is None,
    reason="needs gcc and g++",
)


def _build(tmp_path: Path, name: str, src: str, compiler: str, opt: str) -> Path:
    source = tmp_path / name
    source.write_text(src)
    binary = tmp_path / (source.stem + ".bin")
    subprocess.run(
        [compiler, "-g", opt, str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    return binary


def _subprograms(binary: Path):
    dw = binfmt.dwarf_info(binary)
    assert dw is not None
    for cu in dw.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag == "DW_TAG_subprogram" and "DW_AT_low_pc" in die.attributes:
                yield die


@needs_gcc
def test_cxx_out_of_line_definition_resolves_its_name(tmp_path: Path) -> None:
    binary = _build(tmp_path, "w.cc", CXX_SRC, "g++", "-O0")
    named = [d for d in _subprograms(binary) if "DW_AT_name" in d.attributes]
    resolved = [d for d in _subprograms(binary) if binfmt.die_str_attr(d, "DW_AT_name")]
    # Get() is defined out of line, so its defining DIE has no DW_AT_name.
    assert len(resolved) > len(named)
    assert "Get" in {binfmt.die_str_attr(d, "DW_AT_name") for d in resolved}
    assert "Get" not in {
        d.attributes["DW_AT_name"].value.decode() for d in named  # type: ignore[union-attr]
    }
    assert "Get" in _dwarf_decl(binary)


@needs_gcc
def test_abstract_origin_is_not_followed_in_a_c_unit(tmp_path: Path) -> None:
    """The C corpus must stay bit-identical: no C DIE may gain a name.

    gcc at -O2 keeps an out-of-line copy of a function it also inlined; that DIE
    carries DW_AT_abstract_origin and no DW_AT_name. Following it would enlarge
    the pinned C corpus, so the hop is gated on the CU being C++.
    """
    binary = _build(tmp_path, "h.c", C_SRC, "gcc", "-O2")
    for die in _subprograms(binary):
        assert not binfmt.cu_is_cxx(die.cu)
        direct = die.attributes.get("DW_AT_name")
        chased = binfmt.die_str_attr(die, "DW_AT_name")
        assert chased == (direct.value.decode() if direct is not None else None)


@needs_gcc
def test_cu_is_cxx_distinguishes_the_languages(tmp_path: Path) -> None:
    cxx = _build(tmp_path, "w.cc", CXX_SRC, "g++", "-O0")
    c = _build(tmp_path, "h.c", C_SRC, "gcc", "-O0")
    assert all(binfmt.cu_is_cxx(d.cu) for d in _subprograms(cxx))
    assert not any(binfmt.cu_is_cxx(d.cu) for d in _subprograms(c))
