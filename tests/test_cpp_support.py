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


def test_preprocessed_by_stem_finds_both_extensions(tmp_path: Path) -> None:
    """A collection site that globs only ``*.i`` sees nothing in a C++ tree."""
    from decbench.utils.langs import preprocessed_by_stem

    assert preprocessed_by_stem(tmp_path / "missing") == {}
    (tmp_path / "grep.i").write_text("")
    (tmp_path / "db_impl.cc.ii").write_text("")
    (tmp_path / "notes.txt").write_text("")
    assert preprocessed_by_stem(tmp_path) == {
        "grep": tmp_path / "grep.i",
        "db_impl.cc": tmp_path / "db_impl.cc.ii",
    }


def test_preprocessed_by_stem_warns_on_a_shadowed_unit(tmp_path: Path, caplog) -> None:
    """``parser.i`` and ``parser.ii`` share a stem; the loss must not be silent."""
    import logging

    from decbench.utils.langs import preprocessed_by_stem

    (tmp_path / "parser.i").write_text("")
    (tmp_path / "parser.ii").write_text("")
    with caplog.at_level(logging.WARNING):
        found = preprocessed_by_stem(tmp_path)
    assert found == {"parser": tmp_path / "parser.i"}
    assert "collision" in caplog.text


def test_build_stem_index_warns_instead_of_dropping_silently(caplog) -> None:
    """``main.cc`` and ``main.cpp`` both strip to ``main``."""
    import logging

    from decbench.utils.langs import build_stem_index

    assert build_stem_index(["grep", "db_impl.cc"]) == {"grep": "grep", "db_impl": "db_impl.cc"}
    with caplog.at_level(logging.WARNING):
        index = build_stem_index(["main.cc", "main.cpp"])
    assert index == {"main": "main.cc"}
    assert "collision" in caplog.text


def test_binary_limit_keeps_a_cxx_projects_sources(tmp_path: Path) -> None:
    """--binary-limit/--binary-sample must not empty preprocessed_sources.

    The keys are ``db_impl.cc`` (from ``db_impl.cc.ii``) and can never equal a
    binary stem, so comparing raw stems dropped every C++ source and the project
    scored zero functions with no error.
    """
    from decbench.models.project import OptimizationLevel, Project, ProjectConfig
    from decbench.pipeline.executor import keep_sources_of_retained_binaries

    opt = OptimizationLevel.O2
    project = Project(
        name="leveldb",
        config=ProjectConfig(name="leveldb", repo_url="https://example.invalid/leveldb"),
    )
    project.compiled_binaries[opt] = [tmp_path / "db_impl", tmp_path / "grep"]
    project.preprocessed_sources[opt] = {
        "db_impl.cc": tmp_path / "db_impl.cc.ii",
        "grep": tmp_path / "grep.i",
        "version_set.cc": tmp_path / "version_set.cc.ii",
    }

    keep_sources_of_retained_binaries(project, opt)

    assert set(project.preprocessed_sources[opt]) == {"db_impl.cc", "grep"}


def test_every_source_collection_site_globs_both_extensions() -> None:
    """No `*.i`-only glob outside the dataset/publish family.

    Those four are C-only by disclosure (docs/benchmarking.md); anywhere else a
    hard-coded ``*.i`` means a C++ project silently gets no sources and no score.
    """
    import re

    repo = Path(__file__).resolve().parent.parent
    allowed = {
        "decbench/publish/cfg_export.py",
        "decbench/publish/layout.py",
        "decbench/dataset.py",
        "scripts/compute_dataset_info.py",
    }
    pattern = re.compile(r"""glob\(\s*["']\*\.i["']""")
    offenders = set()
    for path in sorted(repo.rglob("*.py")):
        rel = path.relative_to(repo).as_posix()
        if rel.startswith(("tests/", ".venv/", "build/")):
            continue
        if pattern.search(path.read_text(errors="replace")):
            offenders.add(rel)
    extra = sorted(offenders - allowed)
    assert not extra, f"undisclosed .i-only collection sites: {extra}"


def test_leveldb_cmake_probe_cleanup_is_version_agnostic() -> None:
    """CMake 4.x writes build/CMakeFiles/4.0.x/, so a `3.*` glob leaves its
    compiler-probe binaries in the tree as benchmark targets."""
    repo = Path(__file__).resolve().parent.parent
    candidates = [
        repo / "projects/cpp/leveldb.toml",
        repo / "projects/cpp/disabled/leveldb.toml",
    ]
    toml_path = next((p for p in candidates if p.is_file()), None)
    if toml_path is None:
        pytest.skip("leveldb.toml not present")
    text = toml_path.read_text()
    assert "CMakeFiles/3." not in text
    assert "rm -rf build/CMakeFiles/[0-9]*" in text
