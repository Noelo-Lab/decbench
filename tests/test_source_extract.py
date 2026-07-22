"""Tests for per-function source extraction (the Compare view's source side)."""

from __future__ import annotations

from pathlib import Path

from decbench.utils.source_extract import (
    extract_from_text,
    function_source,
    function_source_ex,
)

SRC = """\
#include <stdio.h>

static int helper(int x) {
    return x * 2;
}

int main(int argc, char **argv) {
    int total = 0;
    for (int i = 0; i < argc; i++) {
        total += helper(i);   /* call site, not a definition */
    }
    if (total > 10) { total = 10; }
    return total;
}

void cleanup(void) {
    printf("bye\\n");
}
"""


class TestExtractFromText:
    def test_extracts_simple_function(self) -> None:
        out = extract_from_text(SRC, "helper")
        assert out is not None
        assert out.startswith("static int helper(int x)")
        assert "return x * 2;" in out
        # Must stop at the function's closing brace, not run into main.
        assert "int main" not in out

    def test_brace_matching_handles_nested_blocks(self) -> None:
        out = extract_from_text(SRC, "main")
        assert out is not None
        assert out.startswith("int main(")
        assert "return total;" in out
        # Balanced braces.
        assert out.count("{") == out.count("}")
        # Should not swallow the following function.
        assert "void cleanup" not in out

    def test_call_site_not_mistaken_for_definition(self) -> None:
        # `helper` is called inside main; extraction must return the real def.
        out = extract_from_text(SRC, "helper")
        assert "return x * 2;" in out

    def test_missing_function_returns_none(self) -> None:
        assert extract_from_text(SRC, "does_not_exist") is None

    def test_string_with_brace_does_not_break_matching(self) -> None:
        out = extract_from_text(SRC, "cleanup")
        assert out is not None
        assert "bye" in out
        assert out.count("{") == out.count("}")

    def test_function_pointer_parameter_signature(self) -> None:
        # The param list contains parens; the naive "first )" would reject this.
        src = "int registerit(void (*cb)(int), int n) {\n" "    return cb ? n : 0;\n" "}\n"
        out = extract_from_text(src, "registerit")
        assert out is not None
        assert out.startswith("int registerit(")
        assert "return cb ? n : 0;" in out


# Classic K&R definition: bare-identifier param list, a run of parameter
# declarations, then the body — plus an ANSI prototype ahead of it.
KNR_SRC = """\
local void send_all_trees OF((deflate_state *s, int a, int b));

local void send_all_trees(s, lcodes, dcodes, blcodes)
    deflate_state *s;
    int lcodes, dcodes, blcodes;
{
    int rank;
    rank = lcodes + dcodes + blcodes;
    return;
}

int next_fn(void) {
    return 0;
}
"""


class TestKandR:
    def test_extracts_knr_definition(self) -> None:
        out = extract_from_text(KNR_SRC, "send_all_trees")
        assert out is not None
        assert out.startswith("local void send_all_trees(s, lcodes, dcodes, blcodes)")
        # The K&R parameter declarations are part of the definition.
        assert "deflate_state *s;" in out
        assert "int lcodes, dcodes, blcodes;" in out
        assert "rank = lcodes + dcodes + blcodes;" in out
        assert out.count("{") == out.count("}")
        # Must stop at its own closing brace, not run into the next function.
        assert "next_fn" not in out

    def test_prototype_only_returns_none(self) -> None:
        # A file with ONLY a prototype (no body) must not yield a definition.
        src = "void file_compress(char *in, char *out);\nint other(void){return 0;}\n"
        assert extract_from_text(src, "file_compress") is None

    def test_bare_param_prototype_not_stitched_to_later_body(self) -> None:
        # The ';' guard: an empty/bare-param prototype must NOT be joined to an
        # unrelated later '{' by the K&R scan.
        src = "int foo();\n\nint bar(void) {\n    return 42;\n}\n"
        out = extract_from_text(src, "foo")
        assert out is None

    def test_prototype_then_knr_def_picks_def(self) -> None:
        # Prototype (OF-macro-expanded, typed params) precedes the real K&R def;
        # extraction must return the definition, not the prototype.
        out = extract_from_text(KNR_SRC, "send_all_trees")
        assert out is not None and "{" in out and "rank" in out


class TestFunctionSourceEx:
    def _binary(self, tmp_path: Path) -> Path:
        # A non-ELF stub: _dwarf_decl fails gracefully, so extraction searches
        # every sibling source without a DWARF hint.
        binary = tmp_path / "bin"
        binary.write_bytes(b"not-an-elf")
        return binary

    def test_c_preferred_status_empty(self, tmp_path: Path) -> None:
        binary = self._binary(tmp_path)
        (tmp_path / "mod.c").write_text("int f(int x){return x + 1;}\n")
        (tmp_path / "mod.i").write_text("int f(int x){return x + 999;}\n")
        code, status = function_source_ex(binary, "f")
        assert status == ""
        assert code is not None and "return x + 1;" in code

    def test_i_fallback_when_no_c(self, tmp_path: Path) -> None:
        binary = self._binary(tmp_path)
        (tmp_path / "mod.i").write_text('# 1 "mod.c"\nstatic int f(int x){return x + 1;}\n')
        code, status = function_source_ex(binary, "f")
        assert status == "preprocessed"
        assert code is not None and "return x + 1;" in code

    def test_status_binary_not_found(self, tmp_path: Path) -> None:
        assert function_source_ex(None, "f") == (None, "binary_not_found")
        # Only a missing DIRECTORY is a dead end; a missing binary in an existing
        # dir just loses the DWARF hint (see next test).
        assert function_source_ex(tmp_path / "gone" / "nope", "f") == (None, "binary_not_found")

    def test_missing_binary_still_searches_sibling_sources(self, tmp_path: Path) -> None:
        (tmp_path / "mod.c").write_text("int f(void) { return 1; }\n")
        code, status = function_source_ex(tmp_path / "nope", "f")
        assert status == ""
        assert code is not None and "return 1;" in code

    def test_status_no_source_files(self, tmp_path: Path) -> None:
        binary = self._binary(tmp_path)
        assert function_source_ex(binary, "f") == (None, "no_source_files")

    def test_status_func_not_in_sources(self, tmp_path: Path) -> None:
        binary = self._binary(tmp_path)
        (tmp_path / "mod.c").write_text("int other(void){return 0;}\n")
        assert function_source_ex(binary, "missing") == (None, "func_not_in_sources")

    def test_status_extract_failed_on_prototype(self, tmp_path: Path) -> None:
        binary = self._binary(tmp_path)
        (tmp_path / "mod.c").write_text("int f(int x);\n")  # prototype only
        assert function_source_ex(binary, "f") == (None, "extract_failed")

    def test_function_source_wrapper_returns_code(self, tmp_path: Path) -> None:
        binary = self._binary(tmp_path)
        (tmp_path / "mod.c").write_text("int f(int x){return x + 1;}\n")
        out = function_source(binary, "f")
        assert out is not None and "return x + 1;" in out
