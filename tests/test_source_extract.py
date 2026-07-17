"""Tests for per-function source extraction (the Compare view's source side)."""

from __future__ import annotations

from decbench.utils.source_extract import extract_from_text

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
