"""Tests for decompiled-C sanitization ahead of Joern parsing."""

from __future__ import annotations

from decbench.utils.cfg import (
    escape_literal_control_bytes,
    rewrite_computed_gotos,
    sanitize_decompiled_c,
)


class TestEscapeLiteralControlBytes:
    def test_escapes_esc_inside_string_literal(self) -> None:
        out = escape_literal_control_bytes('fputs("\x1b[31mred\x1b[0m", stderr);')
        assert out == 'fputs("\\x1b[31mred\\x1b[0m", stderr);'

    def test_escapes_inside_char_literal(self) -> None:
        assert escape_literal_control_bytes("c = '\x07';") == "c = '\\x07';"

    def test_escapes_del(self) -> None:
        assert escape_literal_control_bytes('s = "\x7f";') == 's = "\\x7f";'

    def test_preserves_code_layout_outside_literals(self) -> None:
        code = "int f(void)\n{\n\treturn 1;\n}\n"
        assert escape_literal_control_bytes(code) == code

    def test_keeps_tab_and_newline_inside_literal(self) -> None:
        assert escape_literal_control_bytes('s = "a\tb";') == 's = "a\tb";'

    def test_already_escaped_text_is_unchanged(self) -> None:
        code = 's = "\\x1b[0m";'
        assert escape_literal_control_bytes(code) == code

    def test_escaped_quote_does_not_end_the_literal(self) -> None:
        out = escape_literal_control_bytes('s = "a\\"\x1b";')
        assert out == 's = "a\\"\\x1b";'

    def test_apostrophe_inside_string_does_not_open_a_char_literal(self) -> None:
        out = escape_literal_control_bytes('s = "it\'s";\nt = "\x1b";')
        assert out == 's = "it\'s";\nt = "\\x1b";'

    def test_idempotent(self) -> None:
        once = escape_literal_control_bytes('s = "\x1b";')
        assert escape_literal_control_bytes(once) == once


class TestSanitizeDecompiledC:
    def test_applies_control_byte_escaping(self) -> None:
        assert sanitize_decompiled_c('s = "\x1b";') == 's = "\\x1b";'

    def test_still_rewrites_aggregate_return_type(self) -> None:
        assert sanitize_decompiled_c("char [16] f(void)\n{\n}\n").startswith("char f(void)")

    def test_does_not_rewrite_in_body_array_declaration(self) -> None:
        assert "char buf[16];" in sanitize_decompiled_c("int f(void)\n{\n    char buf[16];\n}\n")

    def test_still_strips_register_annotation(self) -> None:
        assert sanitize_decompiled_c("int f(char arg3 @ rax)") == "int f(char arg3)"

    def test_still_widens_int128(self) -> None:
        assert sanitize_decompiled_c("unsigned __int128 x;") == "unsigned long long x;"

    def test_applies_computed_goto_rewrite(self) -> None:
        assert sanitize_decompiled_c("int f(void)\n{\n    goto *x;\n}\n") == (
            "int f(void)\n{\n    {}\n}\n"
        )


class TestRewriteComputedGotos:
    def test_plain_identifier_target(self) -> None:
        assert rewrite_computed_gotos("goto *x;") == "{}"

    def test_cast_and_parenthesized_target(self) -> None:
        assert rewrite_computed_gotos("goto *((void *)(a0->field_dc->field_10));") == "{}"

    def test_function_pointer_cast_target(self) -> None:
        assert rewrite_computed_gotos("goto *(void (*)(void))expr;") == "{}"

    def test_table_indexed_target(self) -> None:
        assert rewrite_computed_gotos("goto *(fn_table[i]);") == "{}"

    def test_braceless_if_branch_stays_valid(self) -> None:
        out = rewrite_computed_gotos("if (c)\n    goto *p;\nelse\n    goto done;")
        assert out == "if (c)\n    {}\nelse\n    goto done;"

    def test_plain_goto_untouched(self) -> None:
        code = "goto LABEL_800083f;"
        assert rewrite_computed_gotos(code) == code

    def test_string_literal_untouched(self) -> None:
        code = 's = "contains goto *x; in a string";'
        assert rewrite_computed_gotos(code) == code

    def test_comment_untouched(self) -> None:
        code = "// goto *x;\ngoto real_label;"
        assert rewrite_computed_gotos(code) == code

    def test_idempotent(self) -> None:
        once = rewrite_computed_gotos("goto *((void *)(x));")
        assert rewrite_computed_gotos(once) == once
