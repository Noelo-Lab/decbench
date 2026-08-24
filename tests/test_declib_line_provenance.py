"""Declib line-contract validation and variable-occurrence joins."""

from __future__ import annotations

import pytest

from decbench.decompilers.declib_dec import (
    AngrDeclibDecompiler,
    BinjaDeclibDecompiler,
    DeclibDecompiler,
    GhidraDeclibDecompiler,
    IDADeclibDecompiler,
)
from decbench.metrics.variable_features import variable_occurrence_lines
from decbench.models.decompilation import LineMapping, VariableInfo


@pytest.mark.parametrize("backend", [AngrDeclibDecompiler(), GhidraDeclibDecompiler()])
def test_one_based_declib_maps_are_validated(backend: DeclibDecompiler) -> None:
    mappings = backend._extract_line_mappings(
        {
            0: {0x1000},
            1: {0x1000, 0x2000, "not-an-address"},
            2: {0x1004},
            3: 0x1008,
            4: {0x1008},
            "2": {0x1004},
        },
        "line one\nline two\n",
        lifted_addr=0x1000,
        elf_base=0x400000,
        function_size=0x10,
    )

    assert mappings == [
        LineMapping(line_number=1, addresses=[0x401000]),
        LineMapping(line_number=2, addresses=[0x401004]),
    ]


def test_declib_maps_fail_closed_without_a_function_range() -> None:
    backend = AngrDeclibDecompiler()
    assert (
        backend._extract_line_mappings(
            {1: {0x1000}},
            "int f(void) {}",
            lifted_addr=0x1000,
            elf_base=0,
            function_size=None,
        )
        == []
    )
    assert (
        backend._extract_line_mappings(
            [(1, {0x1000})],
            "int f(void) {}",
            lifted_addr=0x1000,
            elf_base=0,
            function_size=1,
        )
        == []
    )


def test_ida_zero_based_rows_are_normalized_without_shifting_the_synthetic_entry() -> None:
    backend = IDADeclibDecompiler()
    mappings = backend._extract_line_mappings(
        {
            0: {0x1001},
            1: {0x1000},
            2: {0x1004},
            99: {0x1008},
        },
        "int f(void)\n{\n    return 0;\n}\n",
        lifted_addr=0x1000,
        elf_base=0x400000,
        function_size=0x10,
    )

    assert mappings == [
        LineMapping(line_number=1, addresses=[0x401000, 0x401001]),
        LineMapping(line_number=3, addresses=[0x401004]),
    ]


def test_binja_declib_map_abstains_on_skipped_row_drift() -> None:
    backend = BinjaDeclibDecompiler()
    assert (
        backend._extract_line_mappings(
            {0: {0x1000}, 1: {0x1004}},
            "int f(void)\n{\n}\n",
            lifted_addr=0x1000,
            elf_base=0,
            function_size=0x10,
        )
        == []
    )


def test_variable_occurrences_are_binding_aware_and_shadow_safe() -> None:
    code = (
        "int f(int a, int aa) {\n"
        "    int shadow = 0;\n"
        "    { int shadow = 1; aa += shadow; }\n"
        "    struct S { int a; } obj;\n"
        "    obj.a = aa; /* a aa */\n"
        '    char *text = "a aa";\n'
        "    return a + aa;\n"
        "}\n"
    )

    assert variable_occurrence_lines(code, "f", ["a", "aa", "shadow"]) == {
        "a": (1, 7),
        "aa": (1, 3, 5, 7),
    }
    assert variable_occurrence_lines(code, "f", ["a", "a"]) == {}
    assert variable_occurrence_lines("int f(int a) { return a;", "f", ["a"]) == {}


def test_declib_variable_lines_join_only_valid_native_rows() -> None:
    code = "int f(int a, int aa) {\n    aa += a;\n    return aa;\n}\n"
    variables = [
        VariableInfo(name="a", type="int", kind="arg", arg_index=0),
        VariableInfo(name="aa", type="int", kind="arg", arg_index=1),
    ]
    DeclibDecompiler._add_variable_evidence(
        variables,
        "f",
        code,
        [
            LineMapping(line_number=1, addresses=[0x1000]),
            LineMapping(line_number=2, addresses=[0x1004]),
            LineMapping(line_number=3, addresses=[0x1008]),
        ],
    )

    assert variables[0].line_numbers == [1, 2]
    assert variables[0].addresses == [0x1000, 0x1004]
    assert variables[1].line_numbers == [1, 2, 3]
    assert variables[1].addresses == [0x1000, 0x1004, 0x1008]


def test_declib_variable_join_abstains_on_duplicate_structured_names() -> None:
    variables = [VariableInfo(name="same"), VariableInfo(name="same")]
    DeclibDecompiler._add_variable_evidence(
        variables,
        "f",
        "int f(int same) { return same; }",
        [LineMapping(line_number=1, addresses=[0x1000])],
    )
    assert all(variable.line_numbers == [] for variable in variables)
    assert all(variable.addresses == [] for variable in variables)
