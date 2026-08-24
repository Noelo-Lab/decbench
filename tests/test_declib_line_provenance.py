"""Declib line-contract validation and variable-occurrence joins."""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from decbench.decompilers.declib_dec import (
    AngrDeclibDecompiler,
    BinjaDeclibDecompiler,
    DeclibDecompiler,
    GhidraDeclibDecompiler,
    IDADeclibDecompiler,
    _pe_file_space_origins,
)
from decbench.metrics.variable_features import variable_occurrence_lines
from decbench.models.decompilation import LineMapping, VariableInfo


def _write_minimal_pe(path: Path) -> None:
    image_base = 0x400000
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 2, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, image_base)
    for index, virtual_address in enumerate((0x1000, 0x3000)):
        section = 0x178 + index * 40
        struct.pack_into("<III", data, section + 8, 0x1000, virtual_address, 0x200)
    path.write_bytes(data)


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


def test_angr_pie_double_lift_is_recovered_only_when_unique_in_function() -> None:
    backend = AngrDeclibDecompiler()
    mappings = backend._extract_line_mappings(
        {1: {-0x3FCAD5}},
        "int f(void) {}",
        lifted_addr=0x352B,
        elf_base=0,
        function_size=0x20,
        address_offsets=(0, 0x400000),
    )
    assert mappings == [LineMapping(line_number=1, addresses=[0x352B])]

    already_correct = backend._extract_line_mappings(
        {1: {0x352B}},
        "int f(void) {}",
        lifted_addr=0x352B,
        elf_base=0,
        function_size=0x20,
        address_offsets=(0, 0x400000),
    )
    assert already_correct == [LineMapping(line_number=1, addresses=[0x352B])]

    ambiguous = backend._extract_line_mappings(
        {1: {0x1000}},
        "int f(void) {}",
        lifted_addr=0x1000,
        elf_base=0,
        function_size=0x10,
        address_offsets=(0, 4),
    )
    assert ambiguous == []


def test_angr_line_map_offsets_include_the_runtime_load_base() -> None:
    backend = AngrDeclibDecompiler()
    assert backend._line_map_address_offsets(SimpleNamespace(binary_base_addr=0x400000)) == (
        0,
        0x400000,
    )
    assert backend._line_map_address_offsets(SimpleNamespace(binary_base_addr=True)) == (0,)


@pytest.mark.parametrize(
    "backend",
    [
        AngrDeclibDecompiler(),
        GhidraDeclibDecompiler(),
        BinjaDeclibDecompiler(),
        IDADeclibDecompiler(),
    ],
)
@pytest.mark.parametrize("backend_base", [0x400000, 0x401000, 0x403000])
def test_declib_pe_uses_the_backend_lift_origin(
    backend: DeclibDecompiler, backend_base: int, tmp_path: Path
) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    assert (
        backend._file_space_base(
            SimpleNamespace(binary_base_addr=backend_base),
            binary,
            header_base=0x400000,
        )
        == backend_base
    )


def test_declib_pe_origins_come_from_the_preferred_image(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    assert _pe_file_space_origins(binary, 0x400000) == frozenset({0x400000, 0x401000, 0x403000})


def test_declib_pe_rejects_an_arbitrary_backend_rebase(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    with pytest.raises(RuntimeError, match="non-canonical PE backend base 0x500000"):
        IDADeclibDecompiler()._file_space_base(
            SimpleNamespace(binary_base_addr=0x500000),
            binary,
            header_base=0x400000,
        )


def test_declib_pe_rejects_a_mismatched_header_base(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    with pytest.raises(ValueError, match="header ImageBase 0x400000 does not match 0x500000"):
        _pe_file_space_origins(binary, 0x500000)


def test_declib_pe_target_round_trips_through_the_backend_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class FakeDeci:
        binary_base_addr = 0x401000

        def __init__(self) -> None:
            self.calls: list[tuple[int, bool]] = []
            self.functions = {0x2280: SimpleNamespace(size=0x20, stack_vars={}, header=None)}

        def decompile(self, address: int, *, map_lines: bool) -> SimpleNamespace:
            self.calls.append((address, map_lines))
            return SimpleNamespace(
                text="int target(void) {\n    return 0;\n}\n",
                line_map={0: {address}},
            )

        def shutdown(self) -> None:
            return None

    deci = FakeDeci()
    backend = IDADeclibDecompiler()
    monkeypatch.setattr(backend, "is_available", lambda: True)
    monkeypatch.setattr(backend, "get_version", lambda: "test")
    monkeypatch.setattr(backend, "_make_deci", lambda _binary, _project: deci)

    result = backend.decompile_binary(binary, functions=[("target", 0x403280)])

    assert deci.calls == [(0x2280, True)]
    assert result.functions["target"].address == 0x403280
    assert result.functions["target"].line_mappings == [
        LineMapping(line_number=1, addresses=[0x403280])
    ]


def test_declib_elf_keeps_the_file_header_base(tmp_path: Path) -> None:
    binary = tmp_path / "sample"
    data = bytearray(20)
    data[:4] = b"\x7fELF"
    struct.pack_into("<H", data, 18, 0x3E)
    binary.write_bytes(data)

    assert (
        IDADeclibDecompiler()._file_space_base(
            SimpleNamespace(binary_base_addr=0x400000),
            binary,
            header_base=0,
        )
        == 0
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
