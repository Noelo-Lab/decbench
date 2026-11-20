"""DWARF relabeling renames the definition each backend actually prints."""

from __future__ import annotations

from pathlib import Path

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)

ANGR = """void snappy::UncheckedByteArraySink::GetAppendBuffer(void* this, unsigned long a0)
{
    return;
}"""
FISSION = """typedef unsigned long long snappy_status;
extern unsigned long long sub_b9b0();

char* fission_symbol_snappy_x3A__x3A_Sink_x3A__x3A_GetAppendBuffer(Sink* const this, size_t len)
{
    return sub_b9b0();
}"""
KUNA = """char * snappy::Sink::GetAppendBuffer(snappy::Sink *this,unsigned long len)
{
  return (char *)0x0;
}"""
GHIDRA = """/* DWARF original prototype: char * GetAppendBuffer(Sink * this, size_t length) */

char * __thiscall snappy::Sink::GetAppendBuffer(Sink *this,size_t length)
{
  return (char *)0x0;
}"""


@pytest.mark.parametrize(
    ("code", "spelled"),
    [
        (ANGR, "snappy::UncheckedByteArraySink::GetAppendBuffer"),
        (FISSION, "fission_symbol_snappy_x3A__x3A_Sink_x3A__x3A_GetAppendBuffer"),
        (KUNA, "snappy::Sink::GetAppendBuffer"),
        (GHIDRA, "snappy::Sink::GetAppendBuffer"),
        ("int add(int a, int b) const noexcept { return a + b; }", "add"),
        ("struct S { void (*cb)(int); };\nint f(void);\nint g(void) {\n  return f();\n}", "g"),
        ("S::~S()\n{\n}", "S::~S"),
        ("int f(void);", None),
    ],
)
def test_definition_name(code: str, spelled: str | None) -> None:
    from scripts import run_benchmark

    assert run_benchmark._definition_name(code) == spelled


@pytest.mark.parametrize(
    ("reported", "code"),
    [
        ("_ZN6snappy22UncheckedByteArraySink15GetAppendBufferEmPc", ANGR),
        ("snappy::Sink::GetAppendBuffer(unsigned long, char*)", FISSION),
        ("snappy::Sink::GetAppendBuffer", KUNA),
        ("FUN_0010c5f0", GHIDRA),
    ],
)
def test_relabel_renames_printed_cpp_definition(
    reported: str, code: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import run_benchmark

    monkeypatch.setattr(run_benchmark.binfmt, "detect", lambda _path: None)
    monkeypatch.setattr("decbench.decompilers.raw.common.elf_min_vaddr", lambda _path: 0)
    function = FunctionDecompilation(
        name=reported, address=0xC5F0, decompiled_code=code, line_count=code.count("\n") + 1
    )
    result = DecompilationResult(
        binary_path=tmp_path / "lib.so",
        binary_name="lib",
        decompiler=DecompilerMetadata(decompiler_name="test"),
        functions={reported: function},
    )

    run_benchmark._relabel_to_dwarf(result, {0xC5F0: "GetAppendBuffer"}, tmp_path / "lib.so")

    relabeled = result.functions["GetAppendBuffer"]
    assert run_benchmark._definition_name(relabeled.decompiled_code) == "GetAppendBuffer"
    assert "fission_symbol" not in relabeled.decompiled_code.split("{")[0].splitlines()[-1]


def test_relabel_keeps_spelling_when_dwarf_name_is_not_a_c_identifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import run_benchmark

    monkeypatch.setattr(run_benchmark.binfmt, "detect", lambda _path: None)
    monkeypatch.setattr("decbench.decompilers.raw.common.elf_min_vaddr", lambda _path: 0)
    code = "void fission_symbol_Sink_x3A__x3A__x7E_Sink(Sink* const this)\n{\n}"
    function = FunctionDecompilation(
        name="snappy::Sink::~Sink()", address=0xC3A8, decompiled_code=code, line_count=3
    )
    result = DecompilationResult(
        binary_path=tmp_path / "lib.so",
        binary_name="lib",
        decompiler=DecompilerMetadata(decompiler_name="test"),
        functions={function.name: function},
    )

    run_benchmark._relabel_to_dwarf(result, {0xC3A8: "~Sink"}, tmp_path / "lib.so")

    assert result.functions["~Sink"].decompiled_code == code
