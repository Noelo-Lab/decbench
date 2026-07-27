"""Tests for the byte-match compilability fixup + operand normalization."""

from __future__ import annotations

import shutil

import pytest

from decbench.metrics.byte_match import _normalize_operands
from decbench.metrics.fixup import compile_with_fixup, sanitize_tokens

gcc_available = shutil.which("gcc") is not None
needs_gcc = pytest.mark.skipif(not gcc_available, reason="gcc not installed")


class TestSanitizeTokens:
    def test_strips_symbol_version_qualifier(self) -> None:
        out = sanitize_tokens("fprintf(GLIBC_2.2.5::stderr, msg);")
        assert "::" not in out
        assert "stderr" in out

    def test_leaves_plain_code_untouched(self) -> None:
        code = "int f(int a) { return a + 1; }"
        assert sanitize_tokens(code) == code

    def test_strips_decompiler_annotations(self) -> None:
        assert "__noreturn" not in sanitize_tokens("int main() __noreturn {")
        assert "__convention" not in sanitize_tokens('void f() __convention("regparm") {')
        out = sanitize_tokens("int __cdecl g(int a)")
        assert "__cdecl" not in out and "g(int a)" in out


class TestNormalizeOperands:
    def test_branch_target_blanked(self) -> None:
        a = _normalize_operands("call", "0x1234")
        b = _normalize_operands("call", "0x9abc")
        assert a == b == "X"

    def test_rip_relative_blanked(self) -> None:
        a = _normalize_operands("lea", "rax, [rip + 0x2e04]")
        b = _normalize_operands("lea", "rax, [rip + 0x10]")
        assert a == b
        assert "0x2e04" not in a

    def test_non_branch_immediate_preserved(self) -> None:
        out = _normalize_operands("add", "rax, 0x10")
        assert "0x10" in out

    def test_indirect_branch_displacement_preserved(self) -> None:
        a = _normalize_operands("call", "qword ptr [rax + 0x20]")
        b = _normalize_operands("call", "qword ptr [rax + 0x40]")
        assert a != b
        assert "0x20" in a

    def test_arm_adrp_immediate_blanked(self) -> None:
        a = _normalize_operands("adrp", "x0, #0x400000")
        b = _normalize_operands("adrp", "x0, #0x10000")
        assert a == b
        assert "0x400000" not in a

    def test_arm_pc_literal_load_blanked(self) -> None:
        a = _normalize_operands("ldr", "x0, [pc, #0x2e04]")
        b = _normalize_operands("ldr", "x0, [pc, #0x10]")
        assert a == b
        assert "0x2e04" not in a


@needs_gcc
class TestCompileWithFixup:
    def test_plain_function_compiles(self) -> None:
        res = compile_with_fixup("int add(int a, int b) { return a + b; }", "add")
        assert res.compilable
        assert res.obj_path is not None and res.obj_path.exists()
        shutil.rmtree(res.obj_path.parent, ignore_errors=True)

    def test_ghidra_pseudotypes_get_defined(self) -> None:
        code = (
            "uint compute(undefined4 x) {\n" "    uint r = (uint)x;\n" "    return r + 1;\n" "}\n"
        )
        res = compile_with_fixup(code, "compute")
        assert res.compilable, res.error
        assert res.iterations >= 2
        shutil.rmtree(res.obj_path.parent, ignore_errors=True)

    def test_undeclared_symbol_stubbed(self) -> None:
        code = "int g(void) { return helper_fn(global_thing); }"
        res = compile_with_fixup(code, "g")
        assert res.compilable, res.error
        shutil.rmtree(res.obj_path.parent, ignore_errors=True)

    def test_unrepairable_returns_no_object(self) -> None:
        res = compile_with_fixup("int bad(void) { return", "bad")
        assert not res.compilable
        assert res.obj_path is None

    def test_abstains_when_toolchain_missing(self, tmp_path) -> None:
        import subprocess

        from decbench.metrics.byte_match import ByteMatchMetric
        from decbench.models.decompilation import (
            DecompilationResult,
            DecompilerMetadata,
            FunctionDecompilation,
        )
        from decbench.utils import binfmt

        if not gcc_available:
            pytest.skip("gcc not installed")
        binary = tmp_path / "b"
        src = tmp_path / "b.c"
        src.write_text("int add(int a,int b){return a+b;}\nint main(){return add(2,3);}\n")
        subprocess.run(["gcc", "-O0", "-g", "-o", str(binary), str(src)], check=True)

        dr = DecompilationResult(
            binary_path=binary,
            binary_name="b",
            decompiler=DecompilerMetadata(decompiler_name="angr"),
            functions={
                "add": FunctionDecompilation(
                    name="add", address=0x1000, decompiled_code="int add(int a,int b){return a+b;}"
                )
            },
        )
        metric = ByteMatchMetric()
        orig = binfmt.tool_available
        binfmt.tool_available = lambda name: False
        try:
            result = metric.compute_for_binary(dr)
        finally:
            binfmt.tool_available = orig
        assert result.function_results == {}
        assert any("abstain" in e for e in result.errors)

    def test_failure_paths_do_not_leak_temp_dirs(self, tmp_path) -> None:
        import glob
        import tempfile

        old = tempfile.tempdir
        tempfile.tempdir = str(tmp_path)
        try:
            for _ in range(5):
                compile_with_fixup("int bad(void) { return", "bad")
        finally:
            tempfile.tempdir = old
        assert glob.glob(f"{tmp_path}/decbench_bm_*") == []
