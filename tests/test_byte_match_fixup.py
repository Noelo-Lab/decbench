"""Tests for the byte-match compile harness, the fixup contract, and operand normalization."""

from __future__ import annotations

import shutil
from types import ModuleType

import pytest

from decbench.metrics import fixups
from decbench.metrics.byte_match import _normalize_operands
from decbench.metrics.fixup import compile_with_fixup

gcc_available = shutil.which("gcc") is not None
needs_gcc = pytest.mark.skipif(not gcc_available, reason="gcc not installed")

GHIDRA_STYLE = "uint compute(undefined4 x) {\n    uint r = (uint)x;\n    return r + 1;\n}\n"


def _module(**attrs: object) -> ModuleType:
    module = ModuleType("fake_fixup")
    for name, value in attrs.items():
        setattr(module, name, value)
    return module


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


class TestFixupRegistry:
    def test_module_name_strips_version_and_dashes(self) -> None:
        assert fixups.module_name("ghidra@12.1") == "ghidra"
        assert fixups.module_name("claude-code@claude-opus-4-8") == "claude_code"

    def test_unknown_decompiler_has_no_module(self) -> None:
        assert fixups.load("no-such-decompiler") is None
        assert fixups.load(None) is None
        assert fixups.fingerprint("no-such-decompiler") == ""

    @pytest.mark.parametrize(
        "flag", ["-Wno-implicit-function-declaration", "-DFOO=1", "-std=gnu99", "-fms-extensions"]
    )
    def test_allowed_flags(self, flag: str) -> None:
        assert fixups.module_flags(_module(FLAGS=[flag])) == [flag]

    @pytest.mark.parametrize("flag", ["-O0", "-m32", "-fno-inline", "-Wa,-mrelax", "-Wp,-include"])
    def test_codegen_flags_rejected(self, flag: str) -> None:
        with pytest.raises(fixups.FixupError):
            fixups.module_flags(_module(FLAGS=[flag]))

    def test_binary_key_is_order_independent(self) -> None:
        assert fixups.binary_key({"a": "1", "b": "2"}) == fixups.binary_key({"b": "2", "a": "1"})
        assert fixups.binary_key({"a": "1"}) != fixups.binary_key({"a": "2"})


@needs_gcc
class TestCompileWithFixup:
    def test_plain_function_compiles(self) -> None:
        res = compile_with_fixup("int add(int a, int b) { return a + b; }", "add")
        assert res.compilable
        assert res.obj_path is not None and res.obj_path.exists()
        shutil.rmtree(res.obj_path.parent, ignore_errors=True)

    def test_no_module_compiles_code_as_emitted(self) -> None:
        res = compile_with_fixup(GHIDRA_STYLE, "compute")
        assert not res.compilable
        assert res.iterations == 1
        assert res.source == GHIDRA_STYLE
        assert "unknown type name" in res.stderr

    def test_prepare_builds_the_translation_unit(self) -> None:
        prelude = "typedef unsigned int uint; typedef unsigned int undefined4;\n"
        seen = []

        def prepare(code: str, ctx: fixups.FixupContext) -> str:
            seen.append(ctx)
            return prelude + code

        res = compile_with_fixup(
            GHIDRA_STYLE, "compute", fixup=_module(prepare=prepare), siblings={"compute": "x"}
        )
        assert res.compilable, res.error
        assert res.source == prelude + GHIDRA_STYLE
        assert seen[0].func_name == "compute" and dict(seen[0].siblings) == {"compute": "x"}
        shutil.rmtree(res.obj_path.parent, ignore_errors=True)

    def test_repair_sees_stderr_and_is_bounded(self) -> None:
        calls = []

        def repair(source: str, stderr: str, ctx: fixups.FixupContext) -> str:
            calls.append(stderr)
            return source + f"\n/* attempt {len(calls)} */"

        res = compile_with_fixup(
            GHIDRA_STYLE, "compute", fixup=_module(prepare=lambda c, ctx: c, repair=repair)
        )
        assert not res.compilable
        assert "unknown type name" in calls[0]
        assert res.iterations == 8 and len(calls) == 7

    def test_repair_returning_none_stops(self) -> None:
        res = compile_with_fixup(
            GHIDRA_STYLE,
            "compute",
            fixup=_module(prepare=lambda c, ctx: c, repair=lambda s, e, ctx: None),
        )
        assert not res.compilable and res.iterations == 1

    def test_raising_module_fails_closed(self) -> None:
        def prepare(code: str, ctx: fixups.FixupContext) -> str:
            raise RuntimeError("bug")

        res = compile_with_fixup("int f(void) { return 0; }", "f", fixup=_module(prepare=prepare))
        assert not res.compilable
        assert res.error == "fixup raised RuntimeError"
        assert res.obj_path is None

    def test_disallowed_flags_fail_closed(self) -> None:
        module = _module(FLAGS=["-O0"], prepare=lambda c, ctx: c)
        res = compile_with_fixup("int f(void) { return 0; }", "f", fixup=module)
        assert not res.compilable
        assert res.error == "fixup raised FixupError"

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
