"""Tests for the declib-backed decompiler plugins."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import decbench.decompilers  # noqa: F401  (registers plugins)
from decbench.decompilers.registry import DecompilerRegistry

ALL_DECOMPILERS = ["angr", "ida", "ghidra", "binja"]

TINY_C_SOURCE = """
#include <stdio.h>
#include <stdlib.h>

int add_nums(int a, int b) {
    int total = a + b;
    char tag = 'x';
    long big = (long)total * 2;
    if (big > 10)
        tag = 'y';
    printf("%d %c %ld\\n", total, tag, big);
    return total;
}

int main(int argc, char **argv) {
    int x = atoi(argv[1]);
    int sum = add_nums(x, 5);
    return sum > 0 ? 0 : 1;
}
"""


def _is_available(name: str) -> bool:
    try:
        return DecompilerRegistry.get(name).is_available()
    except Exception:
        return False


@pytest.fixture(scope="module")
def tiny_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile a small C program with DWARF info at -O0."""
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler available")

    build_dir = tmp_path_factory.mktemp("tiny_bin")
    src = build_dir / "tiny.c"
    src.write_text(TINY_C_SOURCE)
    binary = build_dir / "tiny"
    subprocess.run(
        [cc, "-g", "-O0", "-fno-inline", "-fno-builtin", "-o", str(binary), str(src)],
        check=True,
    )
    return binary


class TestRegistry:
    def test_all_backends_registered(self) -> None:
        registered = DecompilerRegistry.list_registered()
        for name in ALL_DECOMPILERS:
            assert name in registered, f"{name} missing from registry"

    def test_backends_instantiate(self) -> None:
        for name in ALL_DECOMPILERS:
            dec = DecompilerRegistry.get(name)
            assert dec.name == name
            assert isinstance(dec.is_available(), bool)

    def test_binja_registered_even_if_unavailable(self) -> None:
        """Binary Ninja support exists, but the library is not installed here."""
        dec = DecompilerRegistry.get("binja")
        assert dec.display_name == "Binary Ninja"
        if not dec.is_available():
            assert dec.get_version() is None


class _FakeTinfo:
    def __init__(self, text: str) -> None:
        self._text = text

    def dstr(self) -> str:
        return self._text


class _FakeLvar:
    """The slice of Hex-Rays' ``lvar_t`` that ``_extract_variables`` reads."""

    def __init__(self, name: str, type_str: str, is_arg: bool, width: int = 8) -> None:
        self.name = name
        self.is_arg_var = is_arg
        self.width = width
        self.location = None
        self._tinfo = _FakeTinfo(type_str)

    def type(self) -> _FakeTinfo:
        return self._tinfo


class _FakeCfunc:
    def __init__(self, lvars: list[_FakeLvar], argidx: list[int] | None) -> None:
        self._lvars = lvars
        if argidx is not None:
            self.argidx = argidx

    def get_lvars(self) -> list[_FakeLvar]:
        return self._lvars


class TestIDAArgumentOrder:
    """``get_lvars()`` enumerates in allocation order, so argument positions must
    come from ``cfunc.argidx`` — otherwise type_match's by-ABI-position pass
    compares the wrong pairs."""

    @staticmethod
    def _lvars() -> list[_FakeLvar]:
        return [
            _FakeLvar("a3", "int", True),
            _FakeLvar("a1", "leveldb::Slice *", True),
            _FakeLvar("a2", "char *", True),
            _FakeLvar("v4", "int", False),
        ]

    def test_arg_index_follows_argidx_not_enumeration(self) -> None:
        from decbench.decompilers.raw.ida_raw import RawIDADecompiler

        cfunc = _FakeCfunc(self._lvars(), argidx=[1, 2, 0])
        args = [v for v in RawIDADecompiler._extract_variables(cfunc) if v.kind == "arg"]
        assert {v.name: v.arg_index for v in args} == {"a1": 0, "a2": 1, "a3": 2}
        assert [v.type for v in sorted(args, key=lambda v: v.arg_index)] == [
            "leveldb::Slice *",
            "char *",
            "int",
        ]

    def test_locals_are_untouched(self) -> None:
        from decbench.decompilers.raw.ida_raw import RawIDADecompiler

        cfunc = _FakeCfunc(self._lvars(), argidx=[1, 2, 0])
        locals_ = [v for v in RawIDADecompiler._extract_variables(cfunc) if v.kind == "stack"]
        assert [v.name for v in locals_] == ["v4"]
        assert all(v.arg_index is None for v in locals_)

    def test_falls_back_to_enumeration_without_argidx(self) -> None:
        """An IDA build not exposing ``argidx`` keeps the previous behaviour."""
        from decbench.decompilers.raw.ida_raw import RawIDADecompiler

        cfunc = _FakeCfunc(self._lvars(), argidx=None)
        args = [v for v in RawIDADecompiler._extract_variables(cfunc) if v.kind == "arg"]
        assert {v.name: v.arg_index for v in args} == {"a3": 0, "a1": 1, "a2": 2}

    def test_arg_var_missing_from_argidx_gets_a_trailing_slot(self) -> None:
        from decbench.decompilers.raw.ida_raw import RawIDADecompiler

        cfunc = _FakeCfunc(self._lvars(), argidx=[1, 2])
        args = [v for v in RawIDADecompiler._extract_variables(cfunc) if v.kind == "arg"]
        assert {v.name: v.arg_index for v in args} == {"a1": 0, "a2": 1, "a3": 2}


@pytest.mark.parametrize("name", ["angr", "ida", "ghidra"])
class TestSmokeDecompile:
    def test_decompile_tiny_binary(self, name: str, tiny_binary: Path, tmp_path: Path) -> None:
        if not _is_available(name):
            pytest.skip(f"{name} is not available on this system")

        dec = DecompilerRegistry.get(name)
        result = dec.decompile_binary(tiny_binary, output_dir=tmp_path)

        assert result.decompiler.decompiler_name == name
        assert "add_nums" in result.functions, (
            f"{name} did not produce add_nums; got {sorted(result.functions)} "
            f"(failed: {result.decompiler.failed_functions})"
        )

        func = result.functions["add_nums"]
        assert func.decompiled_code.strip()
        assert func.line_count > 0
        assert func.variables, f"{name} produced no variables for add_nums"
        kinds = {v.kind for v in func.variables}
        assert kinds <= {"stack", "arg"}
        assert any(v.stack_offset is not None for v in func.variables)

        assert (tmp_path / f"{name}_{tiny_binary.stem}.c").exists()
