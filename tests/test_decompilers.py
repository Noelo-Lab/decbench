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
            # is_available must never raise
            assert isinstance(dec.is_available(), bool)

    def test_binja_registered_even_if_unavailable(self) -> None:
        """Binary Ninja support exists, but the library is not installed here."""
        dec = DecompilerRegistry.get("binja")
        assert dec.display_name == "Binary Ninja"
        if not dec.is_available():
            assert dec.get_version() is None


@pytest.mark.parametrize("name", ["angr", "ida", "ghidra"])
class TestSmokeDecompile:
    def test_decompile_tiny_binary(
        self, name: str, tiny_binary: Path, tmp_path: Path
    ) -> None:
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
        # Structured variables must be populated (stack vars and/or args)
        assert func.variables, f"{name} produced no variables for add_nums"
        kinds = {v.kind for v in func.variables}
        assert kinds <= {"stack", "arg"}
        # At -O0 every backend recovers at least one stack variable w/ offset
        assert any(v.stack_offset is not None for v in func.variables)

        # Output files were written
        assert (tmp_path / f"{name}_{tiny_binary.stem}.c").exists()
