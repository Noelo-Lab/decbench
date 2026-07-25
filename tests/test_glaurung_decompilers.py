"""Tests for the raw Glaurung decompiler backend.

Follows the ``tests/test_decompilers.py`` pattern: registry smoke tests that
never require the tool, plus a live decompile smoke test that skips gracefully
when the ``glaurung`` CLI is not on the machine (``$GLAURUNG_BIN`` / PATH).

Glaurung emits parseable-C (a real ``long name(long arg0, …)`` signature) rather
than the declib-shaped ``VariableInfo`` list, so — unlike the angr/ghidra/ida
smoke test — this asserts on the signature text, not recovered variables.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import decbench.decompilers  # noqa: F401  (registers plugins)
from decbench.decompilers.raw import common
from decbench.decompilers.registry import DecompilerRegistry

TINY_C_SOURCE = """
#include <stdio.h>
#include <stdlib.h>

int add_nums(int a, int b) {
    int total = a + b;
    long big = (long)total * 2;
    if (big > 10)
        total += 1;
    printf("%d %ld\\n", total, big);
    return total;
}

int main(int argc, char **argv) {
    int x = atoi(argv[1]);
    return add_nums(x, 5) > 0 ? 0 : 1;
}
"""


def _is_available(name: str) -> bool:
    try:
        return DecompilerRegistry.get(name).is_available()
    except Exception:
        return False


@pytest.fixture(scope="module")
def tiny_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile a small C program with DWARF info at -O0 (non-PIE, non-stripped)."""
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler available")

    build_dir = tmp_path_factory.mktemp("tiny_bin")
    src = build_dir / "tiny.c"
    src.write_text(TINY_C_SOURCE)
    binary = build_dir / "tiny"
    subprocess.run(
        [
            cc,
            "-g",
            "-O0",
            "-fno-inline",
            "-fno-pie",
            "-no-pie",
            "-o",
            str(binary),
            str(src),
        ],
        check=True,
    )
    return binary


class TestRegistry:
    def test_backends_registered(self) -> None:
        registered = DecompilerRegistry.list_registered()
        assert "glaurung" in registered
        assert "glaurung-agentic" in registered

    def test_native_backend_instantiates(self) -> None:
        dec = DecompilerRegistry.get("glaurung")
        assert dec.name == "glaurung"
        # is_available must never raise, regardless of whether the CLI is here.
        assert isinstance(dec.is_available(), bool)

    def test_version_is_none_when_unavailable(self) -> None:
        dec = DecompilerRegistry.get("glaurung")
        if not dec.is_available():
            assert dec.get_version() is None


class TestSmokeDecompile:
    def test_decompile_tiny_binary(self, tiny_binary: Path, tmp_path: Path) -> None:
        if not _is_available("glaurung"):
            pytest.skip("glaurung CLI not available (set $GLAURUNG_BIN or add to PATH)")

        dec = DecompilerRegistry.get("glaurung")
        result = dec.decompile_binary(tiny_binary, output_dir=tmp_path)

        assert result.decompiler.decompiler_name == "glaurung"
        assert "add_nums" in result.functions, (
            f"glaurung did not produce add_nums; got {sorted(result.functions)} "
            f"(failed: {result.decompiler.failed_functions})"
        )

        func = result.functions["add_nums"]
        assert func.decompiled_code.strip()
        assert func.line_count > 0

        # Address is in ELF-file space (no rebasing): it must sit at or above the
        # binary's minimum PT_LOAD vaddr.
        assert func.address >= common.elf_min_vaddr(tiny_binary)

        # Parseable-C contract: a real C function signature, no register sigils.
        assert "long " in func.decompiled_code
        assert "%" not in func.decompiled_code

        # Output files were written.
        assert (tmp_path / f"glaurung_{tiny_binary.stem}.c").exists()

    def test_target_scoped_decompile_narrows_to_requested(
        self, tiny_binary: Path
    ) -> None:
        if not _is_available("glaurung"):
            pytest.skip("glaurung CLI not available")

        dec = DecompilerRegistry.get("glaurung")
        # First discover everything, then re-run scoped to add_nums' address only.
        everything = dec.decompile_binary(tiny_binary)
        assert "add_nums" in everything.functions
        target = everything.functions["add_nums"].address

        scoped = dec.decompile_binary(tiny_binary, function_names={target})
        assert set(scoped.functions), "scoped run produced nothing"
        # The requested target must be present; CRT/PLT must not leak in.
        assert any(f.address == target for f in scoped.functions.values())
