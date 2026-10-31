"""Stripping the binaries decompilers are handed.

The benchmark compiles with ``-g`` for ground truth and gives each decompiler a
stripped copy. A host binutils built without multiarch support cannot read a
foreign format such as ARM ELF, so stripping must fall through to the target's
own binutils or LLVM, and must never hand back a copy that still has symbols.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from decbench.utils import binfmt

needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")


def _llvm_strip() -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        for candidate in sorted(glob.glob(os.path.join(directory, "llvm-strip*"))):
            if os.access(candidate, os.X_OK):
                return candidate
    return None


def _tool(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)
    return path


@pytest.fixture
def debug_elf(tmp_path: Path) -> Path:
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    source = tmp_path / "prog.c"
    source.write_text(
        "int add(int a, int b) { return a + b; }\nint main(void) { return add(1, 2); }\n"
    )
    binary = tmp_path / "prog"
    subprocess.run(["gcc", "-g", "-O0", str(source), "-o", str(binary)], check=True)
    assert binfmt.strip_leftovers(binary)
    return binary


def test_tools_prefer_the_target_binutils_then_host_then_llvm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("strip", "arm-none-eabi-strip", "llvm-strip-14", "llvm-strip-18", "llvm-objcopy"):
        _tool(tmp_path, name, "exit 0")
    monkeypatch.setenv("PATH", str(tmp_path))

    tools = binfmt.strip_tools(binfmt.BinInfo("elf", "arm", 32))

    assert [Path(tool).name for tool in tools] == [
        "arm-none-eabi-strip",
        "strip",
        "llvm-strip-18",
        "llvm-strip-14",
        "llvm-objcopy",
    ]


@needs_gcc
def test_strip_copy_removes_symbols_and_dwarf(debug_elf: Path, tmp_path: Path) -> None:
    out = tmp_path / "stripped"

    binfmt.strip_copy(debug_elf, out)

    assert binfmt.strip_leftovers(out) == []
    assert binfmt.strip_leftovers(debug_elf)


@needs_gcc
def test_a_tool_that_leaves_symbols_is_not_trusted(
    debug_elf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _tool(bin_dir, "strip", "exit 0")
    monkeypatch.setenv("PATH", str(bin_dir))
    out = tmp_path / "stripped"

    with pytest.raises(RuntimeError, match="no strip tool"):
        binfmt.strip_copy(debug_elf, out)

    assert not out.exists()


@pytest.mark.skipif(
    shutil.which("clang") is None or _llvm_strip() is None, reason="needs clang and llvm-strip"
)
def test_arm_elf_falls_back_to_llvm_when_host_strip_rejects_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "fw.c"
    source.write_text("int add(int a, int b) { return a + b; }\n")
    obj = tmp_path / "fw.o"
    subprocess.run(
        ["clang", "--target=armv7-none-eabi", "-g", "-c", str(source), "-o", str(obj)], check=True
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _tool(bin_dir, "strip", 'echo "strip: $1: file format not recognized" >&2; exit 1')
    (bin_dir / "llvm-strip").symlink_to(str(_llvm_strip()))
    monkeypatch.setenv("PATH", str(bin_dir))
    out = tmp_path / "fw.stripped.o"

    tool = binfmt.strip_copy(obj, out)

    assert Path(tool).name == "llvm-strip"
    assert binfmt.strip_leftovers(out) == []


@needs_gcc
def test_benchmark_replaces_a_cached_copy_that_kept_symbols(
    debug_elf: Path, tmp_path: Path
) -> None:
    from scripts import run_benchmark

    strip_dir = tmp_path / "stripped"
    strip_dir.mkdir()
    stale = strip_dir / debug_elf.name
    shutil.copy2(debug_elf, stale)
    os.utime(stale, (debug_elf.stat().st_mtime + 10, debug_elf.stat().st_mtime + 10))

    out = run_benchmark._stripped_copy(debug_elf, strip_dir)

    assert out == stale
    assert binfmt.strip_leftovers(out) == []
