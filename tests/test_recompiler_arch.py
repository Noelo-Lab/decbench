"""Tests for choosing a recompiler when the host is not the target."""

from __future__ import annotations

import platform
from unittest import mock

import pytest

from decbench.utils.binfmt import BinInfo, recompiler_for


@pytest.mark.parametrize(
    ("arch", "expected"),
    [("x86-64", "gcc"), ("x86", "gcc"), ("aarch64", "aarch64-linux-gnu-gcc")],
)
def test_an_x86_host_is_unchanged(arch: str, expected: str) -> None:
    with mock.patch.object(platform, "machine", return_value="x86_64"):
        assert recompiler_for(BinInfo("elf", arch, 64)) == expected


def test_a_non_x86_host_does_not_recompile_x86_with_its_own_gcc() -> None:
    """`byte_match` would otherwise pass `-march=x86-64` to an aarch64 gcc.

    That fails for every function, scoring 0.0 rather than abstaining, so a
    retargeted corpus reads as "decompiled fine, bytes never matched".
    """
    with mock.patch.object(platform, "machine", return_value="aarch64"):
        assert recompiler_for(BinInfo("elf", "x86-64", 64)) == "x86_64-linux-gnu-gcc"
        assert recompiler_for(BinInfo("elf", "aarch64", 64)) == "gcc"


@pytest.mark.parametrize("host", ["x86_64", "AMD64", "i686", "i386"])
def test_every_intel_host_spelling_builds_x86_natively(host: str) -> None:
    """`platform.machine()` says `AMD64` on Windows and `i686` on a 32-bit host.

    Missing a spelling costs a real recompile: the host's own `gcc` is there and
    works, but `byte_match` abstains as if no toolchain existed.
    """
    with mock.patch.object(platform, "machine", return_value=host):
        assert recompiler_for(BinInfo("elf", "x86", 32)) == "gcc"


@pytest.mark.parametrize("host", ["ARM64", "arm64", "aarch64"])
def test_arm_host_spellings_are_native(host: str) -> None:
    with mock.patch.object(platform, "machine", return_value=host):
        assert recompiler_for(BinInfo("elf", "aarch64", 64)) == "gcc"


def test_a_32_bit_host_cannot_build_the_64_bit_target() -> None:
    with mock.patch.object(platform, "machine", return_value="i686"):
        assert recompiler_for(BinInfo("elf", "x86-64", 64)) == "x86_64-linux-gnu-gcc"


def test_pe_and_bare_metal_arm_are_host_independent() -> None:
    for host in ("x86_64", "aarch64"):
        with mock.patch.object(platform, "machine", return_value=host):
            assert recompiler_for(BinInfo("pe", "x86-64", 64)) == "x86_64-w64-mingw32-gcc"
            assert recompiler_for(BinInfo("elf", "arm", 32)) == "arm-none-eabi-gcc"
