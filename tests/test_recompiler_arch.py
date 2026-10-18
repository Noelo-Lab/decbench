"""Tests for choosing a recompiler when the host is not the target."""

from __future__ import annotations

import platform
from pathlib import Path
from unittest import mock

import pytest

from decbench.utils.binfmt import BinInfo, recompiler_for


@pytest.mark.parametrize(
    ("arch", "expected"),
    [("x86-64", "gcc"), ("x86", "gcc"), ("aarch64", "aarch64-linux-gnu-gcc")],
)
def test_an_x86_linux_host_is_unchanged(arch: str, expected: str) -> None:
    with (
        mock.patch.object(platform, "system", return_value="Linux"),
        mock.patch.object(platform, "machine", return_value="x86_64"),
    ):
        assert recompiler_for(BinInfo("elf", arch, 64)) == expected


def test_a_non_x86_host_does_not_recompile_x86_with_its_own_gcc() -> None:
    """`byte_match` would otherwise pass `-march=x86-64` to an aarch64 gcc.

    That fails for every function, scoring 0.0 rather than abstaining, so a
    retargeted corpus reads as "decompiled fine, bytes never matched".
    """
    with (
        mock.patch.object(platform, "system", return_value="Linux"),
        mock.patch.object(platform, "machine", return_value="aarch64"),
    ):
        assert recompiler_for(BinInfo("elf", "x86-64", 64)) == "x86_64-linux-gnu-gcc"
        assert recompiler_for(BinInfo("elf", "aarch64", 64)) == "gcc"


@pytest.mark.parametrize("host", ["x86_64", "AMD64", "i686", "i386"])
def test_every_intel_host_spelling_builds_x86_natively(host: str) -> None:
    """Preserve accepted machine spellings on Linux hosts.

    Missing a spelling costs a real recompile: the host's own `gcc` is there and
    works, but `byte_match` abstains as if no toolchain existed.
    """
    with (
        mock.patch.object(platform, "system", return_value="Linux"),
        mock.patch.object(platform, "machine", return_value=host),
    ):
        assert recompiler_for(BinInfo("elf", "x86", 32)) == "gcc"


@pytest.mark.parametrize("host", ["ARM64", "arm64", "aarch64"])
def test_arm_host_spellings_are_native(host: str) -> None:
    with (
        mock.patch.object(platform, "system", return_value="Linux"),
        mock.patch.object(platform, "machine", return_value=host),
    ):
        assert recompiler_for(BinInfo("elf", "aarch64", 64)) == "gcc"


def test_a_32_bit_host_cannot_build_the_64_bit_target() -> None:
    with (
        mock.patch.object(platform, "system", return_value="Linux"),
        mock.patch.object(platform, "machine", return_value="i686"),
    ):
        assert recompiler_for(BinInfo("elf", "x86-64", 64)) == "x86_64-linux-gnu-gcc"


def test_pe_and_bare_metal_arm_are_host_independent() -> None:
    for host in ("x86_64", "aarch64"):
        with (
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value=host),
        ):
            assert recompiler_for(BinInfo("pe", "x86-64", 64)) == "x86_64-w64-mingw32-gcc"
            assert recompiler_for(BinInfo("elf", "arm", 32)) == "arm-none-eabi-gcc"


@pytest.mark.parametrize("system", ["Darwin", "Windows", "FreeBSD"])
@pytest.mark.parametrize("machine,arch", [("arm64", "aarch64"), ("AMD64", "x86-64")])
def test_same_architecture_on_other_os_requires_cross_elf_compiler(
    system: str, machine: str, arch: str
) -> None:
    with (
        mock.patch.object(platform, "system", return_value=system),
        mock.patch.object(platform, "machine", return_value=machine),
    ):
        assert (
            recompiler_for(BinInfo("elf", arch, 64))
            == {"aarch64": "aarch64-linux-gnu-gcc", "x86-64": "x86_64-linux-gnu-gcc"}[arch]
        )


def test_coff_object_identity_requires_a_complete_header(tmp_path: Path) -> None:
    import struct

    from decbench.utils.binfmt import object_info

    obj = tmp_path / "unit.obj"
    obj.write_bytes(struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0) + b"\0" * 40)
    assert object_info(obj) == BinInfo("pe", "x86-64", 64)
    obj.write_bytes(obj.read_bytes()[:30])
    assert object_info(obj) is None
    obj.write_bytes(b"not an object")
    assert object_info(obj) is None


@pytest.mark.parametrize(
    "target,expected",
    [
        (None, None),
        ("x86_64-pc-windows-msvc", BinInfo("pe", "x86-64", 64)),
        ("aarch64-linux-gnu", BinInfo("elf", "aarch64", 64)),
    ],
)
def test_real_compiler_object_identity(
    tmp_path: Path, target: str | None, expected: BinInfo | None
) -> None:
    import shutil
    import subprocess

    from decbench.utils.binfmt import object_info

    compiler = shutil.which("clang")
    if compiler is None:
        pytest.skip("clang required")
    source, obj = tmp_path / "unit.c", tmp_path / "unit.o"
    source.write_text("int f(int x){return x+1;}\n")
    command = [compiler]
    if target:
        command += ["-target", target]
    subprocess.run([*command, "-c", str(source), "-o", str(obj)], check=True, capture_output=True)
    actual = object_info(obj)
    assert actual is not None
    if expected:
        assert actual == expected
    else:
        assert actual.fmt == (
            "macho"
            if platform.system() == "Darwin"
            else "elf" if platform.system() == "Linux" else "pe"
        )


def test_wrong_compiler_object_is_abstention_not_a_byte_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    import decbench.metrics.fixup as fixup
    from decbench.metrics.byte_match import ByteMatchMetric
    from decbench.models.decompilation import FunctionDecompilation
    from decbench.utils import binfmt

    obj_dir = tmp_path / "build"
    obj_dir.mkdir()
    obj = obj_dir / "unit.o"
    obj.write_bytes(b"unproven object")
    monkeypatch.setattr(
        fixup,
        "compile_with_fixup",
        lambda *a, **kw: SimpleNamespace(obj_path=obj, iterations=0, injected=[]),
    )
    monkeypatch.setattr(binfmt, "object_info", lambda path: BinInfo("macho", "aarch64", 64))

    def forbidden(*args: object) -> None:
        raise AssertionError("incompatible object must not reach byte extraction")

    monkeypatch.setattr(binfmt, "object_text_bytes", forbidden)
    result = ByteMatchMetric()._compute_uncached(
        FunctionDecompilation(name="f", address=16, decompiled_code="int f(){return 0;}"),
        b"\x90",
        "gcc",
        [],
        None,
        expected_info=BinInfo("elf", "aarch64", 64),
    )
    assert result.metadata["skipped"] is True
    assert result.metadata["emitted_target"]["fmt"] == "macho"
    assert result.metadata["expected_target"]["fmt"] == "elf"
    assert not obj_dir.exists()


def test_incompatible_target_is_excluded_from_binary_aggregate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from decbench.metrics.byte_match import ByteMatchMetric
    from decbench.models.decompilation import (
        DecompilationResult,
        DecompilerMetadata,
        FunctionDecompilation,
    )
    from decbench.models.metrics import MetricValue
    from decbench.utils import binfmt

    monkeypatch.setattr(binfmt, "detect", lambda path: BinInfo("elf", "x86-64", 64))
    monkeypatch.setattr(binfmt, "recompiler_for", lambda *args: "gcc")
    monkeypatch.setattr(binfmt, "tool_available", lambda compiler: True)
    result = DecompilationResult(
        binary_path=tmp_path / "original",
        binary_name="original",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    result.add_function(
        FunctionDecompilation(name="f", address=16, decompiled_code="int f(){return 0;}")
    )
    metric = ByteMatchMetric()
    monkeypatch.setattr(
        metric,
        "compute_for_function",
        lambda *a, **kw: MetricValue(
            value=0.0, metadata={"skipped": True, "reason": "incompatible compiler target"}
        ),
    )
    scored = metric.compute_for_binary(result)
    assert not scored.function_results
    assert scored.errors == ["f: abstained: incompatible compiler target"]


def test_compatible_compiler_object_preserves_byte_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    import decbench.metrics.fixup as fixup
    from decbench.metrics.byte_match import ByteMatchMetric
    from decbench.models.decompilation import FunctionDecompilation
    from decbench.utils import binfmt

    obj_dir = tmp_path / "build"
    obj_dir.mkdir()
    obj = obj_dir / "unit.o"
    obj.write_bytes(b"verified by stub")
    info = BinInfo("elf", "x86-64", 64)
    monkeypatch.setattr(
        fixup,
        "compile_with_fixup",
        lambda *a, **kw: SimpleNamespace(obj_path=obj, iterations=0, injected=[]),
    )
    monkeypatch.setattr(binfmt, "object_info", lambda path: info)
    monkeypatch.setattr(binfmt, "object_text_bytes", lambda *a: b"\x90")
    result = ByteMatchMetric()._compute_uncached(
        FunctionDecompilation(name="f", address=16, decompiled_code="int f(){return 0;}"),
        b"\x90",
        "gcc",
        [],
        None,
        expected_info=info,
    )
    assert result.value == 1.0
    assert result.metadata["exact_match"] is True
    assert not obj_dir.exists()


def test_elf_object_bitness_comes_from_file_class(tmp_path: Path) -> None:
    import struct

    from decbench.utils.binfmt import object_info

    obj = tmp_path / "x32.o"
    header = bytearray(64)
    header[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<HH", header, 16, 1, 0x3E)
    obj.write_bytes(header)
    assert object_info(obj) == BinInfo("elf", "x86-64", 32)
    struct.pack_into("<H", header, 16, 2)
    obj.write_bytes(header)
    assert object_info(obj) is None
