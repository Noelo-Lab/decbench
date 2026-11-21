"""Tests for the raw Fission decompiler backend.

Mirrors ``tests/test_glaurung_decompilers.py``: registry smoke tests that
never require the CLI, fake-Docker command tests, and live decompile smoke
tests that skip gracefully when ``fission_cli`` is not available.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import decbench.decompilers  # noqa: F401  (registers plugins)
from decbench.decompilers.raw import common
from decbench.decompilers.raw.fission_raw import _DEFAULT_REF, RawFissionDecompiler
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
        assert "fission" in registered

    def test_native_backend_instantiates(self) -> None:
        dec = DecompilerRegistry.get("fission")
        assert dec.name == "fission"
        assert dec.runnable is True
        assert isinstance(dec.is_available(), bool)

    def test_version_is_none_when_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FISSION_BIN", "/nonexistent/fission_cli")
        monkeypatch.setattr(
            "decbench.decompilers.raw.fission_raw._image_present", lambda image: False
        )
        dec = RawFissionDecompiler()
        assert dec.is_available() is False
        assert dec.get_version() is None


def _func_address(binary: Path, name: str) -> int:
    """Return one symbol's entry address from ELF or Mach-O."""
    if binary.read_bytes()[:4] == b"\x7fELF":
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection

        with binary.open("rb") as stream:
            for section in ELFFile(stream).iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        if symbol.name == name and symbol["st_value"]:
                            return int(symbol["st_value"])

    import lief

    parsed = lief.parse(str(binary))
    if parsed is not None:
        for symbol in parsed.symbols:
            sym_name = getattr(symbol, "name", "")
            value = int(getattr(symbol, "value", 0) or 0)
            if sym_name in {name, f"_{name}"} and value:
                return value
    raise AssertionError(f"no symbol {name} in {binary}")


FAKE_DOCKER = """#!/usr/bin/env python3
import os
import sys

argv = sys.argv[1:]
log = os.environ.get("FAKE_DOCKER_LOG")
if log:
    with open(log, "a") as stream:
        stream.write("\\0".join(argv) + "\\n")

if argv[:2] == ["image", "inspect"]:
    raise SystemExit(int(os.environ.get("FAKE_DOCKER_INSPECT_RC", "0")))
if argv[:1] == ["build"]:
    raise SystemExit(0)
if argv[:1] == ["run"]:
    if "--entrypoint" in argv:
        print(os.environ.get("FAKE_DOCKER_REV", "abc1234"))
        raise SystemExit(0)
    print(os.environ.get("FAKE_FISSION_JSON", "[]"))
    raise SystemExit(int(os.environ.get("FAKE_DOCKER_RUN_RC", "0")))
raise SystemExit(2)
"""


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Install a deterministic Docker command double and disable native Fission."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    log = tmp_path / "docker-argv.log"
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("FISSION_BIN", str(tmp_path / "no-such-fission"))
    monkeypatch.setenv("FAKE_DOCKER_LOG", str(log))
    monkeypatch.delenv("FISSION_IMAGE", raising=False)
    monkeypatch.delenv("FISSION_VERSION", raising=False)
    return log


def _docker_calls(log: Path) -> list[list[str]]:
    if not log.exists():
        return []
    return [line.split("\0") for line in log.read_text().splitlines() if line]


class TestDockerInstall:
    def test_explicit_bad_binary_does_not_fall_through_to_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FISSION_BIN", "/nonexistent/fission_cli")
        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/fission_cli")
        monkeypatch.setattr(
            "decbench.decompilers.raw.fission_raw._image_present", lambda image: False
        )

        assert RawFissionDecompiler()._select_path() == ("none", None)

    def test_image_makes_backend_available_without_native_binary(self, fake_docker: Path) -> None:
        dec = RawFissionDecompiler()

        assert dec.is_available() is True
        assert dec._select_path() == ("docker", None)
        assert {tuple(call[:2]) for call in _docker_calls(fake_docker)} == {("image", "inspect")}

    def test_native_binary_wins_over_image(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_docker: Path,
        tmp_path: Path,
    ) -> None:
        native = tmp_path / "fission_cli"
        native.write_text("#!/bin/sh\nexit 0\n")
        native.chmod(0o755)
        monkeypatch.setenv("FISSION_BIN", str(native))

        assert RawFissionDecompiler()._select_path() == ("native", native)
        assert _docker_calls(fake_docker) == []

    def test_docker_version_is_revision_bound(
        self, monkeypatch: pytest.MonkeyPatch, fake_docker: Path
    ) -> None:
        monkeypatch.setenv("FAKE_DOCKER_REV", "5073a1c")

        assert RawFissionDecompiler().get_version() == "git-5073a1c"
        revision_call = next(call for call in _docker_calls(fake_docker) if "--entrypoint" in call)
        assert revision_call[-2:] == ["decbench/fission:latest", "/opt/fission.rev"]

    def test_build_image_pins_resolved_revision(
        self, monkeypatch: pytest.MonkeyPatch, fake_docker: Path
    ) -> None:
        monkeypatch.setenv("FISSION_REF", "main")
        monkeypatch.setattr(
            "decbench.decompilers.raw.fission_raw._resolve_ref",
            lambda repo, ref: "5073a1c63dcf15b5",
        )

        assert RawFissionDecompiler.build_image() == 0
        build = next(call for call in _docker_calls(fake_docker) if call[0] == "build")
        dockerfile = Path(build[build.index("-f") + 1])
        assert dockerfile.name == "fission.Dockerfile"
        assert dockerfile.is_file()
        assert build[build.index("-t") + 1] == "decbench/fission:latest"
        assert "FISSION_REF=5073a1c63dcf15b5" in build
        assert "--no-cache" not in build
        assert Path(build[-1]) == dockerfile.parent

    def test_default_build_uses_evaluated_revision(
        self, monkeypatch: pytest.MonkeyPatch, fake_docker: Path
    ) -> None:
        monkeypatch.delenv("FISSION_REPO", raising=False)
        monkeypatch.delenv("FISSION_REF", raising=False)

        assert RawFissionDecompiler.build_image() == 0
        build = next(call for call in _docker_calls(fake_docker) if call[0] == "build")
        assert f"FISSION_REF={_DEFAULT_REF}" in build

    def test_unresolved_revision_forces_uncached_build(
        self, monkeypatch: pytest.MonkeyPatch, fake_docker: Path
    ) -> None:
        monkeypatch.setattr(
            "decbench.decompilers.raw.fission_raw._resolve_ref",
            lambda repo, ref: None,
        )

        assert RawFissionDecompiler.build_image() == 0
        build = next(call for call in _docker_calls(fake_docker) if call[0] == "build")
        assert "--no-cache" in build

    def test_docker_decompile_is_static_address_scoped(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_docker: Path,
        tiny_binary: Path,
    ) -> None:
        target = _func_address(tiny_binary, "add_nums")
        monkeypatch.setenv(
            "FAKE_FISSION_JSON",
            json.dumps(
                [
                    {
                        "name": "add_nums",
                        "address": hex(target),
                        "code": "int add_nums(int a, int b) { return a + b; }",
                        "fell_back": False,
                    }
                ]
            ),
        )

        result = RawFissionDecompiler().decompile_binary(tiny_binary, function_names={target})

        assert result.functions["add_nums"].address == target
        assert result.decompiler.extra["run_via"] == "docker"
        assert result.decompiler.extra["slice_scoped"] is True
        run = next(
            call
            for call in _docker_calls(fake_docker)
            if call[0] == "run" and "--entrypoint" not in call
        )
        assert "--network" in run and "none" in run
        assert run[run.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
        limit = str(16 * 1024**3)
        assert run[run.index("--memory") + 1] == limit
        assert run[run.index("--memory-swap") + 1] == limit
        assert f"{tiny_binary.resolve()}:/in/{tiny_binary.name}:ro" in run
        assert "decbench/fission:latest" in run
        assert run[run.index("--addr") + 1] == hex(target)
        assert run[-2:] == ["--timeout-ms", "600000"]

    def test_docker_multi_target_mounts_addresses_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_docker: Path,
        tiny_binary: Path,
    ) -> None:
        add_addr = _func_address(tiny_binary, "add_nums")
        main_addr = _func_address(tiny_binary, "main")
        monkeypatch.setenv(
            "FAKE_FISSION_JSON",
            json.dumps(
                [
                    {
                        "name": "add_nums",
                        "address": hex(add_addr),
                        "code": "int add_nums(int a, int b) { return a + b; }",
                        "fell_back": False,
                    },
                    {
                        "name": "main",
                        "address": hex(main_addr),
                        "code": "int main(int argc, char **argv) { return 0; }",
                        "fell_back": False,
                    },
                ]
            ),
        )

        result = RawFissionDecompiler().decompile_binary(
            tiny_binary, function_names={add_addr, main_addr}
        )

        assert set(result.functions) == {"add_nums", "main"}
        run = next(
            call
            for call in _docker_calls(fake_docker)
            if call[0] == "run" and "--entrypoint" not in call
        )
        assert run[run.index("--addresses-file") + 1] == "/in/addresses.txt"
        assert any(arg.endswith(":/in/addresses.txt:ro") for arg in run)

    def test_nonzero_exit_with_json_fails_closed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_docker: Path,
        tiny_binary: Path,
    ) -> None:
        """Partial-looking output from a failed process is not benchmark evidence."""
        target = _func_address(tiny_binary, "add_nums")
        monkeypatch.setenv(
            "FAKE_FISSION_JSON",
            json.dumps(
                [
                    {
                        "name": "add_nums",
                        "address": hex(target),
                        "code": "int add_nums(int a, int b) { return a + b; }",
                        "fell_back": False,
                    }
                ]
            ),
        )
        monkeypatch.setenv("FAKE_DOCKER_RUN_RC", "7")

        result = RawFissionDecompiler().decompile_binary(tiny_binary, function_names={target})

        assert result.functions == {}
        assert result.decompiler.failed_functions == ["all"]
        assert "exited 7" in result.decompiler.extra["error"]


class TestSmokeDecompile:
    def test_decompile_tiny_binary(self, tiny_binary: Path, tmp_path: Path) -> None:
        if not _is_available("fission"):
            pytest.skip("fission_cli not available (set $FISSION_BIN or add to PATH)")

        dec = DecompilerRegistry.get("fission")
        result = dec.decompile_binary(tiny_binary, output_dir=tmp_path)

        assert result.decompiler.decompiler_name == "fission"
        matches = [n for n in result.functions if n.lstrip("_") == "add_nums"]
        assert matches, (
            f"fission did not produce add_nums; got {sorted(result.functions)} "
            f"(failed: {result.decompiler.failed_functions})"
        )

        func = result.functions[matches[0]]
        assert func.decompiled_code.strip()
        assert func.line_count > 0
        assert func.address >= common.elf_min_vaddr(tiny_binary)
        assert not re.search(
            r"%(?:r(?:ax|bp|sp|bx|cx|dx|si|di|8|9|10|11|12|13|14|15))\b", func.decompiled_code
        )
        assert (tmp_path / f"fission_{tiny_binary.stem}.c").exists()

    def test_target_scoped_decompile_narrows_to_requested(self, tiny_binary: Path) -> None:
        if not _is_available("fission"):
            pytest.skip("fission_cli not available")

        dec = DecompilerRegistry.get("fission")
        target = _func_address(tiny_binary, "add_nums")
        scoped = dec.decompile_binary(tiny_binary, function_names={target})
        assert set(scoped.functions), "scoped run produced nothing"
        assert any(f.address == target for f in scoped.functions.values())
