"""Tests for the raw Glaurung decompiler backend.

Follows the ``tests/test_decompilers.py`` pattern: registry smoke tests that
never require the tool, plus a live decompile smoke test that skips gracefully
when the ``glaurung`` CLI is not on the machine (``$GLAURUNG_BIN`` / PATH).

Glaurung emits parseable-C (a real ``long name(long arg0, …)`` signature) rather
than the declib-shaped ``VariableInfo`` list, so — unlike the angr/ghidra/ida
smoke test — this asserts on the signature text, not recovered variables.
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
from decbench.decompilers.raw.glaurung_agentic import GlaurungAgenticDecompiler
from decbench.decompilers.raw.glaurung_raw import RawGlaurungDecompiler
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


def _func_address(binary: Path, name: str) -> int:
    """Return one symbol's ELF-file-space entry address."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    with binary.open("rb") as stream:
        for section in ELFFile(stream).iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name == name and symbol["st_value"]:
                        return int(symbol["st_value"])
    raise AssertionError(f"no symbol {name} in {binary}")


FAKE_DOCKER = """#!/usr/bin/env python3
import json
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
    print(os.environ.get("FAKE_GLAURUNG_JSON", "[]"))
    raise SystemExit(int(os.environ.get("FAKE_DOCKER_RUN_RC", "0")))
raise SystemExit(2)
"""


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Install a deterministic Docker command double and disable native Glaurung."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    log = tmp_path / "docker-argv.log"
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("GLAURUNG_BIN", str(tmp_path / "no-such-glaurung"))
    monkeypatch.setenv("FAKE_DOCKER_LOG", str(log))
    monkeypatch.delenv("GLAURUNG_IMAGE", raising=False)
    monkeypatch.delenv("GLAURUNG_VERSION", raising=False)
    return log


def _docker_calls(log: Path) -> list[list[str]]:
    if not log.exists():
        return []
    return [line.split("\0") for line in log.read_text().splitlines() if line]


class TestDockerInstall:
    def test_explicit_bad_binary_does_not_fall_through_to_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GLAURUNG_BIN", "/nonexistent/glaurung")
        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/glaurung")
        monkeypatch.setattr(
            "decbench.decompilers.raw.glaurung_raw._image_present", lambda image: False
        )

        assert RawGlaurungDecompiler()._select_path() == ("none", None)

    def test_image_makes_backend_available_without_native_binary(self, fake_docker: Path) -> None:
        dec = RawGlaurungDecompiler()

        assert dec.is_available() is True
        assert dec._select_path() == ("docker", None)
        assert {tuple(call[:2]) for call in _docker_calls(fake_docker)} == {("image", "inspect")}

    def test_native_binary_wins_over_image(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_docker: Path,
        tmp_path: Path,
    ) -> None:
        native = tmp_path / "glaurung"
        native.write_text("#!/bin/sh\nexit 0\n")
        native.chmod(0o755)
        monkeypatch.setenv("GLAURUNG_BIN", str(native))

        assert RawGlaurungDecompiler()._select_path() == ("native", native)
        assert _docker_calls(fake_docker) == []

    def test_docker_version_is_revision_bound(
        self, monkeypatch: pytest.MonkeyPatch, fake_docker: Path
    ) -> None:
        monkeypatch.setenv("FAKE_DOCKER_REV", "7ba4a1a")

        assert RawGlaurungDecompiler().get_version() == "git-7ba4a1a"
        revision_call = next(call for call in _docker_calls(fake_docker) if "--entrypoint" in call)
        assert revision_call[-2:] == ["decbench/glaurung:latest", "/opt/glaurung.rev"]

    def test_build_image_pins_resolved_revision(
        self, monkeypatch: pytest.MonkeyPatch, fake_docker: Path
    ) -> None:
        monkeypatch.setenv("GLAURUNG_REF", "master")
        monkeypatch.setattr(
            "decbench.decompilers.raw.glaurung_raw._resolve_ref",
            lambda repo, ref: "7ba4a1acfb1a59bd",
        )

        assert RawGlaurungDecompiler.build_image() == 0
        build = next(call for call in _docker_calls(fake_docker) if call[0] == "build")
        dockerfile = Path(build[build.index("-f") + 1])
        assert dockerfile.name == "glaurung.Dockerfile"
        assert dockerfile.is_file()
        assert build[build.index("-t") + 1] == "decbench/glaurung:latest"
        assert "GLAURUNG_REF=7ba4a1acfb1a59bd" in build
        assert "--no-cache" not in build
        assert Path(build[-1]) == dockerfile.parent

    def test_unresolved_revision_forces_uncached_build(
        self, monkeypatch: pytest.MonkeyPatch, fake_docker: Path
    ) -> None:
        monkeypatch.setattr(
            "decbench.decompilers.raw.glaurung_raw._resolve_ref",
            lambda repo, ref: None,
        )

        assert RawGlaurungDecompiler.build_image() == 0
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
            "FAKE_GLAURUNG_JSON",
            json.dumps(
                [
                    {
                        "name": "add_nums",
                        "entry_va": target,
                        "pseudocode": "int add_nums(int a, int b) { return a + b; }",
                    }
                ]
            ),
        )

        result = RawGlaurungDecompiler().decompile_binary(tiny_binary, function_names={target})

        assert result.functions["add_nums"].address == target
        assert result.decompiler.extra["run_via"] == "docker"
        run = next(
            call
            for call in _docker_calls(fake_docker)
            if call[0] == "run" and "--entrypoint" not in call
        )
        assert "--network" in run and "none" in run
        assert f"{tiny_binary.resolve()}:/in/{tiny_binary.name}:ro" in run
        assert "decbench/glaurung:latest" in run
        assert run[-2:] == ["--vas", hex(target)]


def test_agentic_command_requires_real_llm_and_sets_stage_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "glaurung"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.setenv("GLAURUNG_BIN", str(executable))
    monkeypatch.setenv("DECBENCH_GLAURUNG_LLM_STAGE_TIMEOUT_MS", "120000")

    command = GlaurungAgenticDecompiler()._build_explain_command(tmp_path / "target.elf", 0x401000)

    assert "--require-llm" in command
    assert command[command.index("--timeout-ms") + 1] == "120000"


def test_agentic_payload_requires_observed_llm_provenance() -> None:
    """The accepted shape is taken from a paid bin_000.elf canary run."""
    payload = {
        "entry_va": 0x8350,
        "language": "c",
        "source": "void sub_8350(int fd) { (void)fd; }",
        "stages": {
            "infer_function_signature": {"source": "llm"},
            "classify_function_role": {"source": "llm"},
            "rewrite_function_idiomatic": {"source": "llm"},
        },
    }
    dec = GlaurungAgenticDecompiler()

    assert dec._validated_source(payload, 0x8350) == payload["source"]

    payload["stages"]["rewrite_function_idiomatic"] = {"source": "heuristic"}
    assert dec._validated_source(payload, 0x8350) is None


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
        assert not re.search(
            r"%(?:r(?:ax|bp|sp|bx|cx|dx|si|di|8|9|10|11|12|13|14|15))\b", func.decompiled_code
        )

        # Output files were written.
        assert (tmp_path / f"glaurung_{tiny_binary.stem}.c").exists()

    def test_target_scoped_decompile_narrows_to_requested(self, tiny_binary: Path) -> None:
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
