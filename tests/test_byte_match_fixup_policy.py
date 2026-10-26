"""Compiler-free policy tests for the byte-match compile harness."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from decbench.metrics.byte_match import score_compiled
from decbench.metrics.fixup import FixupResult, _summarize_compiler_errors, compile_with_fixup


def _failed_compile(stderr: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 1, stderr=stderr)


def test_default_mode_demotions_without_repair(monkeypatch) -> None:
    calls: list[tuple[str, list[str]]] = []

    def fake_compile(
        src: str, obj_path: Path, compiler: str, flags: list[str]
    ) -> subprocess.CompletedProcess[str]:
        calls.append((src, list(flags)))
        return _failed_compile("error: implicit declaration of function 'missing_helper'")

    monkeypatch.setattr("decbench.metrics.fixup._gcc_compile", fake_compile)
    caller_flags = [
        "-O2",
        "-w",
        "-Werror",
        "-Werror=implicit-function-declaration",
        "-Werror=incompatible-pointer-types",
        "-Werror=int-conversion",
    ]
    original_flags = list(caller_flags)

    code = "int f(void) { return missing_helper(); }"
    result = compile_with_fixup(code, "f", flags=caller_flags)

    expected_flags = [
        "-O2",
        "-Werror",
        "-Werror=implicit-function-declaration",
        "-Werror=incompatible-pointer-types",
        "-Werror=int-conversion",
        "-std=gnu17",
        "-Wno-error=incompatible-pointer-types",
        "-Wno-error=int-conversion",
    ]
    assert calls == [(code, expected_flags)]
    assert result.source == code
    assert result.iterations == 1
    assert caller_flags == original_flags
    assert not result.compilable


def test_module_flags_follow_neutral_flags(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_compile(
        src: str, obj_path: Path, compiler: str, flags: list[str]
    ) -> subprocess.CompletedProcess[str]:
        calls.append(list(flags))
        return _failed_compile("error: deliberately unrepairable")

    monkeypatch.setattr("decbench.metrics.fixup._gcc_compile", fake_compile)
    module = ModuleType("fake_fixup")
    module.FLAGS = ["-fms-extensions"]
    module.prepare = lambda code, ctx: code

    compile_with_fixup("int f(void) { return 0; }", "f", flags=["-O2"], fixup=module)

    assert calls == [
        [
            "-O2",
            "-std=gnu17",
            "-Wno-error=incompatible-pointer-types",
            "-Wno-error=int-conversion",
            "-fms-extensions",
        ]
    ]


@pytest.mark.parametrize(
    "language_mode",
    [
        ["-ansi"],
        ["--ansi"],
        ["-std=gnu11"],
        ["--std=gnu11"],
        ["-std", "gnu11"],
        ["--std", "gnu11"],
    ],
)
def test_preserves_explicit_language_mode(monkeypatch, language_mode: list[str]) -> None:
    calls: list[list[str]] = []

    def fake_compile(
        src: str, obj_path: Path, compiler: str, flags: list[str]
    ) -> subprocess.CompletedProcess[str]:
        calls.append(list(flags))
        return _failed_compile("error: deliberately unrepairable")

    monkeypatch.setattr("decbench.metrics.fixup._gcc_compile", fake_compile)
    caller_flags = ["-O1", *language_mode, "-Werror"]
    original_flags = list(caller_flags)

    compile_with_fixup("int f(void) { return 0; }", "f", flags=caller_flags)

    assert calls == [
        [
            *original_flags,
            "-Wno-error=incompatible-pointer-types",
            "-Wno-error=int-conversion",
        ]
    ]
    assert "-std=gnu17" not in calls[0]
    assert caller_flags == original_flags


def test_diagnostic_summary_is_deterministic_and_private() -> None:
    first = "\n".join(
        [
            "/tmp/nix-shell.a/tmpA.c:7:9: error: passing argument 1 of "
            "'customer_secret_a' makes pointer from integer without a cast "
            "[-Wint-conversion]",
            "    7 | send(customer_secret_a);",
            "      |      ^~~~~~~~~~~~~~~~~",
            "/tmp/nix-shell.a/tmpA.c:8:2: fatal error: "
            "'/tmp/nix-shell.a/private-a.h': incompatible pointer type "
            "[-Wincompatible-pointer-types]",
            "note: private implementation detail",
        ]
    )
    second = "\n".join(
        [
            "/tmp/nix-shell.b/tmpB.c:91:4: error: passing argument 1 of "
            "'customer_secret_b' makes pointer from integer without a cast "
            "[-Wint-conversion]",
            "   91 | entirely_different_private_source();",
            "      |    ^~~~~",
            "/tmp/nix-shell.b/tmpB.c:104:8: fatal error: "
            "'/tmp/nix-shell.b/private-b.h': incompatible pointer type "
            "[-Wincompatible-pointer-types]",
            "note: another private implementation detail",
        ]
    )

    first_summary = _summarize_compiler_errors(first)
    second_summary = _summarize_compiler_errors(second)

    assert first_summary == second_summary
    assert first_summary == (
        "compiler diagnostics [-Wincompatible-pointer-types, -Wint-conversion]: "
        "error: passing argument 1 of <redacted> makes pointer from integer without a cast; "
        "fatal error: <redacted>: incompatible pointer type"
    )
    assert len(first_summary) <= 400
    assert "/tmp" not in first_summary
    assert "secret" not in first_summary
    assert "source" not in first_summary
    assert "note:" not in first_summary
    assert "^" not in first_summary


def test_diagnostic_summary_rejects_source_excerpts_with_error_text() -> None:
    stderr = "\n".join(
        [
            "/tmp/unit.c:7:9: error: incompatible pointer type " "[-Wincompatible-pointer-types]",
            "    7 | private_label: error: CUSTOMER_PRIVATE_TOKEN",
            '    8 | log_message("prefix: error: CUSTOMER_PRIVATE_QUOTED");',
        ]
    )

    summary = _summarize_compiler_errors(stderr)

    assert summary == (
        "compiler diagnostics [-Wincompatible-pointer-types]: " "error: incompatible pointer type"
    )
    assert "CUSTOMER_PRIVATE_TOKEN" not in summary
    assert "CUSTOMER_PRIVATE_QUOTED" not in summary


def test_terminal_diagnostic_summary_is_bounded_without_midword_cut(monkeypatch) -> None:
    diagnostic = "unit.c:1:1: error: " + "overflow " * 100 + "[-Wint-conversion]"

    def fake_compile(
        src: str, obj_path: Path, compiler: str, flags: list[str]
    ) -> subprocess.CompletedProcess[str]:
        return _failed_compile(diagnostic)

    monkeypatch.setattr("decbench.metrics.fixup._gcc_compile", fake_compile)

    result = compile_with_fixup("int f(void) { return 0; }", "f")

    assert result.error is not None
    assert len(result.error) <= 400
    assert result.error.startswith("compiler diagnostics [-Wint-conversion]: error:")
    assert result.error.endswith("overflow...")


def test_byte_match_retains_fixup_diagnostic() -> None:
    diagnostic = "compiler diagnostics [-Wint-conversion]: error: incompatible pointer conversion"
    failure = FixupResult(None, "int f(void);", False, 2, diagnostic)

    result = score_compiled(failure, "f", 0x1000, b"\x90", None)

    assert result.metadata == {
        "compilable": False,
        "fixup_iterations": 2,
        "error": diagnostic,
    }
