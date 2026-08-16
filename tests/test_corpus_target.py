"""Tests for the corpus-architecture override used by the compile pipeline."""

from __future__ import annotations

import pytest

from decbench.models.project import CompilationConfig
from decbench.pipeline.compile import corpus_target


@pytest.fixture
def compilation() -> CompilationConfig:
    return CompilationConfig(c_compiler="gcc", target_arch=None)


def test_defaults_to_the_project_config(
    compilation: CompilationConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unset, every project compiles exactly as its TOML declares."""
    monkeypatch.delenv("DECBENCH_CC", raising=False)
    monkeypatch.delenv("DECBENCH_TARGET_ARCH", raising=False)
    assert corpus_target(compilation) == ("gcc", None)


def test_env_retargets_the_corpus(
    compilation: CompilationConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One env var retargets a whole corpus without editing every project TOML."""
    monkeypatch.setenv("DECBENCH_CC", "x86_64-linux-gnu-gcc")
    monkeypatch.setenv("DECBENCH_TARGET_ARCH", "x86-64")
    assert corpus_target(compilation) == ("x86_64-linux-gnu-gcc", "x86-64")


def test_env_does_not_override_with_empty_values(
    compilation: CompilationConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty var is the same as unset, not a request to compile with ''."""
    monkeypatch.setenv("DECBENCH_CC", "")
    monkeypatch.setenv("DECBENCH_TARGET_ARCH", "")
    assert corpus_target(compilation) == ("gcc", None)


def test_a_cross_compiled_project_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CPS/malware targets keep their toolchain and their collection filter.

    Retargeting them would build x86-64 and then collect only ARM: no binaries,
    no error.
    """
    monkeypatch.setenv("DECBENCH_CC", "x86_64-linux-gnu-gcc")
    monkeypatch.setenv("DECBENCH_TARGET_ARCH", "x86-64")
    config = CompilationConfig(c_compiler="arm-none-eabi-gcc", target_arch="arm")
    assert corpus_target(config) == ("arm-none-eabi-gcc", "arm")
