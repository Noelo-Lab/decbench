"""Tests for CFG input preparation."""

import shutil
from pathlib import Path

import pyjoern
import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.cfg import (
    extract_cfgs_from_decompilation,
    extract_cfgs_from_source,
    preprocess_decompiled_c,
)


def test_preprocess_decompiled_c_expands_local_macros() -> None:
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("host C preprocessor is unavailable")

    text = """
#include <stdio.h>
#define CHECK(value) do { if (!(value)) fail(7); } while (0)
void target(int value) {
    CHECK(value);
}
"""

    preprocessed = preprocess_decompiled_c(text)

    assert "#define" not in preprocessed
    assert "#include" not in preprocessed
    assert "CHECK" not in preprocessed
    assert "if (!(value)) fail(7)" in preprocessed


def test_preprocess_decompiled_c_skips_plain_text() -> None:
    text = "void target(void) { return; }\n"
    assert preprocess_decompiled_c(text) == text


def test_preprocess_decompiled_c_protects_function_name_from_macro() -> None:
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("host C preprocessor is unavailable")

    text = """
// Function: usage @ 0x1000
#define usage(message) translate(message)
/* usage (via diagnostics) must not be mistaken for the definition. */
void usage(int status) {
    print(usage("help"));
}
"""

    preprocessed = preprocess_decompiled_c(text)

    assert "void usage(int status)" in preprocessed
    assert 'print(translate("help"))' in preprocessed
    assert "__decbench_function_" not in preprocessed


def test_preprocess_decompiled_c_protects_object_macro_collision() -> None:
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("host C preprocessor is unavailable")

    text = """
// Function: target @ 0x1000
#define target 2
static int
target(void) {
    return target;
}
"""

    preprocessed = preprocess_decompiled_c(text)

    assert "target(void)" in preprocessed
    assert "return 2" in preprocessed


def test_extract_cfgs_from_decompilation_marks_source_before_preprocessing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("host C preprocessor is unavailable")

    parsed_text: list[str] = []

    def capture_parse(path: Path) -> dict[str, object]:
        parsed_text.append(path.read_text())
        return {}

    monkeypatch.setattr(pyjoern, "parse_source", capture_parse)
    result = DecompilationResult(
        binary_path=tmp_path / "binary",
        binary_name="binary",
        decompiler=DecompilerMetadata(decompiler_name="test"),
        functions={
            "target": FunctionDecompilation(
                name="target",
                address=0x1000,
                decompiled_code="""
#define target 2
static int target(void) {
    return target;
}
""",
            )
        },
    )

    assert extract_cfgs_from_decompilation(result) == {}
    assert len(parsed_text) == 1
    assert "static int target(void)" in parsed_text[0]
    assert "return 2" in parsed_text[0]


def test_extract_cfgs_from_decompilation_preprocesses_combined_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("host C preprocessor is unavailable")

    parsed_text: list[str] = []

    def capture_parse(path: Path) -> dict[str, object]:
        parsed_text.append(path.read_text())
        return {}

    monkeypatch.setattr(pyjoern, "parse_source", capture_parse)
    result = DecompilationResult(
        binary_path=tmp_path / "binary",
        binary_name="binary",
        decompiler=DecompilerMetadata(decompiler_name="test"),
        functions={
            "define_value": FunctionDecompilation(
                name="define_value",
                address=0x1000,
                decompiled_code="""
#define LOCAL_VALUE 7
int define_value(void) {
    return LOCAL_VALUE;
}
""",
            ),
            "use_value": FunctionDecompilation(
                name="use_value",
                address=0x2000,
                decompiled_code="""
int use_value(void) {
    return LOCAL_VALUE;
}
""",
            ),
        },
    )

    assert extract_cfgs_from_decompilation(result) == {}
    assert len(parsed_text) == 1
    assert parsed_text[0].count("return 7") == 2


def test_extract_cfgs_strict_mode_propagates_parser_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_path = tmp_path / "target.c"
    source_path.write_text("void target(void) {}\n")

    def fail_parse(_path: Path) -> None:
        raise RuntimeError("parser failed")

    monkeypatch.setattr(pyjoern, "parse_source", fail_parse)

    assert extract_cfgs_from_source(source_path) == {}
    with pytest.raises(RuntimeError, match="parser failed"):
        extract_cfgs_from_source(source_path, raise_on_error=True)
