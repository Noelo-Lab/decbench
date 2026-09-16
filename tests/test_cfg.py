"""Tests for CFG input preparation."""

import shutil
from pathlib import Path

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils import cfg as cfg_module
from decbench.utils.cfg import (
    extract_cfg_records_from_decompilation,
    extract_cfg_records_from_source,
    extract_cfgs_from_decompilation,
    extract_cfgs_from_source,
    prepare_decompiled_c,
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


def test_prepare_decompiled_c_records_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    from cindergraph import source_cfg

    monkeypatch.setattr(
        source_cfg,
        "preprocess_decompiled",
        lambda *_args, **_kwargs: source_cfg.PreprocessingReport(
            text="#define X 1\nint target(void) { return X; }\n",
            status="timed-out",
            compiler="/usr/bin/cc",
            stderr="timed out",
        ),
    )
    text = "#define X 1\nint target(void) { return X; }\n"

    prepared, evidence = prepare_decompiled_c(text, timeout=0.01)

    assert prepared == text
    assert evidence.status == "timed-out"
    assert evidence.compiler == "/usr/bin/cc"


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


def test_extract_cfgs_from_decompilation_marks_source_before_preprocessing(tmp_path: Path) -> None:
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("host C preprocessor is unavailable")

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

    graphs = extract_cfgs_from_decompilation(result)
    assert set(graphs) == {"target"}
    assert graphs["target"].graph["cfg_extractor"] == "cindergraph"


def test_extract_cfgs_from_decompilation_preprocesses_combined_source(tmp_path: Path) -> None:
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("host C preprocessor is unavailable")

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

    graphs = extract_cfgs_from_decompilation(result)
    assert set(graphs) == {"define_value", "use_value"}


def test_decompiled_extraction_records_partial_recovery(tmp_path: Path) -> None:
    result = DecompilationResult(
        binary_path=tmp_path / "binary",
        binary_name="binary",
        decompiler=DecompilerMetadata(decompiler_name="test"),
        functions={
            "broken": FunctionDecompilation(
                name="broken",
                address=0x1000,
                decompiled_code="int broken( { int later(void) { return 2; }",
            )
        },
    )

    extraction = extract_cfg_records_from_decompilation(result)

    assert extraction.status == "ok"
    assert extraction.partial_recovery is True
    assert extraction.diagnostics
    assert extraction.preprocessing is not None


def test_source_extraction_replaces_invalid_utf8(tmp_path: Path) -> None:
    source = tmp_path / "damaged.c"
    source.write_bytes(b"\xff\nint surviving(void) { return 1; }\n")

    extraction = extract_cfg_records_from_source(source)

    assert extraction.status == "ok"
    assert "surviving" in extraction.functions


def test_extract_cfgs_strict_mode_propagates_parser_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_path = tmp_path / "target.c"
    source_path.write_text("void target(void) {}\n")

    def fail_parse(self, path: Path, text: str, language: str):
        del self, path, text, language
        raise RuntimeError("parser failed")

    monkeypatch.setattr(cfg_module.CindergraphCfgExtractor, "extract_source", fail_parse)

    assert extract_cfgs_from_source(source_path) == {}
    with pytest.raises(RuntimeError, match="parser failed"):
        extract_cfgs_from_source(source_path, raise_on_error=True)
