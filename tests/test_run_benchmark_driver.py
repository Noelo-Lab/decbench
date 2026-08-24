from __future__ import annotations

from pathlib import Path

import pytest

from decbench.decompilers.raw.common import narrow_to_source
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from scripts.run_benchmark import (
    DECOMPILER_TIMEOUT,
    _load_sampleset_manifest,
    _relabel_to_dwarf,
    needs_source_cfgs,
    skip_finalize,
)


def test_whole_program_docker_backends_have_explicit_time_budgets() -> None:
    assert DECOMPILER_TIMEOUT["retdec"] == 1800
    assert DECOMPILER_TIMEOUT["reko"] == 1800


@pytest.mark.parametrize(
    ("metrics", "expected"),
    [
        (None, True),
        (["ged"], True),
        (["type_match", "ged"], True),
        (["type_match"], False),
        (["byte_match"], False),
    ],
)
def test_source_cfg_requirement_tracks_selected_metrics(
    metrics: list[str] | None, expected: bool
) -> None:
    assert needs_source_cfgs(metrics) is expected


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_skip_finalize_accepts_truthy_values(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("DECBENCH_SKIP_FINALIZE", value)
    assert skip_finalize()


def test_skip_finalize_defaults_to_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DECBENCH_SKIP_FINALIZE", raising=False)
    assert not skip_finalize()


def test_source_address_filter_fails_closed() -> None:
    functions = [("first", 0x1001), ("second", 0x2000)]

    assert narrow_to_source(functions, None, backend="test", binary_name="bin") == functions
    assert narrow_to_source(functions, {0x1000}, backend="test", binary_name="bin") == [
        ("first", 0x1001)
    ]
    assert narrow_to_source(functions, {0xDEAD}, backend="test", binary_name="bin") == []


def test_parent_filter_drops_backend_results_outside_requested_addresses(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "binary"
    binary.write_bytes(b"not-an-elf")
    result = DecompilationResult(
        binary_path=tmp_path / "stripped",
        binary_name="binary",
        decompiler=DecompilerMetadata(decompiler_name="test"),
        functions={
            "sub_1001": FunctionDecompilation(
                name="sub_1001",
                address=0x1001,
                decompiled_code="int sub_1001(void) { return 1; }",
            ),
            "sub_2000": FunctionDecompilation(
                name="sub_2000",
                address=0x2000,
                decompiled_code="int sub_2000(void) { return 2; }",
            ),
        },
    )

    _relabel_to_dwarf(result, {0x1000: "wanted"}, binary)

    assert list(result.functions) == ["wanted"]
    assert result.functions["wanted"].name == "wanted"
    assert "wanted(" in result.functions["wanted"].decompiled_code
    assert result.binary_path == binary
    assert result.decompiler.extra["source_filter_unmatched_dropped"] == 1


@pytest.mark.parametrize("contents", ["not-json", "{}", '{"functions": []}'])
def test_configured_sample_gate_rejects_invalid_or_empty_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    contents: str,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(contents)
    monkeypatch.setenv("DECBENCH_SAMPLESET_MANIFEST", str(manifest))

    with pytest.raises(RuntimeError, match="sample-set manifest"):
        _load_sampleset_manifest()
