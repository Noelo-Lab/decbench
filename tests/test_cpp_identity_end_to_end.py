"""End-to-end regressions for collision-qualified C++ function identity."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from decbench.metrics.byte_match import ByteMatchMetric
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.models.metrics import MetricValue
from decbench.scoring import report_extras
from decbench.utils import results_tree, source_extract
from decbench.utils.function_identity import parse_function_storage_key


def _result(tmp_path: Path) -> DecompilationResult:
    result = DecompilationResult(
        binary_path=tmp_path / "fixture",
        binary_name="fixture",
        decompiler=DecompilerMetadata(decompiler_name="fixture-dec"),
    )
    result.add_function(
        FunctionDecompilation(
            name="same",
            address=0x1000,
            decompiled_code="int same(int x) { return x + 1; }",
        )
    )
    result.add_function(
        FunctionDecompilation(
            name="same",
            address=0x2000,
            decompiled_code="double same(double x) { return x + 2.0; }",
        )
    )
    result.add_function(
        FunctionDecompilation(
            name="unique",
            address=0x3000,
            decompiled_code="int unique(void) { return 3; }",
        )
    )
    return result


def _load_reeval_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "reeval_bytematch.py"
    spec = importlib.util.spec_from_file_location("reeval_identity_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parse_function_storage_key_preserves_legacy_and_collision_forms() -> None:
    assert parse_function_storage_key("unique") == ("unique", None)
    assert parse_function_storage_key("same@0x1a2b") == ("same", 0x1A2B)


def test_c_artifact_round_trip_preserves_collision_storage_keys(tmp_path: Path) -> None:
    result = _result(tmp_path)
    artifact = tmp_path / "fixture.c"
    result.to_c_file(artifact)

    blocks = results_tree.split_functions(artifact)
    assert set(blocks) == {"same@0x1000", "same@0x2000", "unique"}
    assert blocks["same@0x1000"][0] == 0x1000
    assert blocks["same@0x2000"][0] == 0x2000
    assert blocks["unique"][0] == 0x3000

    text = artifact.read_text()
    assert "// Function: same@0x1000 @ 0x1000" in text
    assert "// Function: same@0x2000 @ 0x2000" in text
    assert "// Function: unique @ 0x3000" in text


def test_sample_set_reader_keeps_collision_storage_keys(tmp_path: Path) -> None:
    result = _result(tmp_path)
    decompiled = tmp_path / "O2" / "proj" / "decompiled"
    decompiled.mkdir(parents=True)
    result.to_c_file(decompiled / "fixture-dec_fixture.c")

    reader = report_extras.SampleSetReader(tmp_path)
    blocks = reader.decompiled("O2", "proj", "fixture", "fixture-dec")
    assert set(blocks) == {"same@0x1000", "same@0x2000", "unique"}


def test_report_source_lookup_uses_semantic_name_and_address(
    tmp_path: Path, monkeypatch
) -> None:
    result = _result(tmp_path)
    nested = {"proj": {"O2": {"fixture": {"fixture-dec": result}}}}
    seen: list[tuple[Path, str, int | None]] = []

    def fake_source(
        binary_path: Path | None, func_name: str, func_address: int | None = None
    ) -> tuple[str | None, str]:
        assert binary_path is not None
        seen.append((Path(binary_path), func_name, func_address))
        return "source", "source"

    monkeypatch.setattr(source_extract, "function_source_ex", fake_source)
    source, status = report_extras._lookup_source_ex(
        nested, "proj", "O2", "fixture", "same@0x1000"
    )

    assert (source, status) == ("source", "source")
    assert seen == [(result.binary_path, "same", 0x1000)]


def test_report_source_lookup_parses_key_when_backend_result_is_missing(
    tmp_path: Path, monkeypatch
) -> None:
    result = _result(tmp_path)
    result.functions.pop("same@0x1000")
    nested = {"proj": {"O2": {"fixture": {"fixture-dec": result}}}}
    seen: list[tuple[str, int | None]] = []

    def fake_source(
        _binary_path: Path | None, func_name: str, func_address: int | None = None
    ) -> tuple[str | None, str]:
        seen.append((func_name, func_address))
        return "source", "source"

    monkeypatch.setattr(source_extract, "function_source_ex", fake_source)
    report_extras._lookup_source_ex(nested, "proj", "O2", "fixture", "same@0x1000")
    assert seen == [("same", 0x1000)]


def test_byte_match_context_uses_only_unambiguous_semantic_names(
    tmp_path: Path, monkeypatch
) -> None:
    result = _result(tmp_path)
    captured: dict[str, str] = {}

    def fake_derive(function_codes: dict[str, str]) -> dict[str, str]:
        captured.update(function_codes)
        return {"unique": "int unique(void);"}

    monkeypatch.setattr("decbench.metrics.fixup.derive_context_decls", fake_derive)
    metric = ByteMatchMetric()

    def fake_compute(*_args, **_kwargs) -> MetricValue:
        return MetricValue(value=1.0)

    monkeypatch.setattr(metric, "compute_for_function", fake_compute)
    metric.compute_for_binary(result)

    assert set(captured) == {"unique"}
    assert "same@0x1000" not in captured
    assert "same@0x2000" not in captured
    assert "same" not in captured


def test_disk_bytematch_reeval_uses_semantic_names_but_keeps_storage_keys(
    tmp_path: Path, monkeypatch
) -> None:
    result = _result(tmp_path)
    artifact = tmp_path / "fixture.c"
    result.to_c_file(artifact)
    seen_names: list[str] = []
    captured_context: dict[str, str] = {}

    class FakeMetric:
        def compute_for_function(self, fd, **_kwargs):
            seen_names.append(fd.name)
            return MetricValue(value=1.0, metadata={"compilable": True})

    def fake_derive(function_codes: dict[str, str]) -> dict[str, str]:
        captured_context.update(function_codes)
        return {}

    monkeypatch.setattr("decbench.metrics.byte_match.ByteMatchMetric", FakeMetric)
    monkeypatch.setattr("decbench.metrics.fixup.derive_context_decls", fake_derive)

    module = _load_reeval_module()
    _key, values = module.eval_one(
        ("O2", "proj", "fixture", "fixture-dec", str(result.binary_path), str(artifact))
    )

    assert set(values) == {"same@0x1000", "same@0x2000", "unique"}
    assert seen_names.count("same") == 2
    assert seen_names.count("unique") == 1
    assert set(captured_context) == {"unique"}


def test_legacy_c_artifact_duplicate_names_are_recovered_by_address(tmp_path: Path) -> None:
    artifact = tmp_path / "legacy.c"
    artifact.write_text(
        "// Function: same @ 0x1000\n"
        "int same(int x) { return x + 1; }\n\n"
        "// Function: same @ 0x2000\n"
        "double same(double x) { return x + 2.0; }\n"
    )

    blocks = results_tree.split_functions(artifact)
    assert set(blocks) == {"same@0x1000", "same@0x2000"}
    assert blocks["same@0x1000"][0] == 0x1000
    assert blocks["same@0x2000"][0] == 0x2000


def test_c_artifact_marker_supports_spaced_cpp_names(tmp_path: Path) -> None:
    result = DecompilationResult(
        binary_path=tmp_path / "fixture",
        binary_name="fixture",
        decompiler=DecompilerMetadata(decompiler_name="fixture-dec"),
    )
    result.add_function(
        FunctionDecompilation(
            name="operator new",
            address=0x4000,
            decompiled_code="void *operator_new(unsigned long n) { return (void *)n; }",
        )
    )
    artifact = tmp_path / "operator.c"
    result.to_c_file(artifact)

    blocks = results_tree.split_functions(artifact)
    assert set(blocks) == {"operator new"}
    assert blocks["operator new"][0] == 0x4000


def test_report_source_lookup_keeps_plain_unique_name_only(
    tmp_path: Path, monkeypatch
) -> None:
    result = _result(tmp_path)
    nested = {"proj": {"O2": {"fixture": {"fixture-dec": result}}}}
    seen: list[tuple[str, int | None]] = []

    def fake_source(
        _binary_path: Path | None, func_name: str, func_address: int | None = None
    ) -> tuple[str | None, str]:
        seen.append((func_name, func_address))
        return "source", "source"

    monkeypatch.setattr(source_extract, "function_source_ex", fake_source)
    source, status = report_extras._lookup_source_ex(
        nested, "proj", "O2", "fixture", "unique"
    )

    assert (source, status) == ("source", "source")
    assert seen == [("unique", None)]
