from __future__ import annotations

import json
import pickle
from pathlib import Path

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)
from scripts.sanitize_native_checkpoints import create_sanitized_copy


def _checkpoint(path: Path, project: str = "proj") -> None:
    result = DecompilationResult(
        binary_path=Path("stale/tree/bin"),
        binary_name="bin",
        decompiler=DecompilerMetadata(decompiler_name="ida"),
        functions={
            "target": FunctionDecompilation(
                name="target",
                address=0x1000,
                decompiled_code="int target(int x) { return x; }",
                line_mappings=[LineMapping(line_number=2, addresses=[0x1000])],
                variables=[
                    VariableInfo(
                        name="x",
                        line_numbers=[1, 2],
                        addresses=[0x1000],
                    )
                ],
            )
        },
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        pickle.dumps({"decompile": {"O0": {"bin": {"ida": result}}}, "project": project})
    )


def test_copy_is_atomic_fail_closed_and_preserves_raw_checkpoint(tmp_path: Path) -> None:
    root = tmp_path / "results"
    source = root / "checkpoints" / "proj.pkl"
    _checkpoint(source)
    before = source.read_bytes()
    output = tmp_path / "sanitized-checkpoints"

    manifest = create_sanitized_copy(root, output)

    assert source.read_bytes() == before
    assert output.is_dir()
    with (output / "proj.pkl").open("rb") as stream:
        copied = pickle.load(stream)
    result = copied["decompile"]["O0"]["bin"]["ida"]
    function = result.functions["target"]
    assert result.binary_path == root / "O0" / "proj" / "compiled" / "bin"
    assert function.decompiled_code == "int target(int x) { return x; }"
    assert function.line_mappings == []
    assert function.variables[0].addresses == []
    assert function.variables[0].line_numbers == [1]
    metadata = result.decompiler.extra["native_provenance_sanitizer"]
    assert metadata["status"] == "fail_closed"
    assert "address_drop_samples" not in metadata
    assert manifest["checkpoints"][0]["status_counts"] == {"fail_closed": 1}
    assert json.loads((output / "manifest.json").read_text()) == manifest


def test_failed_batch_never_publishes_partial_output(tmp_path: Path) -> None:
    root = tmp_path / "results"
    _checkpoint(root / "checkpoints" / "a.pkl", "a")
    (root / "checkpoints" / "b.pkl").write_bytes(b"not a pickle")
    output = tmp_path / "derived"

    with pytest.raises(ValueError, match="could not load checkpoint"):
        create_sanitized_copy(root, output)

    assert not output.exists()
    assert not list(tmp_path.glob(".derived.*"))


def test_copy_refuses_existing_or_canonical_output_directory(tmp_path: Path) -> None:
    root = tmp_path / "results"
    _checkpoint(root / "checkpoints" / "proj.pkl")
    existing = tmp_path / "existing"
    existing.mkdir()

    with pytest.raises(ValueError, match="already exists"):
        create_sanitized_copy(root, existing)
    with pytest.raises(ValueError, match="outside the canonical"):
        create_sanitized_copy(root, root / "checkpoints" / "derived")
