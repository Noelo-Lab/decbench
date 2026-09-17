"""Validate partial progress snapshots preserve collision-safe identities."""

from __future__ import annotations

import pickle
from pathlib import Path

from decbench.decompilers.raw.common import dump_progress
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)


def test_partial_progress_pickle_preserves_collision_keys_and_semantics(tmp_path: Path) -> None:
    result = DecompilationResult(
        binary_path=tmp_path / "fixture",
        binary_name="fixture",
        decompiler=DecompilerMetadata(
            decompiler_name="progress-fixture",
            failed_functions=["same@0x3000"],
            extra={"partial": True, "function_identity": "dwarf-low-pc"},
        ),
    )
    result.add_function(
        FunctionDecompilation(
            name="same",
            address=0x1000,
            decompiled_code="int a(void) { return 1; }",
        )
    )
    result.add_function(
        FunctionDecompilation(
            name="same",
            address=0x2000,
            decompiled_code="int b(void) { return 2; }",
        )
    )

    progress = tmp_path / "progress.pkl"
    dump_progress(progress, result)
    assert progress.is_file()
    assert not progress.with_suffix(".pkl.tmp").exists()

    restored = pickle.loads(progress.read_bytes())
    assert isinstance(restored, DecompilationResult)
    assert set(restored.functions) == {"same@0x1000", "same@0x2000"}
    assert {fd.address for fd in restored.functions.values()} == {0x1000, 0x2000}
    assert {fd.name for fd in restored.functions.values()} == {"same"}
    assert restored.decompiler.failed_functions == ["same@0x3000"]
    assert restored.decompiler.extra["partial"] is True
    assert restored.decompiler.extra["function_identity"] == "dwarf-low-pc"
