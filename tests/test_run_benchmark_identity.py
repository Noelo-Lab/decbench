"""Regression tests for canonical DWARF identity in the benchmark driver."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.function_identity import dwarf_function_identities
from decbench.utils.source_extract import function_source_ex


def _load_driver():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_benchmark.py"
    spec = importlib.util.spec_from_file_location("decbench_run_benchmark_identity_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fd(name: str, address: int, body: str | None = None) -> FunctionDecompilation:
    return FunctionDecompilation(
        name=name,
        address=address,
        decompiled_code=body or f"int {name}(void) {{ return 1; }}",
    )


def _result(*functions: FunctionDecompilation, failed: list[str] | None = None):
    return DecompilationResult(
        binary_path=Path("stripped.bin"),
        binary_name="fixture",
        decompiler=DecompilerMetadata(
            decompiler_name="fixture",
            failed_functions=list(failed or []),
        ),
        functions={f"raw-{index}": function for index, function in enumerate(functions)},
    )


def test_relabel_uses_full_target_set_for_ambiguous_storage_keys(monkeypatch):
    driver = _load_driver()
    from decbench.decompilers.raw import common

    monkeypatch.setattr(common, "elf_min_vaddr", lambda _path: 0)
    targets = {0x1000: "same", 0x2000: "same", 0x3000: "unique"}

    complete = _result(_fd("sub_1000", 0x1000), _fd("sub_2000", 0x2000))
    partial = _result(_fd("FUN_1000", 0x1000), _fd("FUN_3000", 0x3000))

    driver._relabel_to_dwarf(complete, targets, Path("unstripped.bin"))
    driver._relabel_to_dwarf(partial, targets, Path("unstripped.bin"))

    assert set(complete.functions) == {"same@0x1000", "same@0x2000"}
    assert set(partial.functions) == {"same@0x1000", "unique"}
    assert partial.functions["same@0x1000"].name == "same"
    assert partial.functions["same@0x1000"].address == 0x1000
    assert partial.decompiler.failed_functions == ["same@0x2000"]
    assert partial.decompiler.extra["function_identity"] == "dwarf-low-pc"


def test_relabel_normalizes_historical_pe_rva_to_dwarf_low_pc(monkeypatch):
    driver = _load_driver()
    from decbench.decompilers.raw import common

    monkeypatch.setattr(common, "elf_min_vaddr", lambda _path: 0x400000)
    result = _result(_fd("sub_1000", 0x1000))

    driver._relabel_to_dwarf(result, {0x401000: "target"}, Path("unstripped.exe"))

    assert set(result.functions) == {"target"}
    assert result.functions["target"].address == 0x401000
    assert result.functions["target"].name == "target"
    assert "target" in result.functions["target"].decompiled_code
    assert result.decompiler.failed_functions == []


def test_relabel_preserves_compact_all_failure_marker(monkeypatch):
    driver = _load_driver()
    from decbench.decompilers.raw import common

    monkeypatch.setattr(common, "elf_min_vaddr", lambda _path: 0)
    result = _result(failed=["all"])

    driver._relabel_to_dwarf(
        result,
        {0x1000: "same", 0x2000: "same"},
        Path("unstripped.bin"),
    )

    assert result.functions == {}
    assert result.decompiler.failed_functions == ["all"]


@pytest.mark.skipif(shutil.which("g++") is None, reason="g++ required")
def test_source_extract_accepts_canonical_storage_key(tmp_path: Path):
    source = tmp_path / "collision.cpp"
    source.write_text(
        "int collide(int x) { return x + 11; }\n"
        "double collide(double x) { return x + 22.0; }\n"
        "int main() { return collide(1); }\n"
    )
    binary = tmp_path / "collision"
    subprocess.run(
        ["g++", "-O0", "-g", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )

    identities = dwarf_function_identities(binary)
    int_overload = next(i for i in identities if i.linkage_name == "_Z7collidei")
    storage_key = f"collide@0x{int_overload.address:x}"

    snippet, status = function_source_ex(binary, storage_key)

    assert status == ""
    assert snippet is not None
    assert "return x + 11" in snippet
    assert "return x + 22.0" not in snippet
