"""Cross-target fixtures do not confer corpus or original-compiler parity."""

import importlib.util
import shutil
from pathlib import Path

import pytest


def test_real_cpp_preprocessing_and_effect_fixture_matrix(tmp_path: Path) -> None:
    compiler = shutil.which("clang++")
    if compiler is None:
        pytest.skip("clang++ required")
    script = Path(__file__).parents[1] / "scripts/audit_cpp_toolchains.py"
    spec = importlib.util.spec_from_file_location("cpp_toolchain_probe", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = module.audit(
        compiler, Path(__file__).parent / "fixtures/cpp_qualification.cpp", tmp_path
    )
    assert report["official_score"] is False
    assert report["executed_programs"] is False
    assert len(report["cells"]) == 9
    assert {row["object_identity"]["fmt"] for row in report["cells"]} == {"elf", "pe", "macho"}
    assert {row["optimization"] for row in report["cells"]} == {"O0", "O2", "O2-noinline"}
    assert all(
        row["text_sections_identical"] and row["exception_ir_present"] for row in report["cells"]
    )


def test_wrong_target_object_fails_fixture_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from decbench.utils.binfmt import BinInfo

    compiler = shutil.which("clang++")
    if compiler is None:
        pytest.skip("clang++ required")
    script = Path(__file__).parents[1] / "scripts/audit_cpp_toolchains.py"
    spec = importlib.util.spec_from_file_location("cpp_toolchain_probe_wrong", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "object_info", lambda path: BinInfo("macho", "aarch64", 64))
    with pytest.raises(ValueError, match="requested target"):
        module.audit(compiler, Path(__file__).parent / "fixtures/cpp_qualification.cpp", tmp_path)
