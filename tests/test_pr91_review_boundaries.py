"""Shared manifest populations and address-preserving source-display boundaries."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from decbench.evalkit import resolve
from decbench.evalkit.export import _resolve_manifest
from decbench.evalkit.ingest import _build_entry, _Counters
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.function_identity import manifest_target_keys, unresolved_manifest_keys


def _driver(name: str) -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"pr91_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "requested,addresses",
    [
        ({"same"}, {0x1000, 0x2000}),
        ({"same@0x2000"}, {0x2000}),
        ({"unique"}, {0x3000}),
        ({"unique@0x3000"}, {0x3000}),
        ({"same", "same@0x2000"}, {0x1000, 0x2000}),
        ({"same@0x9999"}, set()),
        (set(), set()),
    ],
)
def test_manifest_population_agrees_across_benchmark_export_and_ingest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requested: set[str], addresses: set[int]
) -> None:
    mapping = {0x1000: "same", 0x2000: "same", 0x3000: "unique"}
    binary = tmp_path / "fixture"
    monkeypatch.setattr(resolve, "_dwarf_addr_to_name", lambda *_: mapping)
    monkeypatch.setattr(resolve, "discover_binary", lambda *_: binary)
    monkeypatch.setattr(resolve, "source_stems", lambda *_: set())
    monkeypatch.setattr(
        resolve.AddrLookup, "for_binary", lambda *_a, **_kw: resolve.AddrLookup(mapping)
    )
    expected = manifest_target_keys(mapping, requested)
    assert set(expected) == addresses
    benchmark = _driver("run_benchmark")._select_manifest_targets(mapping, requested)
    assert set(benchmark) == addresses
    assert resolve.manifest_functions(binary, requested) == expected
    entries = [
        {"project": "p", "opt": "O0", "binary": "fixture", "function": name} for name in requested
    ]
    exported, failures = _resolve_manifest(tmp_path, entries, False)
    exported_addresses = {a for item in exported for a in item.functions.values()}
    assert exported_addresses == addresses
    assert len(failures) == len(unresolved_manifest_keys(expected, requested))
    if not requested:
        return
    source = "\n".join(f"int sub_{a:x}(void){{return 1;}}" for a in mapping)
    (tmp_path / "kuna_fixture.c").write_text(source)
    manifest = {("p", "O0", "fixture", name) for name in requested}
    counters = _Counters()
    built = _build_entry(
        tmp_path,
        manifest,
        tmp_path,
        "kuna_fixture.c",
        {
            "binary": {"project": "p", "opt": "O0", "binary": "fixture"},
            "functions": {f"sub_{a:x}": hex(a) for a in mapping},
        },
        "review",
        None,
        "sample-set",
        counters,
        [],
    )
    assert built is not None
    result = built.result
    assert {f.address for f in result.functions.values()} == addresses
    assert set(result.functions) == set(expected.values())
    assert set(result.decompiler.failed_functions) == unresolved_manifest_keys(expected, requested)


def test_partial_legacy_manifest_failure_uses_canonical_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mapping = {0x1000: "same", 0x2000: "same"}
    monkeypatch.setattr(resolve, "_dwarf_addr_to_name", lambda *_: mapping)
    monkeypatch.setattr(resolve, "discover_binary", lambda *_: tmp_path / "fixture")
    monkeypatch.setattr(resolve, "source_stems", lambda *_: set())
    monkeypatch.setattr(
        resolve.AddrLookup, "for_binary", lambda *_a, **_kw: resolve.AddrLookup(mapping)
    )
    (tmp_path / "kuna_fixture.c").write_text("int sub_1000(void){return 1;}")
    built = _build_entry(
        tmp_path,
        {("p", "O0", "fixture", "same")},
        tmp_path,
        "kuna_fixture.c",
        {
            "binary": {"project": "p", "opt": "O0", "binary": "fixture"},
            "functions": {"sub_1000": "0x1000"},
        },
        "review",
        None,
        "sample-set",
        _Counters(),
        [],
    )
    assert built is not None
    result = built.result
    assert set(result.functions) == {"same@0x1000"}
    assert result.decompiler.failed_functions == ["same@0x2000"]
    assert result.successful_count == 1


@pytest.mark.parametrize("key,address", [("same@0x1000", 0x1000), ("unique", 0x3000)])
def test_disk_reader_keeps_marker_address(tmp_path: Path, key: str, address: int) -> None:
    module = _driver("rebuild_function_data")
    folder = tmp_path / "O0/p/decompiled"
    folder.mkdir(parents=True)
    (folder / "kuna_fixture.c").write_text(
        f"// Function: {key} @ {hex(address)}\nint f(){{return 1;}}"
    )
    reader = module.DiskReader(tmp_path)
    assert reader.source_identity("O0", "p", "fixture", key, ["kuna"]) == (
        key.split("@")[0],
        address,
    )
    assert reader.decompiled("O0", "p", "fixture", "kuna")[key]


def test_disk_reader_rejects_conflicting_addresses(tmp_path: Path) -> None:
    folder = tmp_path / "O0/p/decompiled"
    folder.mkdir(parents=True)
    for tool, address in [("kuna", 0x1000), ("angr", 0x2000)]:
        (folder / f"{tool}_fixture.c").write_text(
            f"// Function: f @ {hex(address)}\nint f(){{return 1;}}"
        )
    reader = _driver("rebuild_function_data").DiskReader(tmp_path)
    with pytest.raises(ValueError, match="conflicting function addresses"):
        reader.source_identity("O0", "p", "fixture", "f", ["kuna", "angr"])


def test_offline_ged_refuses_qualified_identity_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _driver("reeval_ged")
    artifact = tmp_path / "kuna_fixture.c"
    artifact.write_text("// Function: same@0x1000 @ 0x1000\nint same(){return 1;}")
    monkeypatch.setattr(
        module, "_load_src", lambda *_: pytest.fail("must fail before name-based CFG lookup")
    )
    with pytest.raises(RuntimeError, match="address-aware source/output CFGs"):
        module.eval_one(("O0", "p", "fixture", "kuna", str(artifact), "unused", "", False, {}))


def test_success_count_does_not_subtract_absent_requested_functions() -> None:
    result = DecompilationResult(
        binary_path=Path("unused"),
        binary_name="fixture",
        decompiler=DecompilerMetadata(
            decompiler_name="fixture", failed_functions=["missing1", "missing2"]
        ),
        functions={
            "ok": FunctionDecompilation(name="ok", address=1, decompiled_code="int ok(){return 1;}")
        },
    )
    assert result.successful_count == 1


@pytest.mark.skipif(
    shutil.which("clang") is None or shutil.which("ld.lld") is None,
    reason="clang and ELF lld required",
)
def test_plain_target_keeps_source_with_same_named_non_target_peer(tmp_path: Path) -> None:
    from decbench.scoring.report_extras import _lookup_source_ex
    from decbench.utils.function_identity import dwarf_function_identities
    from decbench.utils.source_extract import _dwarf_decl_by_address

    for stem, offset in [("a", 11), ("b", 22)]:
        source = tmp_path / f"{stem}.c"
        source.write_text(
            f"static int same(int x) {{return x + {offset};}}\n"
            f"int {stem}(int x) {{return same(x);}}\n"
        )
        subprocess.run(
            [
                "clang",
                "--target=x86_64-linux-gnu",
                "-O0",
                "-g",
                "-fno-pic",
                "-c",
                str(source),
                "-o",
                str(tmp_path / f"{stem}.o"),
            ],
            check=True,
            capture_output=True,
        )
    binary = tmp_path / "fixture"
    subprocess.run(
        ["ld.lld", "-e", "a", str(tmp_path / "a.o"), str(tmp_path / "b.o"), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    hints = _dwarf_decl_by_address(binary)
    rows = [r for r in dwarf_function_identities(binary) if r.name == "same"]
    assert len(rows) == 2
    for row in rows:
        origin = Path(hints[row.address][0]).stem
        expected = 11 if origin == "a" else 22
        result = DecompilationResult(
            binary_path=binary,
            binary_name="fixture",
            decompiler=DecompilerMetadata(decompiler_name="fixture"),
            functions={
                "same": FunctionDecompilation(
                    name="same", address=row.address, decompiled_code="int same(int x){return x;}"
                )
            },
        )
        code, status = _lookup_source_ex(
            {"p": {"O0": {"fixture": {"fixture": result}}}}, "p", "O0", "fixture", "same"
        )
        assert code is not None and f"+ {expected};" in code
        assert status == ""


@pytest.mark.parametrize(
    "failed,code,expected",
    [([], "int f(){}", 1), (["ok"], "int f(){}", 0), (["all"], "int f(){}", 1), ([], "  ", 0)],
)
def test_success_count_counts_actual_nonempty_nonfailed_records(
    failed: list[str], code: str, expected: int
) -> None:
    result = DecompilationResult(
        binary_path=Path("unused"),
        binary_name="fixture",
        decompiler=DecompilerMetadata(decompiler_name="fixture", failed_functions=failed),
        functions={"ok": FunctionDecompilation(name="ok", address=1, decompiled_code=code)},
    )
    assert result.successful_count == expected


def test_disk_reader_keeps_legacy_missing_address_fallback(tmp_path: Path) -> None:
    reader = _driver("rebuild_function_data").DiskReader(tmp_path)
    assert reader.source_identity("O0", "p", "fixture", "legacy", ["kuna"]) == ("legacy", None)


@pytest.mark.parametrize("candidate_tag", ["failure", "error", "skipped", "absent"])
def test_validation_comparison_rejects_lost_passes(tmp_path: Path, candidate_tag: str) -> None:
    baseline = tmp_path / "main.xml"
    candidate = tmp_path / "candidate.xml"
    baseline.write_text('<testsuite><testcase classname="owner" name="guard"/></testsuite>')
    child = f'<testcase classname="owner" name="guard"><{candidate_tag}/></testcase>'
    if candidate_tag == "absent":
        child = '<testcase classname="owner" name="other"/>'
    candidate.write_text(f"<testsuite>{child}</testsuite>")
    report = _driver("validate_function_identity").compare(baseline, candidate)
    assert not report["passed"]
    assert report["lost_passing_identities"] == ["owner::guard"]


def test_validation_comparison_rejects_new_failure(tmp_path: Path) -> None:
    baseline = tmp_path / "main.xml"
    candidate = tmp_path / "candidate.xml"
    case = '<testcase classname="owner" name="guard"/>'
    baseline.write_text(f"<testsuite>{case}</testsuite>")
    candidate.write_text(
        f'<testsuite>{case}<testcase classname="owner" name="new">'
        "<failure/></testcase></testsuite>"
    )
    report = _driver("validate_function_identity").compare(baseline, candidate)
    assert not report["passed"]
    assert report["new_failure_identities"] == ["owner::new"]
