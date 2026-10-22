"""Exact native/source/producer CFG joins, independent of display-name reduction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from decbench.metrics.variable_features import function_definitions
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.pipeline.cpp_ged import evaluate_cpp_ged
from decbench.utils.cfg_identity import (
    NativeSource,
    NativeSourceIndex,
    SourceCfgIndex,
    SourceLocation,
    decompiled_cfgs,
    origin_source,
    source_path,
)


def _result(*functions: tuple[str, int, str]) -> DecompilationResult:
    result = DecompilationResult(
        binary_path=Path("unused"),
        binary_name="fixture",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    for name, address, code in functions:
        result.add_function(FunctionDecompilation(name=name, address=address, decompiled_code=code))
    return result


def _index(text: str, filename: str = "unit.ii") -> SourceCfgIndex:
    index = SourceCfgIndex()
    index.add(text, filename)
    return index


def _native(
    address: int, name: str, path: str, line: int, unit: str = "/src/a.cpp"
) -> NativeSource:
    return NativeSource(address, name, (unit,), SourceLocation(path, line), f"fixture:{address:x}")


def test_gcc_and_msvc_origins_preserve_physical_lines() -> None:
    source = origin_source(
        '# 0 "/src/a.cpp"\n# 1 "/usr/include/x.h" 1 3\nint hidden();\n'
        '# 12 "/src/a.cpp" 2\nint f() { return 1; }\n'
    )
    assert source.primary == "/src/a.cpp"
    assert source.origins == {5: SourceLocation("/src/a.cpp", 12)}
    windows = origin_source('#line 15 "D:\\\\src\\\\a.cpp"\r\nint g(){return 2;}\r\n')
    assert windows.origins == {2: SourceLocation("d:/src/a.cpp", 15)}
    assert len(source.text.splitlines()) == 5
    assert source_path(r"C:\new\a.cpp") == "c:/new/a.cpp"


def test_definition_spans_use_bytes_with_unicode_and_large_line_counts() -> None:
    code = "// 한글\n" + "\n" * 10000 + "int f(){return 1;}\nint g(){return 2;}\n"
    definitions = function_definitions(code)
    assert [(d.leaf, d.start_line, d.end_line) for d in definitions] == [
        ("f", 10002, 10002),
        ("g", 10003, 10003),
    ]


def test_overloads_keep_each_definition_and_exact_storage_key(tmp_path: Path) -> None:
    index = _index(
        '# 1 "/src/a.cpp"\nint f(int x){if(x)return 1;return 0;}\nint f(double x){return 2;}\n'
    )
    result = _result(
        ("f", 16, "int sub_10(int x){if(x)return 1;return 0;}"),
        ("f", 32, "int sub_20(double x){return 2;}"),
    )
    native = {16: [_native(16, "f", "/src/a.cpp", 1)], 32: [_native(32, "f", "/src/a.cpp", 2)]}
    binary = tmp_path / "fixture"
    binary.write_bytes(b"synthetic debug fixture")
    result.binary_path = binary
    report = evaluate_cpp_ged(
        result, source_index=index, native_index=NativeSourceIndex(binary, native)
    )
    assert report.paired == 2
    assert report.metric.perfect_count == 2
    assert set(report.metric.function_results) == {"f@0x10", "f@0x20"}
    assert report.official_score is False


def test_same_basename_wrong_tu_and_missing_origin_do_not_fallback() -> None:
    index = _index('# 1 "/other/a.cpp"\nint f(){return 1;}\n')
    result = _result(("f", 16, "int sub_10(){return 1;}"))
    joined = index.resolve(result, {16: [_native(16, "f", "/src/a.cpp", 1)]})
    assert not joined.cfgs


def test_same_line_overloads_and_icf_abstain() -> None:
    index = _index('# 1 "/src/a.cpp"\nint f(int x){return x;} int f(double x){return 2;}\n')
    result = _result(("f", 16, "int sub_10(){return 1;}"))
    row = _native(16, "f", "/src/a.cpp", 1)
    assert (
        index.resolve(result, {16: [row]}).evidence["f"]["status"] == "ambiguous_source_definition"
    )
    assert (
        index.resolve(result, {16: [row, row]}).evidence["f"]["status"]
        == "ambiguous_native_identity"
    )


def test_source_location_cannot_borrow_different_named_function() -> None:
    index = _index('# 1 "/src/a.cpp"\nint g(){return 1;}\n')
    result = _result(("f", 16, "int sub_10(){return 1;}"))
    assert (
        index.resolve(result, {16: [_native(16, "f", "/src/a.cpp", 1)]}).evidence["f"]["status"]
        == "source_name_mismatch"
    )


@pytest.mark.parametrize("native_name", ["bad", "good"])
@pytest.mark.parametrize("prefix", ["", "template<class T> "])
def test_error_recovery_span_is_not_evidence_of_a_name_mismatch(
    native_name: str, prefix: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = prefix + "int bad(){ ?\n int good(){return 1;}\n}\n"
    index = _index('# 1 "/src/a.cpp"\n' + text)
    definitions = function_definitions(text)
    assert len(definitions) == 1 and definitions[0].has_error

    def unexpected_parse(*args: Any, **kwargs: Any) -> None:
        pytest.fail("an erroneous enclosing AST must never reach CFG parsing")

    monkeypatch.setattr("decbench.utils.cfg_identity.parse_definitions", unexpected_parse)
    result = _result((native_name, 16, "int output(){return 1;}"))
    joined = index.resolve(result, {16: [_native(16, native_name, "/src/a.cpp", 2)]})
    assert not joined.cfgs
    assert joined.evidence[native_name]["status"] == "source_syntax_error"


def test_template_definition_abstains_without_specialization_model() -> None:
    index = _index('# 1 "/src/a.cpp"\ntemplate<class T> int f(T x){return x;}\n')
    result = _result(("f", 16, "int sub_10(){return 1;}"))
    assert (
        index.resolve(result, {16: [_native(16, "f", "/src/a.cpp", 1)]}).evidence["f"]["status"]
        == "unsupported_template_specialization"
    )


def test_producer_records_are_isolated_and_prototypes_are_not_bodies() -> None:
    result = _result(
        ("semantic", 16, "extern int helper(); int sub_10(){return helper();}"),
        ("bad", 32, "int bad(){if(}"),
        ("another", 48, "int sub_30(){return 2;}"),
    )
    joined = decompiled_cfgs(result)
    assert set(joined.cfgs) == {"semantic", "another"}
    assert joined.evidence["bad"]["status"] in {"parser_failure", "missing_definition"}


def test_multiple_producer_definitions_never_choose_largest_or_name() -> None:
    result = _result(("f", 16, "int helper(){return 0;} int f(int x){if(x)return 1;return 2;}"))
    joined = decompiled_cfgs(result)
    assert not joined.cfgs
    assert joined.evidence["f"]["status"] == "ambiguous_definitions"


def test_parser_failures_are_reported_and_missing_native_is_explicit() -> None:
    index = _index('# 1 "/src/a.cpp"\nint f(){return 1;}\n')
    result = _result(("f", 16, "int sub_10(){return 1;}"))
    joined = index.resolve(result, {})
    assert joined.evidence["f"]["status"] == "missing_native_identity"


def test_generic_cpp_entry_requires_preprocessed_inputs(tmp_path: Path) -> None:
    path = tmp_path / "raw.cpp"
    path.write_text("int f(){return 1;}")
    with pytest.raises(ValueError, match="preprocessed"):
        evaluate_cpp_ged(_result(), [path])


@pytest.mark.parametrize("dwarf_version", [4, 5])
@pytest.mark.parametrize("optimization", ["-O0", "-O2"])
def test_real_native_dwarf_definition_join(
    tmp_path: Path, dwarf_version: int, optimization: str
) -> None:
    import shutil
    import subprocess

    from decbench.utils.cfg_identity import native_sources
    from decbench.utils.function_identity import dwarf_function_identities

    compiler = shutil.which("clang++")
    if compiler is None:
        pytest.skip("clang++ required for native debug fixture")
    source = tmp_path / "native.cpp"
    source.write_text(
        "namespace outer {\nint f(int x){if(x)return x;return 2;}\n"
        "int f(long x){return 3;}\n}\nint main(){return outer::f(0);}\n"
    )
    obj, binary, preprocessed = tmp_path / "native.o", tmp_path / "native", tmp_path / "native.ii"
    subprocess.run(
        [
            compiler,
            optimization,
            "-g",
            f"-gdwarf-{dwarf_version}",
            "-c",
            str(source),
            "-o",
            str(obj),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run([compiler, str(obj), "-o", str(binary)], check=True, capture_output=True)
    if binary.read_bytes()[:4] != b"\x7fELF":
        subprocess.run(["dsymutil", str(binary)], check=True, capture_output=True)
    preprocessed.write_bytes(
        subprocess.run([compiler, "-E", str(source)], check=True, capture_output=True).stdout
    )
    identities = [row for row in dwarf_function_identities(binary) if row.name == "f"]
    assert len(identities) == 2
    result = _result(
        *[("f", row.address, f"int sub_{row.address:x}(){{return 1;}}") for row in identities]
    )
    result.binary_path = binary
    native = native_sources(binary, {row.address for row in identities})
    assert all(len(records) == 1 for records in native.values())
    report = evaluate_cpp_ged(result, [preprocessed], native_index=native)
    assert report.source_eligible == report.paired == 2, report.model_dump()
    assert all(row["path"] == str(source) for row in report.source_evidence.values())


def test_real_pdb_msvc_line_directive_definition_join(tmp_path: Path) -> None:
    import shutil
    import subprocess

    from decbench.utils.function_identity import dwarf_function_identities

    compiler, linker = shutil.which("clang-cl"), shutil.which("lld-link")
    if compiler is None or linker is None:
        pytest.skip("clang-cl/lld-link required for native PDB fixture")
    source = tmp_path / "native.cpp"
    source.write_text(
        "namespace outer {\nint f(int x){if(x)return x;return 2;}\n"
        'int f(long x){return 3;}\n}\nextern "C" int entry(){return outer::f(0);}\n'
    )
    obj, binary, pdb = tmp_path / "native.obj", tmp_path / "native.exe", tmp_path / "native.pdb"
    preprocessed = tmp_path / "native.ii"
    subprocess.run(
        [
            compiler,
            "--target=x86_64-pc-windows-msvc",
            "/c",
            "/Z7",
            "/Od",
            "/GS-",
            str(source),
            f"/Fo{obj}",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            linker,
            str(obj),
            "/entry:entry",
            "/subsystem:console",
            "/nodefaultlib",
            "/debug:full",
            "/opt:noicf",
            f"/pdb:{pdb}",
            f"/out:{binary}",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [compiler, "--target=x86_64-pc-windows-msvc", "/P", str(source), f"/Fi{preprocessed}"],
        check=True,
        capture_output=True,
    )
    identities = [row for row in dwarf_function_identities(binary) if row.name == "outer::f"]
    assert len(identities) == 2
    result = _result(
        *[("f", row.address, f"int sub_{row.address:x}(){{return 1;}}") for row in identities]
    )
    result.binary_path = binary
    report = evaluate_cpp_ged(result, [preprocessed])
    assert report.source_eligible == report.paired == 2, report.model_dump()


def test_isolated_definition_retains_full_tu_cfg_for_supported_control_flow() -> None:
    from decbench.metrics.ged import _is_isomorphic
    from decbench.utils.cfg_identity import parse_definitions

    code = (
        "extern int read_value(); namespace n { int f(int x){"
        "while(x>0){if(read_value())break;--x;} return x; } }"
    )
    full = parse_definitions(code, "fixture.cpp", "c++")
    definition = function_definitions(code)[0]
    isolated = parse_definitions(definition.code, "isolated.cpp", "c++")
    assert len(full) == len(isolated) == 1
    assert _is_isomorphic(full[0].cfg, isolated[0].cfg)


def test_qualified_scope_must_match_even_with_same_leaf_and_location() -> None:
    index = _index('# 1 "/src/a.cpp"\nnamespace wrong {int f(){return 1;}}\n')
    result = _result(("f", 16, "int sub_10(){return 1;}"))
    native = NativeSource(
        16, "f", ("/src/a.cpp",), SourceLocation("/src/a.cpp", 1), "fixture", "right::f"
    )
    joined = index.resolve(result, {16: [native]})
    assert not joined.cfgs
    assert joined.evidence["f"]["status"] == "source_name_mismatch"


def test_infrastructure_and_unexpected_evaluator_errors_do_not_abstain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rust_joern

    result = _result(("f", 16, "int sub_10(){return 1;}"))

    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("library unavailable")

    monkeypatch.setattr(rust_joern, "parse_code", fail)
    with pytest.raises(RuntimeError, match="library unavailable"):
        decompiled_cfgs(result)


def test_missing_tu_and_missing_header_have_distinct_reasons() -> None:
    index = _index('# 1 "/src/a.cpp"\nint f(){return 1;}\n')
    result = _result(("f", 16, "int sub_10(){return 1;}"))
    tu_miss = index.resolve(result, {16: [_native(16, "f", "/src/b.cpp", 1, "/src/b.cpp")]})
    assert tu_miss.evidence["f"]["status"] == "missing_source_tu"
    header_miss = index.resolve(result, {16: [_native(16, "f", "/usr/include/b.h", 1)]})
    assert header_miss.evidence["f"]["status"] == "missing_source_origin"


def test_unc_paths_match_after_marker_unquoting() -> None:
    path = r"\\server\share\a.cpp"
    source = origin_source('#line 1 "\\\\\\\\server\\\\share\\\\a.cpp"\nint f(){return 1;}\n')
    assert source.primary == source_path(path)


def test_unclosed_lexical_scope_is_not_proven() -> None:
    definitions = function_definitions("namespace n { int f(){return 1;}\n")
    assert definitions and definitions[0].has_error


def test_native_index_rejects_other_or_changed_binary(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"a")
    b.write_bytes(b"a")
    index = NativeSourceIndex(a, {})
    with pytest.raises(ValueError, match="another binary"):
        index.validate(b)
    a.write_bytes(b"changed")
    with pytest.raises(ValueError, match="contents changed"):
        index.validate(a)


def test_nonfinite_ged_is_evaluator_failure_not_population_exclusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from decbench.metrics.ged import GEDMetric
    from decbench.models.metrics import MetricValue

    binary = tmp_path / "fixture"
    binary.write_bytes(b"synthetic debug fixture")
    result = _result(("f", 16, "int sub_10(){return 1;}"))
    result.binary_path = binary
    index = _index('# 1 "/src/a.cpp"\nint f(){return 1;}\n')
    native = NativeSourceIndex(binary, {16: [_native(16, "f", "/src/a.cpp", 1)]})
    monkeypatch.setattr(
        GEDMetric, "compute_for_function", lambda *a, **k: MetricValue(value=float("inf"))
    )
    with pytest.raises(RuntimeError, match="GED evaluator failed"):
        evaluate_cpp_ged(result, source_index=index, native_index=native)


def test_fixed_requested_population_keeps_empty_recovery(tmp_path: Path) -> None:
    binary = tmp_path / "fixture"
    binary.write_bytes(b"synthetic debug fixture")
    result = _result(("extra", 32, "int extra(){return 1;}"))
    result.binary_path = binary
    source = _index('# 1 "/src/a.cpp"\nint f(){return 1;}\n')
    native = NativeSourceIndex(binary, {16: [_native(16, "f", "/src/a.cpp", 1)]})
    before = result.model_dump()
    report = evaluate_cpp_ged(
        result, source_index=source, native_index=native, requested_functions=[("f", 16)]
    )
    assert report.requested == report.source_eligible == 1
    assert report.paired == 0
    assert report.decompiled_statuses == {"empty_output": 1}
    assert result.model_dump() == before
    with pytest.raises(ValueError, match="distinct nonnegative"):
        evaluate_cpp_ged(
            result,
            source_index=source,
            native_index=native,
            requested_functions=[("f", 16), ("other", 16)],
        )


def test_cpp_ged_cli_smoke(tmp_path: Path) -> None:
    import json
    import os
    import shutil
    import subprocess
    import sys

    from decbench.utils.function_identity import dwarf_function_identities

    compiler = shutil.which("clang++")
    if compiler is None:
        pytest.skip("clang++ required for CLI native debug fixture")
    source, obj, binary = tmp_path / "cli.cpp", tmp_path / "cli.o", tmp_path / "cli"
    preprocessed = tmp_path / "cli.ii"
    source.write_text("int f(int x){return x+1;}\nint main(){return f(0);}\n")
    subprocess.run(
        [compiler, "-g", "-O0", "-c", str(source), "-o", str(obj)], check=True, capture_output=True
    )
    subprocess.run([compiler, str(obj), "-o", str(binary)], check=True, capture_output=True)
    if binary.read_bytes()[:4] != b"\x7fELF":
        subprocess.run(["dsymutil", str(binary)], check=True, capture_output=True)
    preprocessed.write_bytes(
        subprocess.run([compiler, "-E", str(source)], check=True, capture_output=True).stdout
    )
    identity = next(row for row in dwarf_function_identities(binary) if row.name == "f")
    result = _result(("f", identity.address, "int sub_10(int x){return x+1;}"))
    result.binary_path = binary
    artifact, requested, output = (
        tmp_path / "result.json",
        tmp_path / "requested.json",
        tmp_path / "report.json",
    )
    artifact.write_text(result.model_dump_json())
    requested.write_text(json.dumps([{"name": "f", "address": identity.address}]))
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(root), DECBENCH_NO_CACHE="1")
    subprocess.run(
        [
            sys.executable,
            str(root / "scripts/evaluate_cpp_ged.py"),
            str(artifact),
            "--requested-functions",
            str(requested),
            "--source",
            str(preprocessed),
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    report = json.loads(output.read_text())
    assert report["paired"] == report["metric"]["perfect_count"] == 1
    assert report["metric"]["metric_name"] == "cpp_ged_diagnostic"
    assert report["official_score"] is False


def test_filtered_origins_are_distinct_from_absent_source() -> None:
    text = '# 1 "/src/a.cpp"\n# 1 "/usr/include/target.hpp" 1 3\nint f(){return 1;}\n'
    index = _index(text)
    native = {16: [_native(16, "f", "/usr/include/target.hpp", 1)]}
    joined = index.resolve(_result(("f", 16, "int f(){return 1;}")), native)
    assert joined.evidence["f"]["status"] == "filtered_source_origin"
    assert index.inputs[0]["filtered_origin_paths"] == ["/usr/include/target.hpp"]
    assert index.inputs[0]["retained_origin_paths"] == []


def test_native_origin_retention_is_exact_and_scoped_to_proven_unit(tmp_path: Path) -> None:
    text = (
        '# 1 "/src/a.cpp"\n# 1 "/usr/include/target.hpp" 1 3\nint f(){return 1;}\n'
        '# 1 "/usr/include/unrequested.hpp" 1 3\nint other(){return 2;}\n'
    )
    path = tmp_path / "captured.ii"
    path.write_text(text)
    binary = tmp_path / "debug"
    binary.write_bytes(b"synthetic debug")
    result = _result(("f", 16, "int f(){return 1;}"))
    result.binary_path = binary
    row = _native(16, "f", "/usr/include/target.hpp", 1)
    report = evaluate_cpp_ged(result, [path], native_index=NativeSourceIndex(binary, {16: [row]}))
    assert report.paired == 1
    assert report.source_inputs[0]["retained_origin_paths"] == ["/usr/include/target.hpp"]
    assert report.source_inputs[0]["filtered_origin_paths"] == ["/usr/include/unrequested.hpp"]
    wrong = _native(16, "f", "/usr/include/target.hpp", 1, "/other/a.cpp")
    rejected = evaluate_cpp_ged(
        result, [path], native_index=NativeSourceIndex(binary, {16: [wrong]})
    )
    assert rejected.source_eligible == 0
    assert rejected.source_inputs[0]["retained_origin_paths"] == []
    ambiguous = evaluate_cpp_ged(
        result, [path], native_index=NativeSourceIndex(binary, {16: [row, row]})
    )
    assert ambiguous.source_eligible == 0
    assert ambiguous.source_inputs[0]["retained_origin_paths"] == []


def test_retention_requires_full_path_and_native_compilation_directory() -> None:
    from dataclasses import replace

    text = '# 1 "src/a.cpp"\n# 10 "include/h.hpp" 1 3\nint f(){return 1;}\n'
    row = NativeSource(
        16,
        "f",
        ("/build/src/a.cpp",),
        SourceLocation("/build/include/h.hpp", 10),
        "fixture",
        compilation_directory="/build",
    )
    index = SourceCfgIndex()
    index.add(text, "local.ii", native_records=(row,))
    assert index.inputs[0]["retained_origin_paths"] == ["include/h.hpp"]
    result = _result(("f", 16, "int f(){return 1;}"))
    assert index.resolve(result, {16: [row]}).evidence["f"]["status"] == "matched"
    index = SourceCfgIndex()
    index.add(
        text,
        "local.ii",
        native_records=(replace(row, location=SourceLocation("/other/h.hpp", 10)),),
    )
    assert index.inputs[0]["retained_origin_paths"] == []
    synthetic = origin_source(
        '# 1 "<built-in>"\nint fake(){return 0;}\n', retain_paths=frozenset({"<built-in>"})
    )
    assert not synthetic.origins


def test_real_native_system_header_recovery(tmp_path: Path) -> None:
    import shutil
    import subprocess

    from decbench.utils.cfg_identity import native_sources
    from decbench.utils.function_identity import dwarf_function_identities

    compiler = shutil.which("clang++")
    if compiler is None:
        pytest.skip("clang++ required")
    include = tmp_path / "sysinclude"
    include.mkdir()
    header = include / "helper.hpp"
    header.write_text(
        "namespace n {\n__attribute__((noinline)) int helper(int x){if(x)return 3;return 4;}\n}\n"
    )
    source, binary, obj, preprocessed = (
        tmp_path / n for n in ("unit.cpp", "unit", "unit.o", "unit.ii")
    )
    source.write_text("#include <helper.hpp>\nint main(){return n::helper(0);}\n")
    flags = [compiler, "-O0", "-g", "-isystem", str(include)]
    subprocess.run([*flags, "-c", str(source), "-o", str(obj)], check=True, capture_output=True)
    subprocess.run([compiler, str(obj), "-o", str(binary)], check=True, capture_output=True)
    if binary.read_bytes()[:4] != b"\x7fELF":
        subprocess.run(["dsymutil", str(binary)], check=True, capture_output=True)
    preprocessed.write_bytes(
        subprocess.run([*flags, "-E", str(source)], check=True, capture_output=True).stdout
    )
    row = next(r for r in dwarf_function_identities(binary) if r.name == "helper")
    native = native_sources(binary, {row.address})
    result = _result(("helper", row.address, "int sub_10(int x){if(x)return 3;return 4;}"))
    result.binary_path = binary
    before = SourceCfgIndex()
    before.add(preprocessed.read_text(), str(preprocessed))
    assert before.resolve(result, native).evidence["helper"]["status"] == "filtered_source_origin"
    report = evaluate_cpp_ged(result, [preprocessed], native_index=native)
    assert report.source_eligible == report.paired == report.metric.perfect_count == 1
    assert report.source_inputs[0]["retained_origin_paths"] == [str(header)]


def test_retained_header_does_not_replace_primary_unit() -> None:
    text = (
        '# 1 "/usr/include/prelude.hpp" 3\nint f(){return 1;}\n'
        '# 1 "/src/a.cpp"\nint g(){return 2;}\n'
    )
    source = origin_source(text, retain_paths=frozenset({"/usr/include/prelude.hpp"}))
    assert source.primary == "/src/a.cpp"
    assert source.origins[2] == SourceLocation("/usr/include/prelude.hpp", 1)


def test_selected_source_definition_has_exact_body_digest() -> None:
    import hashlib

    body = "int f(){return 1;}"
    index = _index('# 1 "/src/a.cpp"\n' + body + "\n")
    row = _native(16, "f", "/src/a.cpp", 1)
    evidence = index.resolve(_result(("f", 16, body)), {16: [row]}).evidence["f"]
    assert evidence["definition_sha256"] == hashlib.sha256(body.encode()).hexdigest()
