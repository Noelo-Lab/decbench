from __future__ import annotations

import hashlib
import json
import os
import pickle
import shutil
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from elftools.elf import elffile

from decbench.auditing import native_provenance
from decbench.auditing.native_provenance import (
    AuditState,
    FunctionCode,
    audit_function,
    audit_results_tree,
    decode_instruction_starts,
    load_manifest,
)
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)
from decbench.utils import binfmt
from scripts.audit_native_provenance import main


@pytest.mark.parametrize(
    ("info", "thumb", "code", "expected"),
    [
        (binfmt.BinInfo("elf", "x86-64", 64), False, b"\x55\x48\x89\xe5\xc3", {0, 1, 4}),
        (binfmt.BinInfo("pe", "x86", 32), False, b"\x55\x89\xe5\xc3", {0, 1, 3}),
        (
            binfmt.BinInfo("elf", "arm", 32),
            False,
            b"\x00\x00\xa0\xe1\x1e\xff\x2f\xe1",
            {0, 4},
        ),
        (binfmt.BinInfo("pe", "arm", 32), True, b"\x00\xbf\x70\x47", {0, 2}),
        (
            binfmt.BinInfo("pe", "aarch64", 64),
            False,
            b"\x1f\x20\x03\xd5\xc0\x03\x5f\xd6",
            {0, 4},
        ),
    ],
)
def test_decode_instruction_starts_supports_target_formats_and_architectures(
    info: binfmt.BinInfo,
    thumb: bool,
    code: bytes,
    expected: set[int],
) -> None:
    start = 0x1000
    assert decode_instruction_starts(
        info,
        [(start, start + len(code))],
        [(start, code)],
        thumb=thumb,
    ) == frozenset(start + offset for offset in expected)


def test_decode_instruction_starts_rejects_non_executable_range() -> None:
    with pytest.raises(ValueError, match="is not executable"):
        decode_instruction_starts(
            binfmt.BinInfo("elf", "x86-64", 64),
            [(0x1000, 0x1001)],
            [(0x2000, b"\xc3")],
            thumb=False,
        )


def test_decode_instruction_starts_accepts_cortex_m_system_registers() -> None:
    start = 0x08001000
    code = bytes.fromhex("eff31183 83f31188")
    info = binfmt.BinInfo("elf", "arm", 32)

    assert decode_instruction_starts(
        info,
        [(start, start + len(code))],
        [(start, code)],
        thumb=True,
        mclass=True,
    ) == frozenset({start, start + 4})


@pytest.mark.parametrize(
    ("machine", "profiles", "expected"),
    [
        ("EM_ARM", [ord("M")], True),
        ("EM_ARM", [ord("A")], False),
        ("EM_ARM", [ord("M"), ord("A")], False),
        ("EM_AARCH64", [ord("M")], False),
    ],
)
def test_arm_mclass_detection_uses_exact_elf_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    machine: str,
    profiles: list[int],
    expected: bool,
) -> None:
    attributes = [
        SimpleNamespace(tag="TAG_CPU_ARCH_PROFILE", value=profile) for profile in profiles
    ]
    scope = SimpleNamespace(iter_attributes=lambda: iter(attributes))
    subsection = SimpleNamespace(
        header=SimpleNamespace(vendor_name="aeabi"),
        iter_subsubsections=lambda: iter((scope,)),
    )
    section = SimpleNamespace(iter_subsections=lambda: iter((subsection,)))
    elf = SimpleNamespace(
        header={"e_machine": machine},
        get_section_by_name=lambda _name: section,
    )
    monkeypatch.setattr(elffile, "ELFFile", lambda _stream: elf)
    binary = tmp_path / "fixture.elf"
    binary.write_bytes(b"ELF fixture")

    assert binfmt.elf_is_arm_mclass(binary) is expected


def test_function_ranges_uses_dwarf_entry_instead_of_lowest_split_range(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    die = SimpleNamespace(tag="DW_TAG_subprogram", attributes={})
    cu = SimpleNamespace(iter_DIEs=lambda: iter((die,)))
    dwarfinfo = SimpleNamespace(iter_CUs=lambda: iter((cu,)))
    ranges = ((0x2670, 0x2FC1), (0x2640, 0x2662))
    monkeypatch.setattr(binfmt, "dwarf_info", lambda _path: dwarfinfo)
    monkeypatch.setattr(binfmt, "die_str_attr", lambda _die, _name: "main")
    monkeypatch.setattr(native_provenance, "_die_ranges", lambda _die, _info: ranges)

    assert native_provenance._function_ranges(tmp_path / "tool", "main", 0x2670, "x86-64") == ranges
    with pytest.raises(ValueError, match="no DWARF function matches"):
        native_provenance._function_ranges(tmp_path / "tool", "main", 0x2640, "x86-64")


def _code(*addresses: int) -> FunctionCode:
    return FunctionCode(
        binary_path=Path("tool"),
        binary_format="elf",
        architecture="x86-64",
        thumb=False,
        ranges=((0x1000, 0x1010),),
        instruction_starts=frozenset(addresses),
    )


def test_audit_function_accepts_line_derived_and_direct_only_variables() -> None:
    state = AuditState(max_findings=20)
    mapped = FunctionDecompilation(
        name="mapped",
        address=0x1000,
        decompiled_code="int mapped(void) {\n return 0;\n}",
        line_mappings=[
            LineMapping(line_number=1, addresses=[0x1000]),
            LineMapping(line_number=2, addresses=[0x1004]),
        ],
        variables=[VariableInfo(name="x", line_numbers=[2], addresses=[0x1004, 0x1008])],
    )
    direct = FunctionDecompilation(
        name="direct",
        address=0x1000,
        decompiled_code="int direct(void) { return 0; }",
        variables=[VariableInfo(name="x", addresses=[0x1008])],
    )

    audit_function(
        state,
        ("p", "O0", "tool", "mapped"),
        "ida",
        mapped,
        _code(0x1000, 0x1004, 0x1008),
    )
    audit_function(state, ("p", "O0", "tool", "direct"), "reko", direct, _code(0x1000, 0x1008))

    assert state.error_count == 0
    assert state.backend_stats["ida"].functions_with_line_maps == 1
    assert state.backend_stats["ida"].functions_with_variable_lines == 1
    assert state.backend_stats["reko"].functions_with_direct_only_addresses == 1


def test_audit_function_rejects_bad_rows_addresses_and_line_join() -> None:
    state = AuditState(max_findings=20)
    function = FunctionDecompilation(
        name="bad",
        address=0x1000,
        decompiled_code="int bad(void) {\n return 0;\n}",
        line_mappings=[
            LineMapping(line_number=4, addresses=[0x1000]),
            LineMapping(line_number=1, addresses=[0x1002]),
            LineMapping(line_number=2, addresses=[0x1000]),
        ],
        variables=[VariableInfo(name="x", line_numbers=[2], addresses=[0x1004])],
    )

    audit_function(
        state,
        ("p", "O0", "tool", "bad"),
        "ida",
        function,
        _code(0x1000, 0x1004),
    )

    assert state.finding_counts == {
        "line_number_out_of_bounds": 1,
        "noninstruction_address": 1,
        "variable_line_address_disagreement": 1,
    }


def test_variable_lines_without_line_map_are_invalid_but_direct_only_is_not() -> None:
    state = AuditState(max_findings=20)
    function = FunctionDecompilation(
        name="bad",
        address=0x1000,
        decompiled_code="int bad(void) { return 0; }",
        variables=[VariableInfo(name="x", line_numbers=[1], addresses=[0x1000])],
    )

    audit_function(state, ("p", "O0", "tool", "bad"), "ida", function, _code(0x1000))

    assert state.finding_counts == {"variable_lines_without_map": 1}


def test_variable_lines_may_include_unmapped_declaration_rows() -> None:
    state = AuditState(max_findings=20)
    function = FunctionDecompilation(
        name="bad",
        address=0x1000,
        decompiled_code=(
            "int bad(int x) {\n" " int result;\n" " result = x;\n" " return result;\n" "}"
        ),
        line_mappings=[
            LineMapping(line_number=3, addresses=[0x1000]),
            LineMapping(line_number=4, addresses=[0x1004]),
        ],
        variables=[
            VariableInfo(name="x", line_numbers=[1, 3]),
            VariableInfo(name="result", line_numbers=[2, 3, 4]),
        ],
    )

    audit_function(
        state,
        ("p", "O0", "tool", "bad"),
        "ida",
        function,
        _code(0x1000, 0x1004),
    )

    assert state.error_count == 0


def test_malformed_nonempty_variable_evidence_cannot_bypass_audit() -> None:
    state = AuditState(max_findings=20)
    variable = VariableInfo(name="x").model_copy(update={"addresses": "0x1000"})
    function = FunctionDecompilation(
        name="bad",
        address=0x1000,
        decompiled_code="int bad(void) { return 0; }",
        variables=[variable],
    )

    assert native_provenance._function_has_provenance(function) is True
    audit_function(state, ("p", "O0", "tool", "bad"), "ida", function, _code(0x1000))

    assert state.finding_counts == {"malformed_address_list": 1}


def _minimal_elf(path: Path, machine: int = 0x3E) -> None:
    payload = bytearray(20)
    payload[:4] = b"\x7fELF"
    payload[18:20] = struct.pack("<H", machine)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _minimal_pe(path: Path, machine: int) -> None:
    payload = bytearray(0x88)
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x80)
    payload[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", payload, 0x84, machine)
    path.write_bytes(payload)


def _write_tree(
    root: Path,
    functions: list[FunctionDecompilation],
    *,
    backend: str = "reko",
) -> tuple[Path, Path]:
    binary = root / "O0/proj/compiled/tool"
    _minimal_elf(binary)
    result = DecompilationResult(
        binary_path=binary,
        binary_name="tool",
        decompiler=DecompilerMetadata(decompiler_name=backend),
        functions={function.name: function for function in functions},
    )
    checkpoints = root / "checkpoints"
    checkpoints.mkdir()
    with (checkpoints / "proj.pkl").open("wb") as stream:
        pickle.dump({"decompile": {"O0": {"tool": {backend: result}}}}, stream)
    manifest = root / "sample_set_manifest.json"
    manifest.write_text(
        json.dumps(
            {"functions": [{"project": "proj", "opt": "O0", "binary": "tool", "function": "f"}]}
        )
    )
    return binary, manifest


def _resolved(binary: Path, function: str, address: int) -> FunctionCode:
    return FunctionCode(
        binary_path=binary,
        binary_format="elf",
        architecture="x86-64",
        thumb=False,
        ranges=((address, address + 1),),
        instruction_starts=frozenset({address}),
    )


def test_tree_audit_enforces_manifest_scope_and_reports_backend_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    valid = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { return 0; }",
        variables=[VariableInfo(name="x", addresses=[0x1000])],
    )
    extra = valid.model_copy(update={"name": "extra", "decompiled_code": "int extra(void){}"})
    _binary, manifest = _write_tree(tmp_path, [valid, extra])
    monkeypatch.setattr(native_provenance, "resolve_function_code", _resolved)

    report = audit_results_tree(tmp_path, manifest_path=manifest, requested_backends=["reko"])

    assert report["valid"] is False
    assert report["validation"]["error_counts"] == {"out_of_manifest_scope": 1}
    assert report["backends"]["reko"]["functions_with_direct_only_addresses"] == 2
    assert report["scope"]["manifest_functions_present_in_any_backend"] == 1
    checkpoint = tmp_path / "checkpoints/proj.pkl"
    assert (
        report["inputs"]["checkpoints"][0]["sha256"]
        == hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    )
    assert report["inputs"]["compiled_binaries"] == [
        {
            "binary": "tool",
            "optimization": "O0",
            "path": str(tmp_path / "O0/proj/compiled/tool"),
            "project": "proj",
            "sha256": hashlib.sha256((tmp_path / "O0/proj/compiled/tool").read_bytes()).hexdigest(),
        }
    ]


def test_tree_audit_allows_missing_line_maps_and_cli_writes_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { return 0; }",
        variables=[VariableInfo(name="x", addresses=[0x1000])],
    )
    tree = tmp_path / "tree"
    _binary, manifest = _write_tree(tree, [function])
    monkeypatch.setattr(native_provenance, "resolve_function_code", _resolved)
    output = tmp_path / "audit.json"

    assert (
        main(
            [
                str(tree),
                "--manifest",
                str(manifest),
                "--backend",
                "reko",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    report = json.loads(output.read_text())
    assert report["valid"] is True
    assert report["backends"]["reko"]["functions_with_direct_only_addresses"] == 1


def test_cli_refuses_to_write_inside_results_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { return 0; }",
    )
    _write_tree(tmp_path, [function])
    output = tmp_path / "audit.json"

    assert main([str(tmp_path), "--output", str(output)]) == 2
    assert not output.exists()
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_cli_atomic_output_does_not_modify_a_hardlinked_result_file(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { return 0; }",
    )
    _write_tree(tree, [function])
    protected = tree / "protected.json"
    protected.write_text("preserve me")
    output = tmp_path / "audit.json"
    os.link(protected, output)

    assert main([str(tree), "--output", str(output)]) == 0

    assert protected.read_text() == "preserve me"
    assert json.loads(output.read_text())["valid"] is True
    assert protected.stat().st_ino != output.stat().st_ino


def test_tree_audit_rejects_unknown_requested_backend(tmp_path: Path) -> None:
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { return 0; }",
    )
    _write_tree(tmp_path, [function])

    report = audit_results_tree(tmp_path, requested_backends=["ida"])

    assert report["valid"] is False
    assert report["validation"]["error_counts"] == {
        "empty_backend_scope": 1,
        "requested_backend_missing": 1,
    }


def test_tree_audit_rejects_duplicate_normalized_slices(tmp_path: Path) -> None:
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { return 0; }",
    )
    _write_tree(tmp_path, [function])
    checkpoint = tmp_path / "checkpoints/proj.pkl"
    payload = pickle.loads(checkpoint.read_bytes())
    payload["decompile"]["O0"][Path("tool")] = payload["decompile"]["O0"]["tool"]
    checkpoint.write_bytes(pickle.dumps(payload))

    report = audit_results_tree(tmp_path)

    assert report["valid"] is False
    assert report["validation"]["error_counts"] == {"duplicate_checkpoint_slice": 1}


@pytest.mark.parametrize(
    "filenames",
    [("tool.exe", "tool.so"), ("tool", "tool.exe")],
)
def test_tree_audit_rejects_ambiguous_same_stem_binaries(
    tmp_path: Path,
    filenames: tuple[str, str],
) -> None:
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { return 0; }",
        variables=[VariableInfo(name="x", addresses=[0x1000])],
    )
    binary, _manifest = _write_tree(tmp_path, [function])
    binary.unlink()
    for filename in filenames:
        _minimal_elf(binary.with_name(filename))

    report = audit_results_tree(tmp_path)

    assert report["validation"]["error_counts"] == {"binary_resolution_failed": 1}
    assert "ambiguous compiled binary" in report["findings"][0]["message"]


def test_tree_binary_resolution_rejects_escape_and_symlinked_scope(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid checkpoint optimization component"):
        native_provenance._resolve_tree_binary(tmp_path, "../../outside", "proj", "tool")

    target = tmp_path / "outside"
    target.mkdir()
    compiled = tmp_path / "O0/proj/compiled"
    compiled.parent.mkdir(parents=True)
    compiled.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="compiled path contains a symlink"):
        native_provenance._resolve_tree_binary(tmp_path, "O0", "proj", "tool")


def test_tree_audit_rejects_checkpoint_metadata_identity_mismatch(tmp_path: Path) -> None:
    function = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { return 0; }",
    )
    _write_tree(tmp_path, [function])
    checkpoint = tmp_path / "checkpoints/proj.pkl"
    payload = pickle.loads(checkpoint.read_bytes())
    result = payload["decompile"]["O0"]["tool"]["reko"]
    result.decompiler.decompiler_name = "ghidra"
    result.binary_name = "other"
    checkpoint.write_bytes(pickle.dumps(payload))

    report = audit_results_tree(tmp_path)

    assert report["validation"]["error_counts"] == {
        "backend_identity_mismatch": 1,
        "binary_identity_mismatch": 1,
    }


def test_manifest_rejects_duplicates(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    row = {"project": "p", "opt": "O0", "binary": "b", "function": "f"}
    path.write_text(json.dumps({"functions": [row, row]}))

    with pytest.raises(ValueError, match="duplicate function keys"):
        load_manifest(path)


def test_manifest_rejects_non_string_identity_fields(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {"functions": [{"project": None, "opt": "O0", "binary": "tool", "function": "f"}]}
        )
    )

    with pytest.raises(ValueError, match="non-string or empty field"):
        load_manifest(path)


def test_resolve_function_code_uses_exact_live_dwarf_range(tmp_path: Path) -> None:
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("no C compiler available")
    source = tmp_path / "tiny.c"
    source.write_text(
        "int add_nums(int a, int b) { int total = a + b; return total; }\n"
        "int main(void) { return add_nums(1, 2); }\n"
    )
    binary = tmp_path / "tiny"
    subprocess.run(
        [compiler, "-g", "-O0", "-fno-inline", "-o", str(binary), str(source)],
        check=True,
    )
    function_range = binfmt._dwarf_function_range(binary, "add_nums")
    assert function_range is not None

    code = native_provenance.resolve_function_code(binary, "add_nums", function_range[0])

    assert code.ranges == (function_range,)
    assert function_range[0] in code.instruction_starts
    assert all(
        function_range[0] <= address < function_range[1] for address in code.instruction_starts
    )


@pytest.mark.parametrize("machine", [0x1C0, 0x1C2, 0x1C4])
def test_detect_recognizes_pe_arm_machine_variants(tmp_path: Path, machine: int) -> None:
    path = tmp_path / f"arm-{machine:x}.exe"
    _minimal_pe(path, machine)

    assert binfmt.detect(path) == binfmt.BinInfo("pe", "arm", 32)


def test_elf_thumb_lookup_prefers_exact_address_over_same_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Symbol:
        def __init__(self, name: str, address: int) -> None:
            self.name = name
            self.fields = {
                "st_info": {"type": "STT_FUNC"},
                "st_size": 4,
                "st_value": address,
            }

        def __getitem__(self, name: str) -> object:
            return self.fields[name]

    symbols = [Symbol("target", 0x1000), Symbol("other", 0x2001)]
    symbol_table = SimpleNamespace(iter_symbols=lambda: iter(symbols))
    elf = SimpleNamespace(
        header={"e_machine": "EM_ARM"},
        get_section_by_name=lambda _name: symbol_table,
    )
    monkeypatch.setattr("elftools.elf.elffile.ELFFile", lambda _stream: elf)
    binary = tmp_path / "arm.elf"
    binary.write_bytes(b"ELF")

    assert binfmt.elf_function_is_thumb(binary, "target", 0x2000) is True
