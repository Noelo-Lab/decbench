"""Object graphs, complete declarations and exact producer correspondence."""

from __future__ import annotations

import copy
import shutil
import struct
import subprocess
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from decbench.decompilers.raw.fission_raw import RawFissionDecompiler
from decbench.metrics.base import MetricConfig
from decbench.metrics.cpp_recovered_types import RecoveredTypeContext
from decbench.metrics.cpp_type_graph import (
    TypeEdge,
    TypeGraph,
    TypeNode,
    dwarf_graph,
    pdb_graph,
    primitive_graph,
)
from decbench.metrics.cpp_type_match import CppTypeMatchMetric
from decbench.metrics.cpp_types import UnsupportedType, parse_type
from decbench.metrics.variable_match import VariableEvidence, extract_decompiler_evidence
from decbench.models.decompilation import FunctionDecompilation, LineMapping, VariableInfo
from decbench.utils import binfmt
from decbench.utils.pdb_info import _Types


def _graph(name: str = "demo::Object") -> TypeGraph:
    return TypeGraph(
        "obj",
        {
            "obj": TypeNode(
                "record",
                16,
                name,
                edges=(
                    TypeEdge("field", "i", "value", 0, access=3),
                    TypeEdge("field", "p", "next", 64, access=3),
                ),
            ),
            "i": TypeNode("signed", 4, rank="int"),
            "p": TypeNode("pointer", 8, edges=(TypeEdge("element", "obj"),)),
        },
    )


def _payload(graph: TypeGraph) -> dict:
    return {
        "schema": "decbench-cpp-type-graph-v1",
        "root": graph.root,
        "nodes": {k: {**asdict(v), "complete": True} for k, v in graph.nodes.items()},
    }


def test_ids_do_not_prove_equality_and_recursive_targets_are_compared() -> None:
    a = _graph()
    payload = _payload(a)
    payload["root"] = "new"
    payload["nodes"]["new"] = payload["nodes"].pop("obj")
    payload["nodes"]["p"]["edges"][0]["target"] = "new"
    b = TypeGraph.from_payload(payload)
    assert a == b
    b.nodes["i"] = TypeNode("unsigned", 4, rank="int")
    assert a != b
    assert a.project("abi") != b.project("abi")


@pytest.mark.parametrize(
    "change", ["field_type", "offset", "field_name", "object_name", "size", "access"]
)
def test_source_object_comparison_requires_all_layout_and_identity_facts(change: str) -> None:
    a = _graph()
    b = copy.deepcopy(a)
    if change == "field_type":
        b.nodes["i"] = TypeNode("float", 4, rank="float")
    else:
        node = b.nodes["obj"]
        updates = {"object_name": {"name": "other::Object"}, "size": {"size": 24}}
        if change in updates:
            node = replace(node, **updates[change])
        else:
            edge = node.edges[0]
            edge = replace(
                edge,
                **{
                    "offset": {"offset_bits": 32},
                    "field_name": {"name": "renamed"},
                    "access": {"access": 1},
                }[change],
            )
            node = replace(node, edges=(edge, node.edges[1]))
        b.nodes["obj"] = node
    assert a != b
    assert (a.project("abi") == b.project("abi")) == (
        change in {"object_name", "field_name", "access"}
    )


def test_size_and_nominal_name_without_fields_are_never_perfect() -> None:
    a = _graph()
    b = TypeGraph("obj", {"obj": TypeNode("record", 16, "demo::Object")})
    assert a != b
    assert a.project("abi") != b.project("abi")


def test_ordinary_and_virtual_inheritance_are_distinct_and_targets_checked() -> None:
    a = _graph("Derived")
    a.nodes["base"] = TypeNode(
        "record", 4, "Base", edges=(TypeEdge("field", "i", "base_value", 0, access=3),)
    )
    a.nodes["obj"] = replace(
        a.nodes["obj"],
        edges=(TypeEdge("base", "base", offset_bits=0, access=3), a.nodes["obj"].edges[1]),
    )
    a.validate()
    b = copy.deepcopy(a)
    b.nodes["obj"] = replace(
        b.nodes["obj"],
        edges=(
            TypeEdge("base", "base", virtual=True, locator="dwarf:1206381c", access=3),
            b.nodes["obj"].edges[1],
        ),
    )
    b.validate()
    assert a != b
    assert a.project("abi") != b.project("abi")
    c = copy.deepcopy(b)
    c.nodes["obj"] = replace(
        c.nodes["obj"],
        edges=(replace(c.nodes["obj"].edges[0], locator="dwarf:1206381d"), c.nodes["obj"].edges[1]),
    )
    assert b != c


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "incomplete",
        "out_of_extent",
        "virtual_offset",
        "schema",
        "pointer_without_target",
    ],
)
def test_incomplete_or_malformed_producer_graphs_abstain(mutation: str) -> None:
    p = _payload(_graph())
    if mutation == "missing":
        del p["nodes"]["i"]
    elif mutation == "incomplete":
        p["nodes"]["obj"]["complete"] = False
    elif mutation == "out_of_extent":
        p["nodes"]["obj"]["edges"][0]["offset_bits"] = 128
    elif mutation == "virtual_offset":
        p["nodes"]["obj"]["edges"][0].update(role="base", virtual=True, locator="locator")
    elif mutation == "schema":
        p["schema"] = "wrong"
    else:
        p["nodes"]["p"]["edges"] = []
    with pytest.raises(UnsupportedType):
        TypeGraph.from_payload(p)


def test_ordinary_emitted_definition_and_recursive_pointer_layout() -> None:
    code = "namespace demo { struct Object { int value; Object *next; }; }"
    recovered = RecoveredTypeContext(code, "LP64").graph("demo::Object")
    assert recovered == _graph()
    assert recovered.project("abi") == _graph("Different").project("abi")
    assert (
        RecoveredTypeContext(code.replace("int value", "unsigned int value"), "LP64").graph(
            "demo::Object"
        )
        != recovered
    )


@pytest.mark.parametrize(
    "code,spelling",
    [
        ("struct X;", "X"),
        ("struct X { int n; }; struct X { int n; };", "X"),
        ("struct X { unsigned int n:3; };", "X"),
        ("struct X { int n; }; #pragma pack(1)", "X"),
        ("struct X { X child; };", "X"),
        ("class X { int n; };", "X"),
        ("struct Base { int n; }; struct X:Base { int n; };", "X"),
    ],
)
def test_recovered_layout_never_guesses_opaque_or_special_abi(code: str, spelling: str) -> None:
    with pytest.raises(UnsupportedType):
        RecoveredTypeContext(code, "LP64").graph(spelling)


def test_arrays_and_typedef_records_use_complete_definitions() -> None:
    ctx = RecoveredTypeContext("typedef struct { char c; int v[2]; } X;", "LP64")
    graph = ctx.graph("X")
    node = graph.nodes[graph.root]
    assert node.size == 12
    assert [(e.name, e.offset_bits) for e in node.edges] == [("c", 0), ("v", 32)]
    array = graph.nodes[node.edges[1].target]
    assert array.kind == "array" and array.count == 2 and array.size == 8


def test_metric_matches_without_using_type_then_compares_object_graph() -> None:
    graph = _graph()
    fn = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="void f() {}",
        variables=[VariableInfo(name="v", type="demo::Object", size=16, addresses=[0x1000])],
        metadata={"type_graphs": {"demo::Object": _payload(graph)}},
    )
    gt = [{"identity": "source:0", "descriptor": graph}]
    evidence = [VariableEvidence("source:0", frozenset({0x1000}))]
    metric = CppTypeMatchMetric(
        MetricConfig(extra_options={"view": "source", "data_model": "LP64"})
    )
    result = metric.compute_for_function(fn, ground_truth_vars=gt, source_evidence=evidence)
    assert result.value == 1 and result.metadata["matched_count"] == 1
    fn.metadata = {}
    result = metric.compute_for_function(fn, ground_truth_vars=gt, source_evidence=evidence)
    assert result.value == 0 and result.metadata["ground_truth_count"] == 1
    assert result.metadata["decisions"][0]["verdict"] == "unsupported_recovered_type"


def test_scoped_fission_lines_never_assign_rhs_or_legacy_lifetime_to_all_occurrences() -> None:
    record = {
        "code_nir": "int f() {\n int a = b;\n return a;\n}",
        "variables": [{"name": "a", "type": "int"}, {"name": "b", "type": "int"}],
        "line_mappings_nir": [
            {"line_number": 2, "addresses": [0x1000], "defined_variables": ["a"]}
        ],
    }
    function = RawFissionDecompiler._build_function(record, "f", 0x1000)
    assert function is not None
    assert function.variables[0].line_numbers == [2]
    assert function.variables[1].line_numbers == []
    function.variables[1].line_numbers = [2]
    rows = extract_decompiler_evidence(function, backend="test")
    assert rows[0].addresses == frozenset({0x1000}) and not rows[1].addresses
    function.line_mappings = [LineMapping(line_number=2, addresses=[0x1000])]
    assert extract_decompiler_evidence(function, backend="test")[1].addresses == frozenset({0x1000})
    function.variables[0].addresses = [0x1004]
    assert extract_decompiler_evidence(function, backend="test")[0].addresses == frozenset({0x1004})


def _field(attrs: int, ty: int, offset: int, name: str) -> bytes:
    data = struct.pack("<HHIH", 0x150D, attrs, ty, offset) + name.encode() + b"\0"
    n = (-len(data)) % 4
    return data + bytes(range(0xF0 + n, 0xF0, -1))


def _record(fields: int, size: int, name: str, flags: int = 0) -> bytes:
    return struct.pack("<HHIIIH", 1, flags, fields, 0, 0, size) + name.encode() + b"\0"


def test_codeview_layout_forward_reference_bitfields_and_continuations() -> None:
    types = _Types(b"")
    types.records = {
        0x1000: (0x1505, _record(0x1001, 4, "X")),
        0x1001: (0x1203, _field(3, 0x1003, 0, "bits") + struct.pack("<HHI", 0x1404, 0, 0x1004)),
        0x1002: (0x1505, _record(0, 0, "X", 0x80)),
        0x1003: (0x1205, struct.pack("<IBB", 0x75, 3, 1)),
        0x1004: (0x1203, b""),
    }
    graph = pdb_graph(types, 0x1002, "LLP64")
    n = graph.nodes[graph.root]
    assert n.name == "X" and n.size == 4
    assert n.edges[0].offset_bits == 1 and n.edges[0].bit_width == 3
    types.records[0x1004] = (0x1203, struct.pack("<HHI", 0x1404, 0, 0x1001))
    types._layout_cache.clear()
    with pytest.raises(ValueError, match="cyclic"):
        pdb_graph(types, 0x1000, "LLP64")


def test_codeview_unknown_leaf_and_duplicate_full_definition_are_not_partial_layout() -> None:
    types = _Types(b"")
    types.records = {
        0x1000: (0x1505, _record(0x1001, 4, "X")),
        0x1001: (0x1203, struct.pack("<H", 0x7777)),
        0x1002: (0x1505, _record(0, 0, "X", 0x80)),
    }
    with pytest.raises(ValueError, match="unsupported CodeView field"):
        pdb_graph(types, 0x1000, "LLP64")
    types.records[0x1003] = types.records[0x1000]
    with pytest.raises(ValueError, match="ambiguous"):
        pdb_graph(types, 0x1002, "LLP64")


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ needed for real debug fixture")
def test_real_debug_object_base_and_field_graph(tmp_path: Path) -> None:
    source = tmp_path / "object.cpp"
    source.write_text(
        "namespace demo { struct Base { int value; }; "
        "struct Object: Base { long long other; }; } "
        "demo::Object object; int main(){return object.value;}"
    )
    binary = tmp_path / "object"
    object_file = tmp_path / "object.o"
    subprocess.run(
        ["clang++", "-g", "-O0", "-c", str(source), "-o", str(object_file)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["clang++", str(object_file), "-o", str(binary)], check=True, capture_output=True
    )
    if binary.read_bytes()[:4] != b"\x7fELF":
        subprocess.run(["dsymutil", str(binary)], check=True, capture_output=True)
    dwarf = binfmt.dwarf_info(binary)
    assert dwarf is not None
    variable = next(
        d
        for cu in dwarf.iter_CUs()
        for d in cu.iter_DIEs()
        if d.tag == "DW_TAG_variable" and binfmt.die_str_attr(d, "DW_AT_name") == "object"
    )
    graph = dwarf_graph(variable, "LP64")
    n = graph.nodes[graph.root]
    assert n.kind == "record" and n.name == "demo::Object" and n.size == 16
    assert [(e.role, e.offset_bits) for e in n.edges] == [("base", 0), ("field", 64)]
    assert graph.nodes[n.edges[0].target].name == "demo::Base"
    assert graph.nodes[graph.nodes[n.edges[0].target].edges[0].target].kind == "signed"


@pytest.mark.skipif(
    shutil.which("clang-cl") is None or shutil.which("lld-link") is None,
    reason="clang-cl/lld-link needed for real CodeView fixture",
)
def test_real_codeview_object_base_and_fields(tmp_path: Path) -> None:
    from decbench.utils.pdb_info import read_pdb

    source = tmp_path / "object.cpp"
    source.write_text(
        "namespace demo { struct Base { int value; }; "
        "struct Object: Base { long long other; }; } "
        'demo::Object object; extern "C" int entry(){return object.value;}'
    )
    obj, binary = tmp_path / "object.obj", tmp_path / "object.exe"
    pdb = tmp_path / "object.pdb"
    subprocess.run(
        [
            "clang-cl",
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
            "lld-link",
            str(obj),
            "/entry:entry",
            "/subsystem:console",
            "/nodefaultlib",
            "/debug:full",
            f"/pdb:{pdb}",
            f"/out:{binary}",
        ],
        check=True,
        capture_output=True,
    )
    native = read_pdb(binary)
    assert native is not None and native.types is not None
    candidates = []
    for index, (leaf, payload) in native.types.records.items():
        if (
            leaf in {0x1504, 0x1505}
            and not struct.unpack_from("<H", payload, 2)[0] & 0x80
            and native.types.record_layout(index)["name"] == "demo::Object"
        ):
            candidates.append(index)
    assert len(candidates) == 1
    graph = pdb_graph(native.types, candidates[0], "LLP64")
    node = graph.nodes[graph.root]
    assert node.name == "demo::Object" and node.size == 16
    assert [(e.role, e.offset_bits) for e in node.edges] == [("base", 0), ("field", 64)]
    base = graph.nodes[node.edges[0].target]
    assert base.name == "demo::Base" and base.edges[0].name == "value"


@pytest.mark.parametrize(
    "spelling",
    ["int", "unsigned long", "const int*", "int* const", "int&", "int&&", "const int[2][3]"],
)
@pytest.mark.parametrize("model", ["LP64", "LLP64", "ILP32"])
def test_scalar_projection_contract_is_preserved_in_graphs(spelling: str, model: str) -> None:
    value = parse_type(spelling, model)
    graph = primitive_graph(value)
    assert graph.byte_size() == value.byte_size()
    assert graph.project("abi") == primitive_graph(value.project("abi")).project("abi")


def test_enum_abi_uses_underlying_storage_but_source_retains_values_and_identity() -> None:
    graph = TypeGraph(
        "enum",
        {
            "enum": TypeNode(
                "enum",
                4,
                "Color",
                edges=(TypeEdge("element", "u"),),
                enumerators=(("red", 1), ("blue", 2)),
            ),
            "u": TypeNode("unsigned", 4, rank="int"),
        },
    )
    graph.validate()
    unsigned = primitive_graph(parse_type("unsigned int", "LP64"))
    assert graph.project("abi") == unsigned.project("abi")
    assert graph != unsigned
    changed = copy.deepcopy(graph)
    changed.nodes["enum"] = replace(graph.nodes["enum"], enumerators=(("red", 3), ("blue", 2)))
    assert changed != graph


def test_by_value_cycles_are_rejected_but_pointer_cycles_remain_valid() -> None:
    payload = _payload(_graph())
    payload["nodes"]["obj"]["edges"] = [
        {"role": "field", "target": "obj", "offset_bits": 0, "name": "self"}
    ]
    with pytest.raises(UnsupportedType, match="by-value"):
        TypeGraph.from_payload(payload)
    TypeGraph.from_payload(_payload(_graph()))


def test_source_definition_line_never_borrows_an_overload_or_guesses_same_line() -> None:
    from decbench.metrics.variable_features import function_definition_at_line

    code = (
        "namespace a { int same(int x) { return x; } }\n"
        "int same(int x){return x+1;}\nint same(double x){return 2;}"
    )
    assert "x+1" in function_definition_at_line(code, "same", 2)
    assert "return 2" in function_definition_at_line(code, "same", 3)
    assert function_definition_at_line(code, "same", 1) is None
    assert "return x" in function_definition_at_line(code, "a::same", 1)
    assert (
        function_definition_at_line("int f(int x){return x;} int f(double x){return 0;}", "f", 1)
        is None
    )


def test_codeview_virtual_base_locator_preserves_pointer_type_and_never_offset_zero() -> None:
    types = _Types(b"")
    types.records = {
        0x1000: (0x1505, _record(0x1001, 4, "Base")),
        0x1001: (0x1203, _field(3, 0x74, 0, "value")),
        0x1002: (0x1505, _record(0x1003, 16, "Derived")),
        0x1003: (0x1203, struct.pack("<HHIIHH", 0x1401, 3, 0x1000, 0x674, 0, 1)),
    }
    graph = pdb_graph(types, 0x1002, "LLP64")
    edge = graph.nodes[graph.root].edges[0]
    assert edge.virtual and edge.offset_bits is None and edge.locator == "codeview:0:1"
    assert graph.nodes[edge.locator_type].kind == "pointer"
    changed = copy.deepcopy(graph)
    pointer = changed.nodes[edge.locator_type]
    target = pointer.edges[0].target
    changed.nodes[target] = TypeNode("float", 4, rank="float")
    assert changed != graph and changed.project("abi") != graph.project("abi")


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ needed for oracle eligibility")
def test_real_oracle_population_does_not_depend_on_missing_recovery(tmp_path: Path) -> None:
    from decbench.metrics.cpp_type_match import CppOracleContext
    from decbench.models.decompilation import DecompilationResult, DecompilerMetadata
    from decbench.utils.function_identity import dwarf_function_identities

    source = tmp_path / "population.cpp"
    source.write_text(
        'struct Object { int value; }; extern "C" int take(Object* p){return p->value;} '
        'extern "C" int mixed(Object* p,int(*f)(int)){return f(p->value);} '
        "int main(){Object o{3};return take(&o);}"
    )
    obj, binary = tmp_path / "population.o", tmp_path / "population"
    subprocess.run(
        ["clang++", "-g", "-O0", "-c", str(source), "-o", str(obj)], check=True, capture_output=True
    )
    subprocess.run(["clang++", str(obj), "-o", str(binary)], check=True, capture_output=True)
    if binary.read_bytes()[:4] != b"\x7fELF":
        subprocess.run(["dsymutil", str(binary)], check=True, capture_output=True)
    addresses = {d.name: d.address for d in dwarf_function_identities(binary)}
    recovered = DecompilationResult(
        binary_path=binary,
        binary_name=binary.name,
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    recovered.add_function(
        FunctionDecompilation(
            name="take",
            address=addresses["take"],
            decompiled_code="struct Object { int value; }; int take(Object* p){return p->value;}",
            variables=[VariableInfo(name="p", type="Object*", size=8, kind="arg", arg_index=0)],
        )
    )
    missing = DecompilationResult(
        binary_path=binary,
        binary_name=binary.name,
        decompiler=DecompilerMetadata(decompiler_name="missing"),
    )
    recovered.add_function(
        FunctionDecompilation(
            name="extra", address=addresses["mixed"], decompiled_code="int extra(){return 0;}"
        )
    )
    oracle = CppOracleContext(binary)
    for view in ["source", "abi"]:
        metric = CppTypeMatchMetric(
            MetricConfig(extra_options={"view": view, "data_model": "LP64"})
        )
        kwargs = {"oracle_context": oracle, "requested_functions": [("take", addresses["take"])]}
        good = metric.compute_for_binary(recovered, **kwargs)
        lost = metric.compute_for_binary(missing, **kwargs)
        assert set(good.function_results) == set(lost.function_results) == {"take"}
        assert good.function_results["take"].value == 1
        assert lost.function_results["take"].value == 0
        excluded = metric.compute_for_binary(
            missing, oracle_context=oracle, requested_functions=[("mixed", addresses["mixed"])]
        )
        assert not excluded.function_results
        assert any("DW_TAG_subroutine_type" in e for e in excluded.errors)
    assert missing.functions == {}
