"""Regression coverage for collision-safe function identity primitives."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    VariableInfo,
)
from decbench.utils.function_identity import (
    dwarf_function_identities,
    identities_by_name,
    insert_function,
)
from decbench.utils.source_extract import function_source_ex

CPP_COLLISIONS = r"""
namespace alpha {
__attribute__((noinline)) int collide(int x) { return x + 1; }
}

namespace beta {
__attribute__((noinline)) int collide(int x) { return x + 2; }
}

__attribute__((noinline)) int collide(int x) { return x + 3; }
__attribute__((noinline)) int collide(double x) { return static_cast<int>(x) + 4; }

struct A { __attribute__((noinline)) int Next(int x) const; };
struct B { __attribute__((noinline)) int Next(int x) const; };

int A::Next(int x) const { return x + 5; }
int B::Next(int x) const { return x + 6; }

int main() {
    A a;
    B b;
    return alpha::collide(1) + beta::collide(1) + collide(1) + collide(1.0)
        + a.Next(1) + b.Next(1);
}
"""


def _func(name: str, address: int) -> FunctionDecompilation:
    return FunctionDecompilation(
        name=name,
        address=address,
        decompiled_code=f"int {name}(void) {{ return 0; }}",
    )


def _result(tmp_path: Path) -> DecompilationResult:
    return DecompilationResult(
        binary_path=tmp_path / "fixture",
        binary_name="fixture",
        decompiler=DecompilerMetadata(decompiler_name="identity-test"),
    )


def _compile_collision_fixture(tmp_path: Path) -> Path:
    source = tmp_path / "identity_collision.cpp"
    binary = tmp_path / "identity_collision"
    source.write_text(CPP_COLLISIONS)
    subprocess.run(
        [
            "g++",
            "-std=c++17",
            "-O0",
            "-g",
            "-fno-inline",
            "-fno-builtin",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return binary


def test_insert_function_preserves_legacy_key_until_collision() -> None:
    functions: dict[str, FunctionDecompilation] = {}

    assert insert_function(functions, _func("foo", 0x1000)) == "foo"
    assert list(functions) == ["foo"]

    assert insert_function(functions, _func("bar", 0x2000)) == "bar"
    assert set(functions) == {"foo", "bar"}


def test_insert_function_rekeys_every_same_name_collision_by_address() -> None:
    functions: dict[str, FunctionDecompilation] = {}

    insert_function(functions, _func("foo", 0x1000))
    insert_function(functions, _func("foo", 0x2000))
    insert_function(functions, _func("foo", 0x3000))

    assert set(functions) == {
        "foo@0x1000",
        "foo@0x2000",
        "foo@0x3000",
    }
    assert {function.address for function in functions.values()} == {0x1000, 0x2000, 0x3000}


def test_insert_function_replaces_same_identity_in_place() -> None:
    functions: dict[str, FunctionDecompilation] = {}
    first = _func("foo", 0x1000)
    second = FunctionDecompilation(
        name="foo",
        address=0x1000,
        decompiled_code="int foo(void) { return 42; }",
    )

    insert_function(functions, first)
    assert insert_function(functions, second) == "foo"
    assert len(functions) == 1
    assert functions["foo"].decompiled_code.endswith("return 42; }")


def test_decompilation_result_exposes_collision_safe_api(tmp_path: Path) -> None:
    result = _result(tmp_path)

    result.add_function(_func("foo", 0x1000))
    result.add_function(_func("foo", 0x2000))
    result.add_function(_func("bar", 0x3000))

    assert result.function_count == 3
    assert set(result.functions) == {"foo@0x1000", "foo@0x2000", "bar"}
    assert {function.address for function in result.functions_named("foo")} == {0x1000, 0x2000}
    assert result.functions_named("missing") == []


def test_ghidra_function_lookup_is_address_keyed() -> None:
    from decbench.decompilers.raw.ghidra_raw import RawGhidraDecompiler

    class Address:
        def __init__(self, offset: int):
            self.offset = offset

        def getOffset(self) -> int:
            return self.offset

    class Function:
        def __init__(self, name: str, offset: int):
            self.name = name
            self.address = Address(offset)

        def getName(self) -> str:
            return self.name

        def getEntryPoint(self) -> Address:
            return self.address

    class FunctionManager:
        def __init__(self, functions):
            self.functions = functions

        def getFunctions(self, _forward: bool):
            return list(self.functions)

    class Program:
        def __init__(self):
            self.base = Address(0x1000)
            self.manager = FunctionManager(
                [Function("same", 0x1010), Function("same", 0x1020)]
            )

        def getImageBase(self) -> Address:
            return self.base

        def getFunctionManager(self) -> FunctionManager:
            return self.manager

    by_address = RawGhidraDecompiler._functions_by_address(Program(), elf_base=0x400000)

    assert set(by_address) == {0x400010, 0x400020}
    assert [by_address[address].getName() for address in sorted(by_address)] == ["same", "same"]


def test_type_match_prefers_address_ground_truth_for_same_name(tmp_path: Path) -> None:
    from decbench.metrics.type_match import TypeMatchMetric

    result = _result(tmp_path)
    first = FunctionDecompilation(
        name="same",
        address=0x1000,
        decompiled_code="int same(int x) { return x; }",
        variables=[VariableInfo(name="x", type="int", kind="arg", arg_index=0)],
    )
    second = FunctionDecompilation(
        name="same",
        address=0x2000,
        decompiled_code="double same(double x) { return x; }",
        variables=[VariableInfo(name="x", type="double", kind="arg", arg_index=0)],
    )
    result.add_function(first)
    result.add_function(second)

    int_gt = [
        {
            "name": "x",
            "type": ["int"],
            "rbp_offset": [],
            "size": 4,
            "is_arg": True,
            "arg_index": 0,
        }
    ]
    double_gt = [
        {
            "name": "x",
            "type": ["double"],
            "rbp_offset": [],
            "size": 8,
            "is_arg": True,
            "arg_index": 0,
        }
    ]

    metric = TypeMatchMetric()
    cache_key = str(result.binary_path)
    metric._ground_truth_cache[cache_key] = {"same": int_gt}
    metric._ground_truth_address_cache[cache_key] = {
        0x1000: int_gt,
        0x2000: double_gt,
    }

    scored = metric.compute_for_binary(result)

    assert set(scored.function_results) == {"same@0x1000", "same@0x2000"}
    assert scored.function_results["same@0x1000"].value == 1.0
    assert scored.function_results["same@0x2000"].value == 1.0


needs_gxx = pytest.mark.skipif(shutil.which("g++") is None, reason="needs g++")


@needs_gxx
def test_real_cpp_dwarf_identity_does_not_collapse_overloads(tmp_path: Path) -> None:
    binary = _compile_collision_fixture(tmp_path)

    identities = dwarf_function_identities(binary)
    interesting = [
        identity for identity in identities if identity.name in {"collide", "Next", "main"}
    ]
    grouped = identities_by_name(interesting)

    assert len(grouped["collide"]) == 4
    assert len(grouped["Next"]) == 2
    assert len(grouped["main"]) == 1
    assert len({identity.address for identity in interesting}) == 7

    linkage_names = [identity.linkage_name for identity in interesting if identity.linkage_name]
    assert len(linkage_names) == 6
    assert len(set(linkage_names)) == 6

    result = _result(tmp_path)
    for identity in interesting:
        result.add_function(_func(identity.name, identity.address))

    assert result.function_count == 7
    assert {function.address for function in result.functions.values()} == {
        identity.address for identity in interesting
    }


@needs_gxx
def test_source_extraction_uses_address_to_distinguish_overloads(tmp_path: Path) -> None:
    binary = _compile_collision_fixture(tmp_path)
    identities = [
        identity for identity in dwarf_function_identities(binary) if identity.name == "collide"
    ]

    int_global = next(identity for identity in identities if identity.linkage_name == "_Z7collidei")
    double_global = next(
        identity for identity in identities if identity.linkage_name == "_Z7collided"
    )

    int_source, int_status = function_source_ex(binary, "collide", int_global.address)
    double_source, double_status = function_source_ex(binary, "collide", double_global.address)

    assert int_status == ""
    assert double_status == ""
    assert int_source is not None and "collide(int x)" in int_source
    assert double_source is not None and "collide(double x)" in double_source
    assert int_source != double_source
