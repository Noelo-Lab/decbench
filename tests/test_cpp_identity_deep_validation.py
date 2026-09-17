"""Extra validation for the C++ function-identity contribution candidate."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
from decbench.scoring.scoreboard import build_scoreboard_from_function_data
from decbench.utils.function_identity import (
    dwarf_function_identities,
    identities_by_name,
)

CPP = r"""
namespace alpha { __attribute__((noinline)) int collide(int x) { return x + 1; } }
namespace beta  { __attribute__((noinline)) int collide(int x) { return x + 2; } }
__attribute__((noinline)) int collide(int x) { return x + 3; }
__attribute__((noinline)) int collide(double x) { return static_cast<int>(x) + 4; }
struct A { __attribute__((noinline)) int Next(int x) const; };
struct B { __attribute__((noinline)) int Next(int x) const; };
int A::Next(int x) const { return x + 5; }
int B::Next(int x) const { return x + 6; }
volatile int seed = 1;
int main() {
    A a; B b;
    int x = seed;
    return alpha::collide(x) + beta::collide(x) + collide(x)
        + collide(static_cast<double>(x)) + a.Next(x) + b.Next(x);
}
"""


def _driver():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_benchmark.py"
    spec = importlib.util.spec_from_file_location("deep_identity_driver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _compile(tmp_path: Path, mode: str) -> Path:
    flags = {
        "O0": ["-O0"],
        "O2": ["-O2"],
        "O2-noinline": ["-O2", "-fno-inline"],
    }[mode]
    source = tmp_path / f"fixture-{mode}.cpp"
    binary = tmp_path / f"fixture-{mode}"
    source.write_text(CPP)
    subprocess.run(
        ["g++", "-std=c++17", *flags, "-g", "-fno-builtin", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )
    return binary


def _fd(name: str, address: int) -> FunctionDecompilation:
    return FunctionDecompilation(
        name=f"FUN_{address:x}",
        address=address,
        decompiled_code=f"int FUN_{address:x}(void) {{ return 0; }}",
    )


@pytest.mark.skipif(shutil.which("g++") is None, reason="g++ required")
@pytest.mark.parametrize("mode", ["O0", "O2", "O2-noinline"])
def test_real_cpp_identity_survives_optimization_modes(tmp_path: Path, mode: str) -> None:
    binary = _compile(tmp_path, mode)
    grouped = identities_by_name(dwarf_function_identities(binary))

    collide = grouped.get("collide", [])
    next_rows = grouped.get("Next", [])
    assert len({row.address for row in collide}) == 4
    assert len({row.address for row in next_rows}) == 2

    selected = [*collide, *next_rows]
    addr2name = {row.address: row.name for row in selected}
    result = DecompilationResult(
        binary_path=binary,
        binary_name=binary.stem,
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
        functions={f"raw-{i}": _fd(row.name, row.address) for i, row in enumerate(selected)},
    )
    _driver()._relabel_to_dwarf(result, addr2name, binary)

    expected = {f"{name}@0x{address:x}" for address, name in addr2name.items()}
    assert set(result.functions) == expected
    assert {fd.address for fd in result.functions.values()} == set(addr2name)
    assert result.decompiler.failed_functions == []


def test_identity_storage_is_insertion_order_deterministic() -> None:
    from decbench.utils.function_identity import insert_function

    rows = [
        FunctionDecompilation(name="same", address=0x1000, decompiled_code="a"),
        FunctionDecompilation(name="same", address=0x2000, decompiled_code="b"),
        FunctionDecompilation(name="same", address=0x3000, decompiled_code="c"),
    ]
    forward: dict[str, FunctionDecompilation] = {}
    reverse: dict[str, FunctionDecompilation] = {}
    for row in rows:
        insert_function(forward, row.model_copy(deep=True))
    for row in reversed(rows):
        insert_function(reverse, row.model_copy(deep=True))

    assert set(forward) == set(reverse) == {
        "same@0x1000",
        "same@0x2000",
        "same@0x3000",
    }
    assert {key: value.address for key, value in forward.items()} == {
        key: value.address for key, value in reverse.items()
    }


def test_same_address_different_name_aliases_do_not_collapse() -> None:
    from decbench.utils.function_identity import insert_function

    functions: dict[str, FunctionDecompilation] = {}
    insert_function(
        functions,
        FunctionDecompilation(name="foo", address=0x1000, decompiled_code="a"),
    )
    insert_function(
        functions,
        FunctionDecompilation(name="bar", address=0x1000, decompiled_code="b"),
    )
    assert set(functions) == {"foo", "bar"}
    assert {fd.name for fd in functions.values()} == {"foo", "bar"}


def test_pydantic_json_roundtrip_preserves_collision_identity(tmp_path: Path) -> None:
    result = DecompilationResult(
        binary_path=tmp_path / "a.out",
        binary_name="a.out",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    result.add_function(FunctionDecompilation(name="foo", address=0x1000, decompiled_code="a"))
    result.add_function(FunctionDecompilation(name="foo", address=0x2000, decompiled_code="b"))

    restored = DecompilationResult.model_validate_json(result.model_dump_json())
    assert set(restored.functions) == {"foo@0x1000", "foo@0x2000"}
    assert [restored.functions[key].name for key in sorted(restored.functions)] == ["foo", "foo"]
    assert {fd.address for fd in restored.functions.values()} == {0x1000, 0x2000}


def test_legacy_plain_name_json_still_loads() -> None:
    legacy = {
        "binary_path": "legacy.bin",
        "binary_name": "legacy",
        "decompiler": {"decompiler_name": "legacy"},
        "functions": {
            "foo": {
                "name": "foo",
                "address": 4096,
                "decompiled_code": "int foo(void) { return 0; }",
            }
        },
    }
    restored = DecompilationResult.model_validate_json(json.dumps(legacy))
    assert set(restored.functions) == {"foo"}
    assert restored.functions["foo"].name == "foo"
    assert restored.functions["foo"].address == 0x1000


def test_toml_writer_keeps_distinct_collision_keys(tmp_path: Path) -> None:
    import toml

    result = DecompilationResult(
        binary_path=tmp_path / "a.out",
        binary_name="a.out",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
    )
    result.add_function(FunctionDecompilation(name="foo", address=0x1000, decompiled_code="a"))
    result.add_function(FunctionDecompilation(name="foo", address=0x2000, decompiled_code="b"))
    out = tmp_path / "result.toml"
    result.to_toml(out)
    data = toml.load(out)

    assert "functions.foo@0x1000" in data
    assert "functions.foo@0x2000" in data
    assert data["functions.foo@0x1000"]["address"] == "0x1000"
    assert data["functions.foo@0x2000"]["address"] == "0x2000"


def test_ged_abstention_does_not_boost_shared_scoreboard_denominator() -> None:
    # f3 has GED only for decompiler B. A's abstention must count as a miss because
    # GED is measurable for someone. f4 has GED for nobody and is uniformly excluded.
    records = [
        FunctionRecord(
            function="f1",
            values={"A": {"ged": 0.0}, "B": {"ged": 0.0}},
            perfects={"A": {"ged": True}, "B": {"ged": True}},
        ),
        FunctionRecord(
            function="f2",
            values={"A": {"ged": 1.0}, "B": {"ged": 1.0}},
            perfects={"A": {"ged": False}, "B": {"ged": False}},
        ),
        FunctionRecord(
            function="ambiguous-measurable",
            values={"A": {}, "B": {"ged": 1.0}},
            perfects={"A": {}, "B": {"ged": False}},
        ),
        FunctionRecord(
            function="ambiguous-unmeasurable",
            values={"A": {}, "B": {}},
            perfects={"A": {}, "B": {}},
        ),
    ]
    fd = FunctionData(
        decompilers=["A", "B"],
        metrics=["ged"],
        groups=[BinaryGroup(project="p", opt_level="O2", binary="b", functions=records)],
    )
    scoreboard = build_scoreboard_from_function_data(fd)
    a = scoreboard.decompiler_scores["A"].metric_scores["ged"]
    b = scoreboard.decompiler_scores["B"].metric_scores["ged"]

    assert a.total_count == b.total_count == 3
    assert a.perfect_count == b.perfect_count == 1
    assert a.perfect_percentage == pytest.approx(100 / 3)
    assert b.perfect_percentage == pytest.approx(100 / 3)
    # Means intentionally summarize only measured values; headline perfect-% uses
    # the shared measurable universe and therefore cannot improve by abstaining.
    assert a.mean == pytest.approx(0.5)
    assert b.mean == pytest.approx(2 / 3)
