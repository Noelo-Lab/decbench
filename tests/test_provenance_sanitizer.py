from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from decbench.decompilers import provenance
from decbench.decompilers.provenance import (
    NativeProvenanceContext,
    sanitize_native_provenance,
)
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)
from decbench.pipeline import decompile as pipeline_decompile
from decbench.utils import binfmt, native_code
from decbench.utils.native_code import FunctionCode, NativeCodeResolver


def _code(*addresses: int, thumb: bool = False) -> FunctionCode:
    return FunctionCode(
        binary_path=Path("tool"),
        binary_format="elf",
        architecture="thumb" if thumb else "x86-64",
        thumb=thumb,
        ranges=((0x1000, 0x1010),),
        instruction_starts=frozenset(addresses),
    )


def _result(*functions: FunctionDecompilation) -> DecompilationResult:
    return DecompilationResult(
        binary_path=Path("tool"),
        binary_name="tool",
        decompiler=DecompilerMetadata(decompiler_name="test"),
        functions={function.name: function for function in functions},
    )


def _arm_mode_resolver(
    *,
    binary_format: str = "elf",
    mclass: bool = False,
    exact: set[bool] | None = None,
    named: list[bool] | None = None,
    pe_machine: int | None = None,
) -> NativeCodeResolver:
    resolver = object.__new__(NativeCodeResolver)
    resolver.info = binfmt.BinInfo(binary_format, "arm", 32)
    resolver.mclass = mclass
    resolver._thumb_by_address = {0x1000: set(exact or ())}  # type: ignore[assignment]
    resolver._thumb_by_name = {"target": list(named or ())}  # type: ignore[assignment]
    resolver._pe_machine = pe_machine
    return resolver


class _Resolver:
    def __init__(self, codes: dict[str, FunctionCode | Exception]):
        self.codes = codes

    def resolve(self, function_name: str, _function_address: int) -> FunctionCode:
        outcome = self.codes[function_name]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_sanitizer_preserves_valid_subsets_and_direct_only_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    function = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(int x) {\n int y;\n y = x;\n return y;\n}",
        line_mappings=[
            LineMapping(line_number=1, addresses=[0x1000, 0x1001, 0x1004]),
            LineMapping(line_number=2, addresses=[0x2000]),
            LineMapping(line_number=3, addresses=[]),
        ],
        variables=[
            VariableInfo(
                name="x",
                line_numbers=[1, 2, 3, 4],
                addresses=[0x1004, 0x1008, 0x2000],
            ),
            VariableInfo(name="direct", addresses=[0x1008]),
        ],
    )
    result = _result(function)
    resolver = _Resolver({"target": _code(0x1000, 0x1004, 0x1008)})
    monkeypatch.setattr(provenance, "NativeCodeResolver", lambda _path: resolver)

    metadata = sanitize_native_provenance(result)

    assert [(row.line_number, row.addresses) for row in function.line_mappings] == [
        (1, [0x1000, 0x1004])
    ]
    assert function.variables[0].addresses == [0x1004, 0x1008]
    assert function.variables[0].line_numbers == [1, 4]
    assert function.variables[1].addresses == [0x1008]
    assert len(function.variables) == 2
    assert metadata["status"] == "sanitized"
    assert metadata["line_mapping_addresses_dropped"] == 2
    assert metadata["line_mapping_rows_dropped"] == 2
    assert metadata["variable_addresses_dropped"] == 1
    assert metadata["variable_line_numbers_dropped"] == 2


def test_sanitizer_normalizes_thumb_state_and_removes_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    function = FunctionDecompilation(
        name="thumb_target",
        address=0x1001,
        decompiled_code="void thumb_target(void) {}",
        line_mappings=[LineMapping(line_number=1, addresses=[0x1001, 0x1000, 0x1003])],
        variables=[VariableInfo(name="x", addresses=[0x1001, 0x1003])],
    )
    result = _result(function)
    resolver = _Resolver({"thumb_target": _code(0x1000, 0x1002, thumb=True)})
    monkeypatch.setattr(provenance, "NativeCodeResolver", lambda _path: resolver)

    metadata = sanitize_native_provenance(result)

    assert function.line_mappings[0].addresses == [0x1000, 0x1002]
    assert function.variables[0].addresses == [0x1000, 0x1002]
    assert metadata["line_mapping_addresses_normalized"] == 2
    assert metadata["line_mapping_address_duplicates_removed"] == 1
    assert metadata["variable_addresses_normalized"] == 2


def test_sanitizer_fails_closed_per_function_without_discarding_code_or_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    function = FunctionDecompilation(
        name="unresolved",
        address=0x1000,
        decompiled_code="int unresolved(int arg) { return arg; }",
        line_mappings=[LineMapping(line_number=2, addresses=[0x1000])],
        variables=[
            VariableInfo(
                name="arg",
                line_numbers=[1, 2],
                addresses=[0x1000],
            )
        ],
    )
    result = _result(function)
    resolver = _Resolver(
        {"unresolved": ValueError("ambiguous DWARF function 'unresolved' at 0x1000")}
    )
    monkeypatch.setattr(provenance, "NativeCodeResolver", lambda _path: resolver)

    metadata = sanitize_native_provenance(result)

    assert function.decompiled_code == "int unresolved(int arg) { return arg; }"
    assert function.line_mappings == []
    assert len(function.variables) == 1
    assert function.variables[0].addresses == []
    assert function.variables[0].line_numbers == []
    assert metadata["status"] == "partial_fail_closed"
    assert metadata["functions_unresolved"] == 1
    assert metadata["variable_line_numbers_dropped"] == 2
    assert metadata["function_failure_reasons"] == {"dwarf_function_ambiguous": 1}


def test_stripped_worker_defers_without_mutating_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    function = FunctionDecompilation(
        name="sub_1000",
        address=0x1000,
        decompiled_code="int sub_1000(void) { return 0; }",
        line_mappings=[LineMapping(line_number=1, addresses=[0x1000])],
        variables=[VariableInfo(name="x", line_numbers=[1], addresses=[0x1000])],
    )
    result = _result(function)

    def unavailable(_path: Path) -> NativeCodeResolver:
        raise ValueError("binary has no readable DWARF")

    monkeypatch.setattr(provenance, "NativeCodeResolver", unavailable)

    metadata = sanitize_native_provenance(result, defer_unavailable=True)

    assert metadata["status"] == "deferred"
    assert function.line_mappings[0].addresses == [0x1000]
    assert function.variables[0].addresses == [0x1000]
    assert function.variables[0].line_numbers == [1]


def test_final_unavailable_binary_clears_claims_and_records_aggregate_reasons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid = list(range(0x1000, 0x1040))
    function = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(void) { return 0; }",
        line_mappings=[LineMapping(line_number=2, addresses=invalid)],
        variables=[VariableInfo(name="x", line_numbers=[1, 2], addresses=invalid)],
    )
    result = _result(function)

    def unavailable(_path: Path) -> NativeCodeResolver:
        raise ValueError("unsupported binary")

    monkeypatch.setattr(provenance, "NativeCodeResolver", unavailable)

    metadata = sanitize_native_provenance(result)

    assert metadata["status"] == "fail_closed"
    assert function.line_mappings == []
    assert function.variables[0].addresses == []
    assert function.variables[0].line_numbers == []
    assert metadata["variable_line_numbers_dropped"] == 2
    assert metadata["address_drop_reasons"] == {"binary_validation_unavailable": 128}
    assert "address_drop_samples" not in metadata


def test_sanitizer_builds_one_binary_context_for_all_functions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = FunctionDecompilation(
        name="first",
        address=0x1000,
        decompiled_code="void first(void) {}",
        variables=[VariableInfo(name="x", addresses=[0x1000])],
    )
    second = FunctionDecompilation(
        name="second",
        address=0x2000,
        decompiled_code="void second(void) {}",
        variables=[VariableInfo(name="y", addresses=[0x2000])],
    )
    created: list[Path] = []
    resolved: list[str] = []

    class Resolver:
        def __init__(self, path: Path):
            created.append(path)

        def resolve(self, function_name: str, address: int) -> FunctionCode:
            resolved.append(function_name)
            return _code(address)

    monkeypatch.setattr(provenance, "NativeCodeResolver", Resolver)

    sanitize_native_provenance(_result(first, second))

    assert created == [Path("tool").resolve()]
    assert resolved == ["first", "second"]


def test_explicit_context_reuses_one_binary_index_across_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[Path] = []

    class Resolver:
        def __init__(self, path: Path):
            created.append(path)

        def resolve(self, _function_name: str, address: int) -> FunctionCode:
            return _code(address)

    monkeypatch.setattr(provenance, "NativeCodeResolver", Resolver)
    context = NativeProvenanceContext(Path("tool"))
    first = _result(
        FunctionDecompilation(
            name="first",
            address=0x1000,
            decompiled_code="void first(void) {}",
            variables=[VariableInfo(name="x", addresses=[0x1000])],
        )
    )
    second = _result(
        FunctionDecompilation(
            name="second",
            address=0x2000,
            decompiled_code="void second(void) {}",
            variables=[VariableInfo(name="y", addresses=[0x2000])],
        )
    )

    sanitize_native_provenance(first, Path("tool"), context=context)
    sanitize_native_provenance(second, Path("tool"), context=context)

    assert created == [Path("tool").resolve()]


def test_sanitizer_drops_line_only_evidence_without_resolving_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    function = FunctionDecompilation(
        name="target",
        address=0x1000,
        decompiled_code="int target(int x) { return x; }",
        variables=[VariableInfo(name="x", line_numbers=[1])],
    )
    result = _result(function)

    def unexpected(_path: Path) -> NativeCodeResolver:
        raise AssertionError("resolver should not be constructed")

    monkeypatch.setattr(provenance, "NativeCodeResolver", unexpected)

    metadata = sanitize_native_provenance(result)

    assert metadata["status"] == "sanitized"
    assert metadata["functions_with_address_provenance"] == 0
    assert metadata["functions_modified"] == 1
    assert metadata["variable_line_numbers_dropped"] == 1
    assert function.variables[0].line_numbers == []


def test_native_resolver_uses_entry_pc_and_indexes_dwarf_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = SimpleNamespace(
        tag="DW_TAG_subprogram",
        attributes={"DW_AT_entry_pc": SimpleNamespace(value=0x2670)},
    )
    second = SimpleNamespace(
        tag="DW_TAG_subprogram",
        attributes={"DW_AT_low_pc": SimpleNamespace(value=0x3000)},
    )
    cu = SimpleNamespace(iter_DIEs=lambda: iter((first, second)))
    dwarf = SimpleNamespace(iter_CUs=lambda: iter((cu,)))
    ranges = {
        id(first): ((0x2670, 0x2700), (0x2640, 0x2662)),
        id(second): ((0x3000, 0x3010),),
    }
    binary = tmp_path / "tool"
    binary.write_bytes(b"fixture")
    calls = {"decode": 0, "dwarf": 0, "regions": 0}

    monkeypatch.setattr(binfmt, "detect", lambda _path: binfmt.BinInfo("elf", "x86-64", 64))

    def dwarf_info(_path: Path) -> object:
        calls["dwarf"] += 1
        return dwarf

    def executable_regions(_path: Path) -> tuple[tuple[int, bytes], ...]:
        calls["regions"] += 1
        return ((0x2000, bytes(0x2000)),)

    monkeypatch.setattr(binfmt, "dwarf_info", dwarf_info)
    monkeypatch.setattr(binfmt, "executable_regions", executable_regions)
    monkeypatch.setattr(
        binfmt,
        "die_str_attr",
        lambda die, _name: "first" if die is first else "second",
    )
    monkeypatch.setattr(native_code, "die_ranges", lambda die, _info: ranges[id(die)])

    def decode(
        _info: object,
        extents: tuple[tuple[int, int], ...],
        _regions: object,
        **_kwargs: object,
    ) -> frozenset[int]:
        calls["decode"] += 1
        return frozenset(begin for begin, _end in extents)

    monkeypatch.setattr(native_code, "decode_instruction_starts", decode)

    resolver = NativeCodeResolver(binary)
    assert resolver.resolve("first", 0x2670).ranges == ranges[id(first)]
    assert resolver.resolve("first", 0x2670).ranges == ranges[id(first)]
    assert resolver.resolve("second", 0x3000).ranges == ranges[id(second)]
    with pytest.raises(ValueError, match="no DWARF function matches"):
        resolver.resolve("first", 0x2640)
    with pytest.raises(ValueError, match="no DWARF function matches"):
        resolver.resolve("first", 0x2640)
    assert calls == {"decode": 2, "dwarf": 1, "regions": 1}


@pytest.mark.parametrize(
    ("resolver", "expected"),
    [
        (_arm_mode_resolver(exact={False}), False),
        (_arm_mode_resolver(exact={True}), True),
        (_arm_mode_resolver(exact={False}, named=[True]), False),
        (_arm_mode_resolver(exact={True}, named=[False, False]), True),
        (_arm_mode_resolver(named=[False]), False),
        (_arm_mode_resolver(named=[True]), True),
        (_arm_mode_resolver(mclass=True), True),
    ],
)
def test_arm_elf_mode_uses_exact_named_and_mprofile_authorities(
    resolver: NativeCodeResolver,
    expected: bool,
) -> None:
    assert resolver._uses_thumb("target", 0x1000) is expected


@pytest.mark.parametrize(
    "resolver",
    [
        _arm_mode_resolver(),
        _arm_mode_resolver(exact={False, True}),
        _arm_mode_resolver(named=[True, True]),
        _arm_mode_resolver(mclass=True, exact={False}),
        _arm_mode_resolver(mclass=True, named=[False]),
        _arm_mode_resolver(mclass=True, named=[True, True]),
    ],
)
def test_arm_elf_mode_fails_closed_on_missing_conflicting_or_nonunique_state(
    resolver: NativeCodeResolver,
) -> None:
    with pytest.raises(ValueError, match="ARM instruction state"):
        resolver._uses_thumb("target", 0x1000)


def test_odd_arm_entry_selects_thumb_before_symbol_fallback() -> None:
    resolver = _arm_mode_resolver(exact={False})

    assert resolver._uses_thumb("target", 0x1001) is True


@pytest.mark.parametrize(
    ("machine", "expected"),
    [
        (0x1C0, False),
        (0x1C2, True),
        (0x1C4, True),
    ],
)
def test_pe_arm_machine_selects_instruction_state(machine: int, expected: bool) -> None:
    resolver = _arm_mode_resolver(binary_format="pe", pe_machine=machine)

    assert resolver._uses_thumb("target", 0x1000) is expected


@pytest.mark.parametrize("machine", [None, 0xFFFF])
def test_pe_arm_unknown_machine_fails_closed(machine: int | None) -> None:
    resolver = _arm_mode_resolver(binary_format="pe", pe_machine=machine)

    with pytest.raises(ValueError, match="ARM instruction state"):
        resolver._uses_thumb("target", 0x1000)


def test_pipeline_sanitizes_adapter_result_with_explicit_deferral(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "stripped"
    result = _result(
        FunctionDecompilation(
            name="sub_1000",
            address=0x1000,
            decompiled_code="void sub_1000(void) {}",
        )
    )
    calls: list[tuple[DecompilationResult, Path, bool]] = []

    class Decompiler:
        def is_available(self) -> bool:
            return True

        def decompile_binary(self, _path: Path, **_kwargs: object) -> DecompilationResult:
            return result

    monkeypatch.setattr(
        pipeline_decompile,
        "DecompilerRegistry",
        SimpleNamespace(get=lambda _name, _config: Decompiler()),
    )

    def sanitize(
        value: DecompilationResult,
        path: Path,
        *,
        defer_unavailable: bool,
    ) -> dict[str, object]:
        calls.append((value, path, defer_unavailable))
        return {"status": "deferred"}

    monkeypatch.setattr(pipeline_decompile, "sanitize_native_provenance", sanitize)

    returned = pipeline_decompile.decompile_binary(
        binary,
        "test",
        defer_provenance_validation=True,
    )

    assert returned is result
    assert calls == [(result, binary, True)]
