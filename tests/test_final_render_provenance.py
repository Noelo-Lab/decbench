"""Exact final-render variable joins used for retired checkpoint evidence."""

from pathlib import Path

import pytest

from decbench.decompilers.final_render_provenance import (
    FINAL_RENDER_PROVENANCE_KEY,
    FINAL_RENDER_PROVENANCE_SCHEMA,
    enrich_final_render_variable_provenance,
)
from decbench.decompilers.provenance import NativeProvenanceContext
from decbench.metrics.variable_match import extract_decompiler_evidence
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
    variable_occurrence_policy,
)
from scripts import reeval_typematch


def _result(
    code: str,
    mappings: list[LineMapping],
    variables: list[VariableInfo],
    *,
    name: str = "f",
    backend: str = "phoenix",
) -> DecompilationResult:
    return DecompilationResult(
        binary_path=Path("bin"),
        binary_name="bin",
        decompiler=DecompilerMetadata(decompiler_name=backend),
        functions={
            name: FunctionDecompilation(
                name=name,
                address=0x1000,
                decompiled_code=code,
                line_mappings=mappings,
                variables=variables,
            )
        },
    )


def test_final_render_join_attaches_only_exact_local_identifiers() -> None:
    result = _result(
        "int f(int a) {\n"
        "    int local = a;\n"
        "    struct S { int local; } obj;\n"
        "    obj.local = local;\n"
        "    return a + local;\n"
        "}\n",
        [
            LineMapping(line_number=1, addresses=[0x1000]),
            LineMapping(line_number=2, addresses=[0x1004]),
            LineMapping(line_number=4, addresses=[0x1008]),
            LineMapping(line_number=5, addresses=[0x100C]),
        ],
        [
            VariableInfo(name="a", type="int", kind="arg", arg_index=0),
            VariableInfo(name="local", type="int"),
        ],
    )

    report = enrich_final_render_variable_provenance(result)

    a, local = result.functions["f"].variables
    assert a.line_numbers == [1, 2, 5]
    assert a.addresses == [0x1000, 0x1004, 0x100C]
    assert local.line_numbers == [2, 4, 5]
    assert local.addresses == [0x1004, 0x1008, 0x100C]
    assert report.functions_enriched == 1
    assert report.variables_enriched == 2
    assert report.addresses_attached == 6
    assert variable_occurrence_policy(result.functions["f"].metadata) == "exact"
    assert result.decompiler.extra[FINAL_RENDER_PROVENANCE_KEY] == {
        "schema": FINAL_RENDER_PROVENANCE_SCHEMA,
        "backend": "phoenix",
        "functions_seen": 1,
        "functions_with_valid_line_maps": 1,
        "functions_enriched": 1,
        "variables_seen": 2,
        "variables_with_existing_evidence": 0,
        "variables_with_exact_occurrences": 2,
        "variables_enriched": 2,
        "addresses_attached": 6,
    }


@pytest.mark.parametrize(
    ("code", "mappings"),
    [
        (
            "int other(int value) { return value; }\n",
            [LineMapping(line_number=1, addresses=[0x1000])],
        ),
        (
            "int f(int value) { return value; }\n",
            [
                LineMapping(line_number=1, addresses=[0x1000]),
                LineMapping(line_number=1, addresses=[0x1004]),
            ],
        ),
        (
            "int f(int value) { return value; }\n",
            [LineMapping(line_number=2, addresses=[0x1000])],
        ),
    ],
)
def test_final_render_join_fails_closed_on_stale_or_malformed_maps(
    code: str,
    mappings: list[LineMapping],
) -> None:
    result = _result(code, mappings, [VariableInfo(name="value", type="int")])

    report = enrich_final_render_variable_provenance(result)

    variable = result.functions["f"].variables[0]
    assert variable.line_numbers == []
    assert variable.addresses == []
    assert report.variables_enriched == 0


def test_final_render_join_abstains_on_shadowing_and_preserves_existing_evidence() -> None:
    result = _result(
        "int f(int keep) {\n"
        "    int shadow = keep;\n"
        "    { int shadow = 1; keep += shadow; }\n"
        "    return keep + shadow;\n"
        "}\n",
        [
            LineMapping(line_number=1, addresses=[0x1000]),
            LineMapping(line_number=2, addresses=[0x1004]),
            LineMapping(line_number=3, addresses=[0x1008]),
            LineMapping(line_number=4, addresses=[0x100C]),
        ],
        [
            VariableInfo(
                name="keep",
                type="int",
                line_numbers=[1],
                addresses=[0x1000],
            ),
            VariableInfo(name="shadow", type="int"),
        ],
    )

    report = enrich_final_render_variable_provenance(result)

    keep, shadow = result.functions["f"].variables
    assert keep.line_numbers == [1]
    assert keep.addresses == [0x1000]
    assert shadow.line_numbers == []
    assert shadow.addresses == []
    assert report.variables_with_existing_evidence == 1
    assert report.variables_enriched == 0


def test_exact_final_render_abstention_disables_generic_regex_address_fallback() -> None:
    result = _result(
        "int f(void) {\n"
        "    int shadow = 0;\n"
        "    { int shadow = 1; shadow++; }\n"
        "    return shadow;\n"
        "}\n",
        [
            LineMapping(line_number=2, addresses=[0x1004]),
            LineMapping(line_number=3, addresses=[0x1008]),
            LineMapping(line_number=4, addresses=[0x100C]),
        ],
        [VariableInfo(name="shadow", type="int")],
    )

    report = enrich_final_render_variable_provenance(result)
    evidence = extract_decompiler_evidence(result.functions["f"], backend="phoenix")

    assert report.variables_enriched == 0
    assert evidence.variables[0].lines == ()
    assert evidence.variables[0].addresses == frozenset()


@pytest.mark.parametrize(
    ("backend", "enriched"),
    [("phoenix", True), ("phoenix@9.2", True), ("angr", False)],
)
def test_reevaluation_enriches_only_retired_phoenix_copies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    enriched: bool,
) -> None:
    binary = (tmp_path / "bin").resolve()
    original = _result(
        "int f(int value) { return value; }\n",
        [LineMapping(line_number=1, addresses=[0x1000])],
        [VariableInfo(name="value", type="int")],
        backend=backend,
    )
    monkeypatch.setattr(
        reeval_typematch,
        "sanitize_native_provenance",
        lambda *_args, **_kwargs: {"status": "validated"},
    )

    prepared = reeval_typematch._prepare_decompilation(
        original,
        None,
        NativeProvenanceContext(binary),
    )

    variable = prepared.functions["f"].variables[0]
    assert bool(variable.addresses) is enriched
    assert (FINAL_RENDER_PROVENANCE_KEY in prepared.decompiler.extra) is enriched
    assert original.functions["f"].variables[0].addresses == []
