from __future__ import annotations

import json
import pickle
import struct
from pathlib import Path

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)
from decbench.results_store import typematch_overlay_provenance, write_typematch_overlay_atomic
from decbench.scoring.typematch_ab import build_report, json_payload, render_markdown
from scripts.report_typematch_ab import main


def _elf(path: Path, machine: int) -> None:
    payload = bytearray(20)
    payload[:4] = b"\x7fELF"
    payload[18:20] = struct.pack("<H", machine)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _fixture_tree(tmp_path: Path) -> tuple[Path, Path]:
    _elf(tmp_path / "O0/proj/compiled/xbin", 0x3E)
    _elf(tmp_path / "O2/proj/compiled/armbin", 0x28)
    _elf(tmp_path / "O2-noinline/proj/compiled/noinlinebin", 0x3E)
    function_data = tmp_path / "function_results.json"
    function_data.write_text(
        json.dumps(
            {
                "perfect_values": {"type_match": 1.0},
                "groups": [
                    {
                        "project": "proj",
                        "opt_level": "O0",
                        "binary": "xbin",
                        "functions": [
                            {
                                "function": "f1",
                                "values": {"a": {"type_match": 0.25}},
                            },
                            {"function": "not_measurable", "values": {}},
                        ],
                    },
                    {
                        "project": "proj",
                        "opt_level": "O2",
                        "binary": "armbin",
                        "functions": [
                            {
                                "function": "f2",
                                "values": {"b": {"type_match": 0.5}},
                            }
                        ],
                    },
                    {
                        "project": "proj",
                        "opt_level": "O2-noinline",
                        "binary": "noinlinebin",
                        "functions": [
                            {
                                "function": "f3",
                                "values": {"a": {"type_match": 1.0}},
                            }
                        ],
                    },
                ],
            }
        )
    )
    manifest = tmp_path / "sample_set_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "functions": [
                    {"project": "proj", "opt": "O0", "binary": "xbin", "function": "f1"},
                    {
                        "project": "proj",
                        "opt": "O0",
                        "binary": "xbin",
                        "function": "not_measurable",
                    },
                    {
                        "project": "proj",
                        "opt": "O2",
                        "binary": "armbin",
                        "function": "f2",
                    },
                    {
                        "project": "proj",
                        "opt": "O2-noinline",
                        "binary": "noinlinebin",
                        "function": "f3",
                    },
                ]
            }
        )
    )
    return function_data, manifest


def _write_overlay(
    path: Path,
    mode: str,
    *,
    drop_auto_f2: bool = False,
    cache_version: str = "8",
    omit_entry_provenance: bool = False,
) -> None:
    a = {
        "proj::O0::xbin::f1": {
            "value": 0.5 if mode == "address" else 1.0,
            "variable_match_evidence": "native" if mode == "address" else "mixed",
            "producer_variable_occurrence_policy": "exact",
            "structured_occurrence_mode": "producer",
        },
        "proj::O2::armbin::f2": {
            "value": 1.0 if mode == "address" else 0.5,
            "variable_match_evidence": ("native" if mode == "address" else "fallback_only"),
            "producer_variable_occurrence_policy": "unavailable",
            "structured_occurrence_mode": "producer",
        },
        "proj::O2-noinline::noinlinebin::f3": {
            "value": 1.0,
            "variable_match_evidence": "native",
            "producer_variable_occurrence_policy": "direct",
            "structured_occurrence_mode": "producer",
        },
    }
    if drop_auto_f2 and mode == "auto":
        a.pop("proj::O2::armbin::f2")
    if omit_entry_provenance:
        a["proj::O0::xbin::f1"].pop("producer_variable_occurrence_policy")
        a["proj::O0::xbin::f1"].pop("structured_occurrence_mode")
    payload = {
        "a": a,
        "b": {
            "proj::O0::xbin::f1": {
                "value": 1.0,
                "variable_match_evidence": "native",
                "producer_variable_occurrence_policy": "undeclared",
                "structured_occurrence_mode": "producer",
            }
        },
    }
    provenance = typematch_overlay_provenance(
        mode=mode,
        resolved_mode="address+usage" if mode == "auto" else mode,
        policy={"min_overlap": 0.1, "address_weight": 0.5},
        metric_cache_version=cache_version,
        structured_occurrence_mode="producer",
        variable_occurrence_policy_schema="decbench-variable-occurrence-policy-v1",
    )
    write_typematch_overlay_atomic(path, payload, provenance)


def _write_checkpoints(path: Path) -> None:
    mapped = FunctionDecompilation(
        name="f1",
        address=0x1000,
        decompiled_code="int f1(void) { return 1; }",
        line_mappings=[LineMapping(line_number=1, addresses=[0x1000])],
        variables=[
            VariableInfo(
                name="local",
                type="int",
                line_numbers=[1],
                addresses=[0x1000],
            )
        ],
    )
    unmapped = FunctionDecompilation(
        name="f2",
        address=0x2000,
        decompiled_code="int f2(void) { return 2; }",
        variables=[VariableInfo(name="local", type="int")],
    )
    unmapped_noinline = unmapped.model_copy(update={"name": "f3"})

    def result(binary: str, function: FunctionDecompilation) -> DecompilationResult:
        return DecompilationResult(
            binary_path=Path(binary),
            binary_name=binary,
            decompiler=DecompilerMetadata(decompiler_name="a"),
            functions={function.name: function},
        )

    path.mkdir(parents=True)
    with (path / "proj.pkl").open("wb") as stream:
        pickle.dump(
            {
                "decompile": {
                    "O0": {"xbin": {"a": result("xbin", mapped)}},
                    "O2": {"armbin": {"a": result("armbin", unmapped)}},
                    "O2-noinline": {"noinlinebin": {"a": result("noinlinebin", unmapped_noinline)}},
                }
            },
            stream,
        )


def _report(tmp_path: Path, *, drift: bool = False) -> dict[str, object]:
    function_data, manifest = _fixture_tree(tmp_path)
    address = tmp_path / "address.json"
    auto = tmp_path / "auto.json"
    _write_overlay(address, "address")
    _write_overlay(auto, "auto", drop_auto_f2=drift)
    checkpoints = tmp_path / "checkpoints"
    _write_checkpoints(checkpoints)
    return build_report(
        function_data_path=function_data,
        results_root=tmp_path,
        manifest_path=manifest,
        modes=(("address", address), ("auto", auto)),
        baseline_mode="address",
        checkpoint_dir=checkpoints,
    )


def test_report_separates_partial_mean_from_shared_perfect_rate(tmp_path: Path) -> None:
    report = _report(tmp_path)

    assert report["schema"] == "decbench-typematch-ab-report-v2"
    assert report["validation"]["valid_for_apples_to_apples"] is True
    assert report["scope"]["selected_functions"] == 4
    assert report["scope"]["globally_type_measurable_functions"] == 3
    assert report["scope"]["strata"] == {"elf/arm": 1, "elf/x86-64": 2}
    assert report["scope"]["optimization_levels"] == {
        "O0": 1,
        "O2": 1,
        "O2-noinline": 1,
    }

    address_a = report["modes"]["address"]["overall"]["backends"]["a"]
    assert address_a["coverage"] == {
        "measured": 3,
        "missing": 0,
        "shared_denominator": 3,
    }
    assert address_a["conditional_partial"]["mean"] == 2.5 / 3
    assert address_a["published_perfect"] == {
        "count": 2,
        "denominator": 3,
        "rate": 2 / 3,
    }

    address_b = report["modes"]["address"]["overall"]["backends"]["b"]
    assert address_b["conditional_partial"]["mean"] == 1.0
    assert address_b["shared_partial"]["zero_filled_mean"] == 1 / 3
    assert address_b["published_perfect"]["rate"] == 1 / 3

    combined = report["modes"]["address"]["overall"]["all_backends"]
    assert combined["coverage"]["shared_denominator"] == 6
    assert combined["coverage"]["measured"] == 4
    assert combined["conditional_partial"]["mean"] == 3.5 / 4
    assert combined["shared_partial"]["zero_filled_mean"] == 3.5 / 6

    address_o0 = report["modes"]["address"]["optimization_levels"]["O0"]
    assert address_o0["backends"]["a"]["published_perfect"]["rate"] == 0.0
    assert address_o0["backends"]["b"]["published_perfect"]["rate"] == 1.0
    comparison = report["comparisons"]["auto_minus_address"]["optimization_levels"]
    assert comparison["O0"]["backends"]["a"]["published_perfect"] == {
        "baseline_count": 0,
        "candidate_count": 1,
        "gained": 1,
        "lost": 0,
        "baseline_rate": 0.0,
        "candidate_rate": 1.0,
        "delta_percentage_points": 100.0,
    }
    assert (
        comparison["O2"]["backends"]["a"]["published_perfect"]["delta_percentage_points"] == -100.0
    )
    assert (
        comparison["O2-noinline"]["backends"]["a"]["published_perfect"]["delta_percentage_points"]
        == 0.0
    )


def test_report_tracks_regressions_evidence_and_producer_coverage(tmp_path: Path) -> None:
    report = _report(tmp_path)
    comparison = report["comparisons"]["auto_minus_address"]["overall"]["backends"]["a"]

    assert comparison["paired_partial"]["improved"] == 1
    assert comparison["paired_partial"]["regressed"] == 1
    assert comparison["paired_partial"]["unchanged"] == 1
    assert comparison["published_perfect"]["gained"] == 1
    assert comparison["published_perfect"]["lost"] == 1
    assert comparison["evidence_transitions"] == {
        "native->fallback_only": 1,
        "native->mixed": 1,
        "native->native": 1,
    }
    assert comparison["regression_examples"] == [
        {
            "backend": "a",
            "function_key": "proj::O2::armbin::f2",
            "baseline": 1.0,
            "candidate": 0.5,
            "delta": -0.5,
            "evidence_transition": "native->fallback_only",
        }
    ]

    producer = report["producer_evidence"]["overall"]["a"]
    assert producer["functions_found"] == 3
    assert producer["functions_with_line_maps"] == 1
    assert producer["functions_with_variable_addresses"] == 1
    assert (
        report["producer_evidence"]["optimization_levels"]["O0"]["a"][
            "functions_with_variable_addresses"
        ]
        == 1
    )
    assert (
        report["producer_evidence"]["optimization_levels"]["O2"]["a"][
            "functions_with_variable_addresses"
        ]
        == 0
    )
    evidence = report["modes"]["address"]["overall"]["backends"]["a"]["evidence"]
    assert evidence["site_caveated"] == 0
    assert evidence["producer_variable_addresses_missing"] == 2
    assert evidence["potential_undercount"] == 2
    assert evidence["asterisk_recommended"] is True
    assert evidence["producer_occurrence_policies"] == {
        "exact": 1,
        "direct": 1,
        "unavailable": 1,
        "undeclared": 0,
        "unreported": 0,
    }
    assert evidence["structured_occurrence_modes"] == {
        "producer": 3,
        "unreported": 0,
    }


def test_coverage_drift_is_reported_and_fails_cli_by_default(tmp_path: Path) -> None:
    report = _report(tmp_path, drift=True)
    assert report["validation"]["valid_for_apples_to_apples"] is False
    assert report["validation"]["errors"] == ["measured key coverage differs across modes for a"]
    comparison = report["comparisons"]["auto_minus_address"]["overall"]["backends"]["a"]
    assert comparison["coverage"]["baseline_only"] == 1
    assert comparison["coverage_loss_examples"] == [
        {"backend": "a", "function_key": "proj::O2::armbin::f2"}
    ]

    function_data = tmp_path / "function_results.json"
    output = tmp_path / "report.json"
    markdown = tmp_path / "report.md"
    exit_code = main(
        [
            "--function-data",
            str(function_data),
            "--manifest",
            str(tmp_path / "sample_set_manifest.json"),
            "--mode",
            f"address={tmp_path / 'address.json'}",
            "--mode",
            f"auto={tmp_path / 'auto.json'}",
            "--output",
            str(output),
            "--markdown",
            str(markdown),
        ]
    )
    assert exit_code == 1
    assert json.loads(output.read_text())["validation"]["valid_for_apples_to_apples"] is False
    assert "Shared denominator: **3** of 4 selected functions" in markdown.read_text()


def test_v11_report_rejects_missing_entry_occurrence_provenance(tmp_path: Path) -> None:
    function_data, manifest = _fixture_tree(tmp_path)
    overlay = tmp_path / "address-v11.json"
    _write_overlay(
        overlay,
        "address",
        cache_version="11",
        omit_entry_provenance=True,
    )

    report = build_report(
        function_data_path=function_data,
        results_root=tmp_path,
        manifest_path=manifest,
        modes=(("address", overlay),),
        baseline_mode="address",
    )

    assert report["validation"]["valid_for_apples_to_apples"] is False
    assert report["validation"]["errors"] == [
        "v11 mode 'address' has 1 entries without complete producer occurrence provenance"
    ]


def test_markdown_explains_shared_denominator(tmp_path: Path) -> None:
    markdown = render_markdown(_report(tmp_path))
    assert "Conditional partial mean" in markdown
    assert "Perfect / shared" in markdown
    assert "Potential measurement undercount" not in markdown
    assert "`elf/arm`" in markdown
    assert "## Optimization levels" in markdown
    assert "## Producer occurrence policy" in markdown
    assert "| `address` | a | 1 | 1 | 1 | 0 | 0 |" in markdown
    assert "`O0` (1 functions)" in markdown
    assert "`O2` (1 functions)" in markdown
    assert "`O2-noinline` (1 functions)" in markdown
    assert (
        "| a | 0.00% → 100.00% (+100.00 pp) | "
        "100.00% → 0.00% (-100.00 pp) | "
        "100.00% → 100.00% (+0.00 pp) |"
    ) in markdown


def test_report_json_is_deterministic_with_optimization_levels(tmp_path: Path) -> None:
    report = _report(tmp_path)

    first = json_payload(report)
    second = json_payload(report)

    assert first == second
    assert json.loads(first)["scope"]["optimization_levels"] == {
        "O0": 1,
        "O2": 1,
        "O2-noinline": 1,
    }
