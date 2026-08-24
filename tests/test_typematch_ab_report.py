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
from decbench.scoring.typematch_ab import build_report, render_markdown
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
) -> None:
    a = {
        "proj::O0::xbin::f1": {
            "value": 0.5 if mode == "address" else 1.0,
            "variable_match_evidence": "native" if mode == "address" else "mixed",
        },
        "proj::O2::armbin::f2": {
            "value": 1.0 if mode == "address" else 0.5,
            "variable_match_evidence": ("native" if mode == "address" else "fallback_only"),
        },
    }
    if drop_auto_f2 and mode == "auto":
        a.pop("proj::O2::armbin::f2")
    payload = {
        "a": a,
        "b": {
            "proj::O0::xbin::f1": {
                "value": 1.0,
                "variable_match_evidence": "native",
            }
        },
    }
    provenance = typematch_overlay_provenance(
        mode=mode,
        resolved_mode="address+usage" if mode == "auto" else mode,
        policy={"min_overlap": 0.1, "address_weight": 0.5},
        metric_cache_version="8",
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

    assert report["validation"]["valid_for_apples_to_apples"] is True
    assert report["scope"]["selected_functions"] == 3
    assert report["scope"]["globally_type_measurable_functions"] == 2
    assert report["scope"]["strata"] == {"elf/arm": 1, "elf/x86-64": 1}

    address_a = report["modes"]["address"]["overall"]["backends"]["a"]
    assert address_a["coverage"] == {
        "measured": 2,
        "missing": 0,
        "shared_denominator": 2,
    }
    assert address_a["conditional_partial"]["mean"] == 0.75
    assert address_a["published_perfect"] == {
        "count": 1,
        "denominator": 2,
        "rate": 0.5,
    }

    address_b = report["modes"]["address"]["overall"]["backends"]["b"]
    assert address_b["conditional_partial"]["mean"] == 1.0
    assert address_b["shared_partial"]["zero_filled_mean"] == 0.5
    assert address_b["published_perfect"]["rate"] == 0.5

    combined = report["modes"]["address"]["overall"]["all_backends"]
    assert combined["coverage"]["shared_denominator"] == 4
    assert combined["coverage"]["measured"] == 3
    assert combined["conditional_partial"]["mean"] == 2.5 / 3
    assert combined["shared_partial"]["zero_filled_mean"] == 2.5 / 4


def test_report_tracks_regressions_evidence_and_producer_coverage(tmp_path: Path) -> None:
    report = _report(tmp_path)
    comparison = report["comparisons"]["auto_minus_address"]["overall"]["backends"]["a"]

    assert comparison["paired_partial"]["improved"] == 1
    assert comparison["paired_partial"]["regressed"] == 1
    assert comparison["published_perfect"]["gained"] == 1
    assert comparison["published_perfect"]["lost"] == 1
    assert comparison["evidence_transitions"] == {
        "native->fallback_only": 1,
        "native->mixed": 1,
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
    assert producer["functions_found"] == 2
    assert producer["functions_with_line_maps"] == 1
    assert producer["functions_with_variable_addresses"] == 1
    evidence = report["modes"]["address"]["overall"]["backends"]["a"]["evidence"]
    assert evidence["site_caveated"] == 0
    assert evidence["producer_variable_addresses_missing"] == 1
    assert evidence["potential_undercount"] == 1
    assert evidence["asterisk_recommended"] is True


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
    assert "Shared denominator: **2** of 3 selected functions" in markdown.read_text()


def test_markdown_explains_shared_denominator(tmp_path: Path) -> None:
    markdown = render_markdown(_report(tmp_path))
    assert "Conditional partial mean" in markdown
    assert "Perfect / shared" in markdown
    assert "Potential measurement undercount" not in markdown
    assert "`elf/arm`" in markdown
