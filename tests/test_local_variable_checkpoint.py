from __future__ import annotations

import json
import pickle
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from decbench.experimental.local_variable_checkpoint import (
    CheckpointFunction,
    FunctionKey,
    ScoreConfig,
    SourceLineCache,
    _record_source_observable_count,
    _select_preprocessed_unit,
    deterministic_sample,
    file_sha256,
    score_checkpoint,
    validate_run_provenance,
    write_jsonl,
)
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)
from decbench.models.project import OptimizationLevel


def test_source_line_cache_parses_a_translation_unit_once(tmp_path: Path) -> None:
    source = tmp_path / "unit.c"
    preprocessed = tmp_path / "unit.i"
    source.write_text("int first;\nint second;\n")
    preprocessed.write_text(
        '# 1 "unit.c"\n' "int first;\n" "int second;\n" '# 7 "included.h"\n' "int from_header;\n"
    )
    cache = SourceLineCache()

    first = cache.lines(source, preprocessed)
    second = cache.lines(source, preprocessed)

    assert first is second
    assert first[("unit.c", 2)] == "int second;"
    assert first[("included.h", 7)] == "int from_header;"
    assert cache.marker_basenames(preprocessed) == {"unit.c", "included.h"}
    assert cache.stats() == {
        "requests": 2,
        "hits": 1,
        "misses": 1,
        "source_files": 1,
        "preprocessed_units": 1,
        "merged_maps": 1,
    }


def test_source_line_cache_prefers_preprocessed_function_code(tmp_path: Path) -> None:
    source = tmp_path / "unit.c"
    preprocessed = tmp_path / "unit.i"
    source.write_text("int target(int value) { return MACRO(value); }\n")
    preprocessed.write_text('# 1 "unit.c"\nint target(int value) { return value + 7; }\n')
    cache = SourceLineCache()

    first = cache.function_code(source, preprocessed, "target")
    second = cache.function_code(source, preprocessed, "target")

    assert first == "int target(int value) { return value + 7; }"
    assert second == first


def test_source_line_cache_explicitly_abstains_on_cxx_usage_features(tmp_path: Path) -> None:
    source = tmp_path / "unit.cc"
    preprocessed = tmp_path / "unit.cc.ii"
    source.write_text("int target(int value) { return value; }\n")
    preprocessed.write_text('# 1 "unit.cc"\nint target(int value) { return value; }\n')

    assert SourceLineCache().function_code(source, preprocessed, "target") == ""


def test_stable_hash_sample_is_independent_of_input_order() -> None:
    rows = [
        CheckpointFunction(FunctionKey("O0", "tool", 0x1000 + index, f"fn_{index}"))
        for index in range(20)
    ]
    shuffled = list(rows)
    random.Random(42).shuffle(shuffled)

    baseline = deterministic_sample(rows, size=7, seed="fixed")
    repeated = deterministic_sample(shuffled, size=7, seed="fixed")

    assert [row.key for row in baseline] == [row.key for row in repeated]
    assert len(baseline) == 7


def test_score_config_validates_usage_matcher_parameters() -> None:
    config = ScoreConfig(
        matcher_mode="usage",
        min_usage_similarity=0.2,
        usage_ambiguity_margin=0.05,
    )

    assert config.matcher_mode == "usage"
    for weight in (0.0, 1.0, 1.1):
        with pytest.raises(ValueError, match="address_weight"):
            ScoreConfig(address_weight=weight)


def test_aggregate_source_eligibility_tracks_matcher_mode() -> None:
    record = {
        "source_status": "ok",
        "source_evidence": {
            "variables": [
                {
                    "identity": "address",
                    "addresses": ["0x10"],
                    "usage_features": {},
                },
                {
                    "identity": "usage",
                    "addresses": [],
                    "usage_features": {"call:named:consume:arg:0": 1},
                },
                {
                    "identity": "generic",
                    "addresses": [],
                    "usage_features": {"use:read": 1},
                },
            ]
        },
    }

    assert _record_source_observable_count(record, "address") == 1
    assert _record_source_observable_count(record, "usage") == 1
    assert _record_source_observable_count(record, "address+usage") == 2


def test_cu_path_resolution_rejects_wrong_hash_and_dirname_units(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "cp"
    binary.touch()
    cp_hash = tmp_path / "cp-hash.i"
    dirname = tmp_path / "dirname.i"
    cp_hash.write_text('# 0 "src/cp-hash.c"\nint cp_hash_source;\n')
    dirname.write_text('# 0 "src/dirname.c"\nint dirname_source;\n')
    cache = SourceLineCache()

    with pytest.raises(ValueError, match="CU 'lib/hash.c'"):
        _select_preprocessed_unit("lib/hash.c", binary, [cp_hash, dirname], cache)
    with pytest.raises(ValueError, match="CU 'lib/dirname.c'"):
        _select_preprocessed_unit("lib/dirname.c", binary, [cp_hash, dirname], cache)


def test_cu_path_resolution_uses_lbracket_not_decl_file_test(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "["
    binary.touch()
    lbracket = tmp_path / "lbracket.i"
    test = tmp_path / "test.i"
    lbracket.write_text('# 0 "src/lbracket.c"\n' '# 1 "src/test.c"\n' "int included_test_body;\n")
    test.write_text('# 0 "src/test.c"\nint standalone_test_body;\n')

    selected = _select_preprocessed_unit(
        "src/lbracket.c",
        binary,
        [lbracket, test],
        SourceLineCache(),
    )

    assert selected == lbracket


def _dwarf_low_pc(binary: Path, name: str) -> int:
    from elftools.elf.elffile import ELFFile

    with binary.open("rb") as stream:
        dwarfinfo = ELFFile(stream).get_dwarf_info()
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                raw_name = die.attributes.get("DW_AT_name")
                low_pc = die.attributes.get("DW_AT_low_pc")
                if raw_name is None or low_pc is None:
                    continue
                actual = raw_name.value
                if isinstance(actual, bytes):
                    actual = actual.decode()
                if actual == name:
                    return int(low_pc.value)
    raise AssertionError(f"no DWARF function {name}")


def _decompilation(
    binary: Path,
    decompiler: str,
    functions: list[tuple[str, int]],
) -> DecompilationResult:
    rows = {}
    for index, (name, address) in enumerate(functions):
        raw_argument = f"{decompiler.upper()}_SECRET_ARGUMENT_{index}"
        raw_local = f"{decompiler.upper()}_SECRET_LOCAL_{index}"
        rows[name] = FunctionDecompilation(
            name=name,
            address=address,
            decompiled_code=(
                f"int {name}(int {raw_argument}) {{\n"
                f"    int {raw_local} = {raw_argument} + 1;\n"
                f"    return {raw_local};\n"
                "}"
            ),
            line_count=4,
            line_mappings=[
                LineMapping(line_number=1, addresses=[address]),
                LineMapping(line_number=2, addresses=[address]),
                LineMapping(line_number=3, addresses=[address]),
            ],
            variables=[
                VariableInfo(
                    name=raw_argument,
                    type="int",
                    size=4,
                    kind="arg",
                    arg_index=0,
                    line_numbers=[1, 2],
                    addresses=[address],
                ),
                VariableInfo(
                    name=raw_local,
                    type="int",
                    size=4,
                    kind="stack",
                    line_numbers=[2, 3],
                    addresses=[address],
                ),
            ],
        )
    return DecompilationResult(
        binary_path=binary,
        binary_name=binary.name,
        decompiler=DecompilerMetadata(decompiler_name=decompiler),
        functions=rows,
    )


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is required")
def test_checkpoint_scorer_resolves_blinds_caches_and_stays_unlabeled(
    tmp_path: Path,
) -> None:
    root = tmp_path / "results"
    compiled = root / "O0" / "coreutils" / "compiled"
    stripped = root / "O0" / "coreutils" / "stripped"
    checkpoints = root / "checkpoints"
    compiled.mkdir(parents=True)
    stripped.mkdir(parents=True)
    checkpoints.mkdir()
    source = compiled / "unit.c"
    preprocessed = compiled / "unit.i"
    binary = compiled / "tool"
    source.write_text(
        "int target_alpha(int SOURCE_SECRET_ARGUMENT_ALPHA) {\n"
        "    int SOURCE_SECRET_LOCAL_ALPHA = SOURCE_SECRET_ARGUMENT_ALPHA + 1;\n"
        "    return SOURCE_SECRET_LOCAL_ALPHA;\n"
        "}\n"
        "int target_beta(int SOURCE_SECRET_ARGUMENT_BETA) {\n"
        "    int SOURCE_SECRET_LOCAL_BETA = SOURCE_SECRET_ARGUMENT_BETA + 2;\n"
        "    return SOURCE_SECRET_LOCAL_BETA;\n"
        "}\n"
        "int main(int SOURCE_SECRET_MAIN_ARG, char **SOURCE_SECRET_MAIN_ARGV) {\n"
        "    int SOURCE_SECRET_MAIN_LOCAL = SOURCE_SECRET_MAIN_ARG;\n"
        "    return target_alpha(1) + target_beta(2) + SOURCE_SECRET_MAIN_LOCAL\n"
        "           + (SOURCE_SECRET_MAIN_ARGV != 0);\n"
        "}\n"
    )
    subprocess.run(
        ["gcc", "-E", str(source), "-o", str(preprocessed)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["gcc", "-g", "-O0", "-fno-pie", "-no-pie", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    shutil.copy2(binary, stripped / binary.name)
    subprocess.run(
        ["strip", "--strip-all", str(stripped / binary.name)],
        check=True,
        capture_output=True,
    )
    functions = [(name, _dwarf_low_pc(binary, name)) for name in ("target_alpha", "target_beta")]
    ida = _decompilation(binary, "ida", functions)
    ghidra = _decompilation(binary, "ghidra", functions)
    checkpoint = checkpoints / "coreutils.pkl"
    checkpoint.write_bytes(
        pickle.dumps(
            {
                "decompile": {OptimizationLevel.O0: {binary.name: {"ida": ida, "ghidra": ghidra}}},
                "evaluate": {},
            }
        )
    )

    records, report, labels = score_checkpoint(
        checkpoint,
        root,
        ScoreConfig(sample_size=0, bootstrap_iterations=20),
    )

    assert len(records) == 3
    assert len(labels) == 4
    assert report["source_line_cache"]["requests"] == 3
    assert report["source_line_cache"]["hits"] == 2
    assert report["source_line_cache"]["preprocessed_units"] == 1
    assert report["sampling"]["selected_size"] == 3
    assert report["source_universe"]["functions_resolved"] == 3
    assert report["source_universe"]["checkpoint_union_functions"] == 2
    assert report["source_universe"]["missing_both_backends"] == 1
    assert [row["name"] for row in report["sampling"]["missing_both_functions"]] == ["main"]
    provenance = report["provenance"]
    assert provenance["checkpoint_sha256"] == file_sha256(checkpoint)
    assert provenance["strict_universe"]["member_count"] == 3
    assert (
        provenance["strict_universe"]["sha256"]
        == report["source_universe"]["strict_universe_digest"]["sha256"]
    )
    assert all(
        record["run_binding_sha256"] == provenance["run_binding_sha256"] for record in records
    )
    scorer_path = tmp_path / "scorer.jsonl"
    write_jsonl(scorer_path, records)
    assert file_sha256(scorer_path) == provenance["scorer_jsonl_sha256"]
    assert validate_run_provenance(report, checkpoint, records) == {
        "checkpoint_sha256": provenance["checkpoint_sha256"],
        "scorer_jsonl_sha256": provenance["scorer_jsonl_sha256"],
        "run_binding_sha256": provenance["run_binding_sha256"],
    }
    stale_checkpoint = tmp_path / "stale.pkl"
    stale_checkpoint.write_bytes(checkpoint.read_bytes() + b"stale")
    with pytest.raises(ValueError, match="checkpoint SHA-256 mismatch"):
        validate_run_provenance(report, stale_checkpoint, records)
    tampered_records = json.loads(json.dumps(records))
    tampered_records[0]["run_binding_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="row run-binding mismatch"):
        validate_run_provenance(report, checkpoint, tampered_records)
    serialized = json.dumps(records)
    assert "SOURCE_SECRET_" not in serialized
    assert "IDA_SECRET_" not in serialized
    assert "GHIDRA_SECRET_" not in serialized
    assert all(record["blinding"]["variable_names_blinded"] for record in records)
    assert all(record["source_status"] == "ok" for record in records)
    for record in records:
        assert record["artifacts"]["resolution_policy"].startswith("address-pinned")
        assert record["source_controls"]["cu_primary_matches_preprocessed_marker"]["passed"]
        if record["function"]["name"] == "main":
            assert {
                decompiler: entry["status"] for decompiler, entry in record["decompilers"].items()
            } == {"ghidra": "missing", "ida": "missing"}
            continue
        for entry in record["decompilers"].values():
            assert entry["status"] == "ok"
            assert entry["matching"]["accepted_count"] >= 1
            assert entry["controls"]["rename_invariance"]["passed"] is True
            assert entry["controls"]["disjoint_address_overlap_zero"]["passed"] is True
            assert entry["controls"]["fake_local_increases_distance_by_one"]["passed"] is True
            assert entry["controls"]["addresses_are_instructions"]["passed"] is True
            assert entry["controls"]["stripped_input_metadata_absent"]["passed"] is True
            assert entry["controls"]["repeated_pair_set_identical"]["passed"] is True
            assert all(
                variable["name"].startswith("decompiled_")
                for variable in entry["evidence"]["variables"]
            )
    for row in report["rows"]:
        assert row["oracle_accuracy"]["status"] == "unlabeled"
        assert row["oracle_accuracy"]["precision_decidable_accepted"] is None
        assert row["oracle_accuracy"]["recall_oracle_matchable_source"] is None
        if row["partition"] == "all":
            assert row["functions_sampled"] == 3
            assert row["function_statuses"] == {"missing": 1, "ok": 2}
            assert (
                row["micro"]["source_observable"]
                > row["success_conditioned_micro"]["source_observable"]
            )
            assert (
                row["micro"]["matcher_coverage"]
                < row["success_conditioned_micro"]["matcher_coverage"]
            )
