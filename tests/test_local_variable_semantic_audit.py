from __future__ import annotations

import json
import pickle
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from decbench.caching import stable_hash
from decbench.experimental.local_variable_checkpoint import (
    ScoreConfig,
    score_checkpoint,
    score_config_payload,
)
from decbench.experimental.local_variable_checkpoint import (
    write_json as write_scorer_json,
)
from decbench.experimental.local_variable_checkpoint import (
    write_jsonl as write_scorer_jsonl,
)
from decbench.experimental.local_variable_semantic_audit import (
    ALIAS_SECRET_FILENAME,
    CASE_FILENAME,
    EVIDENCE_FILENAME,
    FROZEN_BIN_VERSION,
    FROZEN_MINIMUM_GAP_BOUNDS,
    FROZEN_SCORE_BOUNDS,
    LABEL_FILENAME,
    PRIVATE_JOIN_FILENAME,
    SHARD_DIRNAME,
    CheckpointEntry,
    CheckpointIndex,
    DecompiledAuditEvidence,
    _alias_for_identity_group,
    _replace_c_local_identifiers,
    _require_same_non_name_evidence,
    _validate_evidence_case_coverage,
    _validate_score_config_provenance,
    _validate_scorer_backend,
    apply_reviewer_decisions,
    build_audit_package,
    evidence_sha256,
    join_audit_package,
    join_audit_rows,
    make_audit_report,
    merge_reviewer_labels,
    read_jsonl,
    validate_audit_package,
    validate_labels,
    validate_public_evidence,
)
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)
from decbench.models.project import OptimizationLevel


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


def test_evidence_reconstruction_versions_usage_feature_fields() -> None:
    legacy = {
        "code": "",
        "variables": [{"identity": "source:0", "name": "opaque"}],
    }
    reconstructed = {
        "code": "int f(void) { return 0; }",
        "variables": [
            {
                "identity": "source:0",
                "name": "original",
                "usage_features": {"control:return:value": 1},
                "inferred_from_code": False,
            }
        ],
    }

    _require_same_non_name_evidence(
        legacy,
        reconstructed,
        "legacy scorer",
        include_usage_features=False,
    )
    with pytest.raises(ValueError, match="evidence differs"):
        _require_same_non_name_evidence(
            legacy,
            reconstructed,
            "v2 scorer",
            include_usage_features=True,
        )
    _require_same_non_name_evidence(
        reconstructed,
        reconstructed,
        "v2 scorer",
        include_usage_features=True,
    )


def test_score_config_provenance_versions_are_exact_and_backward_compatible() -> None:
    current = score_config_payload(ScoreConfig())
    assert current["version"] == "lved-score-config-v3"
    assert current["production_type_match_policy"] is False
    _validate_score_config_provenance(current)

    legacy_v2 = dict(current)
    legacy_v2["version"] = "lved-score-config-v2"
    legacy_v2.pop("production_type_match_policy")
    _validate_score_config_provenance(legacy_v2)

    legacy_v1 = {
        key: value
        for key, value in legacy_v2.items()
        if key
        not in {
            "matcher_mode",
            "min_usage_similarity",
            "usage_ambiguity_margin",
            "min_combined_similarity",
            "address_weight",
        }
    }
    legacy_v1["version"] = "lved-score-config-v1"
    _validate_score_config_provenance(legacy_v1)

    with pytest.raises(ValueError, match="extra=.*production_type_match_policy"):
        _validate_score_config_provenance({**legacy_v2, "production_type_match_policy": False})
    with pytest.raises(ValueError, match="must be boolean"):
        _validate_score_config_provenance({**current, "production_type_match_policy": "false"})


def _decompilation(
    binary: Path,
    backend: str,
    functions: list[tuple[str, int]],
) -> DecompilationResult:
    rows = {}
    for index, (name, address) in enumerate(functions):
        raw_argument = f"{backend.upper()}_SECRET_ARGUMENT_{index}"
        raw_local = f"{backend.upper()}_SECRET_LOCAL_{index}"
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
        decompiler=DecompilerMetadata(
            decompiler_name=backend,
            decompiler_version=f"{backend}-test-version",
        ),
        functions=rows,
    )


@pytest.fixture
def built_package(tmp_path: Path) -> dict[str, Any]:
    if shutil.which("gcc") is None:
        pytest.skip("gcc is required")
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
        "int target_alpha(int source_alpha) {\n"
        "    int local_alpha = source_alpha + 1;\n"
        "    return local_alpha;\n"
        "}\n"
        "int target_beta(int source_beta) {\n"
        "    int local_beta = source_beta + 2;\n"
        "    return local_beta;\n"
        "}\n"
        "int main(void) { return target_alpha(1) + target_beta(2); }\n"
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
    records, report, _labels = score_checkpoint(
        checkpoint,
        root,
        ScoreConfig(sample_size=0, bootstrap_iterations=0),
    )
    scorer = root / "local_variable_distance_sample.jsonl"
    aggregate = root / "local_variable_distance_aggregate.json"
    write_scorer_jsonl(scorer, records)
    write_scorer_json(aggregate, report)
    package = root / "semantic_audit"
    manifest = build_audit_package(
        scorer,
        checkpoint,
        package,
        sample_manifest_path=aggregate,
        audit_seed="fixed-audit-test-seed",
        shard_count=2,
    )
    return {
        "root": root,
        "package": package,
        "checkpoint": checkpoint,
        "scorer": scorer,
        "aggregate": aggregate,
        "manifest": manifest,
    }


def test_aliases_use_hidden_identities_and_token_aware_replacement() -> None:
    owner_secret = bytes.fromhex("11" * 32)
    first = _alias_for_identity_group(
        alias_secret=owner_secret,
        audit_sample_id="as_example",
        backend_id="ida",
        identities=("ida:3",),
    )
    second = _alias_for_identity_group(
        alias_secret=owner_secret,
        audit_sample_id="as_example",
        backend_id="ida",
        identities=("ida:3",),
    )
    assert first == second
    assert first != _alias_for_identity_group(
        alias_secret=bytes.fromhex("22" * 32),
        audit_sample_id="as_example",
        backend_id="ida",
        identities=("ida:3",),
    )
    # The alias is invariant to any raw-name dictionary because raw names are
    # not an input at all.
    assert "raw_local" not in first
    old_dictionary_guesses = {
        "dv_"
        + stable_hash(
            "local-variable-semantic-audit-alias-v1",
            "public-seed",
            "as_example",
            "ida",
            candidate,
        )[:12]
        for candidate in ("a1", "param_1", "raw_local", "v6", "local_10")
    }
    assert first not in old_dictionary_guesses
    # Public context plus the enumerable backend IDs no longer suffices: an
    # attacker would also have to guess the independent 256-bit package key.
    attacker_guesses = {
        _alias_for_identity_group(
            alias_secret=bytes([candidate]) * 32,
            audit_sample_id="as_example",
            backend_id="ida",
            identities=(f"ida:{index}",),
        )
        for candidate in range(4)
        for index in range(32)
    }
    assert first not in attacker_guesses

    code = (
        "int raw_local = 1;\n"
        'puts("raw_local"); // raw_local in a comment\n'
        "object.raw_local = raw_local;\n"
        "ptr->raw_local += raw_local;\n"
    )
    replaced = _replace_c_local_identifiers(
        code,
        {"raw_local": "dv_hidden"},
    )
    assert "int dv_hidden = 1;" in replaced
    assert "int raw_local =" not in replaced
    assert '"raw_local"' in replaced
    assert "// raw_local in a comment" in replaced
    assert "object.raw_local = dv_hidden;" in replaced
    assert "ptr->raw_local += dv_hidden;" in replaced


def test_build_deduplicates_binds_and_validates_manifest(
    built_package: dict[str, Any],
) -> None:
    package = built_package["package"]
    evidence = read_jsonl(package / EVIDENCE_FILENAME)
    cases = read_jsonl(package / CASE_FILENAME)
    private = read_jsonl(package / PRIVATE_JOIN_FILENAME)
    validation = validate_audit_package(package)

    assert len(evidence) < len(cases)
    assert len(private) == len(cases)
    assert validation["evidence_count"] == len(evidence)
    assert validation["case_count"] == len(cases)
    assert validation["complete"] is False
    assert stat.S_IMODE((package / PRIVATE_JOIN_FILENAME).stat().st_mode) == 0o600
    secret_path = package / ALIAS_SECRET_FILENAME
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
    secret_payload = json.loads(secret_path.read_text())
    manifest_serialized = json.dumps(built_package["manifest"])
    assert secret_payload["secret_hex"] not in manifest_serialized
    assert "secret_hex" not in manifest_serialized
    assert (
        secret_payload["commitment_sha256"]
        == built_package["manifest"]["alias_secret_commitment_sha256"]
    )
    assert all("source_function_code" not in case for case in cases)
    assert all("decompiled" not in case for case in cases)
    assert all(row["kind"].endswith("evidence") for row in evidence)
    serialized = json.dumps(evidence)
    assert "IDA_SECRET_" not in serialized
    assert "GHIDRA_SECRET_" not in serialized

    by_evidence: dict[str, set[str]] = {}
    for case in cases:
        by_evidence.setdefault(case["evidence_id"], set()).add(case["shard_id"])
    assert all(len(shards) == 1 for shards in by_evidence.values())

    leaked = dict(evidence[0])
    leaked["proposed_relation"] = {"looks_right": True}
    with pytest.raises(ValueError, match="schema fields differ"):
        validate_public_evidence(leaked)
    labels = read_jsonl(package / LABEL_FILENAME)
    extra_label = [dict(row) for row in labels]
    extra_label[0]["matcher_guess"] = "hidden"
    with pytest.raises(ValueError, match="schema fields differ"):
        validate_labels(
            extra_label,
            cases,
            evidence,
            require_complete=False,
        )

    original = (package / PRIVATE_JOIN_FILENAME).read_bytes()
    with (package / PRIVATE_JOIN_FILENAME).open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ValueError, match="file digest mismatch"):
        validate_audit_package(package)
    (package / PRIVATE_JOIN_FILENAME).write_bytes(original)
    assert validate_audit_package(package)["case_count"] == len(cases)

    secret_original = secret_path.read_bytes()
    secret_path.chmod(0o644)
    with pytest.raises(ValueError, match="mode 0600"):
        validate_audit_package(package)
    secret_path.chmod(0o600)
    tampered = json.loads(secret_original)
    tampered["secret_hex"] = "ff" * 32
    secret_path.write_text(json.dumps(tampered))
    secret_path.chmod(0o600)
    with pytest.raises(ValueError, match="commitment mismatch"):
        validate_audit_package(package)
    secret_path.write_bytes(secret_original)
    secret_path.chmod(0o600)
    assert validate_audit_package(package)["case_count"] == len(cases)

    external_secret = package.parent / "saved-alias-secret.json"
    external_secret.write_bytes(secret_original)
    secret_path.unlink()
    secret_path.symlink_to(external_secret)
    with pytest.raises(ValueError, match="regular non-symlink"):
        validate_audit_package(package)
    secret_path.unlink()
    secret_path.write_bytes(secret_original)
    secret_path.chmod(0o600)


def test_missing_secret_never_rotates_existing_package(
    built_package: dict[str, Any],
) -> None:
    package = built_package["package"]
    secret_path = package / ALIAS_SECRET_FILENAME
    original = secret_path.read_bytes()
    secret_path.unlink()
    with pytest.raises(ValueError, match="refusing silent key rotation"):
        build_audit_package(
            built_package["scorer"],
            built_package["checkpoint"],
            package,
            sample_manifest_path=built_package["aggregate"],
        )
    secret_path.write_bytes(original)
    secret_path.chmod(0o600)


def test_provenance_exact_lookup_and_fail_closed_ids(
    built_package: dict[str, Any],
    tmp_path: Path,
) -> None:
    stale = tmp_path / "stale.pkl"
    stale.write_bytes(built_package["checkpoint"].read_bytes() + b"stale")
    with pytest.raises(ValueError, match="checkpoint SHA-256 mismatch"):
        build_audit_package(
            built_package["scorer"],
            stale,
            tmp_path / "stale-output",
            sample_manifest_path=built_package["aggregate"],
        )

    index = CheckpointIndex(built_package["checkpoint"])
    private = read_jsonl(built_package["package"] / PRIVATE_JOIN_FILENAME)
    row = private[0]
    function = row["function"]
    assert (
        index.find_exact(
            optimization=function["optimization"],
            binary=function["binary"],
            address=int(function["address"], 0),
            name=function["name"],
            backend_id=row["backend_id"] + "@wrong-version",
        )
        is None
    )

    result = DecompilationResult(
        binary_path=Path("tool"),
        binary_name="tool",
        decompiler=DecompilerMetadata(decompiler_name="ida"),
        functions={},
    )
    function_model = FunctionDecompilation(
        name="fn",
        address=0x1000,
        decompiled_code="int fn(void) { return 0; }",
    )
    checkpoint_entry = CheckpointEntry(
        optimization="O2",
        binary="tool",
        backend_id="ida",
        function=function_model,
        result=result,
    )
    decompiled = DecompiledAuditEvidence(
        public={},
        alias_to_ids={"dv_one": ("ida:0",)},
        id_to_alias={"ida:0": "dv_one"},
        structured_evidence={"variables": [{"identity": "ida:0"}]},
    )
    scorer_entry = {
        "status": "ok",
        "evidence": {"variables": [{"identity": "ida:0"}]},
        "address_filter": {
            "policy": "decoded instruction starts in the DWARF function range",
            "boundary_merge_status": "none",
            "dropped_count": 0,
            "dropped_addresses": [],
        },
        "matching": {
            "decompiled_count": 1,
            "source_observable_count": 1,
            "accepted_count": 1,
            "accepted_matches": [{"source_id": "dwarf:0x1", "decompiled_id": "ida:99"}],
        },
    }
    with pytest.raises(ValueError, match="no exact checkpoint alias"):
        _validate_scorer_backend(
            sample_id="sample",
            backend_id="ida",
            scorer_entry=scorer_entry,
            checkpoint_entry=checkpoint_entry,
            observable_source_ids={"dwarf:0x1"},
            decompiled=decompiled,
        )
    unknown_source = json.loads(json.dumps(scorer_entry))
    unknown_source["matching"]["accepted_matches"][0] = {
        "source_id": "dwarf:0x999",
        "decompiled_id": "ida:0",
    }
    with pytest.raises(ValueError, match="has no observable case"):
        _validate_scorer_backend(
            sample_id="sample",
            backend_id="ida",
            scorer_entry=unknown_source,
            checkpoint_entry=checkpoint_entry,
            observable_source_ids={"dwarf:0x1"},
            decompiled=decompiled,
        )
    with pytest.raises(ValueError, match="says missing"):
        _validate_scorer_backend(
            sample_id="sample",
            backend_id="ida",
            scorer_entry={"status": "missing"},
            checkpoint_entry=checkpoint_entry,
            observable_source_ids={"dwarf:0x1"},
            decompiled=decompiled,
        )
    assert (
        _validate_scorer_backend(
            sample_id="sample",
            backend_id="ida",
            scorer_entry={"status": "missing"},
            checkpoint_entry=None,
            observable_source_ids={"dwarf:0x1"},
            decompiled=None,
        )
        == []
    )

    structurally_stale = json.loads(json.dumps(scorer_entry))
    structurally_stale["matching"]["accepted_matches"][0]["decompiled_id"] = "ida:0"
    structurally_stale["evidence"]["variables"][0]["size"] = 8
    with pytest.raises(ValueError, match="evidence differs"):
        _validate_scorer_backend(
            sample_id="sample",
            backend_id="ida",
            scorer_entry=structurally_stale,
            checkpoint_entry=checkpoint_entry,
            observable_source_ids={"dwarf:0x1"},
            decompiled=decompiled,
        )
    filter_stale = json.loads(json.dumps(scorer_entry))
    filter_stale["matching"]["accepted_matches"][0]["decompiled_id"] = "ida:0"
    filter_stale["address_filter"]["dropped_count"] = 1
    filter_stale["address_filter"]["dropped_addresses"] = ["0x1000"]
    filter_stale["address_filter"][
        "boundary_merge_status"
    ] = "out_of_range_or_noninstruction_evidence_filtered"
    with pytest.raises(ValueError, match="instruction-filter evidence differs"):
        _validate_scorer_backend(
            sample_id="sample",
            backend_id="ida",
            scorer_entry=filter_stale,
            checkpoint_entry=checkpoint_entry,
            observable_source_ids={"dwarf:0x1"},
            decompiled=decompiled,
        )


def test_evidence_case_coverage_rejects_duplicates_and_missing() -> None:
    evidence = {
        "ev": {
            "source_variables": [
                {"audit_id": "sv_one"},
                {"audit_id": "sv_two"},
            ]
        }
    }
    complete = {
        "ev": [
            {"source_variable_audit_id": "sv_one"},
            {"source_variable_audit_id": "sv_two"},
        ]
    }
    _validate_evidence_case_coverage(evidence, complete)
    with pytest.raises(ValueError, match="exactly cover"):
        _validate_evidence_case_coverage(
            evidence,
            {
                "ev": [
                    {"source_variable_audit_id": "sv_one"},
                    {"source_variable_audit_id": "sv_one"},
                ]
            },
        )
    with pytest.raises(ValueError, match="exactly cover"):
        _validate_evidence_case_coverage(
            evidence,
            {"ev": [{"source_variable_audit_id": "sv_one"}]},
        )


def _decision_rows(shard: dict[str, Any]) -> list[dict[str, Any]]:
    evidence_by_id = {evidence["evidence_id"]: evidence for evidence in shard["evidence"]}
    rows = []
    for case in shard["cases"]:
        variables = evidence_by_id[case["evidence_id"]]["decompiled"]["variables"]
        if variables:
            status = "mapped"
            selected = [variables[0]["audit_id"]]
            rationale = "The selected pseudocode variable carries this source value."
        else:
            status = "none_recovered"
            selected = []
            rationale = "The backend produced no pseudocode variable for this case."
        rows.append(
            {
                "schema_version": 2,
                "case_id": case["case_id"],
                "oracle_status": status,
                "selected_decompiled_audit_ids": selected,
                "confidence": "high",
                "rationale": rationale,
            }
        )
    return rows


def test_public_apply_merge_conflict_stale_and_completed_schema(
    built_package: dict[str, Any],
    tmp_path: Path,
) -> None:
    package = built_package["package"]
    shard_paths = sorted((package / SHARD_DIRNAME).glob("shard_*.json"))
    assert len(shard_paths) == 2
    completed = []
    for index, shard_path in enumerate(shard_paths):
        shard = json.loads(shard_path.read_text())
        decisions = tmp_path / f"decisions-{index}.jsonl"
        decisions.write_text("".join(json.dumps(row) + "\n" for row in _decision_rows(shard)))
        output = tmp_path / f"completed-{index}.json"
        apply_reviewer_decisions(
            shard_path,
            decisions,
            output,
            reviewer=f"reviewer-{index}",
        )
        completed.append(output)
        if index == 0:
            with pytest.raises(ValueError):
                apply_reviewer_decisions(
                    package / PRIVATE_JOIN_FILENAME,
                    decisions,
                    tmp_path / "must-not-complete-private.json",
                    reviewer="reviewer-0",
                )

    with pytest.raises(ValueError, match="duplicate/conflicting shard"):
        merge_reviewer_labels(package, [completed[0], completed[0]])
    with pytest.raises(ValueError, match="coverage incomplete"):
        merge_reviewer_labels(package, [completed[0]])
    with pytest.raises(ValueError, match="explicit noncanonical output"):
        merge_reviewer_labels(
            package,
            [completed[0]],
            allow_partial=True,
        )
    partial = tmp_path / "partial-labels.jsonl"
    partial_provenance = merge_reviewer_labels(
        package,
        [completed[0]],
        output_path=partial,
        allow_partial=True,
    )
    assert partial_provenance["complete"] is False
    assert partial.is_file()
    assert validate_audit_package(package)["label_count"] == len(
        read_jsonl(package / CASE_FILENAME)
    )

    stale = json.loads(completed[0].read_text())
    stale["evidence"][0]["source_function_code"] += "\n/* stale */"
    stale_path = tmp_path / "stale-completed.json"
    stale_path.write_text(json.dumps(stale))
    with pytest.raises(ValueError, match="stale reviewer evidence"):
        merge_reviewer_labels(package, [stale_path, completed[1]])

    provenance = merge_reviewer_labels(package, completed)
    assert provenance["complete"] is True
    assert validate_audit_package(package, require_complete=True)["complete"] is True
    report = join_audit_package(package, bootstrap_iterations=5)
    assert (
        report["summary"]["matcher_conditional_on_backend_ok"]["accepted_edges"]["accepted_count"]
        > 0
    )

    labels = read_jsonl(package / LABEL_FILENAME)
    broken = [dict(row) for row in labels]
    broken[0]["rationale"] = ""
    with pytest.raises(ValueError, match="needs rationale"):
        validate_labels(
            broken,
            read_jsonl(package / CASE_FILENAME),
            read_jsonl(package / EVIDENCE_FILENAME),
            require_complete=True,
        )
    unknown = [dict(row) for row in labels]
    unknown[0]["oracle_status"] = "oracle_unknown"
    unknown[0]["selected_decompiled_audit_ids"] = []
    unknown[0]["rationale"] = "unclear"
    with pytest.raises(ValueError, match="meaningful rationale"):
        validate_labels(
            unknown,
            read_jsonl(package / CASE_FILENAME),
            read_jsonl(package / EVIDENCE_FILENAME),
            require_complete=True,
        )

    # Safe rebuilds preserve the owner's completed canonical labels but never
    # seed a fresh reviewer shard with prior oracle decisions.
    build_audit_package(
        built_package["scorer"],
        built_package["checkpoint"],
        package,
        sample_manifest_path=built_package["aggregate"],
        audit_seed="fixed-audit-test-seed",
        shard_count=2,
    )
    for shard_path in sorted((package / SHARD_DIRNAME).glob("shard_*.json")):
        shard = json.loads(shard_path.read_text())
        assert all(label["oracle_status"] is None for label in shard["labels"])


def _public_relation_fixture() -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    evidence_payload = {
        "schema_version": 2,
        "kind": "local-variable-semantic-audit-evidence",
        "evidence_id": "ev_relation",
        "audit_sample_id": "as_relation",
        "backend_id": "ida",
        "function": {
            "project": "coreutils",
            "optimization": "O2",
            "binary": "tool",
            "name": "fn",
        },
        "source_function_code": "int fn(void) { return 0; }",
        "source_variables": [
            {
                "audit_id": "sv_one",
                "name": "one",
                "role": "local",
                "size_bytes": 4,
                "type_candidates": ["int"],
                "declaration": {"file": "unit.c", "line": 1},
                "contexts": [],
            },
            {
                "audit_id": "sv_two",
                "name": "two",
                "role": "local",
                "size_bytes": 4,
                "type_candidates": ["int"],
                "declaration": {"file": "unit.c", "line": 1},
                "contexts": [],
            },
        ],
        "decompiled": {
            "backend_id": "ida",
            "status": "ok",
            "version": "test",
            "code": "",
            "variables": [
                {
                    "audit_id": alias,
                    "roles": ["local"],
                    "type_candidates": ["int"],
                    "sizes_bytes": [4],
                    "use_lines": [],
                    "contexts": [],
                    "alias_group_size": 1,
                    "ambiguous_alias": False,
                }
                for alias in ("d1", "d2")
            ],
        },
        "review_question": "Map every source variable.",
    }
    evidence = {
        **evidence_payload,
        "evidence_sha256": evidence_sha256(evidence_payload),
    }
    cases = []
    private = []
    labels = []
    selections = {"sv_one": ["d1", "d2"], "sv_two": ["d1"]}
    for source_audit_id in ("sv_one", "sv_two"):
        case_id = f"case_{source_audit_id}"
        case_payload = {
            "schema_version": 2,
            "kind": "local-variable-semantic-audit-case",
            "case_id": case_id,
            "evidence_id": "ev_relation",
            "evidence_sha256": evidence["evidence_sha256"],
            "audit_sample_id": "as_relation",
            "backend_id": "ida",
            "source_variable_audit_id": source_audit_id,
            "shard_id": "shard_000",
        }
        case = {**case_payload, "case_sha256": evidence_sha256(case_payload)}
        cases.append(case)
        private.append(
            {
                "schema_version": 2,
                "kind": "local-variable-semantic-audit-private-join",
                "case_id": case_id,
                "case_sha256": case["case_sha256"],
                "evidence_id": "ev_relation",
                "evidence_sha256": evidence["evidence_sha256"],
                "shard_id": "shard_000",
                "sample_id": "private",
                "audit_sample_id": "as_relation",
                "partition": "held_out",
                "function": {**evidence["function"], "address": "0x1000"},
                "backend_id": "ida",
                "backend_version": "test",
                "backend_status": "ok",
                "source_id": f"dwarf:{source_audit_id}",
                "source_audit_id": source_audit_id,
                "decompiled_audit_map": {"d1": ["ida:0"], "d2": ["ida:1"]},
                "checkpoint_decompiled_ids": ["ida:0", "ida:1"],
                "matcher_accepted": [
                    {
                        "decompiled_id": "ida:0",
                        "decompiled_audit_id": "d1",
                        "stage": "overlap",
                        "score": 0.8,
                        "confidence": {"minimum_runner_up_gap": 0.04},
                    }
                ],
            }
        )
        labels.append(
            {
                "schema_version": 2,
                "kind": "local-variable-semantic-audit-label",
                "case_id": case_id,
                "case_sha256": case["case_sha256"],
                "evidence_id": "ev_relation",
                "evidence_sha256": evidence["evidence_sha256"],
                "shard_id": "shard_000",
                "oracle_status": "mapped",
                "selected_decompiled_audit_ids": selections[source_audit_id],
                "confidence": "high",
                "rationale": "The data flow demonstrates this semantic relation.",
                "reviewer": "reviewer",
            }
        )
    return [evidence], cases, private, labels


def test_many_to_many_is_valid_and_report_clusters_by_source_function() -> None:
    evidence, cases, private, raw_labels = _public_relation_fixture()
    labels = validate_labels(
        raw_labels,
        cases,
        evidence,
        require_complete=True,
    )
    joined = join_audit_rows(evidence, cases, private, labels)
    classifications = [
        match["classification"] for row in joined for match in row["matcher"]["accepted"]
    ]
    assert classifications == ["many-to-many", "merge"]

    # Add another backend for the same source-function cluster and one missing
    # pipeline row for a second function.  Overall clustering must be two source
    # functions, not three function×backend pseudo-clusters.
    duplicate_backend = json.loads(json.dumps(joined[0]))
    duplicate_backend["case_id"] = "case_other_backend"
    duplicate_backend["backend_id"] = "ghidra"
    missing = json.loads(json.dumps(joined[0]))
    missing["case_id"] = "case_missing"
    missing["audit_sample_id"] = "as_second"
    missing["backend_status"] = "missing"
    missing["reviewer_visible_decompiled_variable_count"] = 0
    missing["oracle"]["status"] = "none_recovered"
    missing["oracle"]["selected_decompiled_audit_ids"] = []
    missing["oracle"]["topology"] = "none"
    missing["matcher"]["accepted"] = []
    missing["matcher"]["accepted_selected_oracle_neighbor"] = False
    all_rows = [*joined, duplicate_backend, missing]
    manifest_payload = {
        "schema_version": 2,
        "kind": "local-variable-semantic-audit",
        "frozen_bins": {
            "version": FROZEN_BIN_VERSION,
            "score_boundaries": list(FROZEN_SCORE_BOUNDS),
            "minimum_runner_up_gap_boundaries": list(FROZEN_MINIMUM_GAP_BOUNDS),
        },
        "coverage": {
            "source_skipped_count": 0,
            "zero_observable_function_count": 0,
        },
    }
    manifest = {
        **manifest_payload,
        "manifest_payload_sha256": evidence_sha256(manifest_payload),
    }
    report = make_audit_report(
        all_rows,
        manifest=manifest,
        bootstrap_iterations=20,
    )
    matcher = report["summary"]["matcher_conditional_on_backend_ok"]
    assert matcher["source_relations"]["source_function_cluster_count"] == 1
    source_metrics = matcher["source_relations"]["metrics"]
    assert source_metrics["matcher_relation_recall"]["value"] == 1.0
    assert source_metrics["matcher_oracle_edge_recall"]["value"] == 3 / 5
    assert source_metrics["matcher_full_relation_recall"]["value"] == 1 / 3
    assert matcher["candidate_edge_confusion"] == {
        "source_case_count": 3,
        "decidable_source_case_count": 3,
        "candidate_pair_count": 6,
        "true_positive": 3,
        "false_positive": 0,
        "false_negative": 2,
        "true_negative": 1,
        "unknown_or_ambiguous_case_count": 0,
        "excluded_unknown_pair_count": 0,
        "metrics": {
            "precision": {"value": 1.0, "numerator": 3, "denominator": 3},
            "edge_recall": {"value": 0.6, "numerator": 3, "denominator": 5},
            "edge_f1": {"value": 0.75, "numerator": 6, "denominator": 8},
        },
    }
    ida_source_metrics = report["by_backend"]["ida"]["matcher_conditional_on_backend_ok"][
        "source_relations"
    ]["metrics"]
    assert ida_source_metrics["matcher_oracle_edge_recall"]["value"] == 2 / 3
    assert ida_source_metrics["matcher_full_relation_recall"]["value"] == 1 / 2
    end_to_end = report["summary"]["end_to_end_pipeline"]
    assert end_to_end["source_relations"]["source_function_cluster_count"] == 2
    assert end_to_end["candidate_edge_confusion"]["source_case_count"] == 4
    stage = matcher["by_matcher_stage"]["overlap"]
    assert stage["stage_recall"]["defined"] is False
    assert stage["metrics"]["valid_edge_precision"]["value"] == 1.0
    assert stage["accepted_classifications"]["many-to-many"] >= 1
    assert matcher["by_score_bin"]
    assert matcher["by_minimum_runner_up_gap_bin"]
    assert report["by_backend_partition"]["ida"]["held_out"]["matcher_conditional_on_backend_ok"][
        "by_matcher_stage"
    ]["overlap"]
    assert (
        report["summary"]["backend_status_strata"]["source_function_backend_counts"]["missing"] == 1
    )

    unknown = json.loads(json.dumps(joined[0]))
    unknown["case_id"] = "case_unknown"
    unknown["oracle"]["status"] = "oracle_unknown"
    unknown["oracle"]["selected_decompiled_audit_ids"] = []
    unknown["oracle"]["topology"] = "oracle-unknown"
    unknown_report = make_audit_report(
        [*joined, unknown],
        manifest=manifest,
        bootstrap_iterations=0,
    )
    unknown_confusion = unknown_report["summary"]["end_to_end_pipeline"]["candidate_edge_confusion"]
    assert unknown_confusion["source_case_count"] == 3
    assert unknown_confusion["decidable_source_case_count"] == 2
    assert unknown_confusion["candidate_pair_count"] == 4
    assert unknown_confusion["unknown_or_ambiguous_case_count"] == 1
    assert unknown_confusion["excluded_unknown_pair_count"] == 2
