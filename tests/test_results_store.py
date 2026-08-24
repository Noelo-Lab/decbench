"""Tests for decbench.results_store: slice-scoped overlay merges, the coverage
guard, and the canonical finalize. The slice-scoping tests are named regression
tests for the 2026-07-22 kuna@betaflight O2-noinline wipe."""

from __future__ import annotations

import hashlib
import json
import pickle
from pathlib import Path
from typing import Any

import pytest

import decbench.results_store as results_store
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
from decbench.models.metrics import MetricResult, MetricValue
from decbench.models.project import OptimizationLevel
from decbench.results_store import (
    CoverageRegressionError,
    TypeMatchOverlayError,
    audit_tree,
    coverage_counts,
    coverage_regressions,
    finalize_tree,
    merge_typematch_overlay,
    read_ged_overlay,
    read_typematch_overlay,
    typematch_overlay_manifest_path,
    typematch_overlay_provenance,
    update_byte_match,
    update_ged,
    update_type_match,
    write_function_data_guarded,
    write_typematch_overlay_atomic,
)


def _record(name: str, decs: dict[str, dict[str, float]]) -> FunctionRecord:
    return FunctionRecord(
        function=name,
        values={d: dict(mv) for d, mv in decs.items()},
        perfects={d: {m: v == 0.0 for m, v in mv.items()} for d, mv in decs.items()},
        distances={d: dict(mv) for d, mv in decs.items()},
        decompiled={d: True for d in decs},
    )


def _fd_two_slices() -> FunctionData:
    """kuna has inline GED in projA at O0 AND O2-noinline (two slices)."""
    groups = [
        BinaryGroup(
            project="projA",
            opt_level="O0",
            binary="binA",
            functions=[_record("f1", {"kuna": {"ged": 3.0}, "angr": {"ged": 1.0}})],
        ),
        BinaryGroup(
            project="projA",
            opt_level="O2-noinline",
            binary="binA",
            functions=[_record("f1", {"kuna": {"ged": 5.0}, "angr": {"ged": 2.0}})],
        ),
    ]
    return FunctionData(decompilers=["angr", "kuna"], metrics=["ged"], groups=groups)


def test_update_ged_slice_scoped_clear_regression_kuna() -> None:
    """An overlay covering only one of a decompiler's slices must not wipe the
    others — the kuna@betaflight O2-noinline incident (1716 perfects silently
    lost because the whole kuna column was cleared, then only O0/O2 rewritten)."""
    fd = _fd_two_slices()
    overlay = {"O0::projA::binA::kuna::f1": {"value": 0.0, "perfect": True}}
    n = update_ged(fd, overlay)
    assert n == 1
    o0, noinline = fd.groups
    assert o0.functions[0].values["kuna"]["ged"] == 0.0
    assert o0.functions[0].perfects["kuna"]["ged"] is True
    assert noinline.functions[0].values["kuna"]["ged"] == 5.0
    assert o0.functions[0].values["angr"]["ged"] == 1.0
    assert noinline.functions[0].values["angr"]["ged"] == 2.0


def test_update_ged_sidecar_covers_empty_slice() -> None:
    """A slice the reeval evaluated but found empty (sidecar-covered, no entries)
    must CLEAR its stale inline values instead of keeping them."""
    fd = _fd_two_slices()
    overlay = {"O0::projA::binA::kuna::f1": {"value": 0.0, "perfect": True}}
    covered = {
        ("O0", "projA", "binA", "kuna"),
        ("O2-noinline", "projA", "binA", "kuna"),
    }
    update_ged(fd, overlay, covered=covered)
    o0, noinline = fd.groups
    assert o0.functions[0].values["kuna"]["ged"] == 0.0
    assert "ged" not in noinline.functions[0].values["kuna"]
    assert noinline.functions[0].values["angr"]["ged"] == 2.0


def test_update_byte_match_slice_scoped() -> None:
    fd = _fd_two_slices()
    for g in fd.groups:
        for f in g.functions:
            for dec in list(f.values):
                f.values[dec]["byte_match"] = 0.4
                f.compiles[dec] = True
    overlay = {"O0::projA::binA::kuna::f1": {"value": 1.0, "compilable": True, "dist": 0}}
    tally = update_byte_match(fd, overlay)
    o0, noinline = fd.groups
    assert o0.functions[0].values["kuna"]["byte_match"] == 1.0
    assert noinline.functions[0].values["kuna"]["byte_match"] == 0.4
    assert o0.functions[0].values["angr"]["byte_match"] == 0.4
    assert tally["kuna"] == {"comp": 1, "tot": 1}
    fd2 = _fd_two_slices()
    fd2.groups[0].functions[0].values["kuna"]["byte_match"] = 0.4
    update_byte_match(fd2, {"O0::projA::binA::kuna::zzz": {"value": 1.0}}, add_only=True)
    assert fd2.groups[0].functions[0].values["kuna"]["byte_match"] == 0.4


def test_read_ged_overlay_covers_evaluated_empty_slices(tmp_path: Path) -> None:
    """Legacy checkpoint names cover evaluated-empty slices without a sidecar."""
    root = tmp_path
    (root / "ged_new.json").write_text(
        json.dumps({"O0::projA::binA::angr::f1": {"value": 0.0, "perfect": True}})
    )
    (root / "reeval_ged").mkdir()
    (root / "reeval_ged" / "O2-noinline__projA__binA__kuna.json").write_text("{}")
    (root / "reeval_ged" / "O0__projA__binA__angr.json").write_text(
        json.dumps({"f1": {"value": 0.0, "perfect": True}})
    )
    payload, covered = read_ged_overlay(root)
    assert payload is not None
    assert ("O0", "projA", "binA", "angr") in covered
    assert ("O2-noinline", "projA", "binA", "kuna") in covered

    fd = _fd_two_slices()
    update_ged(fd, payload, covered=covered)
    noinline = fd.groups[1]
    assert "ged" not in noinline.functions[0].values["kuna"]


def test_read_ged_overlay_sidecar_excludes_stale_checkpoints(tmp_path: Path) -> None:
    root = tmp_path
    (root / "ged_new.json").write_text(
        json.dumps({"O0::projA::binA::angr::f1": {"value": 0.0, "perfect": True}})
    )
    (root / "ged_new.slices.json").write_text(json.dumps(["O0::projA::binA::angr"]))
    (root / "reeval_ged").mkdir()
    (root / "reeval_ged" / "O2-noinline__retired__binA__phoenix.json").write_text("{}")

    payload, covered = read_ged_overlay(root)

    assert payload is not None
    assert covered == {("O0", "projA", "binA", "angr")}


def test_merge_typematch_overlay() -> None:
    existing = {"kuna": {"a::O0::b::f": {"value": 0.5}}, "angr": {"a::O0::b::f": {"value": 0.2}}}
    fresh = {
        "kuna": {
            "a::O0::b::f": {
                "value": 0.9,
                "variable_match_evidence": "mixed",
            },
            "a::O0::b::g": {"value": 0.1},
        }
    }
    merged = merge_typematch_overlay(existing, fresh)
    assert merged["kuna"]["a::O0::b::f"] == {
        "value": 0.9,
        "variable_match_evidence": "mixed",
    }
    assert merged["kuna"]["a::O0::b::g"] == {"value": 0.1}
    assert merged["angr"]["a::O0::b::f"] == {"value": 0.2}
    assert existing["kuna"]["a::O0::b::f"] == {"value": 0.5}


def _typematch_provenance(*, cache_version: str = "7", **policy: float) -> dict[str, object]:
    return typematch_overlay_provenance(
        mode="auto",
        resolved_mode="address+usage",
        policy=policy or {"min_overlap": 0.1, "address_weight": 0.5},
        metric_cache_version=cache_version,
        structured_occurrence_mode="producer",
        variable_occurrence_policy_schema="decbench-variable-occurrence-policy-v1",
    )


def test_typematch_overlay_manifest_is_digest_bound_but_legacy_is_readable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "type_match_new.json"
    payload = {"angr": {"p::O0::b::f": {"value": 1.0}}}
    path.write_text(json.dumps(payload))
    assert read_typematch_overlay(path) == (payload, None)

    write_typematch_overlay_atomic(path, payload, _typematch_provenance())
    loaded, provenance = read_typematch_overlay(path)
    assert loaded == payload
    assert provenance is not None
    assert provenance["entry_count"] == 1

    path.write_text(json.dumps({"angr": {}}))
    with pytest.raises(TypeMatchOverlayError, match="digest"):
        read_typematch_overlay(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("structured_occurrence_mode", None, "structured_occurrence_mode"),
        ("structured_occurrence_mode", "experimental_legacy_regex", "producer"),
        ("variable_occurrence_policy_schema", None, "variable_occurrence_policy_schema"),
        ("variable_occurrence_policy_schema", "wrong-schema", "policy_schema"),
    ],
)
def test_v11_typematch_write_requires_exact_manifest_occurrence_contract(
    tmp_path: Path,
    field: str,
    value: str | None,
    message: str,
) -> None:
    provenance = _typematch_provenance(cache_version="11")
    if value is None:
        provenance.pop(field)
    else:
        provenance[field] = value

    with pytest.raises(TypeMatchOverlayError, match=message):
        write_typematch_overlay_atomic(tmp_path / "type_match_new.json", {}, provenance)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (1.0, "must be a mapping"),
        (
            {"value": 1.0, "structured_occurrence_mode": "producer"},
            "producer_variable_occurrence_policy",
        ),
        (
            {
                "value": 1.0,
                "producer_variable_occurrence_policy": "guessed",
                "structured_occurrence_mode": "producer",
            },
            "producer_variable_occurrence_policy",
        ),
        (
            {"value": 1.0, "producer_variable_occurrence_policy": "exact"},
            "structured_occurrence_mode",
        ),
        (
            {
                "value": 1.0,
                "producer_variable_occurrence_policy": "exact",
                "structured_occurrence_mode": "experimental_legacy_regex",
            },
            "structured_occurrence_mode",
        ),
    ],
)
def test_v11_typematch_write_rejects_incomplete_entry_provenance(
    tmp_path: Path,
    entry: Any,
    message: str,
) -> None:
    payload = {"angr": {"p::O0::b::f": entry}}

    with pytest.raises(TypeMatchOverlayError, match=message):
        write_typematch_overlay_atomic(
            tmp_path / "type_match_new.json",
            payload,
            _typematch_provenance(cache_version="11"),
        )


def test_v11_typematch_overlay_accepts_declared_and_undeclared_policies(
    tmp_path: Path,
) -> None:
    path = tmp_path / "type_match_new.json"
    payload = {
        "angr": {
            "p::O0::b::declared": {
                "value": 1.0,
                "producer_variable_occurrence_policy": "direct",
                "structured_occurrence_mode": "producer",
            },
            "p::O0::b::legacy": {
                "value": 0.5,
                "producer_variable_occurrence_policy": "undeclared",
                "structured_occurrence_mode": "producer",
            },
        }
    }

    write_typematch_overlay_atomic(
        path,
        payload,
        _typematch_provenance(cache_version="11"),
    )

    assert read_typematch_overlay(path)[0] == payload


def test_v11_typematch_read_rejects_digest_bound_incomplete_entry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "type_match_new.json"
    payload = {
        "angr": {
            "p::O0::b::f": {
                "value": 1.0,
                "producer_variable_occurrence_policy": "exact",
                "structured_occurrence_mode": "producer",
            }
        }
    }
    write_typematch_overlay_atomic(
        path,
        payload,
        _typematch_provenance(cache_version="11"),
    )
    payload["angr"]["p::O0::b::f"].pop("producer_variable_occurrence_policy")
    overlay_bytes = json.dumps(payload, sort_keys=True).encode()
    path.write_bytes(overlay_bytes)
    manifest_path = typematch_overlay_manifest_path(path)
    manifest = json.loads(manifest_path.read_text())
    manifest["overlay_sha256"] = hashlib.sha256(overlay_bytes).hexdigest()
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(TypeMatchOverlayError, match="producer_variable_occurrence_policy"):
        read_typematch_overlay(path)


def test_v11_typematch_read_rejects_wrong_manifest_occurrence_schema(tmp_path: Path) -> None:
    path = tmp_path / "type_match_new.json"
    payload = {
        "angr": {
            "p::O0::b::f": {
                "value": 1.0,
                "producer_variable_occurrence_policy": "exact",
                "structured_occurrence_mode": "producer",
            }
        }
    }
    write_typematch_overlay_atomic(
        path,
        payload,
        _typematch_provenance(cache_version="11"),
    )
    manifest_path = typematch_overlay_manifest_path(path)
    manifest = json.loads(manifest_path.read_text())
    manifest["variable_occurrence_policy_schema"] = "wrong-schema"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(TypeMatchOverlayError, match="variable_occurrence_policy_schema"):
        read_typematch_overlay(path)


def test_pre_v11_typematch_overlay_keeps_legacy_entry_compatibility(tmp_path: Path) -> None:
    path = tmp_path / "type_match_new.json"
    payload = {"angr": {"p::O0::b::f": {"value": 1.0}}}

    write_typematch_overlay_atomic(
        path,
        payload,
        _typematch_provenance(cache_version="10"),
    )

    assert read_typematch_overlay(path)[0] == payload


def test_v11_scoped_typematch_merge_rejects_incomplete_entry_provenance() -> None:
    provenance = _typematch_provenance(cache_version="11")
    valid = {
        "angr": {
            "p::O0::b::f": {
                "value": 1.0,
                "producer_variable_occurrence_policy": "exact",
                "structured_occurrence_mode": "producer",
            }
        }
    }
    incomplete = {"angr": {"p::O0::b::g": {"value": 0.5}}}

    with pytest.raises(TypeMatchOverlayError, match="producer_variable_occurrence_policy"):
        merge_typematch_overlay(
            valid,
            incomplete,
            existing_provenance=provenance,
            fresh_provenance=provenance,
        )


def test_scoped_typematch_merge_rejects_mixed_policy() -> None:
    existing = {"angr": {"p::O0::b::f": {"value": 1.0}}}
    fresh = {"angr": {"p::O0::b::g": {"value": 0.5}}}
    old_policy = _typematch_provenance(min_overlap=0.1)
    new_policy = _typematch_provenance(min_overlap=0.2)

    with pytest.raises(TypeMatchOverlayError, match="policy"):
        merge_typematch_overlay(
            existing,
            fresh,
            existing_provenance=old_policy,
            fresh_provenance=new_policy,
        )

    assert existing == {"angr": {"p::O0::b::f": {"value": 1.0}}}


def test_scoped_typematch_merge_rejects_missing_occurrence_contract() -> None:
    existing = {"angr": {"p::O0::b::f": {"value": 1.0}}}
    fresh = {"angr": {"p::O0::b::g": {"value": 0.5}}}
    legacy = _typematch_provenance()
    legacy.pop("structured_occurrence_mode")
    legacy.pop("variable_occurrence_policy_schema")

    with pytest.raises(TypeMatchOverlayError, match="structured_occurrence_mode"):
        merge_typematch_overlay(
            existing,
            fresh,
            existing_provenance=legacy,
            fresh_provenance=_typematch_provenance(),
        )


def test_atomic_typematch_write_preserves_sentinels_before_serialization_failure(
    tmp_path: Path,
) -> None:
    path = tmp_path / "type_match_new.json"
    manifest = typematch_overlay_manifest_path(path)
    path.write_bytes(b"overlay sentinel\n")
    manifest.write_bytes(b"manifest sentinel\n")

    with pytest.raises(ValueError):
        write_typematch_overlay_atomic(
            path,
            {"angr": {"p::O0::b::f": {"value": float("nan")}}},
            _typematch_provenance(),
        )

    assert path.read_bytes() == b"overlay sentinel\n"
    assert manifest.read_bytes() == b"manifest sentinel\n"


def test_atomic_typematch_write_rolls_back_manifest_when_overlay_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "type_match_new.json"
    manifest = typematch_overlay_manifest_path(path)
    path.write_bytes(b"overlay sentinel\n")
    manifest.write_bytes(b"manifest sentinel\n")
    real_replace = results_store._replace_bytes_atomic
    calls = 0

    def fail_overlay_replace(target: Path, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected overlay replacement failure")
        real_replace(target, payload)

    monkeypatch.setattr(results_store, "_replace_bytes_atomic", fail_overlay_replace)
    with pytest.raises(OSError, match="injected"):
        write_typematch_overlay_atomic(
            path,
            {"angr": {"p::O0::b::f": {"value": 1.0}}},
            _typematch_provenance(),
        )

    assert path.read_bytes() == b"overlay sentinel\n"
    assert manifest.read_bytes() == b"manifest sentinel\n"


def test_update_typematch_replaces_and_clears_row_provenance() -> None:
    fd = _fd_two_slices()
    record = fd.groups[0].functions[0]
    record.metric_evidence = {"kuna": {"type_match": "mixed"}}
    record.producer_variable_occurrence_policy = {"kuna": "direct"}
    key = "projA::O0::binA::f1"

    updated = update_type_match(
        fd,
        {
            "kuna": {
                key: {
                    "value": 0.75,
                    "dist": 1,
                    "variable_match_evidence": "fallback_only",
                    "producer_variable_occurrence_policy": "unavailable",
                }
            }
        },
    )

    assert updated == 1
    assert record.values["kuna"]["type_match"] == 0.75
    assert record.metric_evidence == {"kuna": {"type_match": "fallback_only"}}
    assert record.producer_variable_occurrence_policy == {"kuna": "unavailable"}

    update_type_match(fd, {"kuna": {key: {"value": 1.0, "dist": 0}}})
    assert "kuna" not in record.metric_evidence
    assert "kuna" not in record.producer_variable_occurrence_policy


def test_coverage_guard_catches_column_drop() -> None:
    old = coverage_counts(_fd_two_slices())
    shrunk = _fd_two_slices()
    shrunk.groups[1].functions[0].values.pop("kuna")
    regs = coverage_regressions(old, coverage_counts(shrunk))
    assert any(g == "projA::O2-noinline::binA" and c == "kuna::ged" for g, c, _o, _n in regs)


def test_guard_allows_excluded_project_and_decompiler() -> None:
    old = coverage_counts(_fd_two_slices())
    empty = FunctionData(decompilers=["angr", "kuna"], metrics=["ged"], groups=[])
    assert coverage_regressions(old, coverage_counts(empty), allowed_projects=["projA"]) == []
    no_kuna = _fd_two_slices()
    for g in no_kuna.groups:
        for f in g.functions:
            f.values.pop("kuna")
            f.decompiled.pop("kuna")
    regs = coverage_regressions(old, coverage_counts(no_kuna), allowed_decompilers=["kuna"])
    assert regs == []


def test_guarded_write_blocks_and_preserves_old_file(tmp_path: Path) -> None:
    root = tmp_path
    write_function_data_guarded(_fd_two_slices(), root)
    original = (root / "function_results.json").read_bytes()

    shrunk = _fd_two_slices()
    shrunk.groups[1].functions[0].values.pop("kuna")
    with pytest.raises(CoverageRegressionError):
        write_function_data_guarded(shrunk, root)
    assert (root / "function_results.json").read_bytes() == original
    assert not (root / "function_results.json.tmp").exists()

    write_function_data_guarded(shrunk, root, allow_drops=True)
    assert (root / "function_results.prev.json").read_bytes() == original
    reloaded = FunctionData.from_json(root / "function_results.json")
    assert "kuna" not in reloaded.groups[1].functions[0].values


def _mini_checkpoint(project: str, dec: str = "angr") -> dict:
    fn = FunctionDecompilation(name="main", address=0x1000, decompiled_code="int main(){}\n")
    dr = DecompilationResult(
        binary_path=Path(f"/nonexistent/{project}/bin"),
        binary_name=f"{project}bin",
        decompiler=DecompilerMetadata(decompiler_name=dec, decompiler_version="1.0"),
        functions={"main": fn},
    )
    mr = MetricResult(
        metric_name="ged",
        decompiler_name=dec,
        binary_name=f"{project}bin",
        function_results={"main": MetricValue(value=0.0)},
    )
    return {
        "decompile": {OptimizationLevel.O0: {f"{project}bin": {dec: dr}}},
        "evaluate": {OptimizationLevel.O0: {f"{project}bin": {dec: {"ged": mr}}}},
    }


def _mini_tree(tmp_path: Path, projects: tuple[str, ...] = ("alpha", "beta")) -> Path:
    root = tmp_path / "tree"
    (root / "checkpoints").mkdir(parents=True)
    for p in projects:
        (root / "checkpoints" / f"{p}.pkl").write_bytes(pickle.dumps(_mini_checkpoint(p)))
    return root


def test_finalize_tree_reads_all_checkpoints(tmp_path: Path) -> None:
    root = _mini_tree(tmp_path)
    fd, sb = finalize_tree(root, log=lambda _msg: None)
    assert sorted(g.project for g in fd.groups) == ["alpha", "beta"]
    assert (root / "function_results.json").exists()
    assert (root / "scoreboard.toml").exists()
    assert sb.decompilers == ["angr"]

    (root / "checkpoints" / "beta.pkl").unlink()
    with pytest.raises(CoverageRegressionError):
        finalize_tree(root, log=lambda _msg: None)
    fd2, _sb2 = finalize_tree(root, exclude_projects=["beta"], log=lambda _msg: None)
    assert sorted(g.project for g in fd2.groups) == ["alpha"]


def test_finalize_tree_persists_overlay_occurrence_policy(tmp_path: Path) -> None:
    root = _mini_tree(tmp_path, projects=("alpha",))
    checkpoint_path = root / "checkpoints" / "alpha.pkl"
    checkpoint = pickle.loads(checkpoint_path.read_bytes())
    checkpoint["evaluate"][OptimizationLevel.O0]["alphabin"]["angr"]["type_match"] = MetricResult(
        metric_name="type_match",
        decompiler_name="angr",
        binary_name="alphabin",
        function_results={
            "main": MetricValue(
                value=1.0,
                metadata={"producer_variable_occurrence_policy": "direct"},
            )
        },
    )
    checkpoint_path.write_bytes(pickle.dumps(checkpoint))
    write_typematch_overlay_atomic(
        root / "type_match_new.json",
        {
            "angr": {
                "alpha::O0::alphabin::main": {
                    "value": 0.5,
                    "dist": 1,
                    "producer_variable_occurrence_policy": "unavailable",
                    "structured_occurrence_mode": "producer",
                }
            }
        },
        _typematch_provenance(cache_version="11"),
    )

    fd, _ = finalize_tree(root, log=lambda _msg: None)
    record = fd.groups[0].functions[0]
    assert record.values["angr"]["type_match"] == 0.5
    assert record.producer_variable_occurrence_policy == {"angr": "unavailable"}
    reloaded = FunctionData.from_json(root / "function_results.json")
    assert reloaded.groups[0].functions[0].producer_variable_occurrence_policy == {
        "angr": "unavailable"
    }


def test_finalize_preserves_dataset_info_and_history(tmp_path: Path) -> None:
    root = _mini_tree(tmp_path, projects=("alpha",))
    fd, _ = finalize_tree(root, log=lambda _msg: None)
    fd.dataset_info = {"total_loc": 123}
    fd.history = []
    raw = json.loads((root / "function_results.json").read_text())
    raw["dataset_info"] = {"total_loc": 123}
    raw["history"] = [
        {"decompiler": "ghidra", "version": "11.0", "scores": {"ged": 1.0}, "overall": 1.0}
    ]
    (root / "function_results.json").write_text(json.dumps(raw))

    fd2, _ = finalize_tree(root, log=lambda _msg: None)
    assert fd2.dataset_info == {"total_loc": 123}
    assert [h.decompiler for h in fd2.history] == ["ghidra"]
    reloaded = FunctionData.from_json(root / "function_results.json")
    assert reloaded.dataset_info == {"total_loc": 123}
    assert [h.decompiler for h in reloaded.history] == ["ghidra"]


def test_audit_tree_scopes_slice_scoped_decompilers(tmp_path: Path) -> None:
    """A decompiler whose checkpoint ``DecompilerMetadata.extra`` carries
    ``slice_scoped=True`` (external evalkit submissions) is audited ONLY on the
    manifest slice, exactly like the built-in LLM sample-set backends."""
    root = tmp_path / "tree"
    (root / "checkpoints").mkdir(parents=True)

    def _dr(dec: str, *, scoped: bool) -> DecompilationResult:
        fn = FunctionDecompilation(name="main", address=0x1000, decompiled_code="int main(){}\n")
        return DecompilationResult(
            binary_path=Path("/nonexistent/alphabin"),
            binary_name="alphabin",
            decompiler=DecompilerMetadata(
                decompiler_name=dec,
                extra={"slice_scoped": True} if scoped else {},
            ),
            functions={"main": fn},
        )

    ckpt = {
        "decompile": {
            OptimizationLevel.O0: {
                "alphabin": {
                    "mydec": _dr("mydec", scoped=True),
                    "angr": _dr("angr", scoped=False),
                }
            },
            OptimizationLevel.O2: {"alphabin": {"mydec": _dr("mydec", scoped=True)}},
        },
        "evaluate": {},
    }
    (root / "checkpoints" / "alpha.pkl").write_bytes(pickle.dumps(ckpt))
    (root / "sample_set_manifest.json").write_text(
        json.dumps(
            {
                "functions": [
                    {"project": "alpha", "opt": "O2", "binary": "alphabin", "function": "main"}
                ]
            }
        )
    )

    gaps = audit_tree(root, log=lambda _msg: None)
    flagged = {(g.decompiler, g.opt) for g in gaps}
    assert ("angr", "O0") in flagged
    assert ("mydec", "O0") not in flagged
    assert ("mydec", "O2") in flagged


def test_finalize_tree_strips_excluded_decompilers(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "checkpoints").mkdir(parents=True)
    ckpt = _mini_checkpoint("alpha")
    extra = _mini_checkpoint("alpha", dec="kuna")
    ckpt["decompile"][OptimizationLevel.O0]["alphabin"].update(
        extra["decompile"][OptimizationLevel.O0]["alphabin"]
    )
    ckpt["evaluate"][OptimizationLevel.O0]["alphabin"].update(
        extra["evaluate"][OptimizationLevel.O0]["alphabin"]
    )
    (root / "checkpoints" / "alpha.pkl").write_bytes(pickle.dumps(ckpt))

    fd, sb = finalize_tree(root, exclude_decompilers=["kuna"], log=lambda _msg: None)
    assert fd.decompilers == ["angr"]
    assert sb.decompilers == ["angr"]
    for g in fd.groups:
        for f in g.functions:
            assert "kuna" not in f.values
