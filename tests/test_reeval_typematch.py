"""Safety tests for canonical and A/B type-match overlay reevaluation."""

from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import Literal

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.models.metrics import MetricResult, MetricValue
from decbench.results_store import (
    TypeMatchOverlayError,
    read_typematch_overlay,
    typematch_overlay_manifest_path,
)
from scripts import reeval_typematch


def _make_results_tree(root: Path) -> None:
    checkpoint_dir = root / "checkpoints"
    checkpoint_dir.mkdir(parents=True)
    with open(checkpoint_dir / "proj.pkl", "wb") as file:
        pickle.dump(
            {
                "decompile": {
                    "O0": {
                        "bin": {
                            "angr": {"stub": "decompilation"},
                        }
                    }
                }
            },
            file,
        )
    (root / "function_results.json").write_text(
        json.dumps(
            {
                "groups": [
                    {
                        "project": "proj",
                        "opt_level": "O0",
                        "binary": "bin",
                        "functions": [
                            {
                                "function": "f",
                                "values": {"angr": {"type_match": 0.5}},
                            }
                        ],
                    }
                ]
            }
        )
    )


def _result(*, functions: tuple[str, ...] = ("f",), errors: tuple[str, ...] = ()) -> MetricResult:
    return MetricResult(
        metric_name="type_match",
        decompiler_name="angr",
        binary_name="bin",
        function_results={
            function: MetricValue(
                value=1.0,
                metadata={
                    "fp": 0,
                    "fn": 0,
                    "variable_match_evidence": "native",
                },
            )
            for function in functions
        },
        errors=list(errors),
    )


def _install_metric(
    monkeypatch: pytest.MonkeyPatch,
    outcome: MetricResult | Exception,
) -> None:
    class StubMetric:
        cache_version = "stub-cache-v1"
        variable_match_policy = {"min_overlap": 0.1, "address_weight": 0.5}

        def __init__(self, _config: object) -> None:
            pass

        def compute_for_binary(self, _decompilation: object, **_kwargs: object) -> MetricResult:
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    monkeypatch.setattr(reeval_typematch, "TypeMatchMetric", StubMetric)


@pytest.mark.parametrize("failure", ["exception", "metric_errors", "coverage"])
def test_canonical_failure_preserves_existing_overlay_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Literal["exception", "metric_errors", "coverage"],
) -> None:
    _make_results_tree(tmp_path)
    canonical = tmp_path / "type_match_new.json"
    manifest = typematch_overlay_manifest_path(canonical)
    canonical.write_bytes(b"canonical sentinel\n")
    manifest.write_bytes(b"manifest sentinel\n")
    if failure == "exception":
        outcome: MetricResult | Exception = RuntimeError("scoring exploded")
    elif failure == "metric_errors":
        outcome = _result(errors=("f: inner failure",))
    else:
        outcome = _result(functions=())
    _install_metric(monkeypatch, outcome)

    with pytest.raises(reeval_typematch.CanonicalPromotionError):
        reeval_typematch.main([str(tmp_path), "--emit"])

    assert canonical.read_bytes() == b"canonical sentinel\n"
    assert manifest.read_bytes() == b"manifest sentinel\n"


def test_full_canonical_run_does_not_treat_missing_checkpoint_tree_as_empty_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_results_tree(tmp_path)
    (tmp_path / "checkpoints" / "proj.pkl").unlink()
    _install_metric(monkeypatch, _result())
    canonical = tmp_path / "type_match_new.json"
    canonical.write_bytes(b"canonical sentinel\n")

    with pytest.raises(reeval_typematch.CanonicalPromotionError, match="coverage mismatch"):
        reeval_typematch.main([str(tmp_path), "--emit"])

    assert canonical.read_bytes() == b"canonical sentinel\n"


@pytest.mark.parametrize("alias_kind", ["lexical", "symlink", "hardlink"])
def test_noncanonical_output_cannot_alias_canonical_path(
    tmp_path: Path,
    alias_kind: Literal["lexical", "symlink", "hardlink"],
) -> None:
    canonical = tmp_path / "type_match_new.json"
    canonical.write_text("sentinel")
    if alias_kind == "lexical":
        output = tmp_path / "unused" / ".." / canonical.name
    elif alias_kind == "symlink":
        output = tmp_path / "alias.json"
        output.symlink_to(canonical)
    else:
        output = tmp_path / "alias.json"
        output.hardlink_to(canonical)

    with pytest.raises(SystemExit):
        reeval_typematch.parse_args([str(tmp_path), "--mode", "usage", "--output", str(output)])

    assert canonical.read_text() == "sentinel"


def test_ab_output_remains_raw_json_with_provenance_companion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_results_tree(tmp_path)
    _install_metric(monkeypatch, _result())
    output = tmp_path / "usage-ab.json"

    reeval_typematch.main([str(tmp_path), "--mode", "usage", "--output", str(output)])

    raw = json.loads(output.read_text())
    payload, provenance = read_typematch_overlay(output)
    assert raw == payload
    assert payload["angr"]["proj::O0::bin::f"]["value"] == 1.0
    assert provenance is not None
    assert provenance["mode"] == "usage"
    assert provenance["resolved_mode"] == "usage"
    assert provenance["policy"] == {"address_weight": 0.5, "min_overlap": 0.1}


def test_successful_canonical_run_replaces_sentinel_with_auto_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_results_tree(tmp_path)
    _install_metric(monkeypatch, _result())
    canonical = tmp_path / "type_match_new.json"
    canonical.write_bytes(b"old canonical sentinel\n")

    reeval_typematch.main([str(tmp_path), "--emit"])

    payload, provenance = read_typematch_overlay(canonical)
    assert payload["angr"]["proj::O0::bin::f"]["value"] == 1.0
    assert provenance is not None
    assert provenance["mode"] == "auto"
    assert provenance["resolved_mode"] == "address+usage"


def test_scoped_ab_merge_rejects_incompatible_mode_and_preserves_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_results_tree(tmp_path)
    _install_metric(monkeypatch, _result())
    output = tmp_path / "ab.json"
    reeval_typematch.main([str(tmp_path), "--mode", "address", "--output", str(output)])
    before = output.read_bytes()
    manifest = typematch_overlay_manifest_path(output)
    manifest_before = manifest.read_bytes()

    with pytest.raises(TypeMatchOverlayError, match="incompatible scoped"):
        reeval_typematch.main(
            [
                str(tmp_path),
                "proj",
                "--mode",
                "usage",
                "--output",
                str(output),
            ]
        )

    assert output.read_bytes() == before
    assert manifest.read_bytes() == manifest_before


def test_sample_manifest_filters_before_metric_evaluation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_results_tree(tmp_path)
    decompilation = DecompilationResult(
        binary_path=tmp_path / "O0" / "proj" / "compiled" / "bin",
        binary_name="bin",
        decompiler=DecompilerMetadata(decompiler_name="angr"),
        functions={
            name: FunctionDecompilation(name=name, address=index, decompiled_code="")
            for index, name in enumerate(("f", "g"), start=1)
        },
    )
    with open(tmp_path / "checkpoints" / "proj.pkl", "wb") as file:
        pickle.dump({"decompile": {"O0": {"bin": {"angr": decompilation}}}}, file)
    manifest = tmp_path / "sample.json"
    manifest.write_text(
        json.dumps(
            {"functions": [{"project": "proj", "opt": "O0", "binary": "bin", "function": "f"}]}
        )
    )
    seen: list[set[str]] = []

    class StubMetric:
        cache_version = "stub-cache-v1"
        variable_match_policy = {"min_overlap": 0.1, "address_weight": 0.5}

        def __init__(self, _config: object) -> None:
            pass

        def compute_for_binary(
            self, selected: DecompilationResult, **_kwargs: object
        ) -> MetricResult:
            seen.append(set(selected.functions))
            return _result()

    monkeypatch.setattr(reeval_typematch, "TypeMatchMetric", StubMetric)
    output = tmp_path / "sample-ab.json"

    reeval_typematch.main(
        [str(tmp_path), "--mode", "usage", "--manifest", str(manifest), "--output", str(output)]
    )

    assert seen == [{"f"}]
    payload, provenance = read_typematch_overlay(output)
    assert set(payload["angr"]) == {"proj::O0::bin::f"}
    assert provenance is not None and provenance["mode"] == "usage"


def test_sample_manifest_cannot_promote_canonical_overlay(tmp_path: Path) -> None:
    manifest = tmp_path / "sample.json"
    manifest.write_text('{"functions": []}')

    with pytest.raises(SystemExit):
        reeval_typematch.parse_args([str(tmp_path), "--manifest", str(manifest), "--emit"])
