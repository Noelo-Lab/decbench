from __future__ import annotations

import copy
import json
import os
import pickle
import shutil
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    VariableInfo,
    with_variable_occurrence_policy,
)
from decbench.results_store import read_typematch_overlay, write_typematch_overlay_atomic
from decbench.scoring.typematch_ab import file_sha256, keyset_sha256, load_manifest
from scripts import run_typematch_ab_sharded as driver


def _elf(path: Path) -> None:
    payload = bytearray(20)
    payload[:4] = b"\x7fELF"
    payload[18:20] = struct.pack("<H", 0x3E)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _result(binary: Path, functions: tuple[str, ...], backend: str = "angr") -> DecompilationResult:
    return DecompilationResult(
        binary_path=binary,
        binary_name=binary.name,
        decompiler=DecompilerMetadata(decompiler_name=backend),
        functions={
            name: FunctionDecompilation(
                name=name,
                address=index,
                decompiled_code=f"int {name}(void) {{ return {index}; }}",
            )
            for index, name in enumerate(functions, start=1)
        },
    )


def _tree(tmp_path: Path) -> tuple[Path, Path, set[driver.FunctionKey]]:
    root = tmp_path / "results"
    first = root / "O0" / "proj" / "compiled" / "first"
    second = root / "O2" / "proj" / "compiled" / "second"
    _elf(first)
    _elf(second)
    (root / "checkpoints").mkdir(parents=True)
    with (root / "checkpoints" / "proj.pkl").open("wb") as stream:
        pickle.dump(
            {
                "decompile": {
                    "O0": {"first": {"angr": _result(first, ("f", "unmeasurable"))}},
                    "O2": {"second": {"angr": _result(second, ("g",))}},
                }
            },
            stream,
        )
    (root / "function_results.json").write_text(
        json.dumps(
            {
                "perfect_values": {"type_match": 1.0},
                "groups": [
                    {
                        "project": "proj",
                        "opt_level": "O0",
                        "binary": "first",
                        "functions": [
                            {
                                "function": "f",
                                "values": {"angr": {"type_match": 0.5}},
                            },
                            {"function": "unmeasurable", "values": {}},
                        ],
                    },
                    {
                        "project": "proj",
                        "opt_level": "O2",
                        "binary": "second",
                        "functions": [
                            {
                                "function": "g",
                                "values": {"angr": {"type_match": 0.25}},
                            }
                        ],
                    },
                ],
            }
        )
    )
    keys: set[driver.FunctionKey] = {
        ("proj", "O0", "first", "f"),
        ("proj", "O0", "first", "unmeasurable"),
        ("proj", "O2", "second", "g"),
    }
    manifest = tmp_path / "selected.json"
    manifest.write_text(
        json.dumps(
            {
                "functions": [
                    {"project": project, "opt": opt, "binary": binary, "function": function}
                    for project, opt, binary, function in sorted(keys)
                ]
            }
        )
    )
    (root / "sample_set_manifest.json").write_text(
        json.dumps(
            {"functions": [{"project": "proj", "opt": "O0", "binary": "first", "function": "f"}]}
        )
    )
    return root, manifest, keys


def _entry(value: float = 1.0) -> dict[str, object]:
    return {
        "value": value,
        "dist": 0,
        "variable_match_evidence": "native",
        "producer_variable_occurrence_policy": "exact",
        "structured_occurrence_mode": "producer",
    }


def _job(
    tmp_path: Path,
    *,
    mode: str,
    shard: int,
    function: str,
) -> driver.WorkerJob:
    manifest = tmp_path / f"shard{shard:02d}.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    key = ("proj", "O0", f"bin{shard}", function)
    manifest.write_text(
        json.dumps(
            {
                "functions": [
                    {
                        "project": key[0],
                        "opt": key[1],
                        "binary": key[2],
                        "function": key[3],
                    }
                ]
            }
        )
    )
    base = tmp_path / "workers" / mode / f"shard{shard:02d}"
    return driver.WorkerJob(
        backend="angr",
        mode=mode,
        shard=shard,
        manifest=manifest,
        function_data=tmp_path / "results" / "function_results.json",
        manifest_sha256=file_sha256(manifest),
        selected_key_sha256=keyset_sha256({key}),
        expected=frozenset({(*key, "angr")}),
        output=base.with_suffix(".json"),
        stdout_log=base.with_suffix(".stdout.log"),
        stderr_log=base.with_suffix(".stderr.log"),
        cache_dir=base.with_suffix(".cache"),
        process_record=base.with_suffix(".process.json"),
        receipt=base.with_suffix(".receipt.json"),
        attempts_dir=base.with_suffix(".attempts"),
    )


def _write_job_overlay(job: driver.WorkerJob) -> None:
    score_key = "::".join(next(iter(job.expected))[:4])
    write_typematch_overlay_atomic(
        job.output,
        {job.backend: {score_key: _entry()}},
        driver._metric_provenance(job.mode),
    )


def _commit_job_receipt(
    tmp_path: Path,
) -> tuple[driver.WorkerJob, Path, dict[str, object]]:
    job = _job(tmp_path, mode="address", shard=1, function="f")
    _write_job_overlay(job)
    driver._write_bytes_atomic(job.stderr_log, b"")
    cache_file = job.cache_dir / "metric" / "aa" / "key.json"
    cache_file.parent.mkdir(parents=True)
    cache_file.write_text('{"value":1}')
    root = tmp_path / "results"
    attempt_id = "a" * 32
    attempt_output = job.attempts_dir / attempt_id / "overlay.json"
    command = driver._worker_command(job, root, attempt_output)
    driver._write_bytes_atomic(job.stdout_log, f"wrote {attempt_output}\n".encode())
    driver._write_json_atomic(
        job.process_record,
        {
            "schema": driver.PROCESS_RECORD_SCHEMA,
            "attempt_id": attempt_id,
            "job": job.label,
            "command": list(command),
            "pid": 999999,
            "pgid": 999999,
            "proc_start_ticks": 1,
            "status": "completed",
            "returncode": 0,
            "timed_out": False,
        },
    )
    outcome = driver.WorkerOutcome(
        label=job.label,
        command=command,
        returncode=0,
        stdout=job.stdout_log.read_text(),
        stderr="",
        timed_out=False,
    )
    cache_inventory = driver._seal_cache(job.cache_dir)
    receipt = driver._job_receipt_payload(
        job,
        outcome,
        root=root,
        attempt_id=attempt_id,
        plan_sha256="plan",
        cache_inventory=cache_inventory,
    )
    driver._write_json_atomic(job.receipt, receipt)
    return job, root, receipt


def _restore_cache_permissions(directory: Path) -> None:
    if not directory.exists():
        return
    directory.chmod(0o755)
    for path in directory.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)


def test_dry_run_uses_whole_binary_shards_and_touches_no_outputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, manifest, _keys = _tree(tmp_path)
    output = tmp_path / "analysis"
    canonical = root / "type_match_new.json"
    canonical.write_bytes(b"canonical sentinel\n")

    assert (
        driver.main(
            [
                str(root),
                str(manifest),
                str(output),
                "--shards",
                "2",
                "--backend",
                "angr",
                "--scope",
                "full",
                "--dry-run",
            ]
        )
        == 0
    )

    summary = json.loads(capsys.readouterr().out)
    assert summary["writes"] is False
    assert summary["selected_functions"] == 3
    assert summary["measurable_functions"] == 2
    assert summary["jobs"] == 8
    assert not output.exists()
    assert canonical.read_bytes() == b"canonical sentinel\n"


def test_incomplete_unplanned_shards_are_quarantined_and_regenerated(
    tmp_path: Path,
) -> None:
    _root, manifest, keys = _tree(tmp_path)
    output = tmp_path / "analysis"
    partial = output / "shards" / "manifests" / "shard01.json"
    partial.parent.mkdir(parents=True)
    partial.write_text('{"functions": [')

    directory, index, rows, temporary = driver._prepare_shards(
        manifest,
        keys,
        output,
        2,
        30,
        dry_run=False,
    )

    assert temporary is None
    assert directory == output / "shards"
    assert index["valid"] is True
    assert len(rows) == 2
    quarantined = list((output / "failed_attempts").glob("*/00-shards/manifests/shard01.json"))
    assert len(quarantined) == 1
    assert quarantined[0].read_text() == '{"functions": ['


def test_invalid_planned_shards_fail_closed_without_quarantine(tmp_path: Path) -> None:
    _root, manifest, keys = _tree(tmp_path)
    output = tmp_path / "analysis"
    partial = output / "shards" / "manifests" / "shard01.json"
    partial.parent.mkdir(parents=True)
    partial.write_text('{"functions": [')
    (output / "run_plan.json").write_text("{}")

    with pytest.raises(driver.ShardedTypeMatchError, match="invalid shard index"):
        driver._prepare_shards(manifest, keys, output, 2, 30, dry_run=False)

    assert partial.is_file()
    assert not (output / "failed_attempts").exists()


def test_checkpoint_expected_scope_is_producer_intersection_fixed_denominator(
    tmp_path: Path,
) -> None:
    root, _manifest, selected = _tree(tmp_path)
    measurable = {
        ("proj", "O0", "first", "f"),
        ("proj", "O2", "second", "g"),
    }

    backends, inventory, expected = driver._checkpoint_scope(
        root,
        selected,
        measurable,
        ("angr",),
    )

    assert backends == ["angr"]
    assert len(inventory) == 1
    assert expected == {
        "angr": {
            ("proj", "O0", "first", "f", "angr"),
            ("proj", "O2", "second", "g", "angr"),
        }
    }


@pytest.mark.parametrize("mismatch", ("binary", "backend", "function", "model"))
def test_checkpoint_scope_rejects_inner_outer_identity_mismatches(
    tmp_path: Path,
    mismatch: str,
) -> None:
    root, _manifest, selected = _tree(tmp_path)
    checkpoint = root / "checkpoints" / "proj.pkl"
    with checkpoint.open("rb") as stream:
        payload = pickle.load(stream)
    result = payload["decompile"]["O0"]["first"]["angr"]
    if mismatch == "binary":
        result.binary_name = "wrong"
    elif mismatch == "backend":
        result.decompiler.decompiler_name = "wrong"
    elif mismatch == "function":
        result.functions["f"].name = "wrong"
    else:
        payload["decompile"]["O0"]["first"]["angr"] = {"functions": {}}
    with checkpoint.open("wb") as stream:
        pickle.dump(payload, stream)

    with pytest.raises(driver.ShardedTypeMatchError, match="checkpoint .*identity|not a"):
        driver._checkpoint_scope(root, selected, selected, ("angr",))


def test_checkpoint_scope_accepts_exact_versioned_identity_and_rebindable_stale_path(
    tmp_path: Path,
) -> None:
    root, _manifest, selected = _tree(tmp_path)
    checkpoint = root / "checkpoints" / "proj.pkl"
    with checkpoint.open("rb") as stream:
        payload = pickle.load(stream)
    result = payload["decompile"]["O0"]["first"].pop("angr")
    result.binary_path = Path("/stale/worktree/first")
    result.decompiler.decompiler_name = "angr@1.0"
    payload["decompile"]["O0"]["first"]["angr@1.0"] = result
    with checkpoint.open("wb") as stream:
        pickle.dump(payload, stream)

    backends, _inventory, expected = driver._checkpoint_scope(
        root,
        selected,
        selected,
        ("angr@1.0",),
    )

    assert backends == ["angr@1.0"]
    assert expected["angr@1.0"] == {
        ("proj", "O0", "first", "f", "angr@1.0"),
        ("proj", "O0", "first", "unmeasurable", "angr@1.0"),
    }


def test_scope_policy_separates_full_sample_and_explicit_experimental_runs(
    tmp_path: Path,
) -> None:
    root, manifest, full_keys = _tree(tmp_path)
    sample_keys = load_manifest(root / "sample_set_manifest.json")

    sample = driver._validate_run_scope(
        scope="sample-set",
        root=root,
        selected=sample_keys,
        function_keys=full_keys,
        backends=("angr", "codex@future"),
        explicitly_requested=("angr", "codex@future"),
    )
    assert sample["fairness"] == "frozen-sample-set"
    assert sample["selected_sample_set_only_backends"] == ["codex@future"]

    with pytest.raises(driver.ShardedTypeMatchError, match="sample-set-only"):
        driver._validate_run_scope(
            scope="full",
            root=root,
            selected=load_manifest(manifest),
            function_keys=full_keys,
            backends=("angr", "codex"),
            explicitly_requested=(),
        )
    with pytest.raises(driver.ShardedTypeMatchError, match="exact copy"):
        driver._validate_run_scope(
            scope="sample-set",
            root=root,
            selected=set(full_keys),
            function_keys=full_keys,
            backends=("codex",),
            explicitly_requested=("codex",),
        )

    experimental = driver._validate_run_scope(
        scope="experimental-full",
        root=root,
        selected=full_keys,
        function_keys=full_keys,
        backends=("manifold",),
        explicitly_requested=("manifold",),
    )
    assert experimental["fairness"] == "experimental-full-sample-only-backend"


def test_full_dry_run_accepts_results_tree_without_sample_manifest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, manifest, _full_keys = _tree(tmp_path)
    (root / "sample_set_manifest.json").unlink()

    assert (
        driver.main(
            [
                str(root),
                str(manifest),
                str(tmp_path / "analysis"),
                "--scope",
                "full",
                "--backend",
                "angr",
                "--shards",
                "1",
                "--dry-run",
            ]
        )
        == 0
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary["scope"] == "full"
    assert summary["writes"] is False
    assert not (tmp_path / "analysis").exists()

    with pytest.raises(driver.ShardedTypeMatchError, match="requires a regular frozen"):
        driver._validate_run_scope(
            scope="sample-set",
            root=root,
            selected={("proj", "O0", "first", "f")},
            function_keys=_full_keys,
            backends=("angr",),
            explicitly_requested=("angr",),
        )


def test_worker_transcript_fails_closed_on_stdout_and_stderr(tmp_path: Path) -> None:
    output = tmp_path / "overlay.json"
    accepted = driver.WorkerOutcome(
        label="angr/address/shard01",
        command=("python",),
        returncode=0,
        stdout=f"mode: address\n\nwrote {output}\n",
        stderr="type_match scored 0 for all matched functions in /tmp/bin (gt_funcs=1)\n",
        timed_out=False,
    )
    driver._validate_worker_transcript(accepted, output)

    with pytest.raises(driver.ShardedTypeMatchError, match="failure marker"):
        driver._validate_worker_transcript(
            replace(accepted, stdout=f"  ! metric error\n\nwrote {output}\n"), output
        )
    with pytest.raises(driver.ShardedTypeMatchError, match="unexpected line"):
        driver._validate_worker_transcript(
            replace(accepted, stderr="Traceback: scoring failed\n"), output
        )


def test_resume_requires_digest_valid_overlay_transcript_and_immutable_fresh_cache(
    tmp_path: Path,
) -> None:
    job, root, _receipt = _commit_job_receipt(tmp_path)
    try:
        assert driver._validate_job_receipt(job, root=root, plan_sha256="plan") is True
        assert not (job.cache_dir.stat().st_mode & stat.S_IWUSR)

        job.cache_dir.chmod(0o755)
        with pytest.raises(driver.ShardedTypeMatchError, match="cache is writable"):
            driver._validate_job_receipt(job, root=root, plan_sha256="plan")
    finally:
        _restore_cache_permissions(job.cache_dir)


def test_unreceipted_attempt_is_quarantined_without_reuse_or_deletion(tmp_path: Path) -> None:
    job = _job(tmp_path, mode="usage", shard=1, function="f")
    driver._write_bytes_atomic(job.stdout_log, b"partial worker output\n")
    cache_file = job.cache_dir / "metric" / "aa" / "partial.json"
    cache_file.parent.mkdir(parents=True)
    cache_file.write_text('{"partial":true}')
    receipt_temporary = job.receipt.parent / f".{job.receipt.name}.interrupted.tmp"
    receipt_temporary.write_text("partial receipt")

    with pytest.raises(driver.IncompleteWorkerAttempt):
        driver._validate_job_receipt(job, root=tmp_path / "results", plan_sha256="plan")
    quarantine = driver._quarantine_incomplete_attempt(job)

    assert not job.stdout_log.exists()
    assert not job.cache_dir.exists()
    assert (quarantine / job.stdout_log.name).read_bytes() == b"partial worker output\n"
    assert (quarantine / job.cache_dir.name / "metric" / "aa" / "partial.json").is_file()
    assert (quarantine / receipt_temporary.name).read_text() == "partial receipt"
    record = json.loads((quarantine / "quarantine.json").read_text())
    assert record["reason"] == "artifacts existed without a committed receipt"


def test_queued_jobs_do_not_preallocate_attempt_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _job(tmp_path, mode="usage", shard=1, function="f")

    class PlannedStop(RuntimeError):
        pass

    class StopBeforeTaskExecutor:
        def __init__(self, **_kwargs: object) -> None:
            assert not job.attempts_dir.exists()
            raise PlannedStop

    monkeypatch.setattr(driver, "ThreadPoolExecutor", StopBeforeTaskExecutor)
    with pytest.raises(PlannedStop):
        driver._execute_jobs(
            [job],
            root=tmp_path / "results",
            workers=1,
            timeout=10,
            plan_sha256="plan",
        )
    assert not job.attempts_dir.exists()


@pytest.mark.parametrize("leader_visible", (True, False))
def test_retry_kills_exact_orphan_and_uses_a_new_attempt_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    leader_visible: bool,
) -> None:
    job = _job(tmp_path, mode="usage", shard=1, function="f")
    attempt = driver._new_worker_attempt(job)
    started = tmp_path / "started"
    release = tmp_path / "release"
    late = attempt.directory / "late-write"
    command = (
        sys.executable,
        "-c",
        (
            "import pathlib,time,sys; "
            "pathlib.Path(sys.argv[1]).write_text('started'); "
            "release=pathlib.Path(sys.argv[2]); "
            "\nwhile not release.exists(): time.sleep(0.01)\n"
            "pathlib.Path(sys.argv[3]).write_text('late')"
        ),
        str(started),
        str(release),
        str(late),
    )
    process = subprocess.Popen(command, start_new_session=True)
    deadline = time.monotonic() + 5
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()
    identity = driver._proc_identity(process.pid)
    assert identity is not None
    pgid, start_ticks = identity
    driver._write_json_atomic(
        attempt.process_record,
        {
            "schema": driver.PROCESS_RECORD_SCHEMA,
            "attempt_id": attempt.attempt_id,
            "job": job.label,
            "command": list(command),
            "pid": process.pid,
            "pgid": pgid,
            "proc_start_ticks": start_ticks,
            "status": "running",
            "returncode": None,
            "timed_out": None,
        },
    )
    reaper = threading.Thread(target=process.wait, daemon=True)
    reaper.start()
    if not leader_visible:
        monkeypatch.setattr(driver, "_proc_identity", lambda _pid: None)

    with pytest.raises(driver.IncompleteWorkerAttempt):
        driver._validate_job_receipt(job, root=tmp_path / "results", plan_sha256="plan")
    if not leader_visible:
        with pytest.raises(driver.ShardedTypeMatchError, match="refusing an unsafe retry"):
            driver._quarantine_incomplete_attempt(job)
        assert process.poll() is None
        os.killpg(process.pid, signal.SIGKILL)
        reaper.join(timeout=5)
        assert process.returncode is not None and process.returncode != 0
        return
    quarantine = driver._quarantine_incomplete_attempt(job)
    retry = driver._new_worker_attempt(job)
    release.write_text("go")
    reaper.join(timeout=5)

    assert process.returncode is not None and process.returncode != 0
    assert retry.attempt_id != attempt.attempt_id
    assert retry.directory != attempt.directory
    assert not late.exists()
    assert not (quarantine / attempt.attempt_id / "late-write").exists()
    assert not (retry.directory / "late-write").exists()


def test_job_receipt_rejects_every_tampered_semantic_field(tmp_path: Path) -> None:
    job, root, receipt = _commit_job_receipt(tmp_path)
    mutations = (
        "command",
        "output_path",
        "output_count",
        "output_keys",
        "provenance",
        "stdout_path",
        "stdout_size",
        "cache_path",
        "attempt",
        "process",
    )
    try:
        for mutation in mutations:
            tampered = copy.deepcopy(receipt)
            if mutation == "command":
                tampered["command"] = ["python", "wrong.py"]
            elif mutation == "output_path":
                tampered["output"]["path"] = "/canonical/type_match_new.json"
            elif mutation == "output_count":
                tampered["output"]["entry_count"] = 999
            elif mutation == "output_keys":
                tampered["output"]["score_key_sha256"] = "0" * 64
            elif mutation == "provenance":
                tampered["output"]["provenance"]["mode"] = "usage"
            elif mutation == "stdout_path":
                tampered["stdout"]["path"] = "/tmp/wrong.log"
            elif mutation == "stdout_size":
                tampered["stdout"]["size"] = 999
            elif mutation == "cache_path":
                tampered["cache"]["path"] = "/tmp/shared-cache"
            elif mutation == "attempt":
                tampered["attempt"]["id"] = "b" * 32
            else:
                tampered["attempt"]["process_record"]["payload"]["pid"] = 1
            driver._write_json_atomic(job.receipt, tampered)
            with pytest.raises(driver.ShardedTypeMatchError):
                driver._validate_job_receipt(job, root=root, plan_sha256="plan")
        driver._write_json_atomic(job.receipt, receipt)
        assert driver._validate_job_receipt(job, root=root, plan_sha256="plan") is True
    finally:
        _restore_cache_permissions(job.cache_dir)


def test_job_receipt_rejects_jointly_tampered_process_record_and_receipt(
    tmp_path: Path,
) -> None:
    job, root, receipt = _commit_job_receipt(tmp_path)
    try:
        process = json.loads(job.process_record.read_text())
        process["pid"] = 1
        process["pgid"] = 1
        driver._write_json_atomic(job.process_record, process)
        tampered = copy.deepcopy(receipt)
        tampered["attempt"]["process_record"]["payload"] = process
        tampered["attempt"]["process_record"]["sha256"] = file_sha256(job.process_record)
        driver._write_json_atomic(job.receipt, tampered)

        with pytest.raises(driver.ShardedTypeMatchError, match="process identity is invalid"):
            driver._validate_job_receipt(job, root=root, plan_sha256="plan")
    finally:
        _restore_cache_permissions(job.cache_dir)


def test_merge_is_atomic_exact_union_and_rejects_overlap(tmp_path: Path) -> None:
    jobs: list[driver.WorkerJob] = []
    expected: set[driver.ScoreKey] = set()
    for mode in driver.MODES:
        for shard, function in ((1, "f"), (2, "g")):
            job = _job(tmp_path / mode, mode=mode, shard=shard, function=function)
            _write_job_overlay(job)
            jobs.append(job)
            expected.update(job.expected)

    merged = driver._merge_modes(
        jobs,
        output=tmp_path / "analysis",
        expected_by_backend={"angr": expected},
    )

    assert set(merged) == set(driver.MODES)
    for mode, path in merged.items():
        payload, provenance = read_typematch_overlay(path)
        assert len(payload["angr"]) == 2
        assert provenance is not None and provenance["mode"] == mode

    address_target = merged["address"]
    address_bytes = address_target.read_bytes()
    address_target.write_text("{}")
    with pytest.raises(driver.ShardedTypeMatchError):
        driver._merge_modes(
            jobs,
            output=tmp_path / "analysis",
            expected_by_backend={"angr": expected},
        )
    address_target.write_bytes(address_bytes)

    duplicate = _job(tmp_path / "duplicate", mode="address", shard=3, function="f")
    duplicate = replace(duplicate, expected=jobs[0].expected)
    _write_job_overlay(duplicate)
    with pytest.raises(driver.ShardedTypeMatchError, match="overlap"):
        driver._merge_modes(
            [*jobs, duplicate],
            output=tmp_path / "other-analysis",
            expected_by_backend={"angr": expected},
        )


@pytest.mark.parametrize("partial", ("overlay", "metadata"))
def test_merge_recovers_unreceipted_partial_pair(
    tmp_path: Path,
    partial: str,
) -> None:
    jobs: list[driver.WorkerJob] = []
    expected: set[driver.ScoreKey] = set()
    for mode in driver.MODES:
        job = _job(tmp_path / "jobs" / mode, mode=mode, shard=1, function="f")
        _write_job_overlay(job)
        jobs.append(job)
        expected.update(job.expected)
    output = tmp_path / "analysis"
    target = output / "merged" / "type_match_address.json"
    if partial == "overlay":
        driver._write_bytes_atomic(target, b"{}")
    else:
        driver._write_bytes_atomic(driver.typematch_overlay_manifest_path(target), b"{}")

    merged = driver._merge_modes(
        jobs,
        output=output,
        expected_by_backend={"angr": expected},
    )

    payload, _provenance = read_typematch_overlay(merged["address"])
    assert set(payload["angr"]) == {"proj::O0::bin1::f"}
    assert (output / "failed_attempts").is_dir()


def test_report_stage_without_process_identity_fails_closed(tmp_path: Path) -> None:
    output = tmp_path / "analysis"
    stage = output / "stages" / "report" / ("a" * 32)
    stage.mkdir(parents=True)
    committed = output / "report" / "typematch_ab.json"
    committed.parent.mkdir()
    committed.write_text("sentinel")

    with pytest.raises(driver.ShardedTypeMatchError, match="cannot prove.*process is dead"):
        driver._quarantine_owned_artifacts(
            output=output,
            label="report",
            paths=[committed, stage],
            reason="incomplete report",
            require_process_record_for_directories=True,
        )
    assert stage.is_dir()
    assert committed.read_text() == "sentinel"
    assert not (output / "failed_attempts").exists()


def test_runtime_inventory_binds_dependency_versions_and_effective_pythonpath(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = driver._runtime_inventory()
    distributions = {row["name"] for row in before["distributions"]}
    modules = {row["module"]: row["status"] for row in before["modules"]}

    assert {"pydantic", "pyelftools", "tree-sitter", "tree-sitter-c"} <= distributions
    assert modules["pydantic"] == "available"
    assert str(driver._REPO_ROOT) in before["environment"]["PYTHONPATH"].split(os.pathsep)

    monkeypatch.setenv("PYTHONPATH", "/tmp/adversarial-pythonpath")
    after = driver._runtime_inventory()
    assert before != after
    assert after["environment"]["PYTHONPATH"].endswith("/tmp/adversarial-pythonpath")


def test_output_scope_protects_linked_source_worktrees_and_dataset(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "decbench"
    worktree = tmp_path / "decbench-worktree"
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(checkout)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.name", "Test"],
        check=True,
    )
    marker = checkout / "tracked"
    marker.write_text("tracked")
    subprocess.run(["git", "-C", str(checkout), "add", "tracked"], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "commit", "-m", "fixture"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "worktree", "add", "-b", "fixture", str(worktree)],
        check=True,
        capture_output=True,
    )
    dataset_checkout = tmp_path / "decbench-dataset"
    dataset_worktree = tmp_path / "decbench-dataset-worktree"
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(dataset_checkout)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(dataset_checkout), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(dataset_checkout), "config", "user.name", "Test"],
        check=True,
    )
    dataset_marker = dataset_checkout / "tracked"
    dataset_marker.write_text("tracked")
    subprocess.run(["git", "-C", str(dataset_checkout), "add", "tracked"], check=True)
    subprocess.run(
        ["git", "-C", str(dataset_checkout), "commit", "-m", "fixture"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(dataset_checkout),
            "worktree",
            "add",
            "-b",
            "fixture",
            str(dataset_worktree),
        ],
        check=True,
        capture_output=True,
    )
    results = checkout / "results" / "full_run"
    results.mkdir(parents=True)
    baseline = checkout / "results" / "baseline" / "function_results.json"
    baseline.parent.mkdir()
    baseline.write_text("{}")

    driver._assert_output_scope(results.resolve(), (tmp_path / "analysis").resolve())
    driver._assert_output_scope(
        results.resolve(), (checkout / "results" / "typematch-analysis").resolve()
    )
    protected = (
        checkout / "site" / "analysis",
        checkout / "decbench" / "analysis",
        checkout / "scripts" / "analysis",
        worktree / "site" / "analysis",
        worktree / "tests" / "analysis",
        tmp_path / "decbench-dataset" / "analysis",
        dataset_worktree / "analysis",
        results / "analysis",
        results / "checkpoints" / "analysis",
    )
    for output in protected:
        with pytest.raises(driver.ShardedTypeMatchError):
            driver._assert_output_scope(results.resolve(), output.resolve())
    with pytest.raises(driver.ShardedTypeMatchError, match="function-data baseline tree"):
        driver._assert_output_scope(
            results.resolve(),
            (baseline.parent / "analysis").resolve(),
            function_data=baseline,
        )
    output_with_manifest = tmp_path / "manifest-analysis"
    nested_manifest = output_with_manifest / "inputs" / "selected.json"
    nested_manifest.parent.mkdir(parents=True)
    nested_manifest.write_text('{"functions": []}')
    with pytest.raises(driver.ShardedTypeMatchError, match="source manifest"):
        driver._assert_output_scope(
            results.resolve(),
            output_with_manifest.resolve(),
            manifest=nested_manifest,
        )


@pytest.mark.parametrize("kind", ("hardlink", "fifo"))
def test_output_lock_rejects_non_regular_or_multiply_linked_inode(
    tmp_path: Path,
    kind: str,
) -> None:
    output = tmp_path / "analysis"
    output.mkdir()
    lock = output / ".run.lock"
    if kind == "hardlink":
        source = tmp_path / "foreign-lock"
        source.write_bytes(b"")
        os.link(source, lock)
    else:
        os.mkfifo(lock)

    with (
        pytest.raises(driver.ShardedTypeMatchError, match="regular single-link"),
        driver._output_lock(output.resolve()),
    ):
        pytest.fail("unsafe lock inode was accepted")


def test_output_lock_rejects_symlinked_ancestry(tmp_path: Path) -> None:
    output = tmp_path / "real" / "analysis"
    output.mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(output.parent, target_is_directory=True)

    with pytest.raises(driver.ShardedTypeMatchError, match="ancestry may not contain a symlink"):
        driver._assert_no_symlink_ancestry(alias / "analysis")
    with (
        pytest.raises(driver.ShardedTypeMatchError, match="safely open analysis lock"),
        driver._output_lock(alias / "analysis"),
    ):
        pytest.fail("symlinked output ancestry was accepted")


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is required")
def test_tiny_end_to_end_run_uses_isolated_subprocesses_and_resumes_from_sealed_caches(
    tmp_path: Path,
) -> None:
    root = tmp_path / "results"
    compiled = root / "O0" / "proj" / "compiled"
    compiled.mkdir(parents=True)
    source = tmp_path / "sample.c"
    source.write_text(
        "int f(int x) { int y = x + 1; return y; }\n" "int main(void) { return f(1); }\n"
    )
    binary = compiled / "sample"
    subprocess.run(
        ["gcc", "-g", "-O0", "-fno-inline", "-o", str(binary), str(source)],
        check=True,
    )
    subprocess.run(["gcc", "-E", "-o", str(compiled / "sample.i"), str(source)], check=True)
    function = FunctionDecompilation(
        name="f",
        address=0,
        decompiled_code="int f(int x) { int y = x + 1; return y; }",
        variables=[
            VariableInfo(name="x", type="int", kind="arg", arg_index=0),
            VariableInfo(name="y", type="int", kind="stack"),
        ],
        metadata=with_variable_occurrence_policy({}, "unavailable"),
    )
    result = DecompilationResult(
        binary_path=binary,
        binary_name="sample",
        decompiler=DecompilerMetadata(decompiler_name="fixture"),
        functions={"f": function},
    )
    (root / "checkpoints").mkdir()
    with (root / "checkpoints" / "proj.pkl").open("wb") as stream:
        pickle.dump({"decompile": {"O0": {"sample": {"fixture": result}}}}, stream)
    function_data_payload = {
        "perfect_values": {"type_match": 1.0},
        "groups": [
            {
                "project": "proj",
                "opt_level": "O0",
                "binary": "sample",
                "functions": [
                    {
                        "function": "f",
                        "values": {"fixture": {"type_match": 0.0}},
                    }
                ],
            }
        ],
    }
    baseline = tmp_path / "baseline" / "function_results.json"
    baseline.parent.mkdir()
    baseline.write_text(json.dumps(function_data_payload))
    (root / "function_results.json").write_text(json.dumps({"groups": []}))
    manifest = tmp_path / "selected.json"
    manifest.write_text(
        json.dumps(
            {
                "functions": [
                    {
                        "project": "proj",
                        "opt": "O0",
                        "binary": "sample",
                        "function": "f",
                    }
                ]
            }
        )
    )
    (root / "sample_set_manifest.json").write_bytes(manifest.read_bytes())
    output = tmp_path / "analysis"
    output.mkdir()
    (output / ".run_plan.json.interrupted.tmp").write_text("partial plan")
    (output / ".receipt.json.interrupted.tmp").write_text("partial receipt")
    arguments = [
        str(root),
        str(manifest),
        str(output),
        "--function-data",
        str(baseline),
        "--scope",
        "full",
        "--shards",
        "1",
        "--workers",
        "2",
        "--backend",
        "fixture",
        "--job-timeout",
        "120",
    ]

    try:
        assert driver.main(arguments) == 0
        receipt_before = (output / "receipt.json").read_bytes()
        plan = json.loads((output / "run_plan.json").read_text())
        assert plan["scope"]["name"] == "full"
        assert plan["function_data"]["path"] == str(baseline)
        assert plan["function_data"]["sha256"] == file_sha256(baseline)
        assert plan["report_policy"] == {"regression_limit": 100}
        assert plan["calibration_contract"]["input"].startswith("complete producer")
        assert plan["cache_contract"]["initial_state"] == "new empty directory"
        assert plan["runtime"]["distributions"]
        assert "PYTHONPATH" in plan["runtime"]["environment"]
        final_before = json.loads(receipt_before)
        assert final_before["canonical_outputs_touched"] is False
        assert final_before["scope"] == {"name": "full", "fairness": "full-corpus"}
        report_before_payload = json.loads((output / "report" / "typematch_ab.json").read_text())
        assert report_before_payload["scope"]["declared_run_scope"] == "full"
        assert report_before_payload["scope"]["declared_scope_fairness"] == "full-corpus"
        assert not (root / "type_match_new.json").exists()
        quarantined = list((output / "failed_attempts").glob("*/quarantine.json"))
        assert quarantined
        assert driver.main(arguments) == 0
        assert (output / "receipt.json").read_bytes() == receipt_before

        merge_receipt_path = (output / "merged" / "type_match_address.json").with_suffix(
            ".receipt.json"
        )
        merge_receipt_before = merge_receipt_path.read_bytes()
        merge_receipt = json.loads(merge_receipt_before)
        merge_receipt["expected_entry_count"] = 999
        driver._write_json_atomic(merge_receipt_path, merge_receipt)
        final_receipt = json.loads(receipt_before)
        final_receipt["merged"]["address"]["receipt"]["sha256"] = file_sha256(merge_receipt_path)
        driver._write_json_atomic(output / "receipt.json", final_receipt)
        with pytest.raises(driver.ShardedTypeMatchError, match="merge receipt content mismatch"):
            driver.main(arguments)
        driver._write_bytes_atomic(merge_receipt_path, merge_receipt_before)
        driver._write_bytes_atomic(output / "receipt.json", receipt_before)

        report_receipt_path = output / "report" / "receipt.json"
        report_receipt_before = report_receipt_path.read_bytes()
        report_receipt = json.loads(report_receipt_before)
        report_receipt["command"].append("--tampered")
        driver._write_json_atomic(report_receipt_path, report_receipt)
        final_receipt = json.loads(receipt_before)
        final_receipt["report"]["receipt"]["sha256"] = file_sha256(report_receipt_path)
        driver._write_json_atomic(output / "receipt.json", final_receipt)
        with pytest.raises(driver.ShardedTypeMatchError, match="report receipt content mismatch"):
            driver.main(arguments)
        driver._write_bytes_atomic(report_receipt_path, report_receipt_before)
        driver._write_bytes_atomic(output / "receipt.json", receipt_before)

        report_path = output / "report" / "typematch_ab.json"
        report_before = report_path.read_bytes()
        report_payload = json.loads(report_before)
        report_payload["provenance"]["function_data"]["sha256"] = "0" * 64
        driver._write_json_atomic(report_path, report_payload)
        report_receipt = json.loads(report_receipt_before)
        report_receipt["report"]["sha256"] = file_sha256(report_path)
        report_receipt["report"]["size"] = report_path.stat().st_size
        driver._write_json_atomic(report_receipt_path, report_receipt)
        final_receipt = json.loads(receipt_before)
        final_receipt["report"]["sha256"] = file_sha256(report_path)
        final_receipt["report"]["receipt"]["sha256"] = file_sha256(report_receipt_path)
        driver._write_json_atomic(output / "receipt.json", final_receipt)
        with pytest.raises(
            driver.ShardedTypeMatchError,
            match="frozen-input/checkpoint provenance changed",
        ):
            driver.main(arguments)
        driver._write_bytes_atomic(report_path, report_before)
        driver._write_bytes_atomic(report_receipt_path, report_receipt_before)
        driver._write_bytes_atomic(output / "receipt.json", receipt_before)

        with pytest.raises(driver.ShardedTypeMatchError, match="run plan differs"):
            driver.main([*arguments, "--regression-limit", "7"])

        final_receipt = json.loads(receipt_before)
        final_receipt["expected"]["entry_count_per_mode"] = 999
        driver._write_json_atomic(output / "receipt.json", final_receipt)
        with pytest.raises(driver.ShardedTypeMatchError, match="final receipt content mismatch"):
            driver.main(arguments)
        driver._write_bytes_atomic(output / "receipt.json", receipt_before)

        (output / "receipt.json").unlink()
        report_attempt = json.loads((output / "report" / "receipt.json").read_text())["attempt_id"]
        (output / "report" / "receipt.json").unlink()
        process_temporary = output / "report" / ".typematch_ab.process.json.interrupted.tmp"
        process_temporary.write_text("partial process copy")
        (output / "stages" / "report" / report_attempt).mkdir(parents=True)
        assert driver.main(arguments) == 0
        assert (output / "report" / "typematch_ab.md").is_file()
        assert not process_temporary.exists()
        assert (output / "failed_attempts").is_dir()

        (output / "receipt.json").unlink()
        address = output / "merged" / "type_match_address.json"
        address.with_suffix(".receipt.json").unlink()
        driver.typematch_overlay_manifest_path(address).unlink()
        assert driver.main(arguments) == 0
        assert driver.typematch_overlay_manifest_path(address).is_file()
        for cache in (output / "workers").rglob("*.cache"):
            assert not (cache.stat().st_mode & 0o222)
    finally:
        for cache in (output / "workers").rglob("*.cache") if output.exists() else ():
            _restore_cache_permissions(cache)


@pytest.mark.parametrize("workers", ("0", "33"))
def test_worker_bound_is_enforced(tmp_path: Path, workers: str) -> None:
    with pytest.raises(SystemExit):
        driver.parse_args([str(tmp_path), str(tmp_path), str(tmp_path), "--workers", workers])
