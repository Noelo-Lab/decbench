"""Reproducible exact-checkout regression and stripped LevelDB identity probes."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from types import ModuleType
from typing import Any


def _driver() -> ModuleType:
    path = Path(__file__).with_name("run_benchmark.py")
    spec = importlib.util.spec_from_file_location("identity_validation_driver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cases(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for case in ET.parse(path).getroot().iter("testcase"):
        key = f"{case.get('classname')}::{case.get('name')}"
        if key in rows:
            raise ValueError(f"duplicate JUnit identity: {key}")
        rows[key] = next(
            (tag for tag in ("error", "failure", "skipped") if case.find(tag) is not None),
            "passed",
        )
    if not rows:
        raise ValueError(f"no test results in {path}")
    return rows


def compare(main: Path, candidate: Path) -> dict[str, Any]:
    before, after = _cases(main), _cases(candidate)
    existing = {key for key, status in before.items() if status in {"failure", "error"}}
    failures = {key for key, status in after.items() if status in {"failure", "error"}}
    lost_passes = sorted(
        key for key, value in before.items() if value == "passed" and after.get(key) != "passed"
    )
    report: dict[str, Any] = {
        "main_counts": {
            status: list(before.values()).count(status)
            for status in ("passed", "failure", "error", "skipped")
        },
        "candidate_counts": {
            status: list(after.values()).count(status)
            for status in ("passed", "failure", "error", "skipped")
        },
        "existing_failure_identities": sorted(existing),
        "new_failure_identities": sorted(failures - existing),
        "lost_passing_identities": lost_passes,
        "new_test_identities": sorted(set(after) - set(before)),
    }
    report["passed"] = not report["new_failure_identities"] and not lost_passes
    return report


def leveldb(binary: Path, strip: str) -> dict[str, Any]:
    from decbench.decompilers.raw.angr_raw import RawAngrDecompiler
    from decbench.decompilers.raw.ghidra_raw import RawGhidraDecompiler
    from decbench.evalkit.export import _verify_strip
    from decbench.utils.function_identity import (
        canonical_target_keys,
        dwarf_function_identities,
        identities_by_name,
    )

    identities = dwarf_function_identities(binary)
    universe = {row.address: row.name for row in identities}
    grouped = identities_by_name(identities)
    groups = [
        rows
        for _name, rows in sorted(grouped.items())
        if len({row.address for row in rows}) >= 2 and all(row.linkage_name for row in rows)
    ]
    if not groups:
        raise ValueError("no concrete LevelDB collision pair")
    pair = sorted(groups[0], key=lambda row: row.address)[:2]
    selected = {row.address: row.name for row in pair}
    expected = {address: canonical_target_keys(universe)[address] for address in selected}
    outputs: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="identity-leveldb-") as directory:
        stripped = Path(directory) / binary.name
        shutil.copy2(binary, stripped)
        subprocess.run([strip, "--strip-all", str(stripped)], check=True)
        _verify_strip(binary, stripped)
        stripped_hash = hashlib.sha256(stripped.read_bytes()).hexdigest()
        for backend in (RawAngrDecompiler(), RawGhidraDecompiler()):
            result = backend.decompile_binary(
                stripped,
                functions=[(f"sub_{address:x}", address) for address in selected],
                output_dir=None,
            )
            raw = result.model_dump(mode="json")
            _driver()._relabel_to_dwarf(result, selected, binary, identity_addr2name=universe)
            actual = {function.address: key for key, function in result.functions.items()}
            if actual != expected or any(
                not f.decompiled_code.strip() for f in result.functions.values()
            ):
                raise AssertionError(f"{backend.name} identity mismatch: {actual} != {expected}")
            for address in selected:
                single = result.model_copy(deep=True)
                _driver()._relabel_to_dwarf(
                    single, {address: selected[address]}, binary, identity_addr2name=universe
                )
                if set(single.functions) != {expected[address]}:
                    raise AssertionError("canonical identity changed in singleton slice")
            outputs[backend.name] = {
                "version": backend.get_version(),
                "raw": raw,
                "canonical_keys": sorted(result.functions),
                "failed_functions": result.decompiler.failed_functions,
            }
    return {
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "stripped_sha256": stripped_hash,
        "requested_addresses": sorted(selected),
        "expected_keys": sorted(expected.values()),
        "outputs": outputs,
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    differential = commands.add_parser("compare")
    differential.add_argument("main", type=Path)
    differential.add_argument("candidate", type=Path)
    probe = commands.add_parser("leveldb")
    probe.add_argument("binary", type=Path)
    probe.add_argument("--strip", default="strip")
    for subcommand in (differential, probe):
        subcommand.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = (
        compare(args.main, args.candidate)
        if args.command == "compare"
        else leveldb(args.binary.resolve(), args.strip)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {key: value for key, value in report.items() if key != "outputs"},
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
