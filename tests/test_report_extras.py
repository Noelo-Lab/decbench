"""Tests for report extras: side-by-side samples, hardest source, compile rates."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from decbench.models.function_data import (
    BinaryGroup,
    FunctionData,
    FunctionRecord,
    HardestEntry,
    SampleEntry,
)
from decbench.scoring.report_extras import (
    PUBLISH_MALWARE_ENV,
    attach_extras,
    build_hardest,
    build_samples,
    compute_compile_rates,
    malware_projects,
)

SOURCE = """\
int target(int a, int b) {
    int s = a + b;
    return s * 2;
}
"""


def _make_decompile_results(binary_path: Path):
    """proj -> opt -> binary -> dec -> DecompilationResult-ish mock."""
    func = SimpleNamespace(decompiled_code="int target(int a,int b){return a+b+b;}", line_count=1)
    dec_result = SimpleNamespace(binary_path=binary_path, functions={"target": func})
    return {"proj": {"O0": {"bin1": {"angr": dec_result}}}}


def _function_data():
    fr = FunctionRecord(
        function="target",
        values={"angr": {"ged": 0.0, "type_match": 1.0, "byte_match": 0.5}},
        perfects={"angr": {"ged": True, "type_match": True, "byte_match": False}},
        labels=["O0"],
        datasets=["full", "tiny"],
        size=4,
    )
    return FunctionData(
        decompilers=["angr"],
        metrics=["ged", "type_match", "byte_match"],
        perfect_values={"ged": 0.0, "type_match": 1.0, "byte_match": 1.0},
        groups=[BinaryGroup(project="proj", opt_level="O0", binary="bin1", functions=[fr])],
    )


def test_build_samples_includes_source_and_decompiled(tmp_path: Path) -> None:
    # A fake binary with a sibling .c source (source_extract finds it w/o DWARF).
    binary = tmp_path / "bin1"
    binary.write_bytes(b"\x7fELF not-really")
    (tmp_path / "bin1.c").write_text(SOURCE)

    fd = _function_data()
    samples = build_samples(fd, _make_decompile_results(binary))
    assert len(samples) == 1
    s = samples[0]
    assert s.function == "target"
    assert "angr" in s.decompiled
    assert "return a+b+b" in s.decompiled["angr"]
    assert s.source_code is not None
    assert "return s * 2;" in s.source_code
    # Carries the per-metric scores for display.
    assert s.values["angr"]["byte_match"] == 0.5


def test_build_hardest_fills_source(tmp_path: Path) -> None:
    binary = tmp_path / "bin1"
    binary.write_bytes(b"\x7fELF")
    (tmp_path / "bin1.c").write_text(SOURCE)

    bm = SimpleNamespace(function_results={"target": SimpleNamespace(value=0.5)})
    evaluation = {"proj": {"O0": {"bin1": {"angr": {"byte_match": bm}}}}}
    entries = build_hardest(evaluation, _make_decompile_results(binary))
    assert entries
    e = entries[0]
    assert e.function == "target"
    assert e.decompiled_code is not None
    assert e.source_code is not None and "return s * 2;" in e.source_code


def test_compute_compile_rates() -> None:
    def mv(compilable: bool):
        return SimpleNamespace(metadata={"compilable": compilable})

    bm = SimpleNamespace(function_results={"a": mv(True), "b": mv(False), "c": mv(True)})
    evaluation = {"proj": {"O0": {"bin1": {"angr": {"byte_match": bm}}}}}
    rates = compute_compile_rates(evaluation)
    assert abs(rates["angr"] - (2 / 3)) < 1e-9


# --- Malware code must never reach a published payload -----------------------
#
# The `samples`/`hardest` payloads carry real C source, get committed to site/,
# and are published by GitHub Pages (which is PUBLIC even for a private repo on
# Pro/Team). Six benchmark targets are REAL malware from theZoo. These tests are
# the tripwire: if the filter is ever "optimized" away, they fail.


def _malware_function_data() -> FunctionData:
    """One clean group and one malware-labeled group, each with a function."""

    def rec(name: str) -> FunctionRecord:
        return FunctionRecord(
            function=name,
            values={"angr": {"byte_match": 0.5}},
            perfects={"angr": {"byte_match": False}},
            datasets=["full", "tiny"],
            size=4,
        )

    return FunctionData(
        decompilers=["angr"],
        metrics=["byte_match"],
        perfect_values={"byte_match": 1.0},
        groups=[
            BinaryGroup(project="proj", opt_level="O0", binary="bin1", functions=[rec("target")]),
            BinaryGroup(
                project="mirai",
                opt_level="O0",
                binary="mirai_bin",
                labels=["malware", "do-not-execute"],
                functions=[rec("attack_gre")],
            ),
        ],
    )


def _malware_decompile_results(binary: Path):
    func = SimpleNamespace(decompiled_code="int target(int a,int b){return a+b+b;}", line_count=1)
    clean = SimpleNamespace(binary_path=binary, functions={"target": func})
    evil = SimpleNamespace(
        binary_path=binary,
        functions={"attack_gre": SimpleNamespace(decompiled_code="MALWARE_C", line_count=1)},
    )
    return {
        "proj": {"O0": {"bin1": {"angr": clean}}},
        "mirai": {"O0": {"mirai_bin": {"angr": evil}}},
    }


def test_malware_projects_detected_from_group_label() -> None:
    assert malware_projects(_malware_function_data()) == {"mirai"}


def test_build_samples_excludes_malware_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(PUBLISH_MALWARE_ENV, raising=False)
    binary = tmp_path / "bin1"
    binary.write_bytes(b"\x7fELF")

    samples = build_samples(_malware_function_data(), _malware_decompile_results(binary))

    assert [s.project for s in samples] == ["proj"]
    assert not any("MALWARE_C" in c for s in samples for c in s.decompiled.values())


def test_build_hardest_excludes_malware_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(PUBLISH_MALWARE_ENV, raising=False)
    binary = tmp_path / "bin1"
    binary.write_bytes(b"\x7fELF")

    bm = SimpleNamespace(function_results={"attack_gre": SimpleNamespace(value=0.0)})
    clean_bm = SimpleNamespace(function_results={"target": SimpleNamespace(value=0.5)})
    evaluation = {
        "proj": {"O0": {"bin1": {"angr": {"byte_match": clean_bm}}}},
        "mirai": {"O0": {"mirai_bin": {"angr": {"byte_match": bm}}}},
    }
    entries = build_hardest(
        evaluation, _malware_decompile_results(binary), excluded_projects={"mirai"}
    )

    assert entries and all(e.project == "proj" for e in entries)
    assert not any("MALWARE_C" in (e.decompiled_code or "") for e in entries)


def test_publish_malware_env_re_includes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(PUBLISH_MALWARE_ENV, "1")
    binary = tmp_path / "bin1"
    binary.write_bytes(b"\x7fELF")

    samples = build_samples(_malware_function_data(), _malware_decompile_results(binary))

    assert "mirai" in {s.project for s in samples}
    assert any("MALWARE_C" in c for s in samples for c in s.decompiled.values())


def test_attach_extras_keeps_malware_out_of_code_payloads(tmp_path: Path, monkeypatch) -> None:
    """End-to-end: the real wiring, not the builders in isolation."""
    monkeypatch.delenv(PUBLISH_MALWARE_ENV, raising=False)
    binary = tmp_path / "bin1"
    binary.write_bytes(b"\x7fELF")

    fd = _malware_function_data()
    bm = SimpleNamespace(function_results={"attack_gre": SimpleNamespace(value=0.0)})
    evaluation = {"mirai": {"O0": {"mirai_bin": {"angr": {"byte_match": bm}}}}}
    attach_extras(
        fd,
        evaluation_results=evaluation,
        decompile_results=_malware_decompile_results(binary),
    )

    blob = json.dumps([s.model_dump(mode="json") for s in fd.samples]) + json.dumps(
        [h.model_dump(mode="json") for h in fd.hardest]
    )
    assert "MALWARE_C" not in blob
    assert "mirai" not in blob
    # The score path is untouched: the malware function still counts.
    assert any(g.project == "mirai" for g in fd.groups)


def test_build_payloads_scrubs_prebaked_malware(tmp_path: Path, monkeypatch) -> None:
    """A function_results.json written BEFORE this filter still must not publish.

    `decbench report` / `decbench site build` read that file straight from disk and
    never call attach_extras, so the guard in build_payloads is the only thing
    standing between an old results tree and a public site.
    """
    monkeypatch.delenv(PUBLISH_MALWARE_ENV, raising=False)
    from decbench.models.scoreboard import Scoreboard
    from decbench.rendering.aggregate import build_payloads

    fd = _malware_function_data()
    # Simulate the already-baked payload: malware code sitting in the file.
    fd.samples = [
        SampleEntry(
            project="mirai",
            opt_level="O0",
            binary="mirai_bin",
            function="attack_gre",
            decompiled={"angr": "MALWARE_C"},
        )
    ]
    fd.hardest = [
        HardestEntry(
            metric="byte_match",
            decompiler="angr",
            project="mirai",
            opt_level="O0",
            binary="mirai_bin",
            function="attack_gre",
            value=0.0,
            perfect_value=1.0,
            decompiled_code="MALWARE_C",
        )
    ]

    payloads = build_payloads(fd, Scoreboard(name="t"))

    assert payloads["samples"] == []
    # hardest is stored in function_results.json but never shipped as a payload
    # anymore (the View page's hard tier replaced it) — so prebaked malware in
    # it cannot publish either.
    assert "hardest" not in payloads
    assert "MALWARE_C" not in json.dumps(payloads)
