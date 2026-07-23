"""Tests for render-time decompiler hiding (:mod:`decbench.rendering.visibility`).

Nothing is hidden in the shipped config right now, so these exercise the
mechanism with a synthetic decompiler name ("hiddendec"): the filter must strip
a hidden decompiler from every list / map / payload while leaving the visible
ones — and the inputs — untouched.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from decbench.models.function_data import (
    BinaryGroup,
    DatasetPreset,
    FunctionData,
    FunctionRecord,
    HistoryPoint,
    SampleEntry,
)
from decbench.models.scoreboard import DecompilerScore, Scoreboard
from decbench.rendering.content import load_content
from decbench.rendering.site import build_site
from decbench.rendering.visibility import apply_hidden_decompilers, is_hidden


def _fd() -> FunctionData:
    return FunctionData(
        decompilers=["angr", "hiddendec", "ghidra"],
        decompiler_versions={"angr": "9.2", "hiddendec": "9.2", "ghidra": "12.1"},
        metrics=["ged"],
        perfect_values={"ged": 0.0},
        compile_rates={"angr": 0.4, "hiddendec": 0.3, "ghidra": 0.5},
        groups=[
            BinaryGroup(
                project="proj",
                opt_level="O0",
                binary="bin1",
                functions=[
                    FunctionRecord(
                        function="f1",
                        values={d: {"ged": 0.0} for d in ("angr", "hiddendec", "ghidra")},
                        perfects={d: {"ged": True} for d in ("angr", "hiddendec", "ghidra")},
                        distances={d: {"ged": 0.0} for d in ("angr", "hiddendec", "ghidra")},
                        decompiled={"angr": True, "hiddendec": True, "ghidra": True},
                        datasets=["unoptimized"],
                    )
                ],
            )
        ],
        dataset_presets=[DatasetPreset(name="unoptimized")],
        samples=[
            SampleEntry(
                project="proj",
                opt_level="O0",
                binary="bin1",
                function="f1",
                difficulty="easy",
                decompiled={"angr": "A", "hiddendec": "H", "ghidra": "G"},
                values={d: {"ged": 0.0} for d in ("angr", "hiddendec", "ghidra")},
                perfects={d: {"ged": True} for d in ("angr", "hiddendec", "ghidra")},
            )
        ],
        history=[
            HistoryPoint(decompiler="hiddendec", version="9.2", scores={"ged": 50.0}),
            HistoryPoint(decompiler="ghidra@12.1", version="12.1", scores={"ged": 60.0}),
        ],
    )


def _sb() -> Scoreboard:
    return Scoreboard(
        name="t",
        metrics=["ged"],
        decompilers=["angr", "hiddendec", "ghidra"],
        decompiler_scores={d: DecompilerScore(name=d) for d in ("angr", "hiddendec", "ghidra")},
    )


def _content_hiding(*hidden: str):
    """A Content whose site hides ``hidden`` (site is a frozen dataclass)."""
    content = load_content()
    site = dataclasses.replace(content.site, hidden_decompilers=tuple(hidden))
    return dataclasses.replace(content, site=site)


def test_is_hidden_matches_id_and_base_name() -> None:
    assert is_hidden("hiddendec", {"hiddendec"})
    assert is_hidden("hiddendec@9.2", {"hiddendec"})  # base-name match
    assert not is_hidden("ghidra@12.1", {"hiddendec"})
    assert not is_hidden("angr", {"hiddendec"})


def test_hidden_decompiler_stripped_everywhere() -> None:
    fd, sb = _fd(), _sb()
    out_sb, out_fd = apply_hidden_decompilers(sb, fd, _content_hiding("hiddendec"))

    assert "hiddendec" not in out_sb.decompilers
    assert "hiddendec" not in out_sb.decompiler_scores
    assert out_fd is not None
    assert out_fd.decompilers == ["angr", "ghidra"]
    assert "hiddendec" not in out_fd.decompiler_versions
    assert "hiddendec" not in out_fd.compile_rates
    rec = out_fd.groups[0].functions[0]
    for m in (rec.values, rec.perfects, rec.distances, rec.decompiled):
        assert "hiddendec" not in m and "angr" in m
    s = out_fd.samples[0]
    assert set(s.decompiled) == {"angr", "ghidra"}
    assert [h.decompiler for h in out_fd.history] == ["ghidra@12.1"]  # base-name hide


def test_filter_is_a_copy_inputs_untouched() -> None:
    fd, sb = _fd(), _sb()
    apply_hidden_decompilers(sb, fd, _content_hiding("hiddendec"))
    assert "hiddendec" in fd.decompilers  # original untouched
    assert "hiddendec" in sb.decompilers


def test_no_hidden_is_a_noop() -> None:
    fd, sb = _fd(), _sb()
    out_sb, out_fd = apply_hidden_decompilers(sb, fd, _content_hiding())
    assert out_sb is sb and out_fd is fd  # same objects, no copy


def test_shipped_config_hides_nothing() -> None:
    """The shipped hidden list is exactly empty — any future hide is deliberate.

    The last hidden decompiler was fully removed 2026-07-23; the hide mechanism
    stays, but nothing should be silently hidden by default.
    """
    assert load_content().site.hidden_decompilers == ()


def test_build_site_omits_hidden_decompiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: a hidden decompiler must not appear in any shipped payload."""
    # build_site consults the shipped content for hiding; point it at a content
    # that hides the synthetic decompiler (the shipped list is empty).
    monkeypatch.setattr(
        "decbench.rendering.visibility.load_content", lambda: _content_hiding("hiddendec")
    )
    out = tmp_path / "site"
    build_site(_sb(), _fd(), out)
    agg = json.loads((out / "data" / "aggregates.json").read_text())
    assert "hiddendec" not in agg["decompilers"]
    assert set(agg["decompilers"]) == {"angr", "ghidra"}
    # The decompiler registry is gated on the (already-filtered) decompiler list,
    # so a hidden backend can never re-enter through it.
    assert set(agg["decompiler_registry"]) == {"angr", "ghidra"}
    blob = "".join(
        (out / "data" / f"{name}.json").read_text() for name in ("aggregates", "samples")
    )
    assert "hiddendec" not in blob
