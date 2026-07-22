"""Tests for render-time decompiler hiding (:mod:`decbench.rendering.visibility`).

Phoenix is hidden from the site in ``content/site.toml`` but kept on disk. These
guard that the filter strips a hidden decompiler from every list / map / payload
while leaving the visible ones — and the inputs — untouched.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

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
        decompilers=["angr", "phoenix", "ghidra"],
        decompiler_versions={"angr": "9.2", "phoenix": "9.2", "ghidra": "12.1"},
        metrics=["ged"],
        perfect_values={"ged": 0.0},
        compile_rates={"angr": 0.4, "phoenix": 0.3, "ghidra": 0.5},
        groups=[
            BinaryGroup(
                project="proj",
                opt_level="O0",
                binary="bin1",
                functions=[
                    FunctionRecord(
                        function="f1",
                        values={d: {"ged": 0.0} for d in ("angr", "phoenix", "ghidra")},
                        perfects={d: {"ged": True} for d in ("angr", "phoenix", "ghidra")},
                        distances={d: {"ged": 0.0} for d in ("angr", "phoenix", "ghidra")},
                        decompiled={"angr": True, "phoenix": True, "ghidra": True},
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
                decompiled={"angr": "A", "phoenix": "P", "ghidra": "G"},
                values={d: {"ged": 0.0} for d in ("angr", "phoenix", "ghidra")},
                perfects={d: {"ged": True} for d in ("angr", "phoenix", "ghidra")},
            )
        ],
        history=[
            HistoryPoint(decompiler="phoenix", version="9.2", scores={"ged": 50.0}),
            HistoryPoint(decompiler="ghidra@12.1", version="12.1", scores={"ged": 60.0}),
        ],
    )


def _sb() -> Scoreboard:
    return Scoreboard(
        name="t",
        metrics=["ged"],
        decompilers=["angr", "phoenix", "ghidra"],
        decompiler_scores={d: DecompilerScore(name=d) for d in ("angr", "phoenix", "ghidra")},
    )


def _content_hiding(*hidden: str):
    """A Content whose site hides ``hidden`` (site is a frozen dataclass)."""
    content = load_content()
    site = dataclasses.replace(content.site, hidden_decompilers=tuple(hidden))
    return dataclasses.replace(content, site=site)


def test_is_hidden_matches_id_and_base_name() -> None:
    assert is_hidden("phoenix", {"phoenix"})
    assert is_hidden("phoenix@9.2", {"phoenix"})  # base-name match
    assert not is_hidden("ghidra@12.1", {"phoenix"})
    assert not is_hidden("angr", {"phoenix"})


def test_hidden_decompiler_stripped_everywhere() -> None:
    fd, sb = _fd(), _sb()
    out_sb, out_fd = apply_hidden_decompilers(sb, fd, _content_hiding("phoenix"))

    assert "phoenix" not in out_sb.decompilers
    assert "phoenix" not in out_sb.decompiler_scores
    assert out_fd is not None
    assert out_fd.decompilers == ["angr", "ghidra"]
    assert "phoenix" not in out_fd.decompiler_versions
    assert "phoenix" not in out_fd.compile_rates
    rec = out_fd.groups[0].functions[0]
    for m in (rec.values, rec.perfects, rec.distances, rec.decompiled):
        assert "phoenix" not in m and "angr" in m
    s = out_fd.samples[0]
    assert set(s.decompiled) == {"angr", "ghidra"}
    assert [h.decompiler for h in out_fd.history] == ["ghidra@12.1"]  # base-name hide


def test_filter_is_a_copy_inputs_untouched() -> None:
    fd, sb = _fd(), _sb()
    apply_hidden_decompilers(sb, fd, _content_hiding("phoenix"))
    assert "phoenix" in fd.decompilers  # original untouched
    assert "phoenix" in sb.decompilers


def test_no_hidden_is_a_noop() -> None:
    fd, sb = _fd(), _sb()
    out_sb, out_fd = apply_hidden_decompilers(sb, fd, _content_hiding())
    assert out_sb is sb and out_fd is fd  # same objects, no copy


def test_phoenix_is_hidden_in_the_shipped_config() -> None:
    """The site config actually hides phoenix (the whole point of this feature)."""
    assert "phoenix" in load_content().site.hidden_decompilers


def test_build_site_omits_hidden_decompiler(tmp_path: Path) -> None:
    """End-to-end: phoenix must not appear in any shipped payload."""
    out = tmp_path / "site"
    build_site(_sb(), _fd(), out)
    agg = json.loads((out / "data" / "aggregates.json").read_text())
    assert "phoenix" not in agg["decompilers"]
    assert set(agg["decompilers"]) == {"angr", "ghidra"}
    # The decompiler registry is gated on the (already-filtered) decompiler list,
    # so a hidden backend can never re-enter through it.
    assert set(agg["decompiler_registry"]) == {"angr", "ghidra"}
    blob = "".join(
        (out / "data" / f"{name}.json").read_text() for name in ("aggregates", "samples")
    )
    assert "phoenix" not in blob
