"""Tests for decbench.pipeline.materialized (materialized dataset trees)."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from decbench.models.project import OptimizationLevel
from decbench.pipeline.materialized import (
    discover_decompilations,
    discover_tree_projects,
    load_decompilation,
    load_source_cfgs,
)

DEC_C = """\
// Function: main @ 0x401000
int main(int argc, char **argv) {
    if (argc > 1) {
        return 1;
    }
    return 0;
}

// Function: helper @ 0x401080
int helper(void) { return 42; }
"""

DEC_TOML = """\
binary = "demo"
decompiler = "ghidra"
version = "12.1"
total_time = 1.5
timeout = false
failed_functions = [ "broken_fn",]
"""

# A 4-node diamond: 0 -> {1, 2} -> 3, entry 0, exit 3.
CFG_JSON = {
    "opt": "O0",
    "project": "demo",
    "binary": "demo",
    "generator": "test",
    "functions": {
        "main": {
            "nodes": [0, 1, 2, 3],
            "edges": [[0, 1], [0, 2], [1, 3], [2, 3]],
            "labels": {"0": "entry", "3": "exit"},
            "entry": [0],
            "exit": [3],
        }
    },
}


def _write_tree(root: Path) -> Path:
    proj = root / "O0" / "demo"
    (proj / "compiled").mkdir(parents=True)
    # A minimal but well-formed ELF64 header (e_type=EXEC at offset 16), padded
    # so binfmt/resolve_binary header reads never run short.
    elf = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 + struct.pack("<HH", 2, 0x3E)
    (proj / "compiled" / "demo").write_bytes(elf.ljust(64, b"\x00"))
    (proj / "decompiled").mkdir()
    (proj / "decompiled" / "ghidra_demo.c").write_text(DEC_C)
    (proj / "decompiled" / "ghidra_demo.toml").write_text(DEC_TOML)
    (proj / "source_cfgs").mkdir()
    (proj / "source_cfgs" / "demo.json").write_text(json.dumps(CFG_JSON))
    return proj


def test_load_decompilation_parses_markers_and_toml(tmp_path: Path) -> None:
    proj = _write_tree(tmp_path)
    dr = load_decompilation(
        proj / "decompiled" / "ghidra_demo.c", "ghidra", proj / "compiled" / "demo"
    )
    assert set(dr.functions) == {"main", "helper"}
    assert dr.functions["main"].address == 0x401000
    assert "argc > 1" in dr.functions["main"].decompiled_code
    assert dr.functions["helper"].line_count == 1
    assert dr.binary_name == "demo"
    assert dr.decompiler.decompiler_name == "ghidra"
    assert dr.decompiler.decompiler_version == "12.1"
    assert dr.decompiler.failed_functions == ["broken_fn"]


def test_discover_decompilations_shape_and_filter(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    results = discover_decompilations(tmp_path, [OptimizationLevel.O0])
    assert set(results) == {"demo"}
    per_opt = results["demo"][OptimizationLevel.O0]
    assert set(per_opt) == {"demo"}
    assert set(per_opt["demo"]) == {"ghidra"}
    assert per_opt["demo"]["ghidra"].function_count == 2

    # Decompiler filter excludes non-matching artifacts entirely.
    assert discover_decompilations(tmp_path, [OptimizationLevel.O0], decompilers=["ida"]) == {}


def test_load_source_cfgs_rebuilds_ged_ready_graphs(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    by_binary = load_source_cfgs(tmp_path, "O0", "demo")
    assert by_binary is not None and set(by_binary) == {"demo"}
    cfg = by_binary["demo"]["main"]
    assert cfg.number_of_nodes() == 4
    assert cfg.number_of_edges() == 4
    entries = [n for n in cfg.nodes if n.is_entrypoint]
    exits = [n for n in cfg.nodes if n.is_exitpoint]
    assert [n.id for n in entries] == [0]
    assert [n.id for n in exits] == [3]

    # Missing dir -> None (caller falls back to .i extraction).
    assert load_source_cfgs(tmp_path, "O2", "demo") is None


def test_discover_tree_projects(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    projects, opts = discover_tree_projects(tmp_path)
    assert projects == ["demo"]
    assert opts == ["O0"]
