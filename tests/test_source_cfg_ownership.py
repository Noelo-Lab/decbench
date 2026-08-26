"""Deterministic source-CFG ownership regressions that need no compiler or binary fixture."""

from pathlib import Path
from types import SimpleNamespace

import networkx as nx
import pytest


def _graph(size: int) -> nx.DiGraph:
    cfg = nx.DiGraph()
    cfg.add_edges_from(zip(range(size - 1), range(1, size), strict=True))
    return cfg


def test_source_function_owners_match_object_prefixed_tu_stem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public owner helper uniquely maps a DWARF decl-file to a prefixed TU."""
    from decbench.utils import binfmt

    cu = SimpleNamespace(cu_offset=0, header={"version": 4})
    cu.get_top_DIE = lambda: SimpleNamespace(attributes={})
    die = SimpleNamespace(
        tag="DW_TAG_subprogram",
        cu=cu,
        attributes={
            "DW_AT_low_pc": SimpleNamespace(value=0x12DA),
            "DW_AT_name": SimpleNamespace(value=b"main"),
            "DW_AT_decl_file": SimpleNamespace(value=1),
        },
    )
    cu.iter_DIEs = lambda: iter((die,))
    dwarf = SimpleNamespace(iter_CUs=lambda: iter((cu,)))
    monkeypatch.setattr(binfmt, "dwarf_info", lambda _path: dwarf)
    monkeypatch.setattr(binfmt, "cu_file_table", lambda *_args: [None, "prog1.c"])

    assert binfmt.source_function_owners(Path("unused"), {"package-prog1"}) == {
        0x12DA: ("main", "package-prog1")
    }
    assert binfmt.source_function_owners(Path("unused"), {"first-prog1", "second-prog1"}) == {}


def test_inline_evaluation_carries_partial_dwarf_tu_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Known owners stay exact while unknown addresses retain name fallback."""
    from decbench.evalkit import ingest
    from decbench.models.decompilation import (
        DecompilationResult,
        DecompilerMetadata,
        FunctionDecompilation,
    )

    compiled = tmp_path / "O0" / "shadow" / "compiled"
    compiled.mkdir(parents=True)
    for stem in ("new_subid_range-new_subid_range", "login"):
        (compiled / f"{stem}.i").write_text("")
    binary = compiled / "new_subid_range"

    main = FunctionDecompilation(name="main", address=0x12DA, decompiled_code="")
    helper = FunctionDecompilation(name="helper", address=0x2000, decompiled_code="")
    result = DecompilationResult(
        binary_path=binary,
        binary_name=binary.name,
        decompiler=DecompilerMetadata(decompiler_name="test"),
        functions={"main": main, "helper": helper},
    )
    entry = ingest._Entry("shadow", "O0", binary.name, binary, result, {0x12DA, 0x2000})

    monkeypatch.setattr(
        ingest,
        "_function_owners_for_addrs",
        lambda *_args: {0x12DA: ("main", "new_subid_range-new_subid_range")},
    )
    monkeypatch.setattr(
        "decbench.utils.cfg.extract_cfgs_from_source",
        lambda path: (
            {"main": _graph(4)}
            if path.stem.startswith("new_subid_range")
            else {"main": _graph(40), "helper": _graph(7)}
        ),
    )
    seen: dict[str, int] = {}

    def evaluate(_result, source_cfgs, _metric_names):
        seen["main_nodes"] = source_cfgs["main"].number_of_nodes()
        seen["helper_nodes"] = source_cfgs["helper"].number_of_nodes()
        return {}

    monkeypatch.setattr("decbench.pipeline.evaluate.evaluate_decompilation", evaluate)

    ingest._evaluate_group(tmp_path, "shadow", "O0", [entry], ["ged"], True, [])

    assert seen == {"main_nodes": 4, "helper_nodes": 7}
