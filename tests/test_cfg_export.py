"""Source-CFG export: TU-aware resolution and the serialization round trip.

The regression these guard is decbench#50: the export used to write a
project-wide, name-keyed, last-writer-wins union to every binary, so empty
prototypes displaced real bodies and every binary of a project got an identical
map. Offline GED could then never reproduce the published numbers.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import networkx as nx
import pytest

from decbench.publish import cfg_export
from decbench.utils.cfg import (
    best_source_by_name,
    is_degenerate_source_cfg,
    resolved_source_for_binary,
)


class Nop:
    """Stands in for pyjoern's FUNCTION_START/FUNCTION_END filler statements."""


class Stmt:
    """Stands in for any real (non-``Nop``) statement."""


class Block:
    """Minimal stand-in for a pyjoern CFG block."""

    def __init__(
        self,
        ident: int,
        statements: tuple[object, ...] = (),
        entry: bool = False,
        exit: bool = False,
    ) -> None:
        self.id = ident
        self.statements = list(statements)
        self.is_entrypoint = entry
        self.is_exitpoint = exit

    def __repr__(self) -> str:
        return f"B{self.id}"


def chain(n: int) -> nx.DiGraph:
    """A real ``n``-block function body."""
    blocks = [Block(i, (Stmt(),), entry=(i == 0), exit=(i == n - 1)) for i in range(n)]
    graph = nx.DiGraph()
    graph.add_nodes_from(blocks)
    for a, b in zip(blocks, blocks[1:], strict=False):
        graph.add_edge(a, b)
    return graph


def prototype() -> nx.DiGraph:
    """The single all-``Nop`` block Joern emits for a declaration-only view."""
    graph = nx.DiGraph()
    graph.add_node(Block(0, (Nop(), Nop()), entry=True, exit=True))
    return graph


# --------------------------------------------------------------------------- #
# Serialization round trip.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "cfg, degenerate",
    [
        (chain(1), False),
        (chain(5), False),
        (prototype(), True),
        (nx.DiGraph(), True),
    ],
)
def test_roundtrip_preserves_degeneracy_verdict(cfg: nx.DiGraph, degenerate: bool) -> None:
    """A rebuilt CFG must answer ``is_degenerate_source_cfg`` the same way.

    Without the recorded flag every rebuilt single-block function reads as an
    empty prototype, because serialization drops the statements the predicate
    inspects.
    """
    assert is_degenerate_source_cfg(cfg) is degenerate

    nodes, edges, labels, entry, exit_, flag = cfg_export.relabel_cfg(cfg)
    assert flag is degenerate

    rebuilt = cfg_export.rebuild_cfg(
        {
            "nodes": nodes,
            "edges": edges,
            "labels": labels,
            "entry": entry,
            "exit": exit_,
            "degenerate": flag,
        }
    )
    assert is_degenerate_source_cfg(rebuilt) is degenerate
    assert rebuilt.number_of_nodes() == cfg.number_of_nodes()
    assert rebuilt.number_of_edges() == cfg.number_of_edges()


def test_roundtrip_preserves_entry_exit_flags() -> None:
    """GED reads the entry/exit flags, so they must survive serialization."""
    nodes, edges, labels, entry, exit_, flag = cfg_export.relabel_cfg(chain(3))
    rebuilt = cfg_export.rebuild_cfg(
        {
            "nodes": nodes,
            "edges": edges,
            "labels": labels,
            "entry": entry,
            "exit": exit_,
            "degenerate": flag,
        }
    )
    assert sum(n.is_entrypoint for n in rebuilt.nodes()) == 1
    assert sum(n.is_exitpoint for n in rebuilt.nodes()) == 1


def test_rebuild_defaults_to_degenerate_for_legacy_json() -> None:
    """JSONs written before the flag existed keep the old (statement-less) behaviour."""
    rebuilt = cfg_export.rebuild_cfg({"nodes": [0], "edges": [], "entry": [0], "exit": [0]})
    assert is_degenerate_source_cfg(rebuilt) is True


# --------------------------------------------------------------------------- #
# TU-aware export.
# --------------------------------------------------------------------------- #


@pytest.fixture
def project_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A results tree whose ``.i`` files parse into caller-supplied CFGs."""

    def build(tus: dict[str, dict[str, nx.DiGraph]], opt: str = "O2", project: str = "proj"):
        comp = tmp_path / "root" / opt / project / "compiled"
        comp.mkdir(parents=True)
        for tu in tus:
            # Content-addressed parse dedup hashes the *stripped* text, and
            # stripping keeps only what follows a non-system line marker.
            (comp / f"{tu}.i").write_text(f'# 1 "{tu}.c"\nint tag_{tu};\n')

        monkeypatch.setattr(
            cfg_export,
            "extract_cfgs_from_source",
            lambda path, tus=tus: tus[path.stem],
        )
        return tmp_path / "root", tmp_path / "dest"

    return build


def read_export(dest: Path, stem: str, opt: str = "O2", project: str = "proj") -> dict:
    return json.loads(cfg_export.cfg_json_path(dest, opt, project, stem).read_text())["functions"]


def test_prototype_never_displaces_a_real_body(project_tree) -> None:
    """The decbench#50 regression: a later-sorting prototype used to win.

    ``zzz`` only declares ``helper``; ``aaa`` defines it. Sorted TU order put the
    prototype last, and last-writer-wins handed every binary a 1-block stub that
    GED cannot score.
    """
    root, dest = project_tree(
        {
            "aaa": {"helper": chain(6)},
            "zzz": {"helper": prototype(), "main": chain(4)},
        }
    )
    cfg_export.export_project_cfgs(root, dest, "proj", {"O2": ["aaa", "zzz"]})

    for stem in ("aaa", "zzz"):
        helper = read_export(dest, stem)["helper"]
        assert helper["degenerate"] is False
        assert len(helper["nodes"]) == 6


def test_each_binary_gets_its_own_translation_unit(project_tree) -> None:
    """Per-program functions must come from the binary's own TU, not a sibling's."""
    root, dest = project_tree(
        {
            "cat": {"main": chain(3)},
            "ls": {"main": chain(10)},
        }
    )
    cfg_export.export_project_cfgs(root, dest, "proj", {"O2": ["cat", "ls"]})

    assert len(read_export(dest, "cat")["main"]["nodes"]) == 3
    assert len(read_export(dest, "ls")["main"]["nodes"]) == 10


def test_dwarf_owned_translation_unit_precedes_name_fallback(
    project_tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A binary name need not equal the translation unit that defines its functions."""
    tus = {
        "new_subid_range-new_subid_range": {"main": chain(4)},
        "login": {"main": chain(40)},
    }
    root, dest = project_tree(tus)
    monkeypatch.setattr(cfg_export, "resolve_binary", lambda *_args: root / "new_subid_range")
    monkeypatch.setattr(
        cfg_export.binfmt,
        "source_function_owners",
        lambda *_args: {0x12DA: ("main", "new_subid_range-new_subid_range")},
    )

    cfg_export.export_project_cfgs(
        root,
        dest,
        "proj",
        {"O2": ["new_subid_range"]},
    )

    assert len(read_export(dest, "new_subid_range")["main"]["nodes"]) == 4


def test_known_dwarf_owner_does_not_fall_back_to_another_tu() -> None:
    """Missing source for a known owner is safer than a same-name substitution."""
    tus = {"login": {"main": chain(40)}}
    resolved = resolved_source_for_binary(
        "new_subid_range",
        tus,
        best_source_by_name(tus),
        function_owners={0x12DA: ("main", "new_subid_range-new_subid_range")},
    )

    assert "main" not in resolved


def test_evaluate_project_accepts_precomputed_cfgs_with_dwarf_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The benchmark driver can carry address/TU provenance into evaluation."""
    from decbench.pipeline import evaluate

    tus = {
        "new_subid_range-new_subid_range": {"main": chain(4)},
        "login": {"main": chain(40)},
    }
    seen: dict[str, int] = {}

    def evaluate_one(_decompilation, source_cfgs, _metrics, preprocessed_sources=None):
        seen["main_nodes"] = source_cfgs["main"].number_of_nodes()
        return {}

    monkeypatch.setattr(evaluate, "evaluate_decompilation", evaluate_one)
    project = SimpleNamespace(name="shadow", preprocessed_sources={}, compiled_binaries={})

    evaluate.evaluate_project(
        project,
        {"new_subid_range": {"test": object()}},
        tmp_path,
        optimization="O0",
        metrics=["ged"],
        parallel=False,
        precomputed_source_cfgs=tus,
        source_function_owners={
            "new_subid_range": {
                0x12DA: ("main", "new_subid_range-new_subid_range"),
            }
        },
    )

    assert seen == {"main_nodes": 4}


def test_falls_back_across_tus_for_undefined_functions(project_tree) -> None:
    """Statically-linked helpers a binary's own TU does not define still resolve."""
    root, dest = project_tree(
        {
            "cat": {"main": chain(3)},
            "libutil": {"xalloc": chain(7)},
        }
    )
    cfg_export.export_project_cfgs(root, dest, "proj", {"O2": ["cat"]})

    assert len(read_export(dest, "cat")["xalloc"]["nodes"]) == 7


def test_export_matches_the_pipeline_resolution(project_tree) -> None:
    """The export must agree with what ``pipeline/evaluate.py`` scores against.

    This is the anti-drift guard: both sides go through the same
    ``best_source_by_name`` / ``resolved_source_for_binary`` pair, so compare the
    exported node/edge counts against calling that pair directly.
    """
    tus = {
        "cat": {"main": chain(3), "usage": chain(2), "shared": prototype()},
        "ls": {"main": chain(10), "shared": chain(8)},
        "libutil": {"xalloc": chain(7), "usage": prototype()},
    }
    root, dest = project_tree(tus)
    stems = ["cat", "ls", "libutil"]
    cfg_export.export_project_cfgs(root, dest, "proj", {"O2": stems})

    best = best_source_by_name(tus)
    for stem in stems:
        expected = resolved_source_for_binary(stem, tus, best)
        exported = read_export(dest, stem)
        assert set(exported) == set(expected)
        for name, cfg in expected.items():
            assert len(exported[name]["nodes"]) == cfg.number_of_nodes()
            assert len(exported[name]["edges"]) == cfg.number_of_edges()
            assert exported[name]["degenerate"] is is_degenerate_source_cfg(cfg)


def test_functions_filter_keeps_only_the_binary_own_functions(project_tree) -> None:
    """The published JSONs carry a binary's scored functions, not the whole project."""
    root, dest = project_tree(
        {
            "cat": {"main": chain(3), "usage": chain(2)},
            "libutil": {"xalloc": chain(7), "xrealloc": chain(4)},
        }
    )
    cfg_export.export_project_cfgs(
        root,
        dest,
        "proj",
        {"O2": ["cat"]},
        functions={("O2", "cat"): {"main", "xalloc"}},
    )
    assert set(read_export(dest, "cat")) == {"main", "xalloc"}


def test_functions_filter_is_applied_after_resolution(project_tree) -> None:
    """Filtering must not change which body a surviving name resolves to.

    ``cat`` keeps only ``main``; the cross-TU fallback still has to see every TU
    while resolving, so ``main`` is ``cat``'s 3-block body and not ``ls``'s.
    """
    root, dest = project_tree(
        {
            "cat": {"main": chain(3)},
            "ls": {"main": chain(10)},
        }
    )
    cfg_export.export_project_cfgs(
        root, dest, "proj", {"O2": ["cat"]}, functions={("O2", "cat"): {"main"}}
    )
    exported = read_export(dest, "cat")
    assert set(exported) == {"main"}
    assert len(exported["main"]["nodes"]) == 3


def test_no_filter_keeps_the_whole_resolved_map(project_tree) -> None:
    """``functions=None`` stays the full project-wide name set."""
    root, dest = project_tree({"cat": {"main": chain(3)}, "libutil": {"xalloc": chain(7)}})
    cfg_export.export_project_cfgs(root, dest, "proj", {"O2": ["cat"]})
    assert set(read_export(dest, "cat")) == {"main", "xalloc"}


def test_existing_json_is_not_rewritten_without_overwrite(project_tree) -> None:
    """The export stays resumable: present JSONs are left alone."""
    root, dest = project_tree({"cat": {"main": chain(3)}})
    cfg_export.export_project_cfgs(root, dest, "proj", {"O2": ["cat"]})

    target = cfg_export.cfg_json_path(dest, "O2", "proj", "cat")
    target.write_text(json.dumps({"functions": {"sentinel": {}}}))
    cfg_export.export_project_cfgs(root, dest, "proj", {"O2": ["cat"]})
    assert "sentinel" in json.loads(target.read_text())["functions"]

    cfg_export.export_project_cfgs(root, dest, "proj", {"O2": ["cat"]}, overwrite=True)
    assert "main" in json.loads(target.read_text())["functions"]
