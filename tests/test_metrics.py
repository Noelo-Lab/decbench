"""Tests for metrics system."""

import pytest

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import MetricRegistry, register_metric
from decbench.models.decompilation import FunctionDecompilation, VariableInfo
from decbench.models.metrics import MetricValue


class TestMetricRegistry:
    """Tests for the metric registry."""

    def setup_method(self) -> None:
        MetricRegistry.clear()

    def test_register_metric(self) -> None:
        @register_metric("test_metric")
        class TestMetric(Metric):
            name = "test_metric"

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        assert "test_metric" in MetricRegistry.list_registered()

    def test_get_metric(self) -> None:
        @register_metric("get_test")
        class GetTestMetric(Metric):
            name = "get_test"

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        metric = MetricRegistry.get("get_test")
        assert metric.name == "get_test"

    def test_get_unknown_metric(self) -> None:
        with pytest.raises(KeyError):
            MetricRegistry.get("nonexistent")

    def test_list_registered(self) -> None:
        @register_metric("m1")
        class M1(Metric):
            name = "m1"

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        @register_metric("m2")
        class M2(Metric):
            name = "m2"

            def compute_for_function(self, decompiled, **kwargs):
                return MetricValue(value=0.0)

        registered = MetricRegistry.list_registered()
        assert "m1" in registered
        assert "m2" in registered


class TestGEDMetric:
    """Tests for the GED metric."""

    def test_ged_metric_registration(self) -> None:
        MetricRegistry.clear()
        from decbench.metrics.ged import GEDMetric

        MetricRegistry.register("ged", GEDMetric)
        metric = MetricRegistry.get("ged")
        assert metric.name == "ged"
        assert metric.requires_source_cfg is True
        assert metric.requires_decompiled_cfg is True

    def test_ged_missing_cfg(self) -> None:
        from decbench.metrics.ged import GEDMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int test() { return 0; }",
        )

        metric = GEDMetric()
        result = metric.compute_for_function(func, source_cfg=None, decompiled_cfg=None)
        assert result.value == float("inf")

    def test_ged_degenerate_source_cfg(self) -> None:
        """A <=1-node source CFG (prototype-only / wrong TU) is not scorable.

        It must be EXCLUDED (inf, like a missing CFG) — never a finite score.
        Before this guard, a truncated one-block decompilation scored a perfect
        0 against a 1-node source graph while complete decompilations were
        penalized by their real size.
        """
        import networkx as nx

        from decbench.metrics.ged import GEDMetric

        source = nx.DiGraph()
        source.add_node("decl_only")

        stub = nx.DiGraph()
        stub.add_node("stub_block")

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="void test(void) { /* truncated */ }",
        )

        metric = GEDMetric()
        result = metric.compute_for_function(func, source_cfg=source, decompiled_cfg=stub)
        assert result.value == float("inf")
        assert "degenerate source CFG" in result.metadata["error"]
        assert result.metadata["source_nodes"] == 1

        big = nx.DiGraph()
        big.add_edges_from((i, i + 1) for i in range(10))
        result_big = metric.compute_for_function(func, source_cfg=source, decompiled_cfg=big)
        assert result_big.value == float("inf")

        empty = nx.DiGraph()
        result_empty = metric.compute_for_function(func, source_cfg=empty, decompiled_cfg=stub)
        assert result_empty.value == float("inf")

    def test_ged_identical_cfgs(self) -> None:
        """GED of identical graphs should be 0."""
        pytest.importorskip("cfgutils")
        import networkx as nx

        from decbench.metrics.ged import GEDMetric

        class CFGNode:
            def __init__(self, addr: int, is_entry: bool = False, is_exit: bool = False):
                self.addr = addr
                self.is_entrypoint = is_entry
                self.is_exitpoint = is_exit

            def __hash__(self) -> int:
                return hash(self.addr)

            def __eq__(self, other: object) -> bool:
                return isinstance(other, CFGNode) and self.addr == other.addr

        n0 = CFGNode(0, is_entry=True)
        n1 = CFGNode(1)
        n2 = CFGNode(2, is_exit=True)

        g = nx.DiGraph()
        g.add_edges_from([(n0, n1), (n1, n2)])

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int test() { return 0; }",
        )

        metric = GEDMetric()
        result = metric.compute_for_function(func, source_cfg=g, decompiled_cfg=g)
        assert result.value == 0.0

    def test_ged_large_isomorphic_cfgs_bypass_limit(self, monkeypatch) -> None:
        """Graph isomorphism is checked before the VJ-GED size cutoff."""
        import networkx as nx

        import decbench.metrics.ged as ged_module
        from decbench.metrics.ged import GEDMetric

        class CFGNode:
            def __init__(self, index: int, *, entry: bool = False, exit: bool = False):
                self.index = index
                self.is_entrypoint = entry
                self.is_exitpoint = exit

        def path_graph() -> nx.DiGraph:
            nodes = [CFGNode(i, entry=i == 0, exit=i == 7) for i in range(8)]
            graph = nx.DiGraph()
            graph.add_edges_from(zip(nodes, nodes[1:], strict=False))
            return graph

        monkeypatch.setattr(ged_module, "GED_MAX_NODES", 3)
        monkeypatch.setenv("DECBENCH_NO_CACHE", "1")
        metric = GEDMetric()
        metric._get_vj_ged = lambda: pytest.fail("VJ-GED must not run for isomorphic CFGs")
        func = FunctionDecompilation(name="test", address=0x1000, decompiled_code="")

        result = metric.compute_for_function(
            func,
            source_cfg=path_graph(),
            decompiled_cfg=path_graph(),
        )

        assert result.value == 0.0
        assert result.metadata["method"] == "isomorphism"
        assert result.metadata["isomorphic"] is True

    def test_refined_isomorphism_matches_role_aware_networkx(self) -> None:
        """Joint refinement only prunes; it does not change isomorphism."""
        import random

        import networkx as nx

        from decbench.metrics.ged import _is_isomorphic, _role_graph

        class CFGNode:
            def __init__(self, index: int, *, entry: bool = False, exit: bool = False):
                self.index = index
                self.is_entrypoint = entry
                self.is_exitpoint = exit

        rng = random.Random(20260728)
        role_match = nx.algorithms.isomorphism.categorical_node_match(
            "role",
            (False, False),
        )
        for node_count in range(2, 18):
            source_nodes = [
                CFGNode(
                    index,
                    entry=index == 0,
                    exit=index == node_count - 1,
                )
                for index in range(node_count)
            ]
            decompiled_nodes = [
                CFGNode(
                    index,
                    entry=index == 0,
                    exit=index == node_count - 1,
                )
                for index in range(node_count)
            ]
            source = nx.DiGraph()
            source.add_nodes_from(source_nodes)
            for left in source_nodes:
                for right in source_nodes:
                    if left is not right and rng.random() < 0.14:
                        source.add_edge(left, right)

            permutation = list(range(node_count))
            rng.shuffle(permutation)
            decompiled = nx.DiGraph()
            decompiled.add_nodes_from(decompiled_nodes[index] for index in permutation)
            decompiled.add_edges_from(
                (
                    decompiled_nodes[left.index],
                    decompiled_nodes[right.index],
                )
                for left, right in source.edges()
            )

            assert _is_isomorphic(source, decompiled)
            assert nx.is_isomorphic(
                _role_graph(source),
                _role_graph(decompiled),
                node_match=role_match,
            )

            if source.number_of_edges() > 0:
                left, right = next(iter(decompiled.edges()))
                decompiled.remove_edge(left, right)
                expected = nx.is_isomorphic(
                    _role_graph(source),
                    _role_graph(decompiled),
                    node_match=role_match,
                )
                assert _is_isomorphic(source, decompiled) is expected

    def test_ged_large_role_mismatch_cannot_approximate_to_zero(self, monkeypatch) -> None:
        """Equal-sized non-isomorphic CFGs remain non-perfect above the cutoff."""
        import networkx as nx

        import decbench.metrics.ged as ged_module
        from decbench.metrics.ged import GEDMetric

        class CFGNode:
            def __init__(self, index: int, *, entry: bool = False, exit: bool = False):
                self.index = index
                self.is_entrypoint = entry
                self.is_exitpoint = exit

        def path_graph(*, reverse_roles: bool) -> nx.DiGraph:
            nodes = [
                CFGNode(
                    i,
                    entry=i == (7 if reverse_roles else 0),
                    exit=i == (0 if reverse_roles else 7),
                )
                for i in range(8)
            ]
            graph = nx.DiGraph()
            graph.add_edges_from(zip(nodes, nodes[1:], strict=False))
            return graph

        monkeypatch.setattr(ged_module, "GED_MAX_NODES", 3)
        monkeypatch.setenv("DECBENCH_NO_CACHE", "1")
        metric = GEDMetric()
        metric._get_vj_ged = lambda: pytest.fail("VJ-GED must not run above the cutoff")
        func = FunctionDecompilation(name="test", address=0x1000, decompiled_code="")

        result = metric.compute_for_function(
            func,
            source_cfg=path_graph(reverse_roles=False),
            decompiled_cfg=path_graph(reverse_roles=True),
        )

        assert result.value == 1.0
        assert result.metadata["method"] == "size_lower_bound"
        assert result.metadata["isomorphic"] is False
        assert result.metadata["approximated"] is True

    def test_ged_nonisomorphic_vj_zero_cannot_be_perfect(self, monkeypatch) -> None:
        """VJ-GED's degree-only zero is not a perfect structural match."""
        pytest.importorskip("cfgutils")
        import networkx as nx

        from decbench.metrics.ged import GEDMetric

        class CFGNode:
            is_entrypoint = False
            is_exitpoint = False

        source_nodes = [CFGNode() for _ in range(6)]
        source = nx.DiGraph()
        source.add_edges_from(
            (source_nodes[index], source_nodes[(index + 1) % 6]) for index in range(6)
        )

        decompiled_nodes = [CFGNode() for _ in range(6)]
        decompiled = nx.DiGraph()
        decompiled.add_edges_from(
            [
                (decompiled_nodes[0], decompiled_nodes[1]),
                (decompiled_nodes[1], decompiled_nodes[2]),
                (decompiled_nodes[2], decompiled_nodes[0]),
                (decompiled_nodes[3], decompiled_nodes[4]),
                (decompiled_nodes[4], decompiled_nodes[5]),
                (decompiled_nodes[5], decompiled_nodes[3]),
            ]
        )

        monkeypatch.setenv("DECBENCH_NO_CACHE", "1")
        func = FunctionDecompilation(name="test", address=0x1000, decompiled_code="")
        result = GEDMetric().compute_for_function(
            func,
            source_cfg=source,
            decompiled_cfg=decompiled,
        )

        assert result.value == 1.0
        assert result.raw_value == 0.0
        assert result.metadata["vj_ged_raw"] == 0.0
        assert result.metadata["isomorphic"] is False

    def test_ged_vj_defaults_missing_node_roles_to_false(self, monkeypatch) -> None:
        """Plain NetworkX nodes use the same default roles in exact and VJ paths."""
        import math

        import networkx as nx

        from decbench.metrics.ged import GEDMetric

        source = nx.DiGraph([(0, 1), (1, 2), (2, 3)])
        decompiled = nx.DiGraph([(0, 1), (0, 2), (0, 3)])
        monkeypatch.setenv("DECBENCH_NO_CACHE", "1")
        func = FunctionDecompilation(name="test", address=0x1000, decompiled_code="")

        result = GEDMetric().compute_for_function(
            func,
            source_cfg=source,
            decompiled_cfg=decompiled,
        )

        assert math.isfinite(result.value)
        assert result.value > 0.0
        assert result.metadata["method"] == "vj_ged"

    def test_accelerated_vj_ged_matches_cfgutils(self) -> None:
        """The compiled assignment solver preserves cfgutils' VJ-GED values."""
        import random

        import networkx as nx
        from cfgutils.similarity import vj_ged as cfgutils_vj_ged

        from decbench.metrics.vj_ged import vj_ged

        class CFGNode:
            def __init__(self, index: int, *, entry: bool, exit: bool):
                self.index = index
                self.is_entrypoint = entry
                self.is_exitpoint = exit

        rng = random.Random(20260727)
        for source_count in range(1, 9):
            for decompiled_count in range(1, 9):
                source_nodes = [
                    CFGNode(
                        index,
                        entry=index == 0 and rng.random() < 0.8,
                        exit=index == source_count - 1 and rng.random() < 0.8,
                    )
                    for index in range(source_count)
                ]
                decompiled_nodes = [
                    CFGNode(
                        index,
                        entry=index == 0 and rng.random() < 0.8,
                        exit=index == decompiled_count - 1 and rng.random() < 0.8,
                    )
                    for index in range(decompiled_count)
                ]
                source = nx.DiGraph()
                source.add_nodes_from(source_nodes)
                decompiled = nx.DiGraph()
                decompiled.add_nodes_from(decompiled_nodes)
                for left in source_nodes:
                    for right in source_nodes:
                        if left is not right and rng.random() < 0.2:
                            source.add_edge(left, right)
                for left in decompiled_nodes:
                    for right in decompiled_nodes:
                        if left is not right and rng.random() < 0.2:
                            decompiled.add_edge(left, right)

                assert vj_ged(source, decompiled) == cfgutils_vj_ged(
                    source,
                    decompiled,
                )


class TestTypeMatchMetric:
    """Tests for the type match metric."""

    def test_type_match_registration(self) -> None:
        MetricRegistry.clear()
        from decbench.metrics.type_match import TypeMatchMetric

        MetricRegistry.register("type_match", TypeMatchMetric)
        metric = MetricRegistry.get("type_match")
        assert metric.name == "type_match"
        assert metric.perfect_value == 1.0

    def test_type_normalization(self) -> None:
        from decbench.metrics.type_match import normalize_type

        forms = normalize_type("unsigned int")
        assert "int" in forms

        forms = normalize_type("__int64")
        assert "long long" in forms

        forms = normalize_type("_DWORD")
        assert "int" in forms

    def test_type_match_with_matching_types(self) -> None:
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// structured variables",
            variables=[
                VariableInfo(name="renamed_0", type="int", stack_offset=-4),
                VariableInfo(name="renamed_1", type="char", stack_offset=-5),
                VariableInfo(name="renamed_2", type="long long", stack_offset=-16),
            ],
        )

        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
            {"name": "y", "type": ["char"], "rbp_offset": [-5], "size": 1},
            {"name": "z", "type": ["long long"], "rbp_offset": [-16], "size": 8},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 1.0
        assert result.metadata["tp"] == 3

    def test_type_match_with_mismatched_types(self) -> None:
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// structured variables",
            variables=[
                VariableInfo(name="renamed_0", type="int", stack_offset=-4),
                VariableInfo(name="renamed_1", type="int", stack_offset=-5),
            ],
        )

        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
            {"name": "y", "type": ["char"], "rbp_offset": [-5], "size": 1},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == pytest.approx(0.5)

    def test_type_match_no_ground_truth(self) -> None:
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int x;\n",
        )

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=None)
        assert result.value == 0.0

    def test_extract_types_from_code(self) -> None:
        from decbench.metrics.type_match import extract_types_from_decompiled_code

        code = """
int main() {
    int x;
    char *ptr;
    long long counter;
    return 0;
}
"""
        vars = extract_types_from_decompiled_code(code)
        names = [v["name"] for v in vars]
        assert "x" in names
        assert "counter" in names

    def test_offset_exact_match(self) -> None:
        """Structured var at the exact GT offset and type -> perfect."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls here",
            variables=[
                VariableInfo(name="v0", type="int", stack_offset=-4, kind="stack"),
            ],
        )
        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 1.0
        assert result.metadata["matched_by"] == "structured"
        assert result.metadata["tp"] == 1
        assert result.metadata["calibration_shift"] == 0

    def test_args_match_by_position_with_synthetic_names(self) -> None:
        """O2-style: register args match positionally even with angr names."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="a0", type="unsigned int", kind="arg", arg_index=0),
                VariableInfo(name="a1", type="char *", kind="arg", arg_index=1),
            ],
        )
        gt_vars = [
            {
                "name": "count",
                "type": ["int"],
                "rbp_offset": [],
                "size": 4,
                "is_arg": True,
                "arg_index": 0,
            },
            {
                "name": "buf",
                "type": ["char*"],
                "rbp_offset": [],
                "size": 8,
                "is_arg": True,
                "arg_index": 1,
            },
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 1.0
        assert result.metadata["matched_by"] == "structured"
        assert result.metadata["matched_by_arg"] == 2

    def test_arg_position_type_mismatch_is_fp(self) -> None:
        """Positional arg hit with the wrong type counts as a false positive."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="a0", type="char", kind="arg", arg_index=0),
            ],
        )
        gt_vars = [
            {
                "name": "n",
                "type": ["long long"],
                "rbp_offset": [],
                "size": 8,
                "is_arg": True,
                "arg_index": 0,
            },
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.metadata["fp"] == 1
        assert result.value == 0.0

    def test_register_local_does_not_match_by_name(self) -> None:
        """Names cannot rescue a register local without type-blind evidence."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="sum", type="int", kind="stack"),
            ],
        )
        gt_vars = [
            {"name": "sum", "type": ["int"], "rbp_offset": [], "size": 4},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 0.0
        assert result.metadata["matched_by_name"] == 0
        assert result.metadata["unobservable_source_count"] == 1

    def test_o2_ground_truth_keeps_register_vars(self, tmp_path) -> None:
        """At -O2, register-located vars must still appear in ground truth."""
        import shutil
        import subprocess

        from decbench.metrics.type_match import extract_ground_truth_types

        cc = shutil.which("cc") or shutil.which("gcc")
        if cc is None:
            pytest.skip("no C compiler available")

        src = tmp_path / "t.c"
        src.write_text(
            "int helper(int first, char *second) {\n"
            "    int doubled = first * 2;\n"
            "    return doubled + (second != 0);\n"
            "}\n"
            "int main(int argc, char **argv) { return helper(argc, argv[0]); }\n"
        )
        binary = tmp_path / "t"
        subprocess.run(
            [cc, "-g", "-O2", "-fno-inline", "-o", str(binary), str(src)],
            check=True,
        )

        gt = extract_ground_truth_types(binary)
        assert "helper" in gt, f"helper missing from O2 ground truth: {sorted(gt)}"
        by_name = {v["name"]: v for v in gt["helper"]}
        assert by_name["first"]["is_arg"] is True
        assert by_name["first"]["arg_index"] == 0
        assert by_name["second"]["arg_index"] == 1
        assert "int" in by_name["first"]["type"]

    def test_one_slot_not_double_counted(self) -> None:
        """A single decompiled slot satisfies at most one GT variable."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="i", type="int", stack_offset=-8, kind="stack"),
            ],
        )
        gt_vars = [
            {"name": "i", "type": ["int"], "rbp_offset": [-8], "size": 4},
            {"name": "i", "type": ["int"], "rbp_offset": [-16], "size": 4},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.metadata["tp"] == 1
        assert result.metadata["fn"] == 1
        assert result.value == 0.5

    def test_short_int_dwarf_name_matches_decompiler_short(self) -> None:
        """GCC's DWARF 'short int' must match decompiler 'short'/'_WORD'."""
        from decbench.metrics.type_match import normalize_type

        gt_forms = normalize_type("short int")
        for decompiler_spelling in ("short", "__int16", "_WORD", "ushort"):
            assert gt_forms & normalize_type(
                decompiler_spelling
            ), f"'short int' does not match {decompiler_spelling!r}"

    def test_binary_calibration_ignores_single_slot_coincidences(self) -> None:
        """All-single-var functions must not elect a spurious nonzero shift."""
        from decbench.metrics.type_match import _calibrate_shift_multi

        pairs = [
            ([-8], [-12]),
            ([-12], [-16]),
            ([-16], [-20]),
            ([-4], [-4]),
        ]
        assert _calibrate_shift_multi(pairs) == 0

    def test_offset_miss_is_not_rescued_by_name(self) -> None:
        """An unrelated name match cannot supplement a valid stack match."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="x", type="int", stack_offset=-4, kind="stack"),
                VariableInfo(name="argc", type="int", stack_offset=None, kind="arg"),
            ],
        )
        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
            {"name": "argc", "type": ["int"], "rbp_offset": [-20], "size": 4},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 0.5
        assert result.metadata["matched_by"] == "structured"
        assert result.metadata["tp"] == 1
        assert result.metadata["fn"] == 1

    def test_offset_constant_shift_calibration(self) -> None:
        """Decompiled offsets shifted +16 from GT (2 vars) -> shift -16, perfect."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="v0", type="int", stack_offset=12, kind="stack"),
                VariableInfo(name="v1", type="char", stack_offset=11, kind="stack"),
            ],
        )
        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
            {"name": "y", "type": ["char"], "rbp_offset": [-5], "size": 1},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.metadata["calibration_shift"] == -16
        assert result.value == 1.0
        assert result.metadata["matched_by"] == "structured"

    def test_offset_type_mismatch(self) -> None:
        """Var at matching offset but wrong type -> false positive."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="v0", type="char", stack_offset=-4, kind="stack"),
            ],
        )
        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.metadata["fp"] == 1
        assert result.value == 0.0
        assert result.metadata["matched_by"] == "structured"

    def test_name_only_fallback_is_rejected(self) -> None:
        """Structured vars without anchors or usage do not match by name."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="x", type="int", stack_offset=None, kind="arg"),
            ],
        )
        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.metadata["matched_by"] == "structured"
        assert result.value == 0.0
        assert result.metadata["tp"] == 0
        assert result.metadata["fn"] == 1

    def test_code_parsed_local_without_usage_is_unmatched(self) -> None:
        """Parsing a declaration does not restore the old name-only matcher."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int x;\n",
            variables=[],
        )
        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.metadata["matched_by"] == "structured"
        assert result.value == 0.0
        assert result.metadata["fn"] == 1

    def test_code_parsed_arguments_by_position(self) -> None:
        """A code-only decompiler (no structured vars) gets ABI-position credit
        for its arguments — e.g. ``wcomment(FILE *fp, int c)`` whose only
        variables are its args scored 0 under the old name-only regex fallback."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="wcomment",
            address=0x18A5,
            decompiled_code='void wcomment(FILE *fp, int c)\n{\n    fputs("x", fp);\n}\n',
            variables=[],
        )
        gt_vars = [
            {"name": "fp", "type": ["FILE*"], "is_arg": True, "arg_index": 0, "rbp_offset": [-8]},
            {"name": "i", "type": ["int"], "is_arg": True, "arg_index": 1, "rbp_offset": [-12]},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 1.0
        assert result.metadata["matched_by_arg"] == 2
        assert result.metadata["matched_by"] == "structured"

    def test_offset_loclist_any_of(self) -> None:
        """GT loclist with multiple offsets matches if any aligns."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="v0", type="int", stack_offset=-24, kind="stack"),
            ],
        )
        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-20, -24], "size": 4},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 1.0
        assert result.metadata["matched_by"] == "structured"
        assert result.metadata["tp"] == 1

    def test_type_map_reaches_committed_pointer_spellings(self) -> None:
        """``int4 *`` must normalize like ``int4`` does, one indirection out."""
        from decbench.metrics.type_match import normalize_type

        assert "int*" in normalize_type("int4 *")
        assert "int*" in normalize_type("int4*")
        assert "long long*" in normalize_type("size_t *")
        assert "char**" in normalize_type("uint8_t **")
        # An unmapped pointee is left exactly as it was.
        assert normalize_type("Slice *") == {"Slice *", "Slice*"}

    def test_pointer_normalization_does_not_cross_widths(self) -> None:
        """``int4 *`` is not ``long long*``, and a scalar never becomes a pointer."""
        from decbench.metrics.type_match import normalize_type

        assert "long long*" not in normalize_type("int4 *")
        assert not any("*" in f for f in normalize_type("int4"))

    def test_placeholder_pointees_are_never_mapped(self) -> None:
        """A pointer to N UNKNOWN bytes is not a recovery of a committed type.

        ``undefinedN`` (Ghidra/kuna TYPE_UNKNOWN) and ``_BYTE``/``_WORD``/
        ``_DWORD``/``_QWORD`` (Hex-Rays unknown-width slots) are the only
        TYPE_MAP rows excluded from the pointee mapping; every other row names a
        committed C type and is mapped.
        """
        from decbench.metrics.type_match import _POINTEE_MAP, TYPE_MAP, normalize_type

        assert set(TYPE_MAP) - set(_POINTEE_MAP) == {
            "undefined",
            "undefined1",
            "undefined2",
            "undefined4",
            "undefined8",
            "_BYTE",
            "_WORD",
            "_DWORD",
            "_QWORD",
        }
        for form in ("undefined8 *", "_QWORD *", "_BYTE *", "undefined *", "undefined1 **"):
            assert normalize_type(form) == {form, form.replace(" ", "")}
        # The scalar rows are untouched -- only the POINTER spelling is excluded.
        assert "long long" in normalize_type("undefined8")
        assert "int" in normalize_type("_DWORD")

    def test_uncommitted_pointer_is_a_miss_against_ground_truth(self) -> None:
        """End to end: ``undefined8 *`` must not score as a recovery of ``size_t *``."""
        from decbench.metrics.type_match import TypeMatchMetric, normalize_type

        # The DWARF payload is normalized at extraction time, so normalize here too.
        gt_vars = [
            {
                "name": "n",
                "type": sorted(normalize_type("size_t*")),
                "is_arg": True,
                "arg_index": 0,
            }
        ]

        def score(decompiled_type: str) -> float:
            func = FunctionDecompilation(
                name="f",
                address=0x1000,
                decompiled_code="// no decls",
                variables=[VariableInfo(name="a1", type=decompiled_type, kind="arg", arg_index=0)],
            )
            return TypeMatchMetric().compute_for_function(func, ground_truth_vars=gt_vars).value

        assert score("undefined8 *") == 0.0
        assert score("_QWORD *") == 0.0
        # ... while a committed spelling of the same type still matches.
        assert score("size_t *") == 1.0
        assert score("unsigned long long *") == 1.0

    def test_ground_truth_payload_is_hash_seed_independent(self, tmp_path) -> None:
        """The DWARF payload feeds the metric cache key through ``stable_hash``,
        which sorts dict keys but NOT list elements. Unsorted lists made the key
        depend on ``PYTHONHASHSEED``, so the disk cache mostly missed across
        processes."""
        import os
        import shutil
        import subprocess
        import sys

        cc = shutil.which("cc") or shutil.which("gcc")
        if cc is None:
            pytest.skip("no C compiler available")

        src = tmp_path / "t.c"
        src.write_text(
            "#include <stddef.h>\n"
            "int helper(int first, char *second, size_t third) {\n"
            "    long fourth = first * 2;\n"
            "    unsigned char fifth = (unsigned char)third;\n"
            "    return fourth + (second != 0) + fifth;\n"
            "}\n"
            "int main(int argc, char **argv) { return helper(argc, argv[0], 1); }\n"
        )
        binary = tmp_path / "t"
        subprocess.run([cc, "-g", "-O0", "-o", str(binary), str(src)], check=True)

        prog = (
            "import json,sys;"
            "from decbench.caching import stable_hash;"
            "from decbench.metrics.type_match import extract_ground_truth_types;"
            "print(stable_hash(extract_ground_truth_types(sys.argv[1])))"
        )
        digests = set()
        for seed in ("0", "1", "12345"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            out = subprocess.run(
                [sys.executable, "-c", prog, str(binary)],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
            digests.add(out.stdout.strip())
        assert len(digests) == 1, f"ground-truth hash varies with PYTHONHASHSEED: {digests}"

    def test_namespace_qualifier_is_stripped(self) -> None:
        """DWARF's ``DW_AT_name`` is unqualified, so IDA's ``leveldb::X *``
        needs the qualifier dropped to reach ground truth."""
        from decbench.metrics.type_match import normalize_type

        assert "TableBuilder*" in normalize_type("leveldb::TableBuilder *")
        assert "Mutex*" in normalize_type("leveldb::port::Mutex *")
        assert "string" in normalize_type("std::string")

    def test_namespace_strip_leaves_c_types_alone(self) -> None:
        """No C spelling gains a form from the qualifier strip — including a
        Ghidra symbol-version prefix, whose token starts with a digit."""
        from decbench.metrics.type_match import normalize_type

        assert normalize_type("unsigned int") == {"unsigned int", "int"}
        assert normalize_type("char *") == {"char *", "char*"}
        assert normalize_type("GLIBC_2.2.5::stderr") == {"GLIBC_2.2.5::stderr"}

    def test_namespaced_pointer_matches_unqualified_ground_truth(self) -> None:
        """End to end: IDA's C++ spelling scores against the DWARF name."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="Add",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="a1", type="leveldb::TableBuilder *", kind="arg", arg_index=0),
            ],
        )
        gt_vars = [
            {"name": "this", "type": ["TableBuilder*"], "is_arg": True, "arg_index": 0},
        ]

        result = TypeMatchMetric().compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 1.0

    def test_reference_ground_truth_is_a_pointer(self, tmp_path) -> None:
        """A C++ reference parameter must land as a pointer type, not ``void``.

        Every decompiler renders a reference as a pointer, so ``void`` made those
        ground-truth variables unmatchable for all of them.
        """
        import shutil
        import subprocess

        if shutil.which("g++") is None:
            pytest.skip("needs g++")

        from decbench.metrics.type_match import extract_ground_truth_types

        src = tmp_path / "r.cc"
        src.write_text(
            "struct Blob { int a; int b; };\n"
            "int Take(const Blob& in, Blob&& moved) { return in.a + moved.b; }\n"
            "int main() { Blob b{1, 2}; return Take(b, Blob{3, 4}); }\n"
        )
        binary = tmp_path / "r.bin"
        subprocess.run(
            ["g++", "-g", "-O0", str(src), "-o", str(binary)], check=True, capture_output=True
        )

        take = extract_ground_truth_types(binary).get("Take")
        assert take is not None
        by_name = {v["name"]: v for v in take}
        assert "Blob*" in by_name["in"]["type"]
        assert "Blob*" in by_name["moved"]["type"]
        assert by_name["in"]["type"] != ["void"]

    def test_c_ground_truth_has_no_reference_types(self, tmp_path) -> None:
        """The reference arm cannot move a C result: C has no reference DIEs."""
        import shutil
        import subprocess

        if shutil.which("gcc") is None:
            pytest.skip("needs gcc")

        from decbench.utils import binfmt

        src = tmp_path / "c.c"
        src.write_text(
            "struct Blob { int a; };\n"
            "int take(const struct Blob *in, int n) { return in->a + n; }\n"
            "int main(void) { struct Blob b = {1}; return take(&b, 2); }\n"
        )
        binary = tmp_path / "c.bin"
        subprocess.run(
            ["gcc", "-g", "-O0", str(src), "-o", str(binary)], check=True, capture_output=True
        )

        dw = binfmt.dwarf_info(binary)
        assert dw is not None
        tags = {die.tag for cu in dw.iter_CUs() for die in cu.iter_DIEs()}
        assert "DW_TAG_reference_type" not in tags
        assert "DW_TAG_rvalue_reference_type" not in tags


class TestByteMatchMetric:
    """Tests for the byte match metric."""

    def test_byte_match_registration(self) -> None:
        MetricRegistry.clear()
        from decbench.metrics.byte_match import ByteMatchMetric

        MetricRegistry.register("byte_match", ByteMatchMetric)
        metric = MetricRegistry.get("byte_match")
        assert metric.name == "byte_match"
        assert metric.perfect_value == 1.0

    def test_byte_match_no_binary(self) -> None:
        from decbench.metrics.byte_match import ByteMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="int test() { return 0; }",
        )

        metric = ByteMatchMetric()
        result = metric.compute_for_function(func)
        assert result.value == 0.0
        assert "error" in result.metadata

    def test_jaccard_similarity(self) -> None:
        from decbench.metrics.byte_match import _compute_jaccard_similarity

        lines = ["mov rax, rbx", "add rax, 1", "ret"]
        sim, changed = _compute_jaccard_similarity(lines, lines)
        assert sim == 1.0
        assert changed == 0

        lines_a = ["mov rax, rbx", "ret"]
        lines_b = ["push rbp", "pop rbp"]
        sim, changed = _compute_jaccard_similarity(lines_a, lines_b)
        assert sim == 0.0
        assert changed == len(lines_a) + len(lines_b)

        sim, changed = _compute_jaccard_similarity([], [])
        assert sim == 1.0
        assert changed == 0


class TestMetricConfig:
    """Tests for metric configuration."""

    def test_default_config(self) -> None:
        config = MetricConfig()
        assert config.function_timeout_seconds == 60.0
        assert config.use_cache is True

    def test_custom_config(self) -> None:
        config = MetricConfig(
            function_timeout_seconds=30.0,
            extra_options={"custom_opt": "value"},
        )
        assert config.function_timeout_seconds == 30.0
        assert config.extra_options["custom_opt"] == "value"
