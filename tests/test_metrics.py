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

    def test_get_all(self) -> None:
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

        all_metrics = MetricRegistry.get_all()
        assert "m1" in all_metrics
        assert "m2" in all_metrics


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

        # What Joern produces when it only sees a declaration: one lone node.
        source = nx.DiGraph()
        source.add_node("decl_only")

        # A truncated (prologue-only) decompilation stub: also one node. Under
        # exact GED these "match" for 0 — the exact artifact being excluded.
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

        # A degenerate source must exclude the function no matter how big the
        # decompiled CFG is (previously: bigger output = worse score).
        big = nx.DiGraph()
        big.add_edges_from((i, i + 1) for i in range(10))
        result_big = metric.compute_for_function(func, source_cfg=source, decompiled_cfg=big)
        assert result_big.value == float("inf")

        # An empty source graph is degenerate too.
        empty = nx.DiGraph()
        result_empty = metric.compute_for_function(func, source_cfg=empty, decompiled_cfg=stub)
        assert result_empty.value == float("inf")

    def test_ged_identical_cfgs(self) -> None:
        """GED of identical graphs should be 0."""
        pytest.importorskip("cfgutils")
        import networkx as nx

        from decbench.metrics.ged import GEDMetric

        # cfgutils expects nodes with is_entrypoint attribute
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
            decompiled_code="int x;\nchar y;\nlong long z;\n",
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
            decompiled_code="int x;\nint y;\n",
        )

        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
            {"name": "y", "type": ["char"], "rbp_offset": [-5], "size": 1},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        # x matches, y doesn't
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
        # Register-resident args at -O2: names differ, no stack offsets.
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

    def test_register_local_matches_by_name(self) -> None:
        """O2-style register local (no offsets anywhere) matches by name."""
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
        assert result.value == 1.0
        assert result.metadata["matched_by_name"] == 1

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
        # Register-resident args kept, with positional indices
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
        # Two shadowed locals named "i" at distinct offsets; only one recovered
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

        # Three coincidental +4 alignments from unrelated single slots, and
        # one function genuinely aligned at shift 0.
        pairs = [
            ([-8], [-12]),
            ([-12], [-16]),
            ([-16], [-20]),
            ([-4], [-4]),
        ]
        assert _calibrate_shift_multi(pairs) == 0

    def test_offset_miss_rescued_by_name(self) -> None:
        """GT stack var promoted to an arg (no offset) is rescued by name."""
        from decbench.metrics.type_match import TypeMatchMetric

        func = FunctionDecompilation(
            name="test",
            address=0x1000,
            decompiled_code="// no decls",
            variables=[
                VariableInfo(name="x", type="int", stack_offset=-4, kind="stack"),
                # argc was promoted to an argument: correct name+type, no offset
                VariableInfo(name="argc", type="int", stack_offset=None, kind="arg"),
            ],
        )
        gt_vars = [
            {"name": "x", "type": ["int"], "rbp_offset": [-4], "size": 4},
            {"name": "argc", "type": ["int"], "rbp_offset": [-20], "size": 4},
        ]

        metric = TypeMatchMetric()
        result = metric.compute_for_function(func, ground_truth_vars=gt_vars)
        assert result.value == 1.0
        assert result.metadata["matched_by"] == "structured"
        assert result.metadata["tp"] == 2
        assert result.metadata["fn"] == 0

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

    def test_name_fallback_no_offsets(self) -> None:
        """Structured vars without stack offsets -> fall back to name matching."""
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
        assert result.value == 1.0
        assert result.metadata["tp"] == 1

    def test_code_parsed_local_no_variables(self) -> None:
        """No structured variables -> parse the C, match the local by name."""
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
        # The local declaration is now parsed into a structured variable and
        # matched by name via the structured matcher (value unchanged at 1.0).
        assert result.metadata["matched_by"] == "structured"
        assert result.value == 1.0

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
        # DWARF ground truth: two arguments; the decompiler renamed the 2nd
        # (``c`` vs ``i``), so only ABI position — not name — can match it.
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

        # Returns (similarity, changed_lines). Identical -> perfect, 0 changes.
        lines = ["mov rax, rbx", "add rax, 1", "ret"]
        sim, changed = _compute_jaccard_similarity(lines, lines)
        assert sim == 1.0
        assert changed == 0

        # Completely different -> 0 similarity, every line changed on both sides.
        lines_a = ["mov rax, rbx", "ret"]
        lines_b = ["push rbp", "pop rbp"]
        sim, changed = _compute_jaccard_similarity(lines_a, lines_b)
        assert sim == 0.0
        assert changed == len(lines_a) + len(lines_b)

        # Empty
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
