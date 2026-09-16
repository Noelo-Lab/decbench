"""Contract tests for the provider-neutral CFG extraction boundary."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from decbench.cfg import CindergraphCfgExtractor, graph_from_record, graphs_from_extraction
from decbench.utils.cfg import extract_cfg_records_from_source


def test_cindergraph_source_extraction_is_provider_neutral(tmp_path: Path) -> None:
    source = tmp_path / "branch.c"
    text = "int branch(int x) { if (x) return 1; return 0; }\n"
    source.write_text(text)

    extraction = CindergraphCfgExtractor().extract_source(source, text, "c")

    assert extraction.status == "ok"
    assert extraction.provider == "cindergraph"
    assert extraction.language == "c"
    assert extraction.diagnostics == ()
    record = extraction.functions["branch"]
    assert record.nodes == (0, 1, 2)
    assert record.edges == ((0, 1), (0, 2))
    assert record.entry == (0,)
    assert not record.degenerate

    graph = graph_from_record(record, extraction)
    assert graph.number_of_nodes() == 3
    assert graph.graph["cfg_extractor"] == "cindergraph"
    assert graph.graph["cfg_language"] == "c"
    assert graph.graph["diagnostic_count"] == 0


def test_cxx_is_a_typed_unsupported_outcome(tmp_path: Path) -> None:
    source = tmp_path / "unit.cc.ii"
    source.write_text("int main() { return 0; }\n")

    extraction = extract_cfg_records_from_source(source)

    assert extraction.status == "unsupported-language"
    assert extraction.language == "c++"
    assert extraction.functions == {}
    assert extraction.diagnostics[0].code == "unsupported-language"


def test_one_block_function_is_explicitly_non_degenerate(tmp_path: Path) -> None:
    source = tmp_path / "straight.c"
    source.write_text("int straight(void) { return 7; }\n")

    extraction = extract_cfg_records_from_source(source)
    graphs = graphs_from_extraction(extraction)

    assert not extraction.functions["straight"].degenerate
    assert graphs["straight"].graph["degenerate"] is False


def test_serialized_topology_is_deterministic(tmp_path: Path) -> None:
    source = tmp_path / "loop.c"
    source.write_text("int loop(int n) { while (n--) { if (n == 2) break; } return n; }\n")

    first = extract_cfg_records_from_source(source)
    second = extract_cfg_records_from_source(source)

    assert first.functions == second.functions


def test_serialized_topology_is_deterministic_across_processes() -> None:
    program = """
import json
from dataclasses import asdict
from pathlib import Path
from decbench.cfg import CindergraphCfgExtractor
source = 'int f(int n) { while (n--) { if (n == 2) break; } return n; }'
result = CindergraphCfgExtractor().extract_source(Path('memory.c'), source, 'c')
print(json.dumps(asdict(result.functions['f']), sort_keys=True))
"""

    first = subprocess.check_output([sys.executable, "-c", program], text=True)
    second = subprocess.check_output([sys.executable, "-c", program], text=True)

    assert json.loads(first) == json.loads(second)


def test_provider_neutral_record_is_json_serializable(tmp_path: Path) -> None:
    source = tmp_path / "serial.c"
    source.write_text("int serial(void) { return 1; }\n")
    result = extract_cfg_records_from_source(source)

    encoded = json.dumps(asdict(result.functions["serial"]), sort_keys=True)

    assert json.loads(encoded)["degenerate"] is False


def test_core_control_flow_constructs_are_recovered(tmp_path: Path) -> None:
    source = tmp_path / "constructs.c"
    source.write_text("""
int early(int x) { if (x) return 1; return 0; }
int choose(int x) { switch (x) { case 1: return 2; default: return 3; } }
int jump(int x) { if (x) goto done; x++; done: return x; }
int computed(void *p) { goto *p; }
int empty(void) {}
""")

    result = extract_cfg_records_from_source(source)

    assert set(result.functions) == {"early", "choose", "jump", "computed", "empty"}
    assert not result.functions["early"].degenerate
    assert not result.functions["choose"].degenerate
    assert not result.functions["jump"].degenerate
    assert not result.functions["computed"].degenerate
    # An empty *definition* is still a genuine one-block function and remains
    # scoreable; only declaration-only/missing-body views are degenerate.
    assert not result.functions["empty"].degenerate
