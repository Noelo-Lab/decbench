"""Tests for the cost fact-gathering (:mod:`decbench.scoring.cost`).

Everything runs on tiny fabricated files in ``tmp_path`` — no results tree, no
agent CLIs. What is pinned: the header-only TOML parse (never the ~100 function
tables), the batch mean/median arithmetic, the trace ``.md`` meta parse, both
session-JSONL token formats (claude / codex) plus the unknown-format ``None``
degrade, and the structured cost fields round-tripping through
:class:`FunctionDecompilation`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from decbench.scoring.cost import (
    build_cost_info,
    parse_session_tokens,
    scan_decompile_times,
    scan_llm_traces,
    scan_structured_costs,
)

# -- fixtures ---------------------------------------------------------------


def _write_decompiled_toml(
    tree: Path,
    opt: str,
    project: str,
    stem: str,
    *,
    decompiler: str,
    total_time: float,
    function_count: int,
    body: str = "",
) -> Path:
    """One ``<tree>/<opt>/<proj>/decompiled/<stem>.toml`` artifact."""
    path = tree / opt / project / "decompiled" / f"{stem}.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'binary = "{stem}"\n'
        f'decompiler = "{decompiler}"\n'
        f'version = "1.0"\n'
        f"total_time = {total_time}\n"
        f"timeout = false\n"
        f"function_count = {function_count}\n"
        f"failed_functions = []\n\n" + body
    )
    return path


def _trace_md(traces: Path, backend: str, label: str, *, status: str, elapsed: int) -> None:
    path = traces / backend / f"{label}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"# {backend} trace — {label}\n\n"
        f"- model: test-model\n"
        f"- binary given to agent: target.bin (original: {label})\n"
        f"- status: {status}\n"
        f"- elapsed: {elapsed}s\n\n"
        f"## Prompt\n\n```\nx\n```\n"
    )


def _claude_session(path: Path) -> None:
    """Two assistant records (usage sums across them) plus noise records."""
    records = [
        {"type": "system", "message": {}},
        {
            "type": "assistant",
            "message": {
                "usage": {
                    "input_tokens": 2,
                    "cache_creation_input_tokens": 5000,
                    "cache_read_input_tokens": 14000,
                    "output_tokens": 100,
                    "cache_creation": {
                        "ephemeral_1h_input_tokens": 5000,
                        "ephemeral_5m_input_tokens": 0,
                    },
                }
            },
        },
        {"type": "user", "message": {"content": "tool result"}},
        {
            "type": "assistant",
            "message": {
                "usage": {
                    "input_tokens": 3,
                    "cache_creation_input_tokens": 200,
                    "cache_read_input_tokens": 6000,
                    "output_tokens": 50,
                }
            },
        },
    ]
    path.write_text("\n".join(json.dumps(r) for r in records))


def _codex_session(path: Path) -> None:
    """Running token_count totals — only the LAST one counts."""
    records = [
        {"payload": {"type": "session_meta", "info": {}}},
        {
            "payload": {
                "type": "token_count",
                "info": {
                    "total_token_usage": {
                        "input_tokens": 100,
                        "cached_input_tokens": 90,
                        "output_tokens": 10,
                    }
                },
            }
        },
        {
            "payload": {
                "type": "token_count",
                "info": {
                    "total_token_usage": {
                        "input_tokens": 553000,
                        "cached_input_tokens": 487000,
                        "output_tokens": 6500,
                        "reasoning_output_tokens": 4300,
                    }
                },
            }
        },
    ]
    path.write_text("\n".join(json.dumps(r) for r in records))


# -- batch decompile-time scan ----------------------------------------------


def test_scan_reads_only_the_toml_header(tmp_path: Path) -> None:
    """The per-function tables after the header must never be parsed: a broken
    table body (invalid TOML) cannot fail the scan, because the parse stops at
    the first ``[`` line."""
    _write_decompiled_toml(
        tmp_path,
        "O0",
        "proj",
        "ghidra_grep",
        decompiler="ghidra",
        total_time=10.0,
        function_count=20,
        body='["functions.f1"]\nthis is not valid toml === at all\n',
    )
    times = scan_decompile_times(tmp_path, ["O0"])
    assert times["ghidra"]["functions"] == 20
    assert times["ghidra"]["per_fn_mean_s"] == pytest.approx(0.5)


def test_scan_keys_by_header_decompiler_not_filename(tmp_path: Path) -> None:
    """`claude-code_my_bin.toml` — both halves can hold underscores, so the id
    must come from the header's `decompiler` field, never the stem."""
    _write_decompiled_toml(
        tmp_path,
        "O0",
        "proj",
        "claude-code_my_bin",
        decompiler="claude-code",
        total_time=5.0,
        function_count=5,
    )
    times = scan_decompile_times(tmp_path, ["O0"])
    assert set(times) == {"claude-code"}


def test_scan_mean_median_and_zero_skip(tmp_path: Path) -> None:
    """Mean is amortized (sum/sum); median is over per-binary rates; a binary
    with zero time or zero functions contributes nothing."""
    # Three real binaries: rates 1.0, 2.0 and 6.0 s/fn.
    _write_decompiled_toml(
        tmp_path, "O0", "p1", "angr_a", decompiler="angr", total_time=10.0, function_count=10
    )
    _write_decompiled_toml(
        tmp_path, "O2", "p2", "angr_b", decompiler="angr", total_time=20.0, function_count=10
    )
    _write_decompiled_toml(
        tmp_path, "O2", "p3", "angr_c", decompiler="angr", total_time=60.0, function_count=10
    )
    # Skipped: no functions / no recorded time.
    _write_decompiled_toml(
        tmp_path, "O0", "p4", "angr_d", decompiler="angr", total_time=99.0, function_count=0
    )
    _write_decompiled_toml(
        tmp_path, "O0", "p5", "angr_e", decompiler="angr", total_time=0.0, function_count=9
    )
    times = scan_decompile_times(tmp_path, ["O0", "O2"])["angr"]
    assert times["total_s"] == pytest.approx(90.0)
    assert times["functions"] == 30
    assert times["binaries"] == 3
    assert times["per_fn_mean_s"] == pytest.approx(3.0)  # 90 / 30
    assert times["per_fn_median_s"] == pytest.approx(2.0)  # median of [1, 2, 6]
    assert times["basis"] == "batch"


def test_scan_respects_the_given_opt_levels(tmp_path: Path) -> None:
    _write_decompiled_toml(
        tmp_path, "O0", "p", "ida_x", decompiler="ida", total_time=1.0, function_count=1
    )
    _write_decompiled_toml(
        tmp_path, "O2", "p", "ida_x", decompiler="ida", total_time=9.0, function_count=1
    )
    assert scan_decompile_times(tmp_path, ["O0"])["ida"]["total_s"] == pytest.approx(1.0)


# -- session token parsing --------------------------------------------------


def test_parse_claude_session_tokens(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    _claude_session(path)
    tokens = parse_session_tokens(path)
    assert tokens == {
        "input": 5,  # 2 + 3
        "cached_input": 20000,  # 14000 + 6000
        "cache_write": 5200,  # 5000 + 200 (no double count with the breakdown)
        "output": 150,  # 100 + 50
    }


def test_parse_codex_session_tokens_normalizes_cached_input(tmp_path: Path) -> None:
    """Codex `input_tokens` INCLUDES the cached part; the parse subtracts it so
    pricing never charges cached tokens at the full input rate. Only the LAST
    running total counts."""
    path = tmp_path / "s.jsonl"
    _codex_session(path)
    tokens = parse_session_tokens(path)
    assert tokens == {
        "input": 66000,  # 553000 - 487000
        "cached_input": 487000,
        "cache_write": 0,
        "output": 6500,  # already includes reasoning
    }


def test_parse_unknown_session_format_returns_none(tmp_path: Path) -> None:
    """A future backend's log must degrade to None, not a guess."""
    path = tmp_path / "s.jsonl"
    path.write_text('{"kind": "wire", "data": {"whatever": 1}}\nnot json at all\n')
    assert parse_session_tokens(path) is None
    assert parse_session_tokens(tmp_path / "missing.jsonl") is None


# -- trace scan -------------------------------------------------------------


def test_scan_llm_traces(tmp_path: Path) -> None:
    traces = tmp_path / "traces"
    _trace_md(traces, "claude-code", "O0__p__b__f1_0x1", status="ok", elapsed=100)
    _trace_md(traces, "claude-code", "O0__p__b__f2_0x2", status="FAILED", elapsed=300)
    _trace_md(traces, "claude-code", "O0__p__b__f3_0x3", status="TIMEOUT", elapsed=200)
    _claude_session(traces / "claude-code" / "O0__p__b__f1_0x1.session.jsonl")
    # A dir with no .md files is not a backend.
    (traces / "not-a-backend").mkdir()

    scanned = scan_llm_traces(traces)
    assert set(scanned) == {"claude-code"}
    entry = scanned["claude-code"]
    assert entry["model"] == "test-model"
    assert entry["functions"] == 3
    # FAILED and TIMEOUT both count as failed AND still contribute wall time —
    # that time (and those tokens) were genuinely spent.
    assert entry["failed"] == 2
    assert entry["elapsed"]["total_s"] == pytest.approx(600.0)
    assert entry["elapsed"]["mean_s"] == pytest.approx(200.0)
    assert entry["elapsed"]["median_s"] == pytest.approx(200.0)
    assert entry["tokens"]["sessions"] == 1
    assert entry["tokens"]["output"] == 150


def test_scan_llm_traces_without_parseable_sessions_has_none_tokens(tmp_path: Path) -> None:
    traces = tmp_path / "traces"
    _trace_md(traces, "kimi-code", "O0__p__b__f_0x1", status="ok", elapsed=50)
    (traces / "kimi-code" / "O0__p__b__f_0x1.session.jsonl").write_text('{"kind": "wire"}\n')
    entry = scan_llm_traces(traces)["kimi-code"]
    assert entry["tokens"] is None
    assert entry["elapsed"]["total_s"] == pytest.approx(50.0)
    assert scan_llm_traces(tmp_path / "nope") == {}


# -- structured fields (FunctionDecompilation -> TOML -> scan) ---------------


def test_function_decompilation_round_trips_cost_fields(tmp_path: Path) -> None:
    """The two structured fields survive pydantic serialization AND the
    DecompilationResult TOML artifact; records without them still load (None)."""
    from decbench.models.decompilation import (
        DecompilationResult,
        DecompilerMetadata,
        FunctionDecompilation,
    )

    func = FunctionDecompilation(
        name="f",
        address=0x1000,
        decompiled_code="int f(void) { return 0; }",
        time_seconds=12.5,
        llm_tokens={"input": 10, "cached_input": 5, "cache_write": 2, "output": 3},
    )
    # Pydantic round trip.
    back = FunctionDecompilation.model_validate(json.loads(func.model_dump_json()))
    assert back.time_seconds == 12.5
    assert back.llm_tokens == {"input": 10, "cached_input": 5, "cache_write": 2, "output": 3}
    # Pre-field artifacts still load, defaulting to None.
    legacy = FunctionDecompilation(name="g", address=1, decompiled_code="")
    assert legacy.time_seconds is None and legacy.llm_tokens is None

    # TOML artifact round trip (the structured scan's input).
    import toml

    result = DecompilationResult(
        binary_path=tmp_path / "bin",
        binary_name="bin",
        decompiler=DecompilerMetadata(decompiler_name="claude-code"),
        functions={"f": func, "g": legacy},
    )
    out = tmp_path / "artifact.toml"
    result.to_toml(out)
    data = toml.load(out)
    assert data["functions.f"]["time_seconds"] == 12.5
    assert data["functions.f"]["llm_tokens"]["cached_input"] == 5
    # None fields are omitted, keeping batch backends' artifacts unchanged.
    assert "time_seconds" not in data["functions.g"]
    assert "llm_tokens" not in data["functions.g"]


def test_scan_structured_costs_prefers_new_run_artifacts(tmp_path: Path) -> None:
    from decbench.models.decompilation import (
        DecompilationResult,
        DecompilerMetadata,
        FunctionDecompilation,
    )

    result = DecompilationResult(
        binary_path=tmp_path / "b",
        binary_name="b",
        decompiler=DecompilerMetadata(
            decompiler_name="claude-code",
            decompiler_version="claude-opus-4-8 (2.1.0)",
            failed_functions=["h"],
        ),
        functions={
            "f": FunctionDecompilation(
                name="f",
                address=1,
                decompiled_code="x",
                time_seconds=100.0,
                llm_tokens={"input": 7, "cached_input": 1, "cache_write": 2, "output": 4},
            ),
            "g": FunctionDecompilation(
                name="g", address=2, decompiled_code="y", time_seconds=300.0
            ),
        },
    )
    dest = tmp_path / "O0" / "proj" / "decompiled" / "claude-code_b.toml"
    dest.parent.mkdir(parents=True)
    result.to_toml(dest)
    # A batch artifact without the fields is skipped by the substring sniff.
    _write_decompiled_toml(
        tmp_path, "O0", "proj", "angr_b", decompiler="angr", total_time=5.0, function_count=5
    )

    scanned = scan_structured_costs(tmp_path, ["O0"])
    assert set(scanned) == {"claude-code"}
    entry = scanned["claude-code"]
    assert entry["model"] == "claude-opus-4-8"  # from the header version
    assert entry["functions"] == 2
    assert entry["failed"] == 1
    assert entry["elapsed"]["mean_s"] == pytest.approx(200.0)
    assert entry["tokens"] == {
        "input": 7,
        "cached_input": 1,
        "cache_write": 2,
        "output": 4,
        "sessions": 1,
    }


def test_build_cost_info_merges_scans_structured_first(tmp_path: Path) -> None:
    """build_cost_info = batch scan + (traces overridden by structured fields);
    facts only, JSON-serializable, no prices anywhere."""
    from decbench.models.decompilation import (
        DecompilationResult,
        DecompilerMetadata,
        FunctionDecompilation,
    )

    _write_decompiled_toml(
        tmp_path, "O0", "proj", "ghidra_b", decompiler="ghidra", total_time=10.0, function_count=20
    )
    traces = tmp_path / "traces"
    _trace_md(traces, "codex", "O0__p__b__f_0x1", status="ok", elapsed=400)
    _trace_md(traces, "claude-code", "O0__p__b__f_0x1", status="ok", elapsed=999)
    # claude-code ALSO has structured artifacts — they must win over its traces.
    result = DecompilationResult(
        binary_path=tmp_path / "b",
        binary_name="b",
        decompiler=DecompilerMetadata(decompiler_name="claude-code"),
        functions={
            "f": FunctionDecompilation(name="f", address=1, decompiled_code="x", time_seconds=50.0)
        },
    )
    dest = tmp_path / "O0" / "proj" / "decompiled" / "claude-code_b.toml"
    result.to_toml(dest)

    info = build_cost_info(tmp_path, traces, ["O0"])
    assert info["decompile_time"]["ghidra"]["per_fn_mean_s"] == pytest.approx(0.5)
    assert info["llm"]["codex"]["elapsed"]["mean_s"] == pytest.approx(400.0)  # trace path
    assert info["llm"]["claude-code"]["elapsed"]["mean_s"] == pytest.approx(50.0)  # structured
    json.dumps(info, allow_nan=False)  # the whole blob must be strict-JSON-safe

    # Without a traces dir the llm block still carries the structured backends.
    info = build_cost_info(tmp_path, None, ["O0"])
    assert set(info["llm"]) == {"claude-code"}
