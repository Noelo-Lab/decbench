"""Tests for the LLM / coding-agent decompiler backends.

The pieces that don't require a real (paid, slow) agent call — registration,
the shared prompt, C extraction/renaming, target selection, the cost cap, and
the sample-set manifest exporter — are tested directly. A real single-function
decompile is exercised only when the CLI is installed AND opted into via
``DECBENCH_LLM_LIVE=1`` (kept out of normal CI).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from decbench.decompilers import llm_dec
from decbench.decompilers.registry import DecompilerRegistry
from decbench.models.decompilation import DecompilationResult


def test_backends_register():
    for name in ("codex", "claude-code"):
        dec = DecompilerRegistry.get(name)
        assert dec.id == name
        assert dec.name == name


def test_versioned_spec_sets_model():
    dec = DecompilerRegistry.get("codex@gpt-5.6-sol")
    assert dec.id == "codex@gpt-5.6-sol"
    assert dec._model() == "gpt-5.6-sol"


def test_shared_prompt_states_the_policy():
    p = llm_dec.LLM_DECOMPILE_PROMPT.lower()
    # Banned from decompilers, allowed simple disassemblers.
    assert "banned" in p
    for tool in ("ghidra", "ida", "hex-rays", "binary ninja", "angr"):
        assert tool in p
    assert "objdump" in p
    # Reconstruct C faithful to the original source.
    assert "c source" in p or "reconstruct the original c" in p


def test_extract_c_from_fence():
    text = "Here you go:\n```c\nint f(int a) { return a + 1; }\n```\nDone."
    code = llm_dec._extract_c(text)
    assert code is not None and "int f(int a)" in code


def test_extract_c_from_bare_definition():
    text = "prose\nint g(void)\n{\n  return 0;\n}\ntrailing"
    code = llm_dec._extract_c(text)
    assert code is not None
    assert code.strip().startswith("int g(void)")
    assert code.strip().endswith("}")


def test_rename_func_matches_placeholder():
    code = "int wcomment(char *s) { return wcomment(s); }"
    renamed = llm_dec._rename_func(code, "sub_18a5")
    # Both the definition and the recursive call are renamed.
    assert "int sub_18a5(" in renamed
    assert "wcomment" not in renamed


def test_select_targets_from_addresses():
    dec = DecompilerRegistry.get("codex")
    targets = dec._select_targets(Path("/nonexistent"), None, {0x1000, 0x2000})
    assert sorted(targets) == [("sub_1000", 0x1000), ("sub_2000", 0x2000)]


def test_select_targets_prefers_explicit_functions():
    dec = DecompilerRegistry.get("claude-code")
    targets = dec._select_targets(Path("/x"), [("foo", 0x400)], {0x1000})
    assert targets == [("foo", 0x400)]


def test_cost_cap_truncates(monkeypatch, tmp_path):
    """A binary with more targets than max_funcs must never fan out uncapped."""
    monkeypatch.setenv("DECBENCH_LLM_MAX_FUNCS", "3")
    dec = DecompilerRegistry.get("codex")
    calls: list[int] = []

    def fake_one(binary_path, name, addr, output_dir=None):
        calls.append(addr)
        return f"int {name}(void) {{ return 0; }}"

    monkeypatch.setattr(dec, "_decompile_one", fake_one)
    fake_bin = tmp_path / "b"
    fake_bin.write_bytes(b"\x7fELF")
    res = dec.decompile_binary(fake_bin, function_names={i for i in range(20)})
    assert isinstance(res, DecompilationResult)
    assert len(calls) == 3  # capped, not 20


def test_disasm_hint_on_real_binary():
    """The disassembly hint should produce x86 mnemonics for a real ELF."""
    b = Path("results/full_run/O0/bash/compiled/mksyntax")
    if not b.is_file():
        pytest.skip("sample binary not present")
    hint = llm_dec._disasm_hint(b, 0x18A5)
    # Non-empty and looks like disassembly (has an address + a mnemonic).
    assert hint and "0x18a5" in hint


def test_export_sample_set_shape():
    fr = Path("results/full_run/function_results.json")
    if not fr.is_file():
        pytest.skip("full_run not present")
    from scripts.export_sample_set import export_sample_set  # type: ignore

    manifest = export_sample_set(fr)
    assert manifest.method == "sample-set"
    assert 200 <= len(manifest.functions) <= 250
    keys = {"project", "opt", "binary", "function"}
    assert all(keys == set(e) for e in manifest.functions)


@pytest.mark.skipif(
    os.environ.get("DECBENCH_LLM_LIVE") != "1",
    reason="live agent call is opt-in (DECBENCH_LLM_LIVE=1) — paid + slow",
)
@pytest.mark.parametrize("name", ["codex", "claude-code"])
def test_live_single_function(name, tmp_path):
    import shutil
    import subprocess

    dec = DecompilerRegistry.get(name)
    if not dec.is_available():
        pytest.skip(f"{name} CLI/credentials not available")
    src = Path("results/full_run/O0/bash/compiled/mksyntax")
    if not src.is_file():
        pytest.skip("sample binary not present")
    stripped = tmp_path / src.name
    shutil.copy2(src, stripped)
    subprocess.run(["strip", "--strip-all", str(stripped)], capture_output=True)
    res = dec.decompile_binary(stripped, function_names={0x18A5})
    assert res.functions, "expected at least one reconstructed function"
    fd = next(iter(res.functions.values()))
    assert "{" in fd.decompiled_code and "}" in fd.decompiled_code
