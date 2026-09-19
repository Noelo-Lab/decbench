"""Tests for the LLM / coding-agent decompiler backends.

The pieces that don't require a real (paid, slow) agent call — registration,
the shared prompt, C extraction/renaming, target selection, the cost cap, and
the sample-set manifest exporter — are tested directly. A real single-function
decompile is exercised only when the CLI is installed AND opted into via
``DECBENCH_LLM_LIVE=1`` (kept out of normal CI).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from decbench.decompilers import llm_dec
from decbench.decompilers.registry import DecompilerRegistry
from decbench.models.decompilation import DecompilationResult, LineMapping
from decbench.utils import binfmt


def test_backends_register():
    for name in ("codex", "claude-code", "kimi-code"):
        dec = DecompilerRegistry.get(name)
        assert dec.id == name
        assert dec.name == name


def test_versioned_spec_sets_model():
    dec = DecompilerRegistry.get("codex@gpt-5.6-sol")
    assert dec.id == "codex@gpt-5.6-sol"
    assert dec._model() == "gpt-5.6-sol"
    dec = DecompilerRegistry.get("kimi-code@kimi-code/k3")
    assert dec.id == "kimi-code@kimi-code/k3"
    assert dec._model() == "kimi-code/k3"


def test_shared_prompt_states_the_policy():
    p = llm_dec.LLM_DECOMPILE_PROMPT.lower()
    assert "banned" in p
    for tool in ("ghidra", "ida", "hex-rays", "binary ninja", "angr"):
        assert tool in p
    assert "objdump" in p
    assert "c source" in p or "reconstruct the original c" in p
    assert "address_lines.json" in p
    assert "optional" in p


def test_agent_address_lines_are_validated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "address_lines.json"
    path.write_text(
        json.dumps(
            [
                {"line_number": 2, "addresses": ["0x1004", "0x1004", "0x2000"]},
                {"line_number": 3, "addresses": ["0x1008"]},
                {"line_number": 99, "addresses": ["0x100c"]},
                {"line_number": 1, "addresses": ["not-an-address"]},
            ]
        )
    )
    monkeypatch.setattr(llm_dec.common, "elf_text_ranges", lambda _path: [(0x1000, 0x1010)])
    mappings = llm_dec._read_address_lines(path, "int f(void) {\n return 1;\n}\n", tmp_path / "bin")
    assert [(m.line_number, m.addresses) for m in mappings] == [(2, [0x1004]), (3, [0x1008])]
    shifted = llm_dec._read_address_lines(
        path, "int f(void) {\n return 1;\n}\n", tmp_path / "bin", line_offset=1
    )
    assert [(m.line_number, m.addresses) for m in shifted] == [(1, [0x1004]), (2, [0x1008])]


def test_agent_address_lines_reach_function_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dec = DecompilerRegistry.get("codex")
    monkeypatch.setattr(dec, "get_version", lambda: "test")
    mapping = LineMapping(line_number=1, addresses=[0x1004])
    monkeypatch.setattr(
        dec,
        "_decompile_one",
        lambda *_args: ("int sub_1000(void) { return 1; }\n", 0.1, None, [mapping]),
    )
    result = dec.decompile_binary(tmp_path / "binary", function_names={0x1000})
    function = result.functions["sub_1000"]
    assert function.line_mappings == [mapping]
    assert function.metadata["line_mapping_source"] == "agent_reported"


def test_codex_requires_api_key_and_does_not_copy_subscription_auth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    old_home = tmp_path / ".codex"
    old_home.mkdir()
    (old_home / "auth.json").write_text('{"auth_mode":"chatgpt"}')
    dec = DecompilerRegistry.get("codex")
    api_home = dec._isolated_codex_home()
    assert api_home.name == "codex-home-api"
    assert not (api_home / "auth.json").exists()
    assert (api_home / "skills").is_dir()
    (api_home / "auth.json").write_text('{"auth_mode":"apikey","OPENAI_API_KEY":"test-key"}')
    env = dec._agent_env()
    assert Path(env["CODEX_HOME"]) == api_home
    assert "OPENAI_API_KEY" not in env
    (api_home / "auth.json").write_text('{"auth_mode":"chatgpt"}')
    with pytest.raises(RuntimeError, match="not logged in with the current API key"):
        dec._agent_env()
    (api_home / "auth.json").write_text('{"auth_mode":"apikey","OPENAI_API_KEY":"old"}')
    with pytest.raises(RuntimeError, match="not logged in with the current API key"):
        dec._agent_env()
    monkeypatch.delenv("OPENAI_API_KEY")
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        dec._agent_env()


def test_agent_container_does_not_receive_codex_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPENAI_API_KEY", "codex-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "claude-key")
    dec = DecompilerRegistry.get("claude-code")
    monkeypatch.setattr(dec, "_docker_image", lambda: "agent-image")
    monkeypatch.setattr(llm_dec, "docker_tracking_args", lambda: [])
    monkeypatch.setattr(llm_dec, "docker_memory_args", lambda _limit: [])
    argv, _kwargs = dec._invocation(tmp_path, "prompt", tmp_path / "target.bin")
    assert "ANTHROPIC_API_KEY" in argv
    assert "OPENAI_API_KEY" not in argv
    assert not any(".codex" in arg or "CODEX_HOME" in arg for arg in argv)


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
    assert "int sub_18a5(" in renamed
    assert "wcomment" not in renamed


def test_rename_func_ignores_preprocessor_control_flow():
    code = (
        "#define CHECK(x) \\\n"
        "    if (x) { return 1; }\n"
        "int main(void) { CHECK(0); if (1) { return 0; } }"
    )
    renamed = llm_dec._rename_func(code, "sub_3d20")
    assert "int sub_3d20(void)" in renamed
    assert "if (x)" in renamed
    assert "if (1)" in renamed


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
    assert len(calls) == 3


def test_disasm_hint_on_real_binary():
    """The disassembly hint should produce x86 mnemonics for a real ELF."""
    b = Path("results/full_run/O0/bash/compiled/mksyntax")
    if not b.is_file():
        pytest.skip("sample binary not present")
    hint = llm_dec._disasm_hint(b, 0x18A5)
    assert hint and "0x18a5" in hint


def test_disasm_hint_uses_thumb_for_m_profile_and_odd_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeSection(dict[str, int]):
        def data(self) -> bytes:
            return b"\x00\xbf\x70\x47"

    class FakeELF:
        def __init__(self, _stream: object) -> None:
            pass

        def get_section_by_name(self, name: str) -> FakeSection | None:
            return FakeSection(sh_addr=0x8000B8C) if name == ".text" else None

    mclass = [True]

    def fake_detect(_path: Path) -> binfmt.BinInfo:
        return binfmt.BinInfo("elf", "arm", 32)

    def fake_mclass(_path: Path) -> bool:
        return mclass[0]

    monkeypatch.setattr("elftools.elf.elffile.ELFFile", FakeELF)
    monkeypatch.setattr(binfmt, "detect", fake_detect)
    monkeypatch.setattr(binfmt, "elf_is_arm_mclass", fake_mclass)
    binary = tmp_path / "arm.elf"
    binary.write_bytes(b"fake")
    assert "0x8000b8c: nop" in llm_dec._disasm_hint(binary, 0x8000B8C)
    mclass[0] = False
    assert "0x8000b8c: nop" in llm_dec._disasm_hint(binary, 0x8000B8D)


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


def test_sample_set_gate_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from scripts.run_benchmark import _load_sampleset_manifest

    path = tmp_path / "missing.json"
    monkeypatch.setenv("DECBENCH_SAMPLESET_MANIFEST", str(path))
    with pytest.raises(RuntimeError, match="could not read"):
        _load_sampleset_manifest()
    path.write_text('{"functions": []}')
    with pytest.raises(RuntimeError, match="empty or invalid"):
        _load_sampleset_manifest()


def test_sampleset_resume_requires_every_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from types import SimpleNamespace

    from decbench.models.project import OptimizationLevel
    from scripts import run_benchmark

    o0 = OptimizationLevel.O0
    o2 = OptimizationLevel.O2
    project = SimpleNamespace(
        name="demo",
        compiled_binaries={o0: [tmp_path / "first"], o2: [tmp_path / "second"]},
    )
    monkeypatch.setattr(
        run_benchmark,
        "SAMPLESET_GATE",
        {("demo", "O0", "first"): {"foo"}, ("demo", "O2", "second"): {"bar"}},
    )
    checkpoint = {o0: {"first": {"codex": object()}}, o2: {"second": {}}}
    assert "codex" not in run_benchmark._present_decompilers(checkpoint, project)
    checkpoint[o2]["second"]["codex"] = object()
    assert "codex" in run_benchmark._present_decompilers(checkpoint, project)


@pytest.mark.skipif(
    os.environ.get("DECBENCH_LLM_LIVE") != "1",
    reason="live agent call is opt-in (DECBENCH_LLM_LIVE=1) — paid + slow",
)
@pytest.mark.parametrize("name", ["codex", "claude-code", "kimi-code"])
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
