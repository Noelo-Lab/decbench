"""Unit tests for the dewolf backend's config + JSON-stream parsing.

The real decompilation runs Binary Ninja + dewolf in a separate venv, so these
tests exercise the parts that do NOT need that toolchain: config resolution,
availability gating, and turning the driver's JSON-line protocol into
``FunctionDecompilation`` objects (via a fake driver subprocess).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import decbench.decompilers  # noqa: F401  (registers the raw backends)
from decbench.decompilers.raw.dewolf_raw import RawDewolfDecompiler
from decbench.decompilers.registry import DecompilerRegistry


def test_dewolf_is_registered() -> None:
    dec = DecompilerRegistry.get("dewolf")
    assert isinstance(dec, RawDewolfDecompiler)
    assert dec.id == "dewolf"


def test_unavailable_without_python(monkeypatch) -> None:
    monkeypatch.delenv("DECBENCH_DEWOLF_PYTHON", raising=False)
    monkeypatch.delenv("DECBENCH_DEWOLF_REPO", raising=False)
    dec = RawDewolfDecompiler()
    # No configured interpreter (and the test env has no versions config for it):
    monkeypatch.setattr(dec, "_python", lambda: None)
    assert dec.is_available() is False


def test_child_env_prepends_repo_and_astyle(monkeypatch, tmp_path: Path) -> None:
    dec = RawDewolfDecompiler()
    monkeypatch.setattr(dec, "_repo", lambda: "/opt/dewolf")
    monkeypatch.setattr(dec, "_astyle_dir", lambda: "/opt/astyle/bin")
    monkeypatch.setenv("PYTHONPATH", "/existing")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = dec._child_env()
    assert env["PYTHONPATH"].split(":")[0] == "/opt/dewolf"
    assert "/existing" in env["PYTHONPATH"]
    assert env["PATH"].split(":")[0] == "/opt/astyle/bin"


# A stand-in driver: emits the JSON protocol and exits, so decompile_binary can
# be exercised without Binary Ninja or the dewolf venv.
_FAKE_DRIVER = """\
import json, sys
def e(o): sys.stdout.write(json.dumps(o) + "\\n")
e({"type": "meta", "load_base": 4194304, "count": 2})
e({"type": "func", "name": "alpha", "addr": 4096, "code": "int alpha(){return 1;}"})
e({"type": "fail", "name": "beta", "addr": 8192, "error": "boom"})
e({"type": "func", "name": "gamma", "addr": 12288, "code": "int gamma(){return 3;}"})
e({"type": "done"})
"""


def test_decompile_binary_parses_driver_stream(monkeypatch, tmp_path: Path) -> None:
    driver = tmp_path / "fake_driver.py"
    driver.write_text(_FAKE_DRIVER)
    binary = tmp_path / "bin.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

    dec = RawDewolfDecompiler()
    monkeypatch.setattr(dec, "is_available", lambda: True)
    monkeypatch.setattr(dec, "get_version", lambda: "vTEST")
    monkeypatch.setattr(dec, "_python", lambda: sys.executable)
    monkeypatch.setattr(dec, "_child_env", dict)
    monkeypatch.setattr("decbench.decompilers.raw.dewolf_raw._DRIVER", driver)
    # elf_min_vaddr on our stub bytes → 0; the driver's addrs are already
    # ELF-file-space, so they pass straight through.
    monkeypatch.setattr("decbench.decompilers.raw.dewolf_raw.common.elf_min_vaddr", lambda p: 0)

    out = tmp_path / "out"
    result = dec.decompile_binary(binary, output_dir=out, function_names={4096, 12288})

    assert set(result.functions) == {"alpha", "gamma"}
    assert result.functions["alpha"].address == 4096
    assert result.functions["gamma"].line_count == 1
    assert "beta" in result.decompiler.failed_functions
    assert (out / "dewolf_bin.c").exists()


def test_int_address_filter_arg_is_json(monkeypatch, tmp_path: Path) -> None:
    """Only int targets reach the driver, serialized as a JSON list."""
    captured = {}

    class _FakeProc:
        stdout = iter([json.dumps({"type": "done"})])

        def wait(self):
            return 0

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeProc()

    binary = tmp_path / "bin.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    dec = RawDewolfDecompiler()
    monkeypatch.setattr(dec, "is_available", lambda: True)
    monkeypatch.setattr(dec, "get_version", lambda: "vTEST")
    monkeypatch.setattr(dec, "_python", lambda: "python")
    monkeypatch.setattr(dec, "_child_env", dict)
    monkeypatch.setattr("decbench.decompilers.raw.dewolf_raw.common.elf_min_vaddr", lambda p: 0)
    monkeypatch.setattr("decbench.decompilers.raw.dewolf_raw.subprocess.Popen", fake_popen)

    dec.decompile_binary(binary, function_names={4096, 8192, "not-an-int"})

    addrs_arg = captured["cmd"][-1]
    assert json.loads(addrs_arg) == [4096, 8192]
