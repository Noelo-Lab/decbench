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
from types import SimpleNamespace
from typing import Any

import decbench.decompilers  # noqa: F401  (registers the raw backends)
from decbench.decompilers.raw.dewolf_driver import (
    _configure_worker_threads,
    _native_addresses_for_origins,
    _resolve_ssa_origins,
    _ssa_address_index,
)
from decbench.decompilers.raw.dewolf_raw import RawDewolfDecompiler
from decbench.decompilers.registry import DecompilerRegistry
from decbench.models.decompilation import variable_occurrence_policy


def test_dewolf_is_registered() -> None:
    dec = DecompilerRegistry.get("dewolf")
    assert isinstance(dec, RawDewolfDecompiler)
    assert dec.id == "dewolf"


def test_unavailable_without_python(monkeypatch) -> None:
    monkeypatch.delenv("DECBENCH_DEWOLF_PYTHON", raising=False)
    monkeypatch.delenv("DECBENCH_DEWOLF_REPO", raising=False)
    dec = RawDewolfDecompiler()
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


def test_driver_caps_binary_ninja_workers(monkeypatch) -> None:
    binaryninja = SimpleNamespace(set_worker_thread_count=lambda count: calls.append(count))
    calls: list[int] = []

    monkeypatch.delenv("DECBENCH_DEWOLF_THREADS", raising=False)
    assert _configure_worker_threads(binaryninja) == 2
    monkeypatch.setenv("DECBENCH_DEWOLF_THREADS", "3")
    assert _configure_worker_threads(binaryninja) == 3
    monkeypatch.setenv("DECBENCH_DEWOLF_THREADS", "invalid")
    assert _configure_worker_threads(binaryninja) == 2
    assert calls == [2, 3, 2]


_FAKE_DRIVER = """\
import json, sys
def e(o): sys.stdout.write(json.dumps(o) + "\\n")
e({"type": "meta", "load_base": 4194304, "count": 2, "worker_threads": 2})
e({"type": "func", "name": "alpha", "addr": 4096, "code": "int alpha(){return 1;}",
   "variables": [{"name": "renamed", "type": "int", "size": 4,
                  "kind": "arg", "arg_index": 0,
                  "addresses": [4104, 4100, 4104]}]})
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
    monkeypatch.setattr("decbench.decompilers.raw.dewolf_raw.common.elf_min_vaddr", lambda p: 0)

    out = tmp_path / "out"
    result = dec.decompile_binary(binary, output_dir=out, function_names={4096, 12288})

    assert set(result.functions) == {"alpha", "gamma"}
    assert result.functions["alpha"].address == 4096
    assert result.functions["alpha"].variables[0].model_dump() == {
        "name": "renamed",
        "type": "int",
        "stack_offset": None,
        "size": 4,
        "kind": "arg",
        "arg_index": 0,
        "line_numbers": [],
        "addresses": [4100, 4104],
    }
    assert result.functions["gamma"].line_count == 1
    assert variable_occurrence_policy(result.functions["alpha"].metadata) == "direct"
    assert "beta" in result.decompiler.failed_functions
    assert result.decompiler.extra["worker_threads_per_driver"] == 2
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


def test_sidecar_variables_fail_closed_on_malformed_fields() -> None:
    variables = RawDewolfDecompiler._parse_variables(
        [
            {
                "name": "local",
                "type": "long",
                "size": True,
                "kind": "not-an-arg",
                "arg_index": 4,
                "addresses": [0x1010, True, -1, "0x1020"],
            },
            {"name": "", "addresses": [0x2000]},
            "not-a-record",
        ]
    )
    assert len(variables) == 1
    assert variables[0].kind == "stack"
    assert variables[0].arg_index is None
    assert variables[0].size is None
    assert variables[0].addresses == [0x1010]


class _Mlil(list):
    def __init__(
        self,
        instructions: list[SimpleNamespace],
        definitions: dict[object, SimpleNamespace],
        uses: dict[object, list[SimpleNamespace]],
    ) -> None:
        super().__init__([instructions])
        self.definitions = definitions
        self.uses = uses

    def get_ssa_var_definition(self, variable: object) -> SimpleNamespace | None:
        return self.definitions.get(variable)

    def get_ssa_var_uses(self, variable: object) -> list[SimpleNamespace]:
        return self.uses.get(variable, [])


class _SSA:
    def __init__(self, name: str, version: int, identifier: int) -> None:
        self.var = SimpleNamespace(name=name, identifier=identifier)
        self.version = version


def _ssa(name: str, version: int, identifier: int) -> _SSA:
    return _SSA(name, version, identifier)


def _instruction(
    operation: str,
    address: int,
    *,
    reads: tuple[Any, ...] | list[Any] = (),
    writes: tuple[Any, ...] | list[Any] = (),
    source_operation: str = "",
) -> SimpleNamespace:
    return SimpleNamespace(
        operation=SimpleNamespace(name=operation),
        address=address,
        vars_read=list(reads),
        vars_written=list(writes),
        src=SimpleNamespace(operation=SimpleNamespace(name=source_operation)),
    )


def test_native_ssa_provenance_follows_same_identifier_phi_versions() -> None:
    first = _ssa("value", 1, 7)
    loop = _ssa("value", 2, 7)
    updated = _ssa("value", 3, 7)
    temporary = _ssa("rax", 1, 9)
    first_definition = _instruction("MLIL_SET_VAR_SSA", 0x1010, writes=[first])
    phi = _instruction(
        "MLIL_VAR_PHI",
        0x1020,
        reads=[first, updated],
        writes=[loop],
    )
    updated_definition = _instruction(
        "MLIL_SET_VAR_SSA",
        0x1030,
        reads=[loop],
        writes=[updated],
        source_operation="MLIL_ADD",
    )
    copy = _instruction(
        "MLIL_SET_VAR_SSA",
        0x1040,
        reads=[loop],
        writes=[temporary],
        source_operation="MLIL_VAR_SSA",
    )
    comparison = _instruction("MLIL_IF", 0x1050, reads=[temporary])
    mlil = _Mlil(
        [first_definition, phi, updated_definition, copy, comparison],
        {
            first: first_definition,
            loop: phi,
            updated: updated_definition,
            temporary: copy,
        },
        {
            first: [phi],
            loop: [updated_definition, copy],
            updated: [phi],
            temporary: [comparison],
        },
    )
    variables = {
        (7, 1): first,
        (7, 2): loop,
        (7, 3): updated,
        (9, 1): temporary,
    }
    starts = {0x1010, 0x1020, 0x1030, 0x1040, 0x1050}

    assert _native_addresses_for_origins(mlil, variables, {(7, 2)}, starts) == {
        0x1010,
        0x1030,
        0x1040,
    }
    assert _native_addresses_for_origins(
        mlil,
        variables,
        {(7, 2)},
        starts,
        blocked_origins={(9, 1)},
    ) == {0x1010, 0x1030, 0x1040}


def test_native_ssa_provenance_does_not_cross_identifier_copy() -> None:
    source = _ssa("source", 1, 11)
    destination = _ssa("destination", 1, 12)
    source_definition = _instruction("MLIL_SET_VAR_SSA", 0x2010, writes=[source])
    copy = _instruction(
        "MLIL_SET_VAR_SSA",
        0x2020,
        reads=[source],
        writes=[destination],
        source_operation="MLIL_VAR_SSA",
    )
    destination_use = _instruction("MLIL_CALL", 0x2030, reads=[destination])
    mlil = _Mlil(
        [source_definition, copy, destination_use],
        {source: source_definition, destination: copy},
        {source: [copy], destination: [destination_use]},
    )
    variables = {(11, 1): source, (12, 1): destination}
    starts = {0x2010, 0x2020, 0x2030}

    assert _native_addresses_for_origins(mlil, variables, {(11, 1)}, starts) == {
        0x2010,
        0x2020,
    }
    assert _native_addresses_for_origins(mlil, variables, {(12, 1)}, starts) == {
        0x2020,
        0x2030,
    }


def test_name_version_collision_abstains_from_ssa_join() -> None:
    first = _ssa("value", 1, 21)
    collision = _ssa("value", 1, 22)
    first_definition = _instruction("MLIL_SET_VAR_SSA", 0x3010, writes=[first])
    collision_definition = _instruction("MLIL_SET_VAR_SSA", 0x3020, writes=[collision])
    mlil = _Mlil(
        [first_definition, collision_definition],
        {first: first_definition, collision: collision_definition},
        {},
    )
    function = SimpleNamespace(
        medium_level_il=SimpleNamespace(ssa_form=mlil),
        instructions=[(b"first", 0x3010), (b"collision", 0x3020)],
    )

    _, variables, display_keys, starts = _ssa_address_index(function)

    assert set(variables) == {(21, 1), (22, 1)}
    assert display_keys[("value", 1)] == {(21, 1), (22, 1)}
    assert _resolve_ssa_origins({("value", 1)}, display_keys) == set()
    assert starts == {0x3010, 0x3020}
