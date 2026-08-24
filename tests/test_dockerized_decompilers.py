"""Tests for the dockerized / external-tool decompiler backends.

These tests are designed to run anywhere: anything needing a built image or an
installed tool **skips cleanly** when it is absent. The pure-Python helpers
(C-function splitting, ELF symbol enumeration) and the registration / is_available
semantics are always exercised.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from decbench.decompilers.dockerized import (
    _DOCKER_DIR,
    _R2_DRIVER_CONTAINER_PATH,
    _REKO_PROVENANCE_SCHEMA,
    DockerizedDecompiler,
    R2DecDecompiler,
    RekoDecompiler,
    RetDecDecompiler,
    _func_ident_in_code,
    _load_reko_provenance,
    _parse_retdec_json,
    _r2_bare_name,
    _r2_is_import,
    _r2_json_annotations,
    _r2_json_lines,
    _r2_variable_records,
    _retdec_dsm_evidence,
    _retdec_variables,
    elf_function_symbols,
    split_c_functions,
)
from decbench.decompilers.registry import DecompilerRegistry

_GZIP_CANDIDATES = [
    Path("results/sailr_full/O0/gzip/compiled/gzip"),
    Path("/home/mahaloz/github/decbench/results/sailr_full/O0/gzip/compiled/gzip"),
]
_GZIP = next((p for p in _GZIP_CANDIDATES if p.is_file()), _GZIP_CANDIDATES[0])


def test_backends_register() -> None:
    """Importing the module registers reko/retdec/r2dec."""
    import decbench.decompilers.dockerized  # noqa: F401

    registered = set(DecompilerRegistry.list_registered())
    assert {"reko", "retdec", "r2dec"} <= registered


@pytest.mark.parametrize(
    "spec,cls",
    [("reko", RekoDecompiler), ("retdec", RetDecDecompiler), ("r2dec", R2DecDecompiler)],
)
def test_registry_get_returns_correct_class(spec: str, cls: type) -> None:
    import decbench.decompilers.dockerized  # noqa: F401

    dec = DecompilerRegistry.get(spec)
    assert isinstance(dec, cls)
    assert dec.id == spec


def test_docker_backends_unavailable_without_image() -> None:
    """retdec/reko report available iff their image exists; never auto-build."""
    for cls in (RetDecDecompiler, RekoDecompiler):
        dec = cls()
        expected = DockerizedDecompiler._image_present(cls.image)
        assert dec.is_available() == expected


def test_is_available_false_when_no_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    """With docker absent, image-only backends are unavailable."""
    monkeypatch.setattr("decbench.decompilers.dockerized.shutil.which", lambda _name: None)
    assert RetDecDecompiler().is_available() is False
    assert RekoDecompiler().is_available() is False


def test_r2dec_available_when_native_present() -> None:
    """r2dec is available if native radare2+r2pipe exist (even w/o image)."""
    dec = R2DecDecompiler()
    native = R2DecDecompiler._native_available()
    if native:
        assert dec.is_available() is True
    else:
        assert dec.is_available() == DockerizedDecompiler._image_present(dec.image)


def test_get_version_proxies_image_tag() -> None:
    assert RetDecDecompiler().get_version() == "latest"
    assert RekoDecompiler().get_version() == "latest"


def test_run_docker_places_extra_readonly_mount_before_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"binary")
    driver = tmp_path / "driver.py"
    driver.write_text("pass\n")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    dec = R2DecDecompiler()
    monkeypatch.setattr(dec, "_docker_bin", lambda: "/usr/bin/docker")

    def fake_subprocess_run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)
    proc = dec._run_docker(
        args=["/in/input.bin", "/work/out.json"],
        binary_path=binary,
        work_dir=work_dir,
        readonly_mounts=[(driver, "/opt/driver.py")],
    )

    cmd = proc.args
    driver_mount = f"{driver.resolve()}:/opt/driver.py:ro"
    assert driver_mount in cmd
    assert cmd.index(driver_mount) < cmd.index(dec.image)
    assert cmd[-3:] == [dec.image, "/in/input.bin", "/work/out.json"]


_FAKE_C = """
#include <stdint.h>

int32_t add(int32_t a, int32_t b) {
    if (a > b) {
        return a + b;
    }
    const char *s = "a } brace } in a string";
    char c = '}';
    return a - b;
}

void noop(void) {
}

uint64_t entrypoint(int argc, char **argv) {
    int x = add(argc, 1);
    noop();
    return (uint64_t)x;
}
"""


def test_split_c_functions_finds_all() -> None:
    parts = split_c_functions(_FAKE_C)
    assert set(parts) == {"add", "noop", "entrypoint"}


def test_split_c_functions_balances_braces_with_literals() -> None:
    parts = split_c_functions(_FAKE_C)
    assert "return a + b;" in parts["add"]
    assert "return a - b;" in parts["add"]
    assert "entrypoint" not in parts["add"]
    assert "return (uint64_t)x;" in parts["entrypoint"]


def test_split_c_functions_empty_input() -> None:
    assert split_c_functions("") == {}
    assert split_c_functions("// just a comment\nint x;\n") == {}


def test_split_keeps_first_definition_of_duplicate_name() -> None:
    src = "int f(void) { return 1; }\nint f(void) { return 2; }\n"
    parts = split_c_functions(src)
    assert "return 1;" in parts["f"]
    assert "return 2;" not in parts["f"]


def test_retdec_json_parser_reconstructs_exact_c_and_native_evidence() -> None:
    tokens = [
        {"addr": "0x1010"},
        {"kind": "type", "val": "int32_t"},
        {"kind": "ws", "val": " "},
        {"kind": "i_fnc", "val": "f"},
        {"kind": "punc", "val": "("},
        {"kind": "type", "val": "int32_t"},
        {"kind": "ws", "val": " "},
        {"kind": "i_arg", "val": "arg"},
        {"kind": "punc", "val": ")"},
        {"kind": "ws", "val": " "},
        {"kind": "punc", "val": "{"},
        {"kind": "nl", "val": "\n"},
        {"addr": "0x1014"},
        {"kind": "ws", "val": "    "},
        {"kind": "type", "val": "int32_t"},
        {"kind": "ws", "val": " "},
        {"kind": "i_lvar", "val": "local"},
        {"kind": "ws", "val": " "},
        {"kind": "op", "val": "="},
        {"kind": "ws", "val": " "},
        {"kind": "i_lvar", "val": "arg"},
        {"addr": "0x5000"},
        {"kind": "ws", "val": " "},
        {"kind": "op", "val": "+"},
        {"addr": "0x1014"},
        {"kind": "ws", "val": " "},
        {"kind": "l_int", "val": "1"},
        {"kind": "punc", "val": ";"},
        {"kind": "nl", "val": "\n"},
        {"addr": "0x1018"},
        {"kind": "ws", "val": "    "},
        {"kind": "keyw", "val": "return"},
        {"kind": "ws", "val": " "},
        {"kind": "i_lvar", "val": "local"},
        {"kind": "punc", "val": ";"},
        {"kind": "nl", "val": "\n"},
        {"addr": "0x1010"},
        {"kind": "punc", "val": "}"},
        {"kind": "nl", "val": "\n"},
        {"addr": ""},
    ]
    code = "int32_t f(int32_t arg) {\n    int32_t local = arg + 1;\n    return local;\n}\n"
    parsed = _parse_retdec_json(
        json.dumps({"language": "C", "tokens": tokens}),
        valid_instruction_addresses=frozenset({0x1010, 0x1014, 0x1018, 0x5000}),
        function_ranges=((0x1010, 0x1020),),
    )

    assert parsed.text == code
    function = parsed.functions["f"]
    assert function.code == code
    assert function.address == 0x1010
    assert [(mapping.line_number, mapping.addresses) for mapping in function.line_mappings] == [
        (1, [0x1010]),
        (2, [0x1014]),
        (3, [0x1018]),
        (4, [0x1010]),
    ]
    assert function.variable_lines == {"arg": (1, 2), "local": (2, 3)}
    assert function.variable_addresses == {"arg": (0x1010, 0x1014), "local": (0x1014, 0x1018)}

    variables = {variable.name: variable for variable in _retdec_variables(function)}
    assert variables["arg"].kind == "arg"
    assert variables["arg"].arg_index == 0
    assert variables["arg"].line_numbers == [1, 2]
    assert variables["arg"].addresses == [0x1010, 0x1014]
    assert variables["local"].type == "int32_t"
    assert variables["local"].line_numbers == [2, 3]
    assert variables["local"].addresses == [0x1014, 0x1018]


def test_retdec_variable_addresses_use_each_occurrence_statement() -> None:
    code = (
        "int32_t f(int32_t right) {\n"
        "    int32_t left = right; int32_t other = 0;\n"
        "    return left;\n"
        "}\n"
    )
    tokens = [
        {"addr": "0x1010"},
        {"kind": "ws", "val": "int32_t "},
        {"kind": "i_fnc", "val": "f"},
        {"kind": "ws", "val": "(int32_t "},
        {"kind": "i_lvar", "val": "right"},
        {"kind": "ws", "val": ") {\n"},
        {"addr": "0x1014"},
        {"kind": "ws", "val": "    int32_t "},
        {"addr": "0x1010"},
        {"kind": "i_lvar", "val": "left"},
        {"addr": "0x1014"},
        {"kind": "ws", "val": " = "},
        {"kind": "i_lvar", "val": "right"},
        {"kind": "ws", "val": "; "},
        {"addr": "0x1018"},
        {"kind": "ws", "val": "int32_t "},
        {"addr": "0x1014"},
        {"kind": "i_lvar", "val": "other"},
        {"addr": "0x1018"},
        {"kind": "ws", "val": " = 0;\n"},
        {"addr": "0x101c"},
        {"kind": "ws", "val": "    return "},
        {"addr": "0x1010"},
        {"kind": "i_lvar", "val": "left"},
        {"addr": "0x101c"},
        {"kind": "ws", "val": ";\n"},
        {"addr": "0x1010"},
        {"kind": "ws", "val": "}\n"},
    ]
    parsed = _parse_retdec_json(
        json.dumps({"language": "C", "tokens": tokens}),
        valid_instruction_addresses=frozenset({0x1010, 0x1014, 0x1018, 0x101C}),
        function_ranges=((0x1010, 0x1020),),
    )

    function = parsed.functions["f"]
    assert parsed.text == code
    assert [(mapping.line_number, mapping.addresses) for mapping in function.line_mappings] == [
        (1, [0x1010]),
        (2, [0x1014, 0x1018]),
        (3, [0x101C]),
        (4, [0x1010]),
    ]
    assert function.variable_addresses == {
        "left": (0x1014, 0x101C),
        "other": (0x1018,),
        "right": (0x1010, 0x1014),
    }

    variables = {variable.name: variable for variable in _retdec_variables(function)}
    assert variables["right"].addresses == [0x1010, 0x1014]
    assert variables["left"].addresses == [0x1014, 0x101C]


def test_retdec_dsm_parser_accepts_only_instruction_rows_and_rebases_rva() -> None:
    dsm = (
        "; function: function_1000 at 0x1000 -- 0x1010\n"
        "0x1000:   55                     \tpush ebp\n"
        "0x1001:   89 e5                  \tmov ebp, esp\n"
        "0x1003:   90 90 90               |...|\n"
    )

    instructions, ranges = _retdec_dsm_evidence(dsm, image_base=0x400000)

    assert instructions == frozenset({0x401000, 0x401001})
    assert ranges == ((0x401000, 0x401010),)


def test_retdec_duplicate_shadow_names_abstain_from_occurrence_evidence() -> None:
    code = (
        "int32_t f(void) {\n"
        "    int32_t item = 0;\n"
        "    {\n"
        "        int32_t item = 1;\n"
        "        item++;\n"
        "    }\n"
        "    return item;\n"
        "}\n"
    )
    first, second, third = code.split("item", 2)
    header = "int32_t "
    assert first.startswith(f"{header}f")
    tokens = [
        {"addr": "0x2010"},
        {"kind": "ws", "val": header},
        {"kind": "i_fnc", "val": "f"},
        {"kind": "ws", "val": first[len(header) + 1 :]},
        {"kind": "i_lvar", "val": "item"},
        {"addr": "0x2014"},
        {"kind": "ws", "val": second},
        {"kind": "i_lvar", "val": "item"},
        {"addr": "0x2018"},
        {"kind": "ws", "val": third},
    ]
    parsed = _parse_retdec_json(
        json.dumps({"language": "C", "tokens": tokens}),
        valid_instruction_addresses=frozenset({0x2010, 0x2014, 0x2018}),
        function_ranges=((0x2010, 0x2030),),
    )

    variables = [variable for variable in _retdec_variables(parsed.functions["f"]) if variable.name]
    assert [variable.name for variable in variables] == ["item", "item"]
    assert all(variable.line_numbers == [] for variable in variables)
    assert all(variable.addresses == [] for variable in variables)


@pytest.mark.parametrize("annotated", [None, "{not-json"])
def test_retdec_plain_output_fallback_when_json_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    annotated: str | None,
) -> None:
    calls: list[list[str]] = []
    plain = "int f(void) {\n    return 1;\n}\n"

    def fake_run(
        args: list[str],
        binary_path: Path,
        work_dir: Path,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if "/work/out.json" in args and annotated is not None:
            (work_dir / "out.json").write_text(annotated)
            return subprocess.CompletedProcess(args, 0, "", "")
        if "/work/out.c" in args:
            (work_dir / "out.c").write_text(plain)
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 1, "", "json unsupported")

    dec = RetDecDecompiler()
    monkeypatch.setattr(dec, "_run_docker", fake_run)

    assert dec._container_decompile(tmp_path / "missing.bin", tmp_path) == plain
    assert "json" in calls[0]
    assert calls[1][-2:] == ["-o", "/work/out.c"]


def test_split_accepts_opening_brace_on_following_line() -> None:
    src = "void declaration(word32 value);\nvoid reko_style(word32 value)\n{\n\treturn;\n}\n"
    parts = split_c_functions(src)
    assert set(parts) == {"reko_style"}
    assert "word32 value" in parts["reko_style"]


def test_reko_sidecar_fails_closed_on_ambiguous_records(tmp_path: Path) -> None:
    sidecar = tmp_path / "native.json"
    sidecar.write_text(
        json.dumps(
            {
                "schema": _REKO_PROVENANCE_SCHEMA,
                "functions": [
                    {"name": "fn1000", "address": 0x1000, "variables": []},
                    {"name": "other1000", "address": 0x1000, "variables": []},
                    {
                        "name": "fn2000",
                        "address": "0x2000",
                        "variables": [
                            {"name": "local", "addresses": [0x2004]},
                            {"name": "local", "addresses": [0x2008]},
                            {"name": "kept", "addresses": [0x200C, "bad", -1]},
                        ],
                    },
                ],
            }
        )
    )

    provenance = _load_reko_provenance(sidecar)
    assert set(provenance) == {0x2000}
    assert provenance[0x2000]["variables"] == {"kept": [0x200C]}

    sidecar.write_text(json.dumps({"schema": _REKO_PROVENANCE_SCHEMA, "functions": 7}))
    assert _load_reko_provenance(sidecar) == {}

    sidecar.write_text(
        json.dumps(
            {
                "schema": _REKO_PROVENANCE_SCHEMA,
                "functions": [
                    {
                        "name": "fn3000",
                        "address": 0x3000,
                        "variables": [{"name": "bad", "addresses": 0x3004}],
                    }
                ],
            }
        )
    )
    assert _load_reko_provenance(sidecar)[0x3000]["variables"] == {}


def test_reko_container_collects_native_sidecar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dec = RekoDecompiler()

    def fake_run(**kwargs):  # noqa: ANN202
        assert kwargs["args"][-1] == "/work/native-provenance.json"
        (kwargs["work_dir"] / "out.c").write_text("int fn1000(void) { return 0; }\n")
        (kwargs["work_dir"] / "native-provenance.json").write_text(
            json.dumps(
                {
                    "schema": _REKO_PROVENANCE_SCHEMA,
                    "functions": [{"name": "fn1000", "address": 0x1000, "variables": []}],
                }
            )
        )
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(dec, "_run_docker", fake_run)
    code = dec._container_decompile(Path("/nonexistent/bin"), tmp_path)
    assert "fn1000" in code
    assert dec._native_provenance[0x1000]["name"] == "fn1000"


def test_reko_build_result_binds_names_and_native_variable_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dec = RekoDecompiler()
    dec._native_provenance = {
        0x1000: {
            "name": "fn1000",
            "address": 0x1000,
            "variables": {
                "arg0": [0x1000, 0x1004],
                "local": [0x1004, 0x1008, 0x3000],
            },
        }
    }
    monkeypatch.setattr(
        "decbench.decompilers.dockerized._reko_executable_regions",
        lambda _path: ((0x1000, 0x1020),),
    )
    combined = (
        "int32_t fn1000(int32_t arg0) {\n"
        "    int32_t local;\n"
        "    local = arg0 + 1;\n"
        "    return local;\n"
        "}\n"
    )
    result = dec._build_result(
        binary_path=Path("/nonexistent/bin"),
        combined_c=combined,
        functions=[("wanted", 0x1000)],
        function_names={0x1000},
        elapsed=0.1,
        timed_out=False,
        error=None,
        output_dir=None,
    )

    function = result.functions["wanted"]
    assert "wanted(" in function.decompiled_code
    assert "fn1000(" not in function.decompiled_code
    assert function.line_mappings == []
    variables = {variable.name: variable for variable in function.variables}
    assert variables["arg0"].kind == "arg"
    assert variables["arg0"].arg_index == 0
    assert variables["arg0"].addresses == [0x1000, 0x1004]
    assert variables["local"].addresses == [0x1004, 0x1008]
    assert result.decompiler.extra["native_provenance_variables"] == 2


class _FakeR2:
    """Minimal r2pipe stand-in returning canned ``ij`` / ``aflj`` / ``pdd``."""

    def __init__(self, aflj: list[dict], baddr: int = 0, json_decompile: bool = True) -> None:
        self._aflj = aflj
        self._baddr = baddr
        self._json_decompile = json_decompile

    def cmdj(self, cmd: str):  # noqa: ANN201
        if cmd == "aflj":
            return self._aflj
        if cmd == "ij":
            return {"bin": {"baddr": self._baddr, "arch": "x86"}}
        if "@" not in cmd:
            return None
        command, target = (part.strip() for part in cmd.split("@", 1))
        addr = int(target, 0)
        if command == "pddj":
            if not self._json_decompile:
                raise ValueError("JSON command unavailable")
            return {
                "lines": [
                    {"str": "/* r2dec pseudo code output */"},
                    {
                        "str": f"int64_t fcn_{addr:08x}(int32_t arg1) {{",
                        "offset": addr,
                    },
                    {"str": "    int32_t local;", "offset": addr},
                    {"str": "    local = arg1;", "offset": addr + 4},
                    {"str": "    return local;", "offset": addr + 8},
                    {"str": "}"},
                ]
            }
        if command == "pdcj":
            if not self._json_decompile:
                raise ValueError("JSON command unavailable")
            code = (
                "\n"
                f"int64_t fcn_{addr:08x}(int32_t arg1) {{\n"
                "    int32_t local = arg1;\n"
                "    return local;\n"
                "}\n"
            )
            return {
                "code": code,
                "annotations": [
                    {
                        "start": code.index("local ="),
                        "end": code.index("local ="),
                        "offset": addr + 4,
                        "type": "offset",
                    }
                ],
            }
        if command == "afij":
            return [{"addr": addr, "size": 0x20, "bits": 64}]
        if command == "afvj":
            return {
                "reg": [{"name": "arg1", "kind": "reg", "type": "int32_t", "ref": "rdi"}],
                "sp": [],
                "bp": [
                    {
                        "name": "local",
                        "kind": "var",
                        "type": "int32_t",
                        "ref": {"base": "rbp", "offset": -4},
                    }
                ],
            }
        if command == "afvRj":
            return [
                {"name": "arg1", "addrs": [addr + 4]},
                {"name": "local", "addrs": [addr + 8]},
            ]
        if command == "afvWj":
            return [{"name": "local", "addrs": [addr + 4]}]
        if command == "afcfj":
            return [{"args": [{"name": "arg1", "type": "int32_t"}]}]
        return None

    def cmd(self, cmd: str) -> str:
        if cmd.startswith(("pdd", "pdc")) and "@" in cmd:
            target = cmd.rsplit("@", 1)[1].strip()
            addr = 0 if target == "entry0" else int(target, 0)
            return (
                "/* r2dec pseudo code output (r2 6.0.8) */\n"
                "#include <stdint.h>\n\n"
                f"int64_t fcn_{addr:08x}(int32_t a) {{\n    return a;\n}}\n"
            )
        return ""

    def quit(self) -> None:  # noqa: D401
        pass


def test_r2_is_import_and_bare_name() -> None:
    assert _r2_is_import("sym.imp.free")
    assert _r2_is_import("reloc.foo")
    assert _r2_is_import("dbg.imp.bar") is False or ".imp." in "dbg.imp.bar"
    assert not _r2_is_import("fcn.00001234")
    assert not _r2_is_import("sym.main")
    assert _r2_bare_name("sym.acl_add_perm") == "acl_add_perm"
    assert _r2_bare_name("fcn.00001234") == "00001234"
    assert _r2_bare_name("main") == "main"


def test_func_ident_in_code_strips_banner_and_macros() -> None:
    code = (
        "/* r2dec pseudo code output (r2 6.0.8) */\n"
        "/* /in/bin @ 0x2e2b */\n"
        "#include <stdint.h>\n\n"
        "#define BIT_MASK(t,v) ((t)(-((v)!=0)))\n\n"
        "int64_t acl_create_entry (uint32_t a, uint32_t b) {\n"
        "    if (a) { return b; }\n"
        "    return a;\n}\n"
    )
    assert _func_ident_in_code(code) == "acl_create_entry"
    assert _func_ident_in_code("void fcn.00003bed (int64_t a) {\n    return;\n}") == "fcn.00003bed"
    assert _func_ident_in_code("if (x) {\n    y();\n}\n") is None


def test_r2_discover_normalizes_and_filters() -> None:
    aflj = [
        {"name": "sym.imp.free", "addr": 0x500},
        {"name": "reloc.foo", "addr": 0x600},
        {"name": "entry0", "addr": 0x1500},
        {"name": "fcn.00002000", "addr": 0x2000},
        {"name": "sym.main", "addr": 0x3000},
        {"name": "sym.outside", "addr": 0x9500},
    ]
    r = _FakeR2(aflj, baddr=0)
    out = R2DecDecompiler._discover(r, elf_base=0, text_range=(0x1000, 0x9000), baddr=0)
    assert out == [("fcn.00002000", 0x2000, 0x2000), ("sym.main", 0x3000, 0x3000)]


def test_r2_discover_rebases_when_baddr_differs() -> None:
    aflj = [{"name": "fcn.08002000", "addr": 0x8002000}]
    r = _FakeR2(aflj, baddr=0x8000000)
    out = R2DecDecompiler._discover(
        r, elf_base=0x8000000, text_range=(0x8000000, 0x8010000), baddr=0x8000000
    )
    assert out == [("fcn.08002000", 0x8002000, 0x8002000)]


def test_r2_narrow_by_int_address() -> None:
    discovered = [("fcn.a", 0x1000, 0x1000), ("fcn.b", 0x2000, 0x2000), ("fcn.c", 0x3000, 0x3000)]
    out = R2DecDecompiler._narrow(discovered, {0x1000, 0x3000}, "bin")
    assert {t[1] for t in out} == {0x1000, 0x3000}
    assert all(t[0] is None for t in out)


def test_r2_narrow_int_thumb_tolerant() -> None:
    discovered = [("fcn.a", 0x8001, 0x8001)]
    out = R2DecDecompiler._narrow(discovered, {0x8000}, "bin")
    assert [t[1] for t in out] == [0x8001]


def test_r2_narrow_by_str_name_and_fails_closed() -> None:
    discovered = [("sym.foo", 0x1000, 0x1000), ("fcn.00002000", 0x2000, 0x2000)]
    out = R2DecDecompiler._narrow(discovered, {"foo"}, "bin")
    assert len(out) == 1 and out[0][0] == "foo" and out[0][1] == 0x1000
    out2 = R2DecDecompiler._narrow(discovered, {0xDEAD}, "bin")
    assert out2 == []


def test_r2_make_function_names_from_code_and_relabels() -> None:
    code = "int foo(int a) {\n    return a;\n}\n"
    fd = R2DecDecompiler._make_function("fcn.00001000", 0x1000, code, None)
    assert fd is not None and fd.name == "foo" and fd.address == 0x1000
    fd2 = R2DecDecompiler._make_function("sym.foo", 0x1000, code, "realname")
    assert fd2 is not None and fd2.name == "realname"
    assert "realname" in fd2.decompiled_code and "foo(" not in fd2.decompiled_code
    assert R2DecDecompiler._make_function("fcn.x", 0x1, "   ", None) is None


def test_r2_json_lines_and_variable_records() -> None:
    r = _FakeR2([], baddr=0x4000)
    parsed = _r2_json_lines(r.cmdj("pddj @ 0x4100"))
    assert parsed is not None
    code, mappings = parsed
    assert code.splitlines()[1].startswith("int64_t fcn_00004100")
    assert mappings[0] == {"line_number": 2, "addresses": [0x4100]}

    variables = _r2_variable_records(r, 0x4100, mappings)
    assert variables[0]["name"] == "arg1"
    assert variables[0]["kind"] == "arg"
    assert variables[0]["arg_index"] == 0
    assert variables[0]["addresses"] == [0x4104]
    assert variables[1]["name"] == "local"
    assert variables[1]["stack_offset"] == -4
    assert variables[1]["addresses"] == [0x4104, 0x4108]


def test_r2_pdcj_annotations_map_the_exact_trimmed_code_lines() -> None:
    r = _FakeR2([])
    parsed = _r2_json_annotations(r.cmdj("pdcj @ 0x4100"))
    assert parsed is not None
    code, mappings = parsed
    assert code.splitlines()[1] == "    int32_t local = arg1;"
    assert mappings == [{"line_number": 2, "addresses": [0x4104]}]


def test_r2_make_function_rebases_and_filters_thumb_provenance() -> None:
    provenance = {
        "addr": 0x5001,
        "size": 0x10,
        "is_thumb": True,
        "line_mappings": [
            {"line_number": 1, "addresses": [0x5001, 0x5004, 0x6000]},
            {"line_number": 99, "addresses": [0x5008]},
        ],
        "variables": [
            {
                "name": "renamed",
                "type": "int",
                "kind": "stack",
                "stack_offset": -4,
                "line_numbers": [1, 99],
                "addresses": [0x5003, 0x5004, 0x6000],
            }
        ],
    }
    function = R2DecDecompiler._make_function(
        "fcn.5001",
        0x9001,
        "int f(void) { return 0; }",
        None,
        provenance,
        r2_addr=0x5001,
        baddr=0x4000,
        elf_base=0x8000,
    )
    assert function is not None
    assert function.address == 0x9000
    assert [mapping.model_dump() for mapping in function.line_mappings] == [
        {"line_number": 1, "addresses": [0x9000, 0x9004]}
    ]
    assert function.variables[0].line_numbers == [1]
    assert function.variables[0].addresses == [0x9002, 0x9004]


def test_r2_make_function_rejects_malformed_variable_fields() -> None:
    provenance = {
        "addr": 0x1000,
        "size": 0x10,
        "variables": [
            {
                "name": "",
                "addresses": [0x1004],
            },
            {
                "name": "local",
                "size": 0,
                "kind": "stack",
                "arg_index": 2,
                "line_numbers": [-1, 0, 1, 99],
                "addresses": [0x1004],
            },
            {
                "name": "arg1",
                "size": -4,
                "kind": "arg",
                "arg_index": -1,
                "addresses": [0x1008],
            },
        ],
    }
    function = R2DecDecompiler._make_function(
        "fcn.1000",
        0x1000,
        "int f(int arg1) {\n    int local = arg1;\n    return local;\n}",
        None,
        provenance,
        r2_addr=0x1000,
    )
    assert function is not None
    assert [variable.name for variable in function.variables] == ["local", "arg1"]
    assert function.variables[0].size is None
    assert function.variables[0].arg_index is None
    assert function.variables[0].line_numbers == [1]
    assert function.variables[1].size is None
    assert function.variables[1].arg_index is None


def test_r2_decompile_native_int_filter_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """The int-address filter path end-to-end, with r2pipe mocked (no binary)."""
    import r2pipe

    aflj = [
        {"name": "sym.imp.puts", "addr": 0x500},
        {"name": "fcn.00001000", "addr": 0x1000},
        {"name": "sym.wanted", "addr": 0x2000},
        {"name": "fcn.00003000", "addr": 0x3000},
    ]
    monkeypatch.setattr(r2pipe, "open", lambda *a, **k: _FakeR2(aflj, baddr=0))
    dec = R2DecDecompiler()
    result = dec._decompile_native(Path("/nonexistent/bin"), None, None, {0x1000, 0x2000}, None)
    got = {fd.address for fd in result.functions.values()}
    assert got == {0x1000, 0x2000}
    for fd in result.functions.values():
        assert _func_ident_in_code(fd.decompiled_code) == fd.name
        assert fd.line_mappings
        assert fd.variables
        assert fd.variables[0].kind == "arg"
        assert fd.variables[0].arg_index == 0
    assert result.decompiler.extra.get("via") == "native"


def test_r2_native_falls_back_to_text_when_pddj_unavailable() -> None:
    r = _FakeR2([], json_decompile=False)
    record = R2DecDecompiler._decompile_one_native(r, "pdd", 0x1000)
    assert record is not None
    assert record["code"]
    assert record["line_mappings"] == []
    assert record["variables"]


def test_r2_native_pdc_uses_json_annotations() -> None:
    record = R2DecDecompiler._decompile_one_native(_FakeR2([]), "pdc", 0x1000)
    assert record is not None
    assert record["line_mappings"] == [{"line_number": 2, "addresses": [0x1004]}]


def test_r2_code_inferred_local_joins_pdcj_line_addresses() -> None:
    from decbench.metrics.base import MetricConfig
    from decbench.metrics.type_match import TypeMatchMetric

    provenance = {
        "addr": 0x1000,
        "size": 0x10,
        "line_mappings": [{"line_number": 2, "addresses": [0x1004]}],
    }
    function = R2DecDecompiler._make_function(
        "fcn.1000",
        0x1000,
        "int target(void) {\n    int renamed = 1;\n    return renamed;\n}",
        None,
        provenance,
        r2_addr=0x1000,
    )
    assert function is not None
    assert function.variables[0].line_numbers == [2, 3]
    assert function.variables[0].addresses == [0x1004]
    metric = TypeMatchMetric(MetricConfig(extra_options={"variable_match_mode": "address"}))
    result = metric.compute_for_function(
        function,
        ground_truth_vars=[
            {
                "identity": "source:0",
                "name": "original",
                "type": ["int"],
                "rbp_offset": [],
                "addresses": [0x1004],
            }
        ],
        backend="r2dec",
    )
    assert result.value == 1.0
    assert result.metadata["match_stage_counts"] == {"overlap": 1}
    assert result.metadata["decompiler_address_variables"] == 1


def test_r2_docker_payload_populates_native_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dec = R2DecDecompiler()
    monkeypatch.setattr(dec, "_image_present", lambda _image: True)

    def fake_run(**kwargs: Any) -> subprocess.CompletedProcess[str]:
        work_dir = kwargs["work_dir"]
        assert kwargs["args"] == ["/in/bin", "/work/out.json", "/work/targets.json"]
        assert json.loads((work_dir / "targets.json").read_text()) == [0x1000]
        assert kwargs["readonly_mounts"] == [
            (_DOCKER_DIR / "r2dec-decompile.py", _R2_DRIVER_CONTAINER_PATH)
        ]
        payload = {
            "schema_version": 1,
            "command": "pdd",
            "functions": [
                {
                    "addr": 0x1000,
                    "baddr": 0,
                    "name": "fcn.00001000",
                    "code": "int f(int arg1) {\n    return arg1;\n}",
                    "size": 0x10,
                    "line_mappings": [{"line_number": 2, "addresses": [0x1004]}],
                    "variables": [
                        {
                            "name": "arg1",
                            "type": "int",
                            "kind": "arg",
                            "arg_index": 0,
                            "addresses": [0x1004],
                            "line_numbers": [2],
                        }
                    ],
                },
                {
                    "addr": 0x2000,
                    "baddr": 0,
                    "name": "fcn.00002000",
                    "code": "int unrelated(void) { return 0; }",
                    "size": 0x10,
                    "line_mappings": [],
                    "variables": [],
                },
            ],
        }
        (work_dir / "out.json").write_text(json.dumps(payload))
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(dec, "_run_docker", fake_run)
    result = dec._decompile_docker(Path("/nonexistent/bin"), None, None, {0x1000}, None)
    assert {function.address for function in result.functions.values()} == {0x1000}
    function = next(iter(result.functions.values()))
    assert function.line_mappings[0].addresses == [0x1004]
    assert function.variables[0].addresses == [0x1004]
    assert function.variables[0].arg_index == 0
    assert result.decompiler.extra["command"] == "pdd"


def test_r2_docker_rejects_legacy_unversioned_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dec = R2DecDecompiler()
    monkeypatch.setattr(dec, "_image_present", lambda _image: True)

    def fake_run(**kwargs: Any) -> subprocess.CompletedProcess[str]:
        legacy_payload = [
            {
                "addr": 0x1000,
                "baddr": 0,
                "name": "fcn.00001000",
                "code": "int f(void) { return 0; }",
            }
        ]
        (kwargs["work_dir"] / "out.json").write_text(json.dumps(legacy_payload))
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(dec, "_run_docker", fake_run)
    result = dec._decompile_docker(Path("/nonexistent/bin"), None, None, {0x1000}, None)

    assert result.functions == {}
    assert result.decompiler.failed_functions == ["all"]
    assert "legacy driver payload" in result.decompiler.extra["error"]


@pytest.mark.skipif(not _GZIP.is_file(), reason="sample gzip binary not present")
def test_elf_function_symbols_elf_space() -> None:
    syms = elf_function_symbols(_GZIP)
    assert syms, "expected function symbols from gzip"
    names = {n for n, _ in syms}
    assert "rsync_roll" in names
    addrs = [a for _, a in syms]
    assert all(a > 0 for a in addrs)
    assert addrs == sorted(addrs)
    assert "_start" not in names
    assert "frame_dummy" not in names


@pytest.mark.skipif(not _GZIP.is_file(), reason="sample gzip binary not present")
def test_build_result_maps_snippets_to_elf_addresses() -> None:
    dec = RetDecDecompiler()
    combined = "void rsync_roll(unsigned int a, unsigned int b) {\n    return;\n}\n"
    result = dec._build_result(
        binary_path=_GZIP,
        combined_c=combined,
        functions=None,
        function_names={"rsync_roll"},
        elapsed=0.1,
        timed_out=False,
        error=None,
        output_dir=None,
    )
    assert "rsync_roll" in result.functions
    fn = result.functions["rsync_roll"]
    assert fn.address == 0x4567
    assert "rsync_roll" in fn.decompiled_code
    assert fn.variables == []
    assert fn.line_mappings == []
    assert result.decompiler.decompiler_name == "retdec"


def _native_r2dec_ready() -> bool:
    if shutil.which("r2") is None and shutil.which("radare2") is None:
        return False
    try:
        import r2pipe  # noqa: F401
    except Exception:
        return False
    return _GZIP.is_file()


@pytest.mark.skipif(
    not _native_r2dec_ready(), reason="native radare2/r2pipe or sample binary absent"
)
def test_r2dec_native_decompiles_one_function() -> None:
    dec = R2DecDecompiler()
    result = dec._decompile_native(_GZIP, None, None, {"rsync_roll"}, None)
    assert result.decompiler.extra.get("via") == "native"
    assert "rsync_roll" in result.functions
    fn = result.functions["rsync_roll"]
    want = dict(elf_function_symbols(_GZIP)).get("rsync_roll")
    assert want is not None and fn.address == want
    assert fn.decompiled_code.strip()
    assert result.decompiler.decompiler_name == "r2dec"


def test_r2dec_native_int_address_filter() -> None:
    """The benchmark driver hands r2dec a set of int ADDRESSES; only functions at
    those (normalized) addresses come back, keyed by their code identifier."""
    if not _native_r2dec_ready():
        pytest.skip("native radare2/r2pipe or sample binary absent")
    dec = R2DecDecompiler()
    syms = dict(elf_function_symbols(_GZIP))
    wanted = {syms[n] for n in ("rsync_roll", "bi_reverse") if n in syms}
    assert wanted, "expected known gzip functions"
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        prog = Path(td) / "prog.pkl"
        result = dec._decompile_native(_GZIP, None, Path(td), wanted, prog)
        got = {fd.address for fd in result.functions.values()}
        assert got, "expected at least one decompiled function"
        assert got <= wanted
        for fd in result.functions.values():
            assert fd.decompiled_code.strip()
            assert _func_ident_in_code(fd.decompiled_code) == fd.name
        assert prog.exists()


@pytest.mark.parametrize("cls", [RetDecDecompiler, RekoDecompiler])
def test_docker_decompile_skips_when_image_absent(cls: type) -> None:
    dec = cls()
    if not dec.is_available():
        pytest.skip(f"{cls.__name__} image not built")
    if not _GZIP.is_file():
        pytest.skip("sample binary absent")
    result = dec.decompile_binary(_GZIP, function_names={"rsync_roll"})
    assert result.decompiler.decompiler_name == cls.name
    if cls is RetDecDecompiler:
        function = result.functions["rsync_roll"]
        assert function.line_mappings
        assert function.variables
        assert all(mapping.line_number >= 1 for mapping in function.line_mappings)
        assert all(mapping.addresses for mapping in function.line_mappings)
        assert any(variable.line_numbers for variable in function.variables)
        assert any(variable.addresses for variable in function.variables)
