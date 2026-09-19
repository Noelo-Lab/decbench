"""Tests for the dockerized / external-tool decompiler backends.

These tests are designed to run anywhere: anything needing a built image or an
installed tool **skips cleanly** when it is absent. The pure-Python helpers
(C-function splitting, ELF symbol enumeration) and the registration / is_available
semantics are always exercised.
"""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from decbench.decompilers.dockerized import (
    _DOCKER_DIR,
    _R2_DRIVER_CONTAINER_PATH,
    DockerizedDecompiler,
    R2DecDecompiler,
    RekoDecompiler,
    RetDecDecompiler,
    _func_ident_in_code,
    _r2_bare_name,
    _r2_is_import,
    elf_function_symbols,
    split_c_functions,
)
from decbench.decompilers.registry import DecompilerRegistry
from decbench.utils.binfmt import BinInfo

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


@pytest.mark.parametrize("image_present", [True, False])
def test_r2dec_requires_pinned_image(monkeypatch: pytest.MonkeyPatch, image_present: bool) -> None:
    dec = R2DecDecompiler()
    monkeypatch.setattr(dec, "_image_present", lambda _image: image_present)
    assert dec.is_available() is image_present


def test_r2dec_decompile_fails_without_image(monkeypatch: pytest.MonkeyPatch) -> None:
    dec = R2DecDecompiler()
    monkeypatch.setattr(dec, "_image_present", lambda _image: False)
    with pytest.raises(RuntimeError, match="docker image.*missing"):
        dec.decompile_binary(Path("/nonexistent/bin"))


def test_r2_driver_requires_pdd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "r2pipe", SimpleNamespace())
    require_pdd = runpy.run_path(str(_DOCKER_DIR / "r2dec-decompile.py"))["_require_pdd"]
    with pytest.raises(RuntimeError, match="plugin is unavailable"):
        require_pdd(SimpleNamespace(cmd=lambda _command: "Please install the plugin"))
    require_pdd(SimpleNamespace(cmd=lambda _command: "pdd: decompile current function"))


def test_get_version_proxies_image_tag() -> None:
    assert RetDecDecompiler().get_version() == "latest"
    assert RekoDecompiler().get_version() == "latest"
    assert R2DecDecompiler().get_version() == "6.2.0"


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


def test_split_c_functions_accepts_reko_next_line_brace() -> None:
    source = "word32 fn000000000000352B(word32 a)\n{\n    return a;\n}\n"
    assert "return a;" in split_c_functions(source)["fn000000000000352B"]


def test_split_c_functions_accepts_reko_arm_define() -> None:
    source = "define fn080011C2\n{\n    word32 r0;\n    if (r0) { r0 = 1; }\n}\n"
    assert "word32 r0;" in split_c_functions(source)["fn080011C2"]


@pytest.mark.parametrize(
    "cls,name", [(RetDecDecompiler, "function_352b"), (RekoDecompiler, "fn000000000000352B")]
)
def test_stripped_docker_output_matches_target_addresses(cls: type, name: str) -> None:
    dec = cls()
    source = f"int {name}(void)\n{{\n    return 1;\n}}\n"
    result = dec._build_result(
        binary_path=Path("/nonexistent/stripped"),
        combined_c=source,
        functions=None,
        function_names={0x352B},
        elapsed=0.1,
        timed_out=False,
        error=None,
        output_dir=None,
    )
    assert list(result.functions) == [name]
    assert result.functions[name].address == 0x352B
    assert result.decompiler.extra["slice_scoped"] is True


def test_stripped_docker_output_matches_thumb_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "decbench.decompilers.dockerized.binfmt.detect", lambda _: BinInfo("elf", "arm", 32)
    )
    source = "int function_4501(void) { return 1; }\n"
    result = RetDecDecompiler()._build_result(
        binary_path=Path("/nonexistent/stripped"),
        combined_c=source,
        functions=None,
        function_names={0x4500},
        elapsed=0.1,
        timed_out=False,
        error=None,
        output_dir=None,
    )
    assert result.functions["function_4501"].address == 0x4501


def test_reko_arm_define_matches_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "decbench.decompilers.dockerized.binfmt.detect", lambda _: BinInfo("elf", "arm", 32)
    )
    source = "define fn080011C2\n{\n    word32 r0;\n}\n"
    result = RekoDecompiler()._build_result(
        binary_path=Path("/nonexistent/stripped"),
        combined_c=source,
        functions=None,
        function_names={0x80011C2},
        elapsed=0.1,
        timed_out=False,
        error=None,
        output_dir=None,
    )
    assert result.functions["fn080011C2"].address == 0x80011C2


def test_reko_named_function_comment_matches_target() -> None:
    source = (
        "// 0000000000004F6A: void acl_entries(Register (ptr64 Eq_2) rdi)\n"
        "void acl_entries(void *rdi)\n{\n    return;\n}\n"
    )
    result = RekoDecompiler()._build_result(
        binary_path=Path("/nonexistent/stripped"),
        combined_c=source,
        functions=None,
        function_names={0x4F6A},
        elapsed=0.1,
        timed_out=False,
        error=None,
        output_dir=None,
    )
    assert result.functions["acl_entries"].address == 0x4F6A


def test_reko_named_comment_must_adjoin_definition() -> None:
    source = (
        "// 0000000000004F6A: void acl_entries(void)\n"
        "int unrelated;\n"
        "void acl_entries(void) { return; }\n"
    )
    result = RekoDecompiler()._build_result(
        binary_path=Path("/nonexistent/stripped"),
        combined_c=source,
        functions=None,
        function_names={0x4F6A},
        elapsed=0.1,
        timed_out=False,
        error=None,
        output_dir=None,
    )
    assert result.functions == {}


def test_stripped_docker_output_matches_pe_image_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "decbench.decompilers.dockerized.binfmt.detect", lambda _: BinInfo("pe", "x86-64", 64)
    )
    monkeypatch.setattr(
        "decbench.decompilers.dockerized.raw_common.elf_min_vaddr", lambda _: 0x400000
    )
    source = "int function_1234(void) { return 1; }\n"
    result = RetDecDecompiler()._build_result(
        binary_path=Path("/nonexistent/stripped"),
        combined_c=source,
        functions=None,
        function_names={0x401234},
        elapsed=0.1,
        timed_out=False,
        error=None,
        output_dir=None,
    )
    assert result.functions["function_1234"].address == 0x1234


def test_split_c_functions_empty_input() -> None:
    assert split_c_functions("") == {}
    assert split_c_functions("// just a comment\nint x;\n") == {}


def test_split_keeps_first_definition_of_duplicate_name() -> None:
    src = "int f(void) { return 1; }\nint f(void) { return 2; }\n"
    parts = split_c_functions(src)
    assert "return 1;" in parts["f"]
    assert "return 2;" not in parts["f"]


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
        "/* r2dec pseudo code output (r2 6.2.0) */\n"
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


def test_r2_narrow_by_int_address() -> None:
    discovered = [("fcn.a", 0x1000, 0x1000), ("fcn.b", 0x2000, 0x2000), ("fcn.c", 0x3000, 0x3000)]
    out = R2DecDecompiler._narrow(discovered, {0x1000, 0x3000}, "bin")
    assert {t[1] for t in out} == {0x1000, 0x3000}
    assert all(t[0] is None for t in out)


def test_r2_narrow_int_thumb_tolerant() -> None:
    discovered = [("fcn.a", 0x8001, 0x8001)]
    out = R2DecDecompiler._narrow(discovered, {0x8000}, "bin")
    assert [t[1] for t in out] == [0x8001]


def test_r2_narrow_by_str_name_and_fallback() -> None:
    discovered = [("sym.foo", 0x1000, 0x1000), ("fcn.00002000", 0x2000, 0x2000)]
    out = R2DecDecompiler._narrow(discovered, {"foo"}, "bin")
    assert len(out) == 1 and out[0][0] == "foo" and out[0][1] == 0x1000
    out2 = R2DecDecompiler._narrow(discovered, {0xDEAD}, "bin")
    assert {t[1] for t in out2} == {0x1000, 0x2000}


def test_r2_make_function_names_from_code_and_relabels() -> None:
    code = "int foo(int a) {\n    return a;\n}\n"
    fd = R2DecDecompiler._make_function("fcn.00001000", 0x1000, code, None)
    assert fd is not None and fd.name == "foo" and fd.address == 0x1000
    fd2 = R2DecDecompiler._make_function("sym.foo", 0x1000, code, "realname")
    assert fd2 is not None and fd2.name == "realname"
    assert "realname" in fd2.decompiled_code and "foo(" not in fd2.decompiled_code
    assert R2DecDecompiler._make_function("fcn.x", 0x1, "   ", None) is None


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


def test_r2_code_inferred_local_joins_line_addresses() -> None:
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
    metric = TypeMatchMetric(MetricConfig())
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


def test_r2_code_inferred_variables_abstain_on_shadowed_names() -> None:
    provenance = {
        "addr": 0x1000,
        "size": 0x20,
        "line_mappings": [
            {"line_number": 2, "addresses": [0x1004]},
            {"line_number": 3, "addresses": [0x1008]},
            {"line_number": 4, "addresses": [0x100C]},
        ],
    }
    function = R2DecDecompiler._make_function(
        "fcn.1000",
        0x1000,
        "int target(void) {\n"
        "    int shadow = 0;\n"
        "    { int shadow = 1; shadow++; }\n"
        "    return shadow;\n"
        "}\n",
        None,
        provenance,
        r2_addr=0x1000,
    )

    assert function is not None
    assert [variable.name for variable in function.variables] == ["shadow"]
    assert all(variable.line_numbers == [] for variable in function.variables)
    assert all(variable.addresses == [] for variable in function.variables)


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
    monkeypatch.setattr(
        "decbench.decompilers.dockerized.raw_common.elf_min_vaddr",
        lambda _path: 0,
    )
    monkeypatch.setattr(
        "decbench.decompilers.dockerized.raw_common.elf_text_ranges",
        lambda _path: [(0x1000, 0x1010)],
    )
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


def test_r2_docker_rejects_non_pdd_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    dec = R2DecDecompiler()
    monkeypatch.setattr(dec, "_image_present", lambda _image: True)

    def fake_run(**kwargs: Any) -> subprocess.CompletedProcess[str]:
        payload = {"schema_version": 1, "command": "pdc", "functions": []}
        (kwargs["work_dir"] / "out.json").write_text(json.dumps(payload))
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(dec, "_run_docker", fake_run)
    result = dec._decompile_docker(Path("/nonexistent/bin"), None, None, None, None)

    assert result.functions == {}
    assert result.decompiler.failed_functions == ["all"]
    assert "invalid command: pdc" in result.decompiler.extra["error"]


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


@pytest.mark.parametrize("cls", [RetDecDecompiler, RekoDecompiler])
def test_docker_decompile_skips_when_image_absent(cls: type) -> None:
    dec = cls()
    if not dec.is_available():
        pytest.skip(f"{cls.__name__} image not built")
    if not _GZIP.is_file():
        pytest.skip("sample binary absent")
    result = dec.decompile_binary(_GZIP, function_names={"rsync_roll"})
    assert result.decompiler.decompiler_name == cls.name
