"""Unit tests for the manifold backend's path selection + TU splitting.

The real decompilation runs manifold (a Rust binary) either natively or in its
Docker image, so these tests exercise the parts that do NOT need either
installed: executable resolution, native-over-Docker path selection,
availability gating, splitting one whole-program translation unit into
per-function definitions, and the address mapping -- the last two through a
fake ``manifold`` and a fake ``docker`` that emit a canned translation unit.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import decbench.decompilers  # noqa: F401  (registers the raw backends)
from decbench.decompilers.raw.manifold_raw import (
    ManifoldDecompiler,
    _clight_function_addresses,
    _needs_clight_function_addresses,
    parse_translation_unit,
    split_functions,
)
from decbench.decompilers.registry import DecompilerRegistry

TINY_C_SOURCE = """
int add_nums(int a, int b) {
    return a + b;
}

int main(void) {
    return add_nums(1, 2);
}
"""

# A translation unit in manifold's own shape: preprocessor lines, a struct, file
# scope globals, prototypes, then Allman-braced definitions.
SAMPLE_TU = """#include <stdint.h>

struct struct_1 {
    long f_0;
    struct struct_2 *f_8;
};

struct struct_2 {
    int f_0;
};

long L_1f27b;
extern unsigned char __TMC_END__;

long FUN_401136(void *p0, long p1);
int FUN_4011a0(struct struct_1 *p0);

long FUN_401136(void *p0, long p1)
{
    /* a comment with an unbalanced brace { */
    char *var_0 = "a string with } and { braces";
    return p1;
}

int FUN_4011a0(struct struct_1 *p0)
{
    return (int)(p0->f_0 + L_1f27b);
}
"""


def test_manifold_is_registered() -> None:
    dec = DecompilerRegistry.get("manifold")
    assert isinstance(dec, ManifoldDecompiler)
    assert dec.id == "manifold"
    assert dec.display_name == "Manifold"
    # is_available must never raise, whether or not the tool is installed.
    assert isinstance(dec.is_available(), bool)


def test_unavailable_without_binary_or_image(monkeypatch) -> None:
    """Unavailable needs BOTH paths absent -- so the image has to be neutralized
    too, or this passes only on machines that never ran `decompiler-build`."""
    monkeypatch.setenv("MANIFOLD_BIN", "/nonexistent/manifold")
    monkeypatch.setenv("MANIFOLD_IMAGE", "decbench/manifold:no-such-tag")
    assert ManifoldDecompiler().is_available() is False


def test_env_override_wins(monkeypatch, tmp_path: Path) -> None:
    exe = tmp_path / "manifold"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(exe))
    assert ManifoldDecompiler().is_available() is True


def test_split_functions_finds_definitions_not_prototypes() -> None:
    funcs = dict(split_functions(SAMPLE_TU))
    assert sorted(funcs) == ["FUN_401136", "FUN_4011a0"]


def test_split_functions_ignores_braces_in_strings_and_comments() -> None:
    funcs = dict(split_functions(SAMPLE_TU))
    body = funcs["FUN_401136"]
    # The definition must be complete: a brace inside the string literal or the
    # comment must not have closed the body early.
    assert body.rstrip().endswith("}")
    assert "return p1;" in body


def test_each_function_carries_the_file_scope_it_references() -> None:
    funcs = dict(split_functions(SAMPLE_TU))
    # FUN_4011a0 dereferences struct_1 and reads L_1f27b, so both must ride along
    # -- and struct_1 names struct_2, so the preamble is transitive.
    a0 = funcs["FUN_4011a0"]
    assert "struct struct_1 {" in a0
    assert "struct struct_2 {" in a0
    assert "long L_1f27b;" in a0
    # ... but not the unrelated global.
    assert "__TMC_END__" not in a0
    # Preprocessor lines ride along with every function.
    assert "#include <stdint.h>" in a0


def test_parse_translation_unit_classifies_entities() -> None:
    entities = parse_translation_unit(SAMPLE_TU)
    functions = [e for e in entities if e.is_function]
    assert len(functions) == 2
    # struct definitions and prototypes are not functions
    assert any("struct struct_1" in e.text and not e.is_function for e in entities)


@pytest.fixture(scope="module")
def tiny_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler available")
    build_dir = tmp_path_factory.mktemp("manifold_bin")
    src = build_dir / "tiny.c"
    src.write_text(TINY_C_SOURCE)
    binary = build_dir / "tiny"
    subprocess.run([cc, "-g", "-O0", "-fno-inline", "-o", str(binary), str(src)], check=True)
    return binary


@pytest.fixture
def minimal_pe(tmp_path: Path) -> Path:
    data = bytearray(0x100)
    pe_offset = 0x80
    data[:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    data[pe_offset + 4 : pe_offset + 6] = (0x14C).to_bytes(2, "little")
    binary = tmp_path / "tiny.dll"
    binary.write_bytes(data)
    return binary


def _func_address(binary: Path, name: str) -> int:
    """The ELF-file-space entry address of ``name`` from the symbol table."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    with open(binary, "rb") as f:
        for sec in ELFFile(f).iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym.name == name and sym["st_value"]:
                        return int(sym["st_value"])
    raise AssertionError(f"no symbol {name} in {binary}")


def test_decompile_binary_maps_fun_names_to_addresses(
    monkeypatch, tiny_binary: Path, tmp_path: Path
) -> None:
    """A fake manifold emits a TU; the backend must key it by ELF-space address."""
    # Use the fixture's own function addresses so the .text-range filter (which
    # correctly drops anything outside .text) sees real targets.
    add_nums = _func_address(tiny_binary, "add_nums")
    main = _func_address(tiny_binary, "main")
    tu = SAMPLE_TU.replace("FUN_401136", f"FUN_{add_nums:x}").replace("FUN_4011a0", f"FUN_{main:x}")

    fake = tmp_path / "manifold"
    out_tu = tmp_path / "tu.c"
    out_tu.write_text(tu)
    # manifold's CLI is `manifold <input> <output.c>`; copy the canned TU there.
    fake.write_text(f'#!/bin/sh\ncat "{out_tu}" > "$2"\n')
    fake.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(fake))

    dec = ManifoldDecompiler()
    result = dec.decompile_binary(tiny_binary, output_dir=tmp_path)

    assert result.decompiler.decompiler_name == "manifold"
    assert sorted(result.functions) == sorted([f"FUN_{add_nums:x}", f"FUN_{main:x}"])
    # FUN_<hex> is manifold's name for the function entering at that vaddr, and
    # manifold reports the ELF's own addresses -- so no rebasing is applied.
    assert result.functions[f"FUN_{add_nums:x}"].address == add_nums
    assert result.functions[f"FUN_{main:x}"].address == main
    assert result.functions[f"FUN_{add_nums:x}"].decompiled_code.strip()
    # The adapter consumes no variable/line lineage from the Clight sidecar.
    assert all(not function.line_mappings for function in result.functions.values())
    assert all(not function.variables for function in result.functions.values())
    assert (tmp_path / f"manifold_{tiny_binary.stem}.c").exists()


def test_decompile_binary_narrows_to_requested_addresses(
    monkeypatch, tiny_binary: Path, tmp_path: Path
) -> None:
    """``function_names`` carries target ADDRESSES; only those survive."""
    add_nums = _func_address(tiny_binary, "add_nums")
    main = _func_address(tiny_binary, "main")
    tu = SAMPLE_TU.replace("FUN_401136", f"FUN_{add_nums:x}").replace("FUN_4011a0", f"FUN_{main:x}")
    fake = tmp_path / "manifold"
    out_tu = tmp_path / "tu.c"
    out_tu.write_text(tu)
    fake.write_text(f'#!/bin/sh\ncat "{out_tu}" > "$2"\n')
    fake.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(fake))

    result = ManifoldDecompiler().decompile_binary(tiny_binary, function_names={add_nums})

    assert sorted(result.functions) == [f"FUN_{add_nums:x}"]


def test_decompile_binary_maps_literal_main_from_clight_sidecar(
    monkeypatch, tiny_binary: Path, tmp_path: Path
) -> None:
    """A stripped-style literal ``main`` keeps manifold's exact native address."""
    import decbench.decompilers.raw.manifold_raw as manifold_raw

    main = _func_address(tiny_binary, "main")
    tu = tmp_path / "tu.c"
    tu.write_text("int main(void);\n\nint main(void)\n{\n    return 3;\n}\n")
    sidecar = tmp_path / "tu.clight.json"
    sidecar.write_text(
        json.dumps(
            {
                "compcert_clight": True,
                "functions": [{"name": "main", "address": f"0x{main:x}", "temps": []}],
            }
        )
    )
    argv_log = tmp_path / "argv.log"
    fake = tmp_path / "manifold"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, shutil, sys\n"
        f"out = pathlib.Path(sys.argv[2])\n"
        f"shutil.copyfile({str(tu)!r}, out)\n"
        f"shutil.copyfile({str(sidecar)!r}, out.with_suffix('.clight.json'))\n"
        f"pathlib.Path({str(argv_log)!r}).write_text('\\n'.join(sys.argv[1:]))\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(fake))
    monkeypatch.setattr(manifold_raw, "_symbol_addresses", lambda _binary: {})

    result = ManifoldDecompiler().decompile_binary(tiny_binary, function_names={main})

    assert list(result.functions) == ["main"]
    function = result.functions["main"]
    assert function.address == main
    assert function.variables == []
    assert function.line_mappings == []
    assert result.decompiler.failed_functions == []
    assert result.decompiler.extra["clight_function_addresses"] == 1
    assert argv_log.read_text().splitlines()[-1] == "--dump-clight-json"


def test_decompile_binary_maps_pe_names_from_clight_sidecar(
    monkeypatch, minimal_pe: Path, tmp_path: Path
) -> None:
    import decbench.decompilers.raw.manifold_raw as manifold_raw

    region_start = 0x400000
    partial_crc = region_start + 0x120
    full_crc = region_start + 0x180
    tu = tmp_path / "tu.c"
    tu.write_text(
        "int PartialCRC(int p0);\n"
        "int FullCRC(int p0);\n\n"
        "int PartialCRC(int p0)\n{\n    return p0 + 1;\n}\n\n"
        "int FullCRC(int p0)\n{\n    return p0 + 2;\n}\n"
    )
    sidecar = tmp_path / "tu.clight.json"
    sidecar.write_text(
        json.dumps(
            {
                "compcert_clight": True,
                "functions": [
                    {"name": "PartialCRC", "address": f"0x{partial_crc:x}", "temps": [1]},
                    {"name": "FullCRC", "address": f"0x{full_crc:x}", "temps": [2]},
                ],
            }
        )
    )
    argv_log = tmp_path / "argv.log"
    fake = tmp_path / "manifold"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, shutil, sys\n"
        "out = pathlib.Path(sys.argv[2])\n"
        f"shutil.copyfile({str(tu)!r}, out)\n"
        f"shutil.copyfile({str(sidecar)!r}, out.with_suffix('.clight.json'))\n"
        f"pathlib.Path({str(argv_log)!r}).write_text('\\n'.join(sys.argv[1:]))\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(fake))
    monkeypatch.setattr(
        manifold_raw.binfmt,
        "executable_regions",
        lambda _binary: ((region_start, bytes(0x1000)),),
    )

    result = ManifoldDecompiler().decompile_binary(
        minimal_pe,
        function_names={partial_crc},
    )

    assert list(result.functions) == ["PartialCRC"]
    function = result.functions["PartialCRC"]
    assert function.address == partial_crc
    assert function.variables == []
    assert function.line_mappings == []
    assert result.decompiler.failed_functions == []
    assert result.decompiler.extra["clight_function_addresses"] == 2
    assert argv_log.read_text().splitlines()[-1] == "--dump-clight-json"


def test_clight_function_addresses_accept_all_unique_relations(tmp_path: Path) -> None:
    sidecar = tmp_path / "all.clight.json"
    sidecar.write_text(
        json.dumps(
            {
                "compcert_clight": True,
                "functions": [
                    {"name": "PartialCRC", "address": "0x1120"},
                    {"name": "FullCRC", "address": "0x1180"},
                    {"name": "outside", "address": "0x2000"},
                ],
            }
        )
    )

    assert _clight_function_addresses(
        sidecar,
        ((0x1000, 0x1200),),
        accepted_name=None,
    ) == {"PartialCRC": 0x1120, "FullCRC": 0x1180}
    assert (
        _clight_function_addresses(
            sidecar,
            ((0x1000, 0x1200),),
            accepted_name="main",
        )
        == {}
    )


def test_clight_function_addresses_fail_closed(tiny_binary: Path, tmp_path: Path) -> None:
    from decbench.decompilers.raw import common

    text_range = common.elf_text_range(tiny_binary)
    assert text_range is not None
    executable_ranges = (text_range,)
    main = _func_address(tiny_binary, "main")
    documents = [
        "not json",
        json.dumps({"compcert_clight": True, "functions": "not-a-list"}),
        json.dumps(
            {
                "compcert_clight": True,
                "functions": [{"name": "main", "address": "not-hex"}],
            }
        ),
        json.dumps(
            {
                "compcert_clight": True,
                "functions": [
                    {"name": "main", "address": f"0x{main:x}"},
                    {"name": "main", "address": f"0x{main:x}"},
                ],
            }
        ),
        json.dumps(
            {
                "compcert_clight": True,
                "functions": [
                    {"name": "main", "address": f"0x{main:x}"},
                    {"name": "alias", "address": f"0x{main:x}"},
                ],
            }
        ),
        json.dumps(
            {
                "compcert_clight": True,
                "functions": [{"name": "main", "address": f"0x{text_range[1]:x}"}],
            }
        ),
    ]
    for index, document in enumerate(documents):
        path = tmp_path / f"bad-{index}.clight.json"
        path.write_text(document)
        assert "main" not in _clight_function_addresses(
            path,
            executable_ranges,
            accepted_name=None,
        )
    assert (
        _clight_function_addresses(
            tmp_path / "missing.clight.json",
            executable_ranges,
            accepted_name=None,
        )
        == {}
    )
    assert _clight_function_addresses(tmp_path, (), accepted_name=None) == {}


def test_clight_sidecar_is_requested_for_pe_and_x86_libc_entry(
    tiny_binary: Path, minimal_pe: Path, tmp_path: Path
) -> None:
    assert _needs_clight_function_addresses(tiny_binary) is True
    assert _needs_clight_function_addresses(minimal_pe) is True
    arm_header = tmp_path / "tiny-arm"
    arm_bytes = bytearray(tiny_binary.read_bytes())
    elf_em_arm = 40
    arm_bytes[18:20] = elf_em_arm.to_bytes(2, "little")
    arm_header.write_bytes(arm_bytes)
    assert _needs_clight_function_addresses(arm_header) is False
    non_elf = tmp_path / "not-elf"
    non_elf.write_bytes(b"not an ELF")
    assert _needs_clight_function_addresses(non_elf) is False


def test_decompile_binary_reports_failure_without_output(
    monkeypatch, tiny_binary: Path, tmp_path: Path
) -> None:
    fake = tmp_path / "manifold-fail"
    fake.write_text('#!/bin/sh\necho "unsupported architecture" >&2\nexit 1\n')
    fake.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(fake))

    result = ManifoldDecompiler().decompile_binary(tiny_binary)

    assert result.functions == {}
    assert result.decompiler.failed_functions == ["all"]
    assert "unsupported architecture" in result.decompiler.extra["error"]


# --------------------------------------------------------------------------- #
# Docker path
# --------------------------------------------------------------------------- #

# A stand-in for the docker CLI covering the three calls the backend makes:
# `image inspect` (availability), `build` (decompiler-build), and `run` -- both
# the decompile run, which writes the canned TU into the /work bind mount, and
# the `--entrypoint cat` read of the image's baked-in revision.
FAKE_DOCKER = """#!/usr/bin/env python3
import os
import pathlib
import sys

argv = sys.argv[1:]
log = os.environ.get("FAKE_DOCKER_LOG")
if log:
    with open(log, "a") as fh:
        fh.write("\\0".join(argv) + "\\n")

if argv[:2] == ["image", "inspect"]:
    sys.exit(int(os.environ.get("FAKE_DOCKER_INSPECT_RC", "0")))
if argv[:1] == ["build"]:
    sys.exit(0)
if argv[:1] == ["run"]:
    if "--entrypoint" in argv:
        sys.stdout.write(os.environ.get("FAKE_DOCKER_REV", "abc1234") + "\\n")
        sys.exit(0)
    work = next(
        argv[i + 1].rsplit(":", 1)[0]
        for i, a in enumerate(argv)
        if a == "-v" and argv[i + 1].endswith(":/work")
    )
    output_arg = next(a for a in argv if a.startswith("/work/") and a.endswith(".c"))
    dest = pathlib.Path(work) / pathlib.Path(output_arg).name
    dest.write_text(pathlib.Path(os.environ["FAKE_DOCKER_TU"]).read_text())
    sys.exit(0)
sys.exit(2)
"""


@pytest.fixture
def fake_docker(monkeypatch, tmp_path: Path) -> Path:
    """Put a fake ``docker`` first on PATH and force the native path unavailable.

    ``MANIFOLD_BIN`` pointing at a nonexistent file is the documented way to say
    "no native manifold": the env override wins outright, so no config entry or
    stray ``$PATH`` manifold on the test host can leak in. Returns the path the
    fake logs its argv to, one NUL-joined call per line.
    """
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("MANIFOLD_BIN", str(tmp_path / "no-such-manifold"))
    monkeypatch.setenv("FAKE_DOCKER_LOG", str(tmp_path / "docker-argv.log"))
    monkeypatch.delenv("MANIFOLD_VERSION", raising=False)
    monkeypatch.delenv("MANIFOLD_IMAGE", raising=False)
    monkeypatch.delenv("MANIFOLD_THREADS", raising=False)
    return tmp_path / "docker-argv.log"


def _docker_calls(log: Path) -> list[list[str]]:
    if not log.exists():
        return []
    return [line.split("\0") for line in log.read_text().splitlines() if line]


def test_docker_image_makes_it_available_without_a_binary(fake_docker: Path) -> None:
    dec = ManifoldDecompiler()
    assert dec.is_available() is True
    assert dec._select_path() == ("docker", None)
    # Availability must never build the image (a multi-minute side effect) nor
    # run it -- inspecting is the only docker call it is allowed to make.
    assert {tuple(c[:2]) for c in _docker_calls(fake_docker)} == {("image", "inspect")}


def test_unavailable_when_neither_binary_nor_image(monkeypatch, fake_docker: Path) -> None:
    monkeypatch.setenv("FAKE_DOCKER_INSPECT_RC", "1")
    dec = ManifoldDecompiler()
    assert dec.is_available() is False
    assert dec._select_path() == ("none", None)


def test_native_binary_wins_over_the_image(monkeypatch, fake_docker: Path, tmp_path: Path) -> None:
    """A resolvable executable skips the container round-trip entirely."""
    native = tmp_path / "manifold"
    native.write_text("#!/bin/sh\nexit 0\n")
    native.chmod(0o755)
    monkeypatch.setenv("MANIFOLD_BIN", str(native))

    mode, exe = ManifoldDecompiler()._select_path()

    assert mode == "native"
    assert exe == native
    assert _docker_calls(fake_docker) == []


def test_docker_run_mounts_the_binary_and_reads_back_the_unit(
    monkeypatch, fake_docker: Path, tiny_binary: Path, tmp_path: Path
) -> None:
    """The container path must produce the same result as the native one."""
    add_nums = _func_address(tiny_binary, "add_nums")
    main = _func_address(tiny_binary, "main")
    tu = tmp_path / "tu.c"
    tu.write_text(
        SAMPLE_TU.replace("FUN_401136", f"FUN_{add_nums:x}").replace("FUN_4011a0", f"FUN_{main:x}")
    )
    monkeypatch.setenv("FAKE_DOCKER_TU", str(tu))
    monkeypatch.setenv("MANIFOLD_THREADS", "4")

    result = ManifoldDecompiler().decompile_binary(tiny_binary)

    assert sorted(result.functions) == sorted([f"FUN_{add_nums:x}", f"FUN_{main:x}"])
    assert result.functions[f"FUN_{main:x}"].address == main
    assert result.decompiler.extra["run_via"] == "docker"
    assert result.decompiler.extra["image"] == "decbench/manifold:latest"

    run = next(c for c in _docker_calls(fake_docker) if c[0] == "run" and "--entrypoint" not in c)
    assert f"{tiny_binary.resolve()}:/in/{tiny_binary.name}:ro" in run
    assert "decbench/manifold:latest" in run
    assert run[-3:] == [
        f"/in/{tiny_binary.name}",
        f"/work/{tiny_binary.stem}.c",
        "--dump-clight-json",
    ]
    # MANIFOLD_THREADS caps the container's rayon pool, as it does a native run.
    assert "RAYON_NUM_THREADS=4" in run


def test_docker_version_reports_the_image_revision(monkeypatch, fake_docker: Path) -> None:
    """A dockerized run reports the same ``git-<rev>`` shape a native one does."""
    monkeypatch.setenv("FAKE_DOCKER_REV", "90fa808")

    assert ManifoldDecompiler().get_version() == "git-90fa808"

    read = next(c for c in _docker_calls(fake_docker) if "--entrypoint" in c)
    assert read[-2:] == ["decbench/manifold:latest", "/opt/manifold.rev"]


def test_docker_version_is_probed_once_per_instance(fake_docker: Path) -> None:
    """Reading the revision spawns a container, so a corpus run must not repeat
    it per binary -- and it must not be charged to a decompile's reported time."""
    dec = ManifoldDecompiler()
    assert dec.get_version() == dec.get_version() == "git-abc1234"

    assert len([c for c in _docker_calls(fake_docker) if "--entrypoint" in c]) == 1


def test_image_env_override_retags_every_docker_call(monkeypatch, fake_docker: Path) -> None:
    monkeypatch.setenv("MANIFOLD_IMAGE", "local/manifold:dev")

    assert ManifoldDecompiler().is_available() is True

    inspect = next(c for c in _docker_calls(fake_docker) if c[:2] == ["image", "inspect"])
    assert inspect[-1] == "local/manifold:dev"


def test_build_image_builds_the_dockerfile_with_the_docker_dir_as_context(
    fake_docker: Path,
) -> None:
    """``decbench decompiler-build manifold`` reaches this through build_image."""
    assert ManifoldDecompiler.build_image() == 0

    build = next(c for c in _docker_calls(fake_docker) if c[0] == "build")
    dockerfile = Path(build[build.index("-f") + 1])
    assert dockerfile.name == "manifold.Dockerfile"
    assert dockerfile.is_file(), "the Dockerfile build_image points at must exist"
    assert build[build.index("-t") + 1] == "decbench/manifold:latest"
    # Build context is docker/, matching the other container-backed backends.
    assert Path(build[-1]) == dockerfile.parent


def test_build_passes_a_resolved_sha_so_a_rebuild_is_not_stale(
    monkeypatch, fake_docker: Path, tmp_path: Path
) -> None:
    """The whole point of resolving the ref: docker keys the clone layer on the
    command string, so a bare `master` rebuilds the revision already cached."""
    monkeypatch.setenv("MANIFOLD_REF", "master")
    calls: list[list[str]] = []

    def fake_ls_remote(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "fb5b1bfdeadbeef\trefs/heads/master\n", "")

    import decbench.decompilers.raw.manifold_raw as mr

    monkeypatch.setattr(mr, "_resolve_ref", lambda repo, ref: "fb5b1bfdeadbeef")
    assert ManifoldDecompiler.build_image() == 0

    build = next(c for c in _docker_calls(fake_docker) if c[0] == "build")
    assert "MANIFOLD_REF=fb5b1bfdeadbeef" in build, "must pin the SHA, not the branch name"
    assert "--no-cache" not in build, "an unchanged upstream should still hit the cache"


def test_build_falls_back_to_no_cache_when_the_ref_cannot_be_resolved(
    monkeypatch, fake_docker: Path
) -> None:
    """Offline or a bad ref: a slow honest build beats a fast stale one."""
    import decbench.decompilers.raw.manifold_raw as mr

    monkeypatch.setattr(mr, "_resolve_ref", lambda repo, ref: None)
    assert ManifoldDecompiler.build_image() == 0

    build = next(c for c in _docker_calls(fake_docker) if c[0] == "build")
    assert "--no-cache" in build


def test_resolve_ref_passes_through_a_sha_without_touching_the_network(monkeypatch) -> None:
    import decbench.decompilers.raw.manifold_raw as mr

    monkeypatch.setattr(mr.shutil, "which", lambda n: None)  # no git available
    assert mr._resolve_ref("https://example/repo", "fb5b1bf") == "fb5b1bf"
    assert mr._resolve_ref("https://example/repo", "master") is None


def test_registry_backend_exposes_the_build_hook() -> None:
    """The CLI finds the builder by getattr, so it must live on the instance."""
    assert callable(getattr(DecompilerRegistry.get("manifold"), "build_image", None))
