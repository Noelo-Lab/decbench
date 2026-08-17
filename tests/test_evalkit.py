"""Tests for the external eval-kit flow (decbench.evalkit).

Covers the three legs against a synthetic gcc -g -O0 mini-tree:
- export: kit layout, strip verification, functions.json truth vs nm/DWARF,
  anon-name determinism, strict vs allow_unresolved behavior, zip layout;
- package.py: run as a REAL subprocess inside a kit — happy path plus every
  validation-error class;
- ingest: checkpoint + artifact contents, DWARF relabeling, slice_scoped extras,
  failed_functions, extra-address drops, force semantics, raw-json rejection,
  and TypeMatch-only preprocessed-source forwarding without source-CFG work;
- AddrLookup tolerance rules and CliRunner smoke tests for export + ingest.
"""

from __future__ import annotations

import json
import pickle
import random
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from decbench.evalkit import EvalKitError, kit_package, resolve
from decbench.evalkit.export import export_kit
from decbench.evalkit.ingest import ingest_submission

pytestmark = pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("strip") is None,
    reason="host gcc + strip are required to build the synthetic eval-kit tree",
)

_PROG1_C = """\
int add_nums(int a, int b) { return a + b; }
int mul_nums(int a, int b) { return a * b; }
int main(void) { return add_nums(1, 2) + mul_nums(3, 4); }
"""

_PROG2_C = """\
int helper_one(int x) { return x + 1; }
int helper_two(int x) { return x * 2; }
int main(void) { return helper_one(5) + helper_two(6); }
"""

_MANIFEST_FUNCS = [
    {"project": "proj1", "opt": "O0", "binary": "prog1", "function": "add_nums"},
    {"project": "proj1", "opt": "O0", "binary": "prog1", "function": "mul_nums"},
    {"project": "proj2", "opt": "O0", "binary": "prog2", "function": "helper_one"},
    {"project": "proj2", "opt": "O0", "binary": "prog2", "function": "helper_two"},
]

_MANIFEST_BY_BINARY = {
    "prog1": ["add_nums", "mul_nums"],
    "prog2": ["helper_one", "helper_two"],
}


def _nm_addrs(binary: Path) -> dict[str, int]:
    """Ground-truth symbol addresses via nm (same space as DWARF low_pc)."""
    out = subprocess.check_output(["nm", str(binary)], text=True)
    addrs: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t"):
            addrs[parts[2]] = int(parts[0], 16)
    return addrs


@pytest.fixture(scope="module")
def tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A synthetic results tree: compiled binaries + manifest + empty .i files."""
    root = tmp_path_factory.mktemp("evalkit") / "tree"
    for proj, prog, src in [("proj1", "prog1", _PROG1_C), ("proj2", "prog2", _PROG2_C)]:
        compiled = root / "O0" / proj / "compiled"
        compiled.mkdir(parents=True)
        c_file = compiled / f"{prog}.c"
        c_file.write_text(src)
        subprocess.run(
            ["gcc", "-g", "-O0", "-o", str(compiled / prog), c_file.name],
            cwd=compiled,
            check=True,
            capture_output=True,
        )
        (compiled / f"{prog}.i").write_text("")
    manifest = {"method": "std", "k": 1.0, "threshold": 10.0, "functions": _MANIFEST_FUNCS}
    (root / "sample_set_manifest.json").write_text(json.dumps(manifest, indent=2))
    return root


@pytest.fixture(scope="module")
def kit(tree: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One exported kit (module-scoped; tests that mutate use kit_copy)."""
    out = tmp_path_factory.mktemp("kit-out") / "decbench-evalkit-sample-set"
    summary = export_kit(tree, out)
    assert summary.kit_dir == out
    assert summary.zip_path is not None and summary.zip_path.is_file()
    return out


@pytest.fixture
def kit_copy(kit: Path, tmp_path: Path) -> Path:
    """A throwaway copy of the kit for package.py mutation tests."""
    dst = tmp_path / kit.name
    shutil.copytree(kit, dst)
    return dst


@pytest.fixture
def tree_copy(tree: Path, tmp_path: Path) -> Path:
    """A throwaway copy of the tree for ingest tests (ingest mutates the tree)."""
    dst = tmp_path / "tree"
    shutil.copytree(tree, dst)
    return dst


def _functions_json(kit_dir: Path) -> dict:
    return json.loads((kit_dir / "functions.json").read_text())


def _write_submission(kit_dir: Path, results: dict, c_files: dict[str, str]) -> None:
    """Write a contributor submission (results.json + .c files) into a kit."""
    results_dir = kit_dir / "results"
    for name, text in c_files.items():
        (results_dir / name).write_text(text)
    (results_dir / "results.json").write_text(json.dumps(results, indent=2))


def _full_submission(kit_dir: Path) -> dict:
    """A complete contributor submission covering every kit binary/address."""
    public = _functions_json(kit_dir)["public"]
    results: dict = {"decompiler": {"name": "mydec", "version": "1.2.3"}, "results": {}}
    c_files: dict[str, str] = {}
    for anon in sorted(public):
        c_name = f"{Path(anon).stem}.c"
        funcs: dict[str, str] = {}
        body: list[str] = []
        for addr in public[anon]:
            name = f"sub_{addr[2:]}"
            funcs[name] = addr
            body.append(f"int {name}(int a, int b) {{ return a + b; }}\n")
        c_files[c_name] = "\n".join(body)
        results["results"][c_name] = {"binary": anon, "functions": funcs}
    _write_submission(kit_dir, results, c_files)
    return results


def _run_package(kit_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the kit's package.py exactly like a contributor would."""
    return subprocess.run(
        [sys.executable, "package.py", *args],
        cwd=kit_dir,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def packaged_zip(kit: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A happy-path results.zip produced by a REAL package.py run."""
    work = tmp_path_factory.mktemp("packaged") / kit.name
    shutil.copytree(kit, work)
    _full_submission(work)
    proc = _run_package(work)
    assert proc.returncode == 0, proc.stderr
    zip_path = work / "results.zip"
    assert zip_path.is_file()
    return zip_path


def test_export_layout_and_zip(kit: Path) -> None:
    assert (kit / "README.md").is_file()
    assert (kit / "functions.json").is_file()
    assert (kit / "results" / "README.md").is_file()
    assert (kit / "package.py").read_text() == Path(kit_package.__file__).read_text()

    fj = _functions_json(kit)
    assert fj["kit_format_version"] == 1
    assert fj["dataset"] == "sample-set"
    shipped = {p.name for p in (kit / "binaries").iterdir()}
    assert shipped == set(fj["public"]) == set(fj["private"])
    assert len(shipped) == 2

    example = json.loads((kit / "results" / "results.example.json").read_text())
    (entry,) = example["results"].values()
    assert entry["binary"] == sorted(fj["public"])[0]
    assert set(entry["functions"].values()) <= set(fj["public"][entry["binary"]])

    zip_path = kit.parent / f"{kit.name}.zip"
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
    assert names and all(n.startswith(f"{kit.name}/") for n in names)
    expected = {f"{kit.name}/{p.relative_to(kit)}" for p in kit.rglob("*") if p.is_file()}
    assert set(names) == expected


def test_export_functions_json_matches_dwarf_truth(kit: Path, tree: Path) -> None:
    import hashlib

    fj = _functions_json(kit)
    for anon, ident in fj["private"].items():
        original = tree / ident["opt"] / ident["project"] / "compiled" / ident["file"]
        assert original.is_file()
        assert Path(ident["file"]).stem == ident["binary"]
        assert ident["format"] == "ELF64-x86-64"
        shipped = kit / "binaries" / anon
        assert ident["sha256_stripped"] == hashlib.sha256(shipped.read_bytes()).hexdigest()
        truth = _nm_addrs(original)
        expected = sorted(truth[fn] for fn in _MANIFEST_BY_BINARY[ident["binary"]])
        assert fj["public"][anon] == [f"0x{a:x}" for a in expected]


def test_export_strip_verification(kit: Path, tree: Path) -> None:
    from elftools.elf.elffile import ELFFile

    def sections(path: Path) -> dict[str, bytes]:
        with open(path, "rb") as f:
            return {s.name: s.data() for s in ELFFile(f).iter_sections()}

    fj = _functions_json(kit)
    for anon, ident in fj["private"].items():
        original = tree / ident["opt"] / ident["project"] / "compiled" / ident["file"]
        shipped = kit / "binaries" / anon
        stripped = sections(shipped)
        assert not any(name.startswith(".debug") for name in stripped)
        assert ".symtab" not in stripped
        assert stripped[".text"] == sections(original)[".text"]
        assert not shipped.stat().st_mode & 0o111


def test_verify_strip_rejects_an_unstripped_binary(kit: Path, tree: Path) -> None:
    """The strip verification must actually fail on unstripped input.

    Regression guard for the PE case in particular: PE section headers are 8
    bytes, so `.debug_*` live in the COFF string table and appear as `/29`-style
    names — a plain `startswith('.debug')` scan sees nothing and an unstripped
    PE would sail through. _verify_strip resolves those names.
    """
    from decbench.evalkit.export import _verify_strip

    fj = _functions_json(kit)
    ident = next(iter(fj["private"].values()))
    original = tree / ident["opt"] / ident["project"] / "compiled" / ident["file"]
    with pytest.raises(EvalKitError, match="survived strip"):
        _verify_strip(original, original)


def test_export_anon_assignment_deterministic(tree: Path, kit: Path, tmp_path: Path) -> None:
    again = export_kit(tree, tmp_path / "kit2")
    fj_a, fj_b = _functions_json(kit), _functions_json(again.kit_dir)
    assert fj_a["public"] == fj_b["public"]
    assert fj_a["private"] == fj_b["private"]

    idents = sorted(
        [(v["project"], v["opt"], v["file"]) for v in fj_a["private"].values()],
    )
    random.Random(1337).shuffle(idents)
    expected = {f"bin_{i:03d}.elf": ident for i, ident in enumerate(idents)}
    got = {a: (v["project"], v["opt"], v["file"]) for a, v in fj_a["private"].items()}
    assert got == expected


def test_export_strict_vs_allow_unresolved(tree: Path, tmp_path: Path) -> None:
    bogus = {
        "method": "std",
        "k": 1.0,
        "threshold": 10.0,
        "functions": [
            *_MANIFEST_FUNCS,
            {"project": "proj1", "opt": "O0", "binary": "prog1", "function": "no_such_fn"},
            {"project": "proj9", "opt": "O0", "binary": "ghost", "function": "f"},
        ],
    }
    manifest = tmp_path / "bogus_manifest.json"
    manifest.write_text(json.dumps(bogus))

    with pytest.raises(EvalKitError) as exc:
        export_kit(tree, tmp_path / "strict", manifest=manifest, make_zip=False)
    assert "no_such_fn" in str(exc.value)
    assert "ghost" in str(exc.value)

    summary = export_kit(
        tree, tmp_path / "lenient", manifest=manifest, make_zip=False, allow_unresolved=True
    )
    assert summary.n_binaries == 2
    assert summary.n_functions == 4
    assert len(summary.skipped) == 2
    assert summary.zip_path is None


def test_export_rejects_non_sample_set_dataset(tree: Path, tmp_path: Path) -> None:
    with pytest.raises(EvalKitError, match="only sample-set"):
        export_kit(tree, tmp_path / "kit", dataset="large")


def test_package_happy_path(kit_copy: Path) -> None:
    submitted = _full_submission(kit_copy)
    proc = _run_package(kit_copy)
    assert proc.returncode == 0, proc.stderr
    assert "binaries covered 2/2" in proc.stdout
    assert "functions 4/4" in proc.stdout

    fj = _functions_json(kit_copy)
    with zipfile.ZipFile(kit_copy / "results.zip") as zf:
        names = set(zf.namelist())
        packaged = json.loads(zf.read("results.json"))
    assert names == {"results.json", *submitted["results"]}

    assert packaged["kit_format_version"] == 1
    assert packaged["dataset"] == "sample-set"
    assert packaged["decompiler"] == {"name": "mydec", "version": "1.2.3"}
    for c_name, entry in packaged["results"].items():
        anon = entry["anon_binary"]
        ident = fj["private"][anon]
        assert entry["binary"] == {k: ident[k] for k in ("project", "opt", "binary", "file")}
        assert entry["functions"] == submitted["results"][c_name]["functions"]


def test_package_out_flag_writes_elsewhere(kit_copy: Path, tmp_path: Path) -> None:
    _full_submission(kit_copy)
    out = tmp_path / "custom" / "sub.zip"
    out.parent.mkdir()
    proc = _run_package(kit_copy, "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()
    assert not (kit_copy / "results.zip").exists()


def test_package_missing_results_json(kit_copy: Path) -> None:
    proc = _run_package(kit_copy)
    assert proc.returncode == 1
    assert "results.json" in proc.stderr
    assert "not found" in proc.stderr


def test_package_unparseable_results_json(kit_copy: Path) -> None:
    (kit_copy / "results" / "results.json").write_text("{not json")
    proc = _run_package(kit_copy)
    assert proc.returncode == 1
    assert "cannot parse results.json" in proc.stderr


def test_package_listed_c_file_missing(kit_copy: Path) -> None:
    submitted = _full_submission(kit_copy)
    missing = sorted(submitted["results"])[0]
    (kit_copy / "results" / missing).unlink()
    proc = _run_package(kit_copy)
    assert proc.returncode == 1
    assert f"results/{missing} is missing" in proc.stderr
    assert not (kit_copy / "results.zip").exists()


def test_package_unknown_binary(kit_copy: Path) -> None:
    results = {
        "decompiler": {"name": "mydec"},
        "results": {"who.c": {"binary": "bin_999.elf", "functions": {"f": "0x1"}}},
    }
    _write_submission(kit_copy, results, {"who.c": "int f(void) { return 0; }\n"})
    proc = _run_package(kit_copy)
    assert proc.returncode == 1
    assert "unknown binary 'bin_999.elf'" in proc.stderr


def test_package_address_not_in_public_list(kit_copy: Path) -> None:
    submitted = _full_submission(kit_copy)
    c_name = sorted(submitted["results"])[0]
    submitted["results"][c_name]["functions"]["sub_dead"] = "0xdead0000"
    _write_submission(kit_copy, submitted, {})
    proc = _run_package(kit_copy)
    assert proc.returncode == 1
    assert "0xdead0000 is not a target address" in proc.stderr


def test_package_non_identifier_function_name(kit_copy: Path) -> None:
    submitted = _full_submission(kit_copy)
    c_name = sorted(submitted["results"])[0]
    funcs = submitted["results"][c_name]["functions"]
    name, addr = next(iter(sorted(funcs.items())))
    del funcs[name]
    funcs["not-an-identifier"] = addr
    _write_submission(kit_copy, submitted, {})
    proc = _run_package(kit_copy)
    assert proc.returncode == 1
    assert "not a valid C identifier" in proc.stderr


def test_package_duplicate_function_names(kit_copy: Path) -> None:
    submitted = _full_submission(kit_copy)
    c_name = sorted(submitted["results"])[0]
    entry = submitted["results"][c_name]
    addrs = sorted(entry["functions"].values())
    entry_text = json.dumps(entry["functions"])[:-1] + f', "dup_fn": "{addrs[0]}", '
    entry_text += f'"dup_fn": "{addrs[1]}"}}'
    raw = json.dumps(submitted).replace(json.dumps(entry["functions"]), entry_text)
    (kit_copy / "results" / "results.json").write_text(raw)
    proc = _run_package(kit_copy)
    assert proc.returncode == 1
    assert "duplicate key 'dup_fn'" in proc.stderr


def test_package_duplicate_addresses_in_one_file(kit_copy: Path) -> None:
    submitted = _full_submission(kit_copy)
    c_name = sorted(submitted["results"])[0]
    funcs = submitted["results"][c_name]["functions"]
    addr = sorted(funcs.values())[0]
    funcs["second_claim"] = addr
    _write_submission(kit_copy, submitted, {c_name: "int second_claim(void) { return 0; }\n"})
    proc = _run_package(kit_copy)
    assert proc.returncode == 1
    assert f"address {addr} claimed by both" in proc.stderr


def test_package_tolerates_thumb_odd_addresses(kit_copy: Path) -> None:
    """ARM tools report Thumb entry points with the low bit set and the kit
    README promises that form is tolerated — package.py must normalize it, not
    reject an otherwise-valid ARM submission."""
    submitted = _full_submission(kit_copy)
    first_c = sorted(submitted["results"])[0]
    entry = submitted["results"][first_c]
    fn_name, even = next(iter(entry["functions"].items()))
    entry["functions"][fn_name] = f"0x{int(even, 16) | 1:x}"
    _write_submission(kit_copy, submitted, {})

    proc = _run_package(kit_copy)
    assert proc.returncode == 0, proc.stderr
    with zipfile.ZipFile(kit_copy / "results.zip") as zf:
        packaged = json.loads(zf.read("results.json"))
    assert packaged["results"][first_c]["functions"][fn_name] == f"0x{int(even, 16):x}"


def test_package_partial_submission_warns_but_packages(kit_copy: Path) -> None:
    submitted = _full_submission(kit_copy)
    dropped = sorted(submitted["results"])[-1]
    del submitted["results"][dropped]
    _write_submission(kit_copy, submitted, {})
    proc = _run_package(kit_copy)
    assert proc.returncode == 0
    assert "no submission for 1 of 2 kit binaries" in proc.stderr
    assert "bin_001.elf" in proc.stderr
    assert proc.stderr.count("no submission") == 1
    assert (kit_copy / "results.zip").is_file()

    quiet = _run_package(kit_copy, "--quiet")
    assert quiet.returncode == 0
    assert "no submission" not in quiet.stderr


def _load_dec_result(tree: Path, project: str, stem: str, dec_id: str):
    from decbench.models.project import OptimizationLevel

    ckpt = pickle.loads((tree / "checkpoints" / f"{project}.pkl").read_bytes())
    return ckpt["decompile"][OptimizationLevel("O0")][stem][dec_id]


def _packaged_dir(
    tmp_path: Path,
    funcs: dict[str, str],
    c_text: str,
    project: str = "proj1",
    stem: str = "prog1",
) -> Path:
    """A hand-crafted PACKAGED submission dir (as if unpacked from results.zip)."""
    sub = tmp_path / "submission"
    sub.mkdir()
    (sub / "out.c").write_text(c_text)
    payload = {
        "kit_format_version": 1,
        "dataset": "sample-set",
        "packaged_at": "2026-07-25T00:00:00+00:00",
        "decompiler": {"name": "handdec", "version": None},
        "results": {
            "out.c": {
                "binary": {"project": project, "opt": "O0", "binary": stem, "file": stem},
                "anon_binary": "bin_000.elf",
                "functions": funcs,
            }
        },
    }
    (sub / "results.json").write_text(json.dumps(payload, indent=2))
    return sub


def test_ingest_packaged_zip_happy_path(packaged_zip: Path, tree_copy: Path) -> None:
    summary = ingest_submission(packaged_zip, tree_copy, "mydec", evaluate=False)
    assert summary.dec_id == "mydec"
    assert summary.n_binaries == 2
    assert summary.n_functions == 4
    assert summary.n_relabeled == 4
    assert summary.n_dropped_extra == 0
    assert summary.n_failed == 0

    truth = _nm_addrs(tree_copy / "O0" / "proj1" / "compiled" / "prog1")
    result = _load_dec_result(tree_copy, "proj1", "prog1", "mydec")
    assert set(result.functions) == {"add_nums", "mul_nums"}
    assert result.binary_name == "prog1"
    assert result.decompiler.decompiler_name == "mydec"
    assert result.decompiler.decompiler_version == "1.2.3"
    assert result.decompiler.extra["slice_scoped"] is True
    assert result.decompiler.extra["external_submission"] is True
    assert result.decompiler.extra["kit_dataset"] == "sample-set"
    assert result.decompiler.failed_functions == []
    for name in ("add_nums", "mul_nums"):
        func = result.functions[name]
        assert func.address == truth[name]
        assert name in func.decompiled_code
        assert "sub_" not in func.decompiled_code

    c_art = tree_copy / "O0" / "proj1" / "decompiled" / "mydec_prog1.c"
    assert f"// Function: add_nums @ 0x{truth['add_nums']:x}" in c_art.read_text()
    assert (tree_copy / "O0" / "proj1" / "decompiled" / "mydec_prog1.toml").is_file()
    assert (tree_copy / "O0" / "proj2" / "decompiled" / "mydec_prog2.c").is_file()

    for needle in ("mydec", "finalize_results.py", "DECBENCH_REEVAL_DECOMPILERS"):
        assert needle in summary.next_steps


def test_ingest_type_match_forwards_preprocessed_sources_without_source_cfgs(
    packaged_zip: Path,
    tree_copy: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from decbench.metrics.type_match import TypeMatchMetric
    from decbench.models.metrics import MetricResult
    from decbench.utils import cfg as cfg_module

    proj2_i = tree_copy / "O0" / "proj2" / "compiled" / "prog2.i"
    proj2_ii = proj2_i.with_suffix(".ii")
    proj2_i.rename(proj2_ii)

    captured: dict[str, dict[str, Any]] = {}

    def capture(
        self: TypeMatchMetric,
        decompilation: Any,
        **kwargs: Any,
    ) -> MetricResult:
        captured[decompilation.binary_name] = kwargs
        return MetricResult(
            metric_name=self.name,
            decompiler_name=decompilation.decompiler.decompiler_name,
            binary_name=decompilation.binary_name,
        )

    def reject_cfg_extraction(_path: Path) -> None:
        pytest.fail("TypeMatch-only ingest must not extract source CFGs")

    monkeypatch.setattr(TypeMatchMetric, "compute_for_binary", capture)
    monkeypatch.setattr(cfg_module, "extract_cfgs_from_source", reject_cfg_extraction)

    summary = ingest_submission(
        packaged_zip,
        tree_copy,
        "typetest",
        evaluate=True,
        metrics=["type_match"],
    )

    assert summary.n_binaries == 2
    assert set(captured) == {"prog1", "prog2"}
    assert captured["prog1"]["source_cfgs"] is None
    assert captured["prog2"]["source_cfgs"] is None
    assert captured["prog1"]["preprocessed_sources"] == [
        tree_copy / "O0" / "proj1" / "compiled" / "prog1.i"
    ]
    assert captured["prog2"]["preprocessed_sources"] == [proj2_ii]


def test_ingest_partial_submission_failed_functions(tree_copy: Path, tmp_path: Path) -> None:
    truth = _nm_addrs(tree_copy / "O0" / "proj1" / "compiled" / "prog1")
    addr = truth["add_nums"]
    sub = _packaged_dir(
        tmp_path,
        {"sub_a": f"0x{addr:x}"},
        "int sub_a(int a, int b) { return a + b; }\n",
    )
    summary = ingest_submission(sub, tree_copy, "partdec", evaluate=False)
    assert summary.n_functions == 1
    assert summary.n_failed == 1
    result = _load_dec_result(tree_copy, "proj1", "prog1", "partdec")
    assert result.decompiler.failed_functions == ["mul_nums"]
    assert set(result.functions) == {"add_nums"}
    assert not (tree_copy / "checkpoints" / "proj2.pkl").exists()
    assert any("1/2 manifest" in w for w in summary.warnings)


def test_ingest_drops_extra_and_unparseable_addresses(tree_copy: Path, tmp_path: Path) -> None:
    truth = _nm_addrs(tree_copy / "O0" / "proj1" / "compiled" / "prog1")
    funcs = {
        "sub_good": f"0x{truth['add_nums']:x}",
        "sub_main": f"0x{truth['main']:x}",
        "sub_ghost": "0x999999",
        "sub_bad": "zzz",
    }
    c_text = "".join(f"int {n}(int a, int b) {{ return a; }}\n\n" for n in funcs)
    sub = _packaged_dir(tmp_path, funcs, c_text)
    summary = ingest_submission(sub, tree_copy, "extradec", evaluate=False)
    assert summary.n_functions == 1
    assert summary.n_dropped_extra == 3
    assert any("sub_main" in w and "not a manifest function" in w for w in summary.warnings)
    assert any("sub_ghost" in w for w in summary.warnings)
    assert any("sub_bad" in w and "unparseable" in w for w in summary.warnings)
    result = _load_dec_result(tree_copy, "proj1", "prog1", "extradec")
    assert set(result.functions) == {"add_nums"}


def test_ingest_relabel_collision_keeps_larger_body(tree_copy: Path, tmp_path: Path) -> None:
    truth = _nm_addrs(tree_copy / "O0" / "proj1" / "compiled" / "prog1")
    addr = f"0x{truth['add_nums']:x}"
    small = "int sub_aa(int a, int b) { return a; }\n"
    large = "int sub_bb(int a, int b) {\n  int big_marker = 12345;\n  return a + big_marker;\n}\n"
    sub = _packaged_dir(tmp_path, {"sub_aa": addr, "sub_bb": addr}, small + "\n" + large)
    summary = ingest_submission(sub, tree_copy, "coldec", evaluate=False)
    assert any("keeping the larger body" in w for w in summary.warnings)
    result = _load_dec_result(tree_copy, "proj1", "prog1", "coldec")
    assert set(result.functions) == {"add_nums"}
    assert "big_marker" in result.functions["add_nums"].decompiled_code


def test_ingest_force_semantics(packaged_zip: Path, tree_copy: Path) -> None:
    ingest_submission(packaged_zip, tree_copy, "mydec", evaluate=False)
    with pytest.raises(EvalKitError, match="force"):
        ingest_submission(packaged_zip, tree_copy, "mydec", evaluate=False)
    summary = ingest_submission(packaged_zip, tree_copy, "mydec", evaluate=False, force=True)
    assert summary.n_functions == 4
    other = ingest_submission(packaged_zip, tree_copy, "otherdec", evaluate=False)
    assert other.n_functions == 4
    result = _load_dec_result(tree_copy, "proj1", "prog1", "mydec")
    assert set(result.functions) == {"add_nums", "mul_nums"}


def test_force_reingest_purges_slices_the_new_submission_dropped(
    packaged_zip: Path, tree_copy: Path, tmp_path: Path
) -> None:
    """A corrected resubmission covering fewer binaries must not leave the old
    submission's slices behind — the column would mix two submissions."""
    ingest_submission(packaged_zip, tree_copy, "mydec", evaluate=False)
    assert (tree_copy / "O0" / "proj2" / "decompiled" / "mydec_prog2.c").is_file()

    work = tmp_path / "resub"
    work.mkdir()
    with zipfile.ZipFile(packaged_zip) as zf:
        zf.extractall(work)
    payload = json.loads((work / "results.json").read_text())
    payload["results"] = {
        k: v for k, v in payload["results"].items() if v["binary"]["project"] == "proj1"
    }
    (work / "results.json").write_text(json.dumps(payload))

    summary = ingest_submission(work, tree_copy, "mydec", evaluate=False, force=True)
    assert summary.n_binaries == 1
    assert any("dropped stale" in w and "proj2" in w for w in summary.warnings)
    assert not (tree_copy / "O0" / "proj2" / "decompiled" / "mydec_prog2.c").exists()
    assert not (tree_copy / "O0" / "proj2" / "decompiled" / "mydec_prog2.toml").exists()
    with pytest.raises(KeyError):
        _load_dec_result(tree_copy, "proj2", "prog2", "mydec")
    assert set(_load_dec_result(tree_copy, "proj1", "prog1", "mydec").functions) == {
        "add_nums",
        "mul_nums",
    }


def test_ingest_warns_when_the_tree_manifest_drifted_from_the_kit(
    packaged_zip: Path, tree_copy: Path
) -> None:
    """Re-freezing the manifest after a kit went out otherwise shows up only as
    functions quietly dropped — which reads like a bad submission, not a stale
    kit. The fingerprint carried through the package makes the cause explicit."""
    manifest_path = tree_copy / "sample_set_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["functions"] = [f for f in manifest["functions"] if f["function"] != "helper_two"] + [
        {"project": "proj2", "opt": "O0", "binary": "prog2", "function": "main"}
    ]
    manifest_path.write_text(json.dumps(manifest))

    summary = ingest_submission(packaged_zip, tree_copy, "driftdec", evaluate=False)
    assert any("MANIFEST DRIFT" in w for w in summary.warnings)


def test_ingest_rejects_raw_unpackaged_results(tree_copy: Path, tmp_path: Path) -> None:
    sub = tmp_path / "raw"
    sub.mkdir()
    (sub / "bin_000.c").write_text("int sub_1129(void) { return 0; }\n")
    raw = {
        "decompiler": {"name": "mydec"},
        "results": {"bin_000.c": {"binary": "bin_000.elf", "functions": {"sub_1129": "0x1129"}}},
    }
    (sub / "results.json").write_text(json.dumps(raw))
    with pytest.raises(EvalKitError, match="package.py"):
        ingest_submission(sub, tree_copy, "mydec", evaluate=False)


def test_ingest_rejects_bad_dec_id(packaged_zip: Path, tree_copy: Path) -> None:
    for bad in ("My_Dec", "ghidra@12.1", "9lives", ""):
        with pytest.raises(EvalKitError, match="invalid decompiler id"):
            ingest_submission(packaged_zip, tree_copy, bad, evaluate=False)


def test_ingest_requires_sample_manifest(packaged_zip: Path, tmp_path: Path) -> None:
    bare = tmp_path / "bare-tree"
    bare.mkdir()
    with pytest.raises(EvalKitError, match="sample_set_manifest"):
        ingest_submission(packaged_zip, bare, "mydec", evaluate=False)


def test_addrlookup_tolerances() -> None:
    lookup = resolve.AddrLookup({0x401000: "f", 0x8008000: "g"}, min_vaddr=0x400000)
    assert lookup.name_for(0x401000) == "f"
    assert lookup.name_for(0x8008001) == "g"
    assert lookup.name_for(0x1000) == "f"
    assert lookup.name_for(0x7C08001) == "g"
    assert lookup.name_for(0x5000) is None


def test_cli_export_smoke(tree: Path, tmp_path: Path) -> None:
    from decbench.cli import main

    out = tmp_path / "cli-kit"
    runner = CliRunner()
    result = runner.invoke(main, ["evalkit", "export", str(tree), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "2 binaries, 4 functions" in result.output
    assert (out / "functions.json").is_file()
    assert (tmp_path / "cli-kit.zip").is_file()


def test_cli_ingest_smoke(packaged_zip: Path, tree_copy: Path) -> None:
    from decbench.cli import main

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "evalkit",
            "ingest",
            str(packaged_zip),
            str(tree_copy),
            "--id",
            "clidec",
            "--no-evaluate",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Ingested" in result.output
    assert "Next steps" in result.output
    assert (tree_copy / "checkpoints" / "proj1.pkl").is_file()
