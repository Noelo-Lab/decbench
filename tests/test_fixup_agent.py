"""Tests for the fixup agent's workbench and driver (scripts/fixup_agent.py)."""

from __future__ import annotations

import gzip
import json
import shutil
from pathlib import Path

import pytest

from decbench.metrics.fixups import workbench
from scripts import fixup_agent

needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not installed")

FIXUP = """FLAGS = []

def prepare(code, ctx):
    return "typedef unsigned int uint;\\n" + code
"""


def _dataset(path: Path) -> Path:
    group = {
        "group": "O0/demo/demo",
        "compiler": "gcc",
        "flags": ["-O0", "-c", "-fno-builtin", "-w"],
        "cs": [3, 8],
        "siblings": {
            "plain": "int plain(int a) { return a + 1; }",
            "typed": "uint typed(uint a) { return a * 2; }",
            "broken": "int broken(void) { return missing_thing; }",
        },
        "funcs": [
            {"name": n, "address": 0, "orig": "c3", "raw_ok": n == "plain", "raw_bm": 0.0}
            for n in ("plain", "typed", "broken")
        ],
    }
    with gzip.open(path, "wt") as f:
        f.write(json.dumps(group) + "\n")
    return path


@needs_gcc
def test_workbench_scores_a_candidate_module(tmp_path: Path) -> None:
    dataset = _dataset(tmp_path / "dev.jsonl.gz")
    module = tmp_path / "fixup.py"
    module.write_text(FIXUP)

    rows = workbench.evaluate(dataset, module, workers=1)
    summary = workbench.summarize(rows)

    assert {r["id"]: r["ok"] for r in rows} == {
        "O0/demo/demo/broken": False,
        "O0/demo/demo/plain": True,
        "O0/demo/demo/typed": True,
    }
    assert summary["compile_rate"] == pytest.approx(2 / 3)
    assert summary["raw_compile_rate"] == pytest.approx(1 / 3)
    assert summary["regressions"] == 0
    assert summary["perfect_rate"] == pytest.approx(0.0)
    broken = next(r for r in rows if r["id"].endswith("broken"))
    assert broken["cluster"] == "'…' undeclared (first use in this function)"
    assert broken["token"] == "'missing_thing'"


@needs_gcc
def test_show_diffs_the_recompiled_instructions(tmp_path: Path, capsys) -> None:
    (tmp_path / "data").mkdir()
    _dataset(tmp_path / "data" / "dev.jsonl.gz")
    (tmp_path / "fixup.py").write_text(FIXUP)

    workbench.main(["--workspace", str(tmp_path), "show", "O0/demo/demo/plain"])

    out = capsys.readouterr().out
    assert "bytematch=" in out
    assert "--- original" in out and "+++ recompiled" in out


def test_error_cluster_passes_through_harness_errors() -> None:
    assert workbench.error_cluster("", "fixup raised KeyError") == ("fixup raised KeyError", "")


def test_heldout_split_is_fixed() -> None:
    assert fixup_agent.is_heldout("openssh-portable")
    assert not fixup_agent.is_heldout("bash")


def test_malware_projects_are_known() -> None:
    assert {"mirai", "mydoom", "dexter"} <= fixup_agent.malware_projects()


def test_sandbox_hides_home_and_tmp(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    argv = fixup_agent.sandbox_argv(tmp_path, package)
    assert argv[0] == "bwrap" and argv[-1] == "--"
    pairs = list(zip(argv, argv[1:], strict=False))
    assert ("--tmpfs", str(Path.home())) in pairs
    assert ("--tmpfs", "/tmp") in pairs
    assert "--unshare-pid" in argv and ("--proc", "/proc") in pairs
    assert argv.index("--tmpfs") < argv.index("--bind")
    assert argv[argv.index("--bind") + 1] == str(tmp_path)
    assert argv.index("--bind") < len(argv) - 1 - argv[::-1].index(str(package))


def test_package_snapshot_has_no_fixup_modules(tmp_path: Path, monkeypatch) -> None:
    fixups_dir = tmp_path / "repo" / "decbench" / "metrics" / "fixups"
    (fixups_dir / "generated").mkdir(parents=True)
    for name in ("__init__.py", "workbench.py", "PROMPT.md", "generated/ghidra.py"):
        (fixups_dir / name).write_text("")
    monkeypatch.setattr(fixup_agent, "REPO", tmp_path / "repo")
    monkeypatch.setattr(fixup_agent, "FIXUPS", fixups_dir)

    package = fixup_agent.snapshot_package(tmp_path / "pkg")

    copied = sorted(p.name for p in (package / "decbench" / "metrics" / "fixups").iterdir())
    assert copied == ["PROMPT.md", "__init__.py", "workbench.py"]
