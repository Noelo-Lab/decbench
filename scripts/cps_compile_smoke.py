#!/usr/bin/env python
"""Compile a CPS/embedded target through decbench's real compile path and report.

Validates that a `projects/cps/*.toml` actually flows through
``decbench.pipeline.compile.compile_project`` to produce a cross-compiled ELF
(and, where the build allows, ``.i`` preprocessed sources + DWARF). Intended to
run inside the ARM-toolchain image (see Dockerfile / docker CPS deps).

Usage:
    PYTHONPATH=<repo> python scripts/cps_compile_smoke.py <project.toml> <out_dir> [opt]

Only imports the (light) compile path, so it runs without angr/ghidra/pyjoern.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from decbench.models.project import Project
from decbench.pipeline.compile import compile_project

# ELF e_machine values we care about.
_EM = {0x28: "ARM", 0xB7: "AArch64", 0x3E: "x86-64", 0x03: "x86"}


def _elf_machine(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            if f.read(4) != b"\x7fELF":
                return None
            f.seek(18)
            return _EM.get(struct.unpack("<H", f.read(2))[0], "other")
    except OSError:
        return None


def main() -> int:
    toml_path = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    opt = sys.argv[3] if len(sys.argv) > 3 else None

    project = Project.from_toml(toml_path)
    if opt is None:
        opt = project.compilation.optimization_levels[0].value
    print(f"=== compiling {project.name} @ {opt} (cc={project.compilation.c_compiler}) ===")

    results = compile_project(project, out_dir, optimization=opt)

    compiled = out_dir / opt / project.name / "compiled"
    elfs: dict[str, int] = {}
    arm_bins: list[str] = []
    for entry in sorted(compiled.glob("*")) if compiled.is_dir() else []:
        m = _elf_machine(entry)
        if m:
            elfs[m] = elfs.get(m, 0) + 1
            if m in ("ARM", "AArch64"):
                arm_bins.append(entry.name)
    i_files = list(compiled.glob("*.i")) if compiled.is_dir() else []

    ok = sum(1 for r in results if r.success)
    print(f"compile results: {ok} ok / {len(results)} total")
    print(f"collected ELF by arch: {elfs or '(none)'}")
    print(f".i preprocessed files: {len(i_files)}")
    if arm_bins:
        print(f"ARM binaries (sample): {arm_bins[:5]}")
    verdict = "PASS" if arm_bins else "FAIL (no ARM ELF collected)"
    print(f"VERDICT: {verdict}")
    return 0 if arm_bins else 1


if __name__ == "__main__":
    raise SystemExit(main())
