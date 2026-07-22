#!/usr/bin/env python
"""Freeze the ``sample-set`` preset to an on-disk manifest.

The ``sample-set`` slice (~250 functions, seed 1337) is otherwise a *post-hoc*
tag re-derived in memory at every ``decbench report`` / ``site build`` — it does
not exist on disk (see :mod:`decbench.scoring.datasets`). The expensive LLM
decompiler backends (codex, claude-code) must run on **exactly that slice** and
nothing else, so the run driver gates on a frozen manifest instead of re-deriving
membership (which could drift if the underlying ``function_results.json`` grows a
new column). This script writes that manifest.

The manifest reuses the :class:`~decbench.scoring.subset.SubsetManifest` schema
(``method``/``k``/``threshold``/``functions``), with one entry per selected
function::

    {"project": "grep", "opt": "O0", "binary": "grep", "function": "main"}

``scripts/run_benchmark.py`` reads it via ``DECBENCH_SAMPLESET_MANIFEST`` and
restricts every binary's decompile target set to the listed function *names*
(the driver already has the DWARF name<->address map, so name-keyed gating is
robust — no address resolution needed here).

Usage:
    export_sample_set.py <results_tree | function_results.json> [-o OUT] [--seed N]

Default OUT is ``<tree>/sample_set_manifest.json``.
"""

from __future__ import annotations

import sys
from pathlib import Path

from decbench.models.function_data import FunctionData
from decbench.scoring.datasets import assign_datasets
from decbench.scoring.subset import SubsetManifest


def _resolve_input(arg: str) -> Path:
    p = Path(arg)
    if p.is_dir():
        p = p / "function_results.json"
    if not p.is_file():
        raise SystemExit(f"error: no function_results.json at {p}")
    return p


def export_sample_set(fr_json: Path, seed: int | None = None) -> SubsetManifest:
    """Load ``function_results.json``, tag datasets, collect the sample-set."""
    fd = FunctionData.from_json(fr_json)
    assign_datasets(fd, seed=seed)  # seed=None -> DEFAULT_SAMPLE_SEED (1337)
    functions: list[dict] = []
    for g in fd.groups:
        for f in g.functions:
            if "sample-set" in (f.datasets or []):
                functions.append(
                    {
                        "project": g.project,
                        "opt": g.opt_level,
                        "binary": g.binary,
                        "function": f.function,
                    }
                )
    functions.sort(key=lambda d: (d["project"], d["opt"], d["binary"], d["function"]))
    return SubsetManifest(method="sample-set", k=0.0, threshold=0.0, functions=functions)


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    fr_json = _resolve_input(args[0])
    out: Path | None = None
    seed: int | None = None
    i = 1
    while i < len(args):
        if args[i] in ("-o", "--out"):
            out = Path(args[i + 1])
            i += 2
        elif args[i] == "--seed":
            seed = int(args[i + 1])
            i += 2
        else:
            raise SystemExit(f"error: unknown arg {args[i]!r}")
    if out is None:
        out = fr_json.parent / "sample_set_manifest.json"

    manifest = export_sample_set(fr_json, seed=seed)
    manifest.to_json(out)

    # Report the shape so the operator can sanity-check the slice.
    by_opt: dict[str, int] = {}
    by_proj: dict[str, int] = {}
    for e in manifest.functions:
        by_opt[e["opt"]] = by_opt.get(e["opt"], 0) + 1
        by_proj[e["project"]] = by_proj.get(e["project"], 0) + 1
    print(f"sample-set: {len(manifest.functions)} functions -> {out}")
    print("  by opt:    " + ", ".join(f"{k}={v}" for k, v in sorted(by_opt.items())))
    print(f"  projects:  {len(by_proj)} distinct")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
