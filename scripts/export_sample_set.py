#!/usr/bin/env python
"""Freeze the ``sample-set`` preset to an on-disk manifest.

The ``sample-set`` slice (~250 functions, seed 1337) is otherwise a *post-hoc*
tag re-derived in memory at every ``decbench report`` / ``site build`` — it does
not exist on disk (see :mod:`decbench.scoring.datasets`). The expensive LLM
decompiler backends (codex, claude-code) must run on **exactly that slice** and
nothing else, so the run driver gates on a frozen manifest instead of re-deriving
membership (which could drift if the underlying ``function_results.json`` grows a
new column). This script writes that manifest. Once a manifest exists at the tree
root, the canonical finalize (``scripts/finalize_results.py``) pins the
``sample-set`` tags to it — the manifest is the single source of truth.

The manifest reuses the :class:`~decbench.scoring.subset.SubsetManifest` schema
(``method``/``k``/``threshold``/``functions``), with one entry per selected
function::

    {"project": "grep", "opt": "O0", "binary": "grep", "function": "main"}

``scripts/run_benchmark.py`` reads it via ``DECBENCH_SAMPLESET_MANIFEST`` and
restricts every binary's decompile target set to the listed function *names*
(the driver already has the DWARF name<->address map, so name-keyed gating is
robust — no address resolution needed here).

Top-up (project removal): ``--exclude-project NAME`` re-draws with that project's
candidates skipped IN-SCAN, so every other pick of the same seed is preserved and
only the excluded project's slots are refilled from the same buckets. This is only
stable while the excluded project is still PRESENT in ``function_results.json`` —
run this BEFORE stripping the project from the tree. ``--base MANIFEST`` verifies
exactly that: every base pick outside the excluded projects must survive, else the
export aborts (``--allow-drift`` overrides).

Usage:
    export_sample_set.py <results_tree | function_results.json> [-o OUT] [--seed N]
        [--exclude-project NAME]... [--base MANIFEST] [--allow-drift]

Default OUT is ``<tree>/sample_set_manifest.json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from decbench.models.function_data import FunctionData
from decbench.scoring.datasets import assign_datasets, topup_sample_members
from decbench.scoring.subset import SubsetManifest


def _resolve_input(arg: str) -> Path:
    p = Path(arg)
    if p.is_dir():
        p = p / "function_results.json"
    if not p.is_file():
        raise SystemExit(f"error: no function_results.json at {p}")
    return p


def _manifest_from_members(members: set[tuple[str, str, str, str]]) -> SubsetManifest:
    functions = [{"project": p, "opt": o, "binary": b, "function": fn} for (p, o, b, fn) in members]
    functions.sort(key=lambda d: (d["project"], d["opt"], d["binary"], d["function"]))
    return SubsetManifest(method="sample-set", k=0.0, threshold=0.0, functions=functions)


def export_sample_set(
    fr_json: Path, seed: int | None = None, exclude_projects: frozenset[str] = frozenset()
) -> SubsetManifest:
    """Load ``function_results.json`` and freeze a fresh sample-set draw."""
    return collect_sample_set(FunctionData.from_json(fr_json), seed, exclude_projects)


def collect_sample_set(
    fd: FunctionData, seed: int | None = None, exclude_projects: frozenset[str] = frozenset()
) -> SubsetManifest:
    """Tag datasets on an already-loaded dataset and freeze the sample-set.

    ``exclude_projects`` here is a plain filter of a FRESH draw (used only when no
    ``--base`` manifest is given); to preserve an existing manifest's picks use
    :func:`topup_from_base`.
    """
    # seed=None -> DEFAULT_SAMPLE_SEED (1337)
    assign_datasets(fd, seed=seed)
    members = {
        (g.project, g.opt_level, g.binary, f.function)
        for g in fd.groups
        for f in g.functions
        if "sample-set" in (f.datasets or []) and g.project not in exclude_projects
    }
    return _manifest_from_members(members)


def topup_from_base(
    fd: FunctionData,
    base_members: set[tuple[str, str, str, str]],
    exclude_projects: frozenset[str],
    seed: int | None = None,
) -> SubsetManifest:
    """Keep a base manifest's surviving picks and refill the freed slots."""
    members = topup_sample_members(fd, base_members, exclude_projects, seed=seed)
    return _manifest_from_members(members)


def _key(e: dict) -> tuple[str, str, str, str]:
    return (e["project"], e["opt"], e["binary"], e["function"])


def diff_against_base(
    manifest: SubsetManifest, base_path: Path, exclude_projects: frozenset[str]
) -> tuple[int, list[dict], list[dict], list[dict]]:
    """(kept, dropped_excluded, added, MISSING) vs a previous manifest.

    ``MISSING`` — base picks from non-excluded projects that the new draw lost:
    the drift the top-up mechanism promises cannot happen; non-empty means the
    underlying data changed under the manifest (abort unless ``--allow-drift``).
    """
    base = json.loads(base_path.read_text()).get("functions", [])
    new_keys = {_key(e) for e in manifest.functions}
    base_keep = [e for e in base if e["project"] not in exclude_projects]
    dropped = [e for e in base if e["project"] in exclude_projects]
    missing = [e for e in base_keep if _key(e) not in new_keys]
    kept = len(base_keep) - len(missing)
    base_keys = {_key(e) for e in base}
    added = [e for e in manifest.functions if _key(e) not in base_keys]
    return kept, dropped, added, missing


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    fr_json = _resolve_input(args[0])
    out: Path | None = None
    seed: int | None = None
    base: Path | None = None
    allow_drift = False
    exclude: set[str] = set()
    i = 1
    while i < len(args):
        if args[i] in ("-o", "--out"):
            out = Path(args[i + 1])
            i += 2
        elif args[i] == "--seed":
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--exclude-project":
            exclude.add(args[i + 1])
            i += 2
        elif args[i] == "--base":
            base = Path(args[i + 1])
            i += 2
        elif args[i] == "--allow-drift":
            allow_drift = True
            i += 1
        else:
            raise SystemExit(f"error: unknown arg {args[i]!r}")
    if out is None:
        out = fr_json.parent / "sample_set_manifest.json"

    excluded = frozenset(exclude)
    # One parse of the (large) dataset for both the presence check and the draw.
    fd = FunctionData.from_json(fr_json)
    present = {g.project for g in fd.groups}
    for name in sorted(excluded - present):
        raise SystemExit(
            f"error: --exclude-project {name} is not in {fr_json} — the top-up is only "
            "pick-stable while the excluded project is still present; run this BEFORE "
            "stripping the project from the tree"
        )

    if base is not None and base.is_file():
        # Top-up: preserve the base manifest's surviving picks, refill freed slots.
        base_members = {_key(e) for e in json.loads(base.read_text()).get("functions", [])}
        manifest = topup_from_base(fd, base_members, excluded, seed=seed)
    else:
        manifest = collect_sample_set(fd, seed=seed, exclude_projects=excluded)

    if base is not None and base.is_file():
        kept, dropped, added, missing = diff_against_base(manifest, base, excluded)
        print(f"vs base {base}: kept={kept} dropped(excluded)={len(dropped)} added={len(added)}")
        for e in dropped:
            print(f"  - dropped: {e['project']}/{e['opt']}/{e['binary']}::{e['function']}")
        for e in added:
            print(f"  + added:   {e['project']}/{e['opt']}/{e['binary']}::{e['function']}")
        if missing:
            for e in missing:
                print(f"  ! MISSING: {e['project']}/{e['opt']}/{e['binary']}::{e['function']}")
            if not allow_drift:
                print(
                    f"error: {len(missing)} non-excluded base picks did not survive the "
                    "re-draw — the data drifted under the manifest. Not writing. "
                    "(--allow-drift overrides.)",
                    file=sys.stderr,
                )
                return 2
            print("[export] --allow-drift: writing despite the missing base picks above")

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
