"""Repair corrupted per-(function, decompiler) ``decompiled`` flags in
``function_results.json`` before publishing.

Two repairs, both grounded in on-disk truth (never in the presence of metric
values — overlay merges can attach values to functions a decompiler's current
artifact no longer contains):

1. **Flag flips** — a flag that is False (or absent) while the function's block
   EXISTS in the stored decompiled artifact ``<opt>/<proj>/decompiled/
   <dec>_<stem>.c`` is wrong (a later failed re-decompile overwrote the
   checkpoint while the artifact from the earlier successful pass survived).
   Artifact marker presence is the ground truth, so such flags are set True.

2. **LLM off-slice pruning** — the sample-set-only backends (codex,
   claude-code) only ever attempt the functions in
   ``sample_set_manifest.json``; the finalize marked every OTHER universe
   function ``decompiled: False`` for them (~67k phantom failures per backend).
   Never-attempted must be ABSENT, not False: their keys are deleted from
   ``values``/``perfects``/``distances``/``decompiled``/``compiles`` for every
   function outside the manifest. Attempted-but-failed functions keep their
   False flag. A scored value outside the manifest is never pruned — it is
   reported as an anomaly instead.

Dry-run by default; ``--apply`` writes function_results.json back in place.
Idempotent: a second run reports 0 changes.

Usage:  python scripts/repair_decompiled_flags.py results/full_run [--apply]
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

from decbench.models.function_data import FunctionData

MARKER = re.compile(r"^// Function: (\S+) @ (0x[0-9a-fA-F]+)\s*$", re.M)
LLM_DECOMPILERS = ("codex", "claude-code")
PER_DEC_FIELDS = ("values", "perfects", "distances", "decompiled", "compiles")


def marker_names(
    root: Path, opt: str, proj: str, stem: str, dec: str, cache: dict[tuple, set[str] | None]
) -> set[str] | None:
    """Function names present in one decompiled artifact (None = no artifact)."""
    key = (opt, proj, stem, dec)
    if key not in cache:
        cf = root / opt / proj / "decompiled" / f"{dec}_{stem}.c"
        if not cf.is_file():
            cache[key] = None
        else:
            text = cf.read_text(errors="replace")
            cache[key] = {m.group(1) for m in MARKER.finditer(text)}
    return cache[key]


def load_attempted(root: Path) -> set[tuple[str, str, str, str]]:
    """The (project, opt, binary, function) set the LLM backends were asked for."""
    manifest = root / "sample_set_manifest.json"
    if not manifest.is_file():
        raise SystemExit(f"no sample-set manifest at {manifest}; cannot scope the LLM pruning")
    data = json.loads(manifest.read_text())
    return {(f["project"], f["opt"], f["binary"], f["function"]) for f in data["functions"]}


def fix_flags(fd: FunctionData, root: Path, attempted: set[tuple[str, str, str, str]]) -> Counter:
    """Set decompiled=True wherever the artifact holds the function's block.

    Slice-scoped (LLM) decompilers are only flagged for functions inside the
    sample-set manifest: an off-manifest block (an extra decompilation beyond
    the official slice) is pruned by :func:`prune_llm_off_slice`, and flagging
    it here would just re-create the key the prune removes — a flip/prune
    ping-pong that breaks idempotency.
    """
    flips: Counter[str] = Counter()
    cache: dict[tuple, set[str] | None] = {}
    for g in fd.groups:
        for f in g.functions:
            for dec in fd.decompilers:
                if f.decompiled.get(dec) is True:
                    continue
                if (
                    dec in LLM_DECOMPILERS
                    and (g.project, g.opt_level, g.binary, f.function) not in attempted
                ):
                    continue
                names = marker_names(root, g.opt_level, g.project, g.binary, dec, cache)
                if names and f.function in names:
                    f.decompiled[dec] = True
                    flips[dec] += 1
    return flips


def prune_llm_off_slice(
    fd: FunctionData, attempted: set[tuple[str, str, str, str]]
) -> tuple[Counter, Counter, list[str]]:
    """Delete never-attempted codex/claude-code entries; keep attempted ones.

    Returns (pruned counts, retained attempted counts, anomalies) per decompiler.
    An off-slice entry with actual metric values is an anomaly and is kept.
    """
    pruned: Counter[str] = Counter()
    retained: Counter[str] = Counter()
    anomalies: list[str] = []
    llm = [d for d in LLM_DECOMPILERS if d in fd.decompilers]
    for g in fd.groups:
        for f in g.functions:
            in_slice = (g.project, g.opt_level, g.binary, f.function) in attempted
            for dec in llm:
                present = any(dec in getattr(f, field) for field in PER_DEC_FIELDS)
                if not present:
                    continue
                if in_slice:
                    retained[dec] += 1
                    continue
                if f.values.get(dec):
                    anomalies.append(
                        f"{g.project}::{g.opt_level}::{g.binary}::{f.function}::{dec} "
                        f"scored off-slice: {f.values[dec]}"
                    )
                    continue
                removed = False
                for field in PER_DEC_FIELDS:
                    if getattr(f, field).pop(dec, None) is not None:
                        removed = True
                if removed:
                    pruned[dec] += 1
    return pruned, retained, anomalies


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--apply"]
    apply = "--apply" in sys.argv[1:]
    root = Path(args[0] if args else "results/full_run")

    fd = FunctionData.from_json(root / "function_results.json")
    n_fns = sum(len(g.functions) for g in fd.groups)
    print(
        f"[repair] {n_fns} functions, {len(fd.groups)} binaries, "
        f"decompilers={fd.decompilers}, apply={apply}",
        flush=True,
    )

    attempted = load_attempted(root)
    flips = fix_flags(fd, root, attempted)
    print(f"[repair] flag flips (artifact has block, flag was not True): {dict(flips)}")

    pruned, retained, anomalies = prune_llm_off_slice(fd, attempted)
    print(f"[repair] LLM off-slice pruned: {dict(pruned)}")
    print(f"[repair] LLM attempted entries retained: {dict(retained)}")
    for a in anomalies:
        print(f"[repair] ANOMALY (kept): {a}")

    total = sum(flips.values()) + sum(pruned.values())
    if not apply:
        print(f"[repair] DRY RUN — {total} change(s) would be made; nothing written")
        return
    if total == 0:
        print("[repair] nothing to change; not rewriting")
        return
    # Round-trip sanity: the untouched heavyweight fields must survive the write.
    assert fd.samples is not None and fd.hardest is not None, "samples/hardest lost in round-trip"
    fd.to_json(root / "function_results.json")
    print(f"[repair] wrote {root / 'function_results.json'} ({total} changes)")


if __name__ == "__main__":
    main()
