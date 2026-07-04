"""Recompute ONLY the byte_match metric over an existing results tree.

The decompilations (the slow part) are already on disk as ``decompiled/{dec}_
{binary}.c`` (function blocks delimited by ``// Function: name @ 0xADDR``); the
original binaries sit in ``compiled/{binary}``. This lets us re-score byte_match
with the new fixup + operand-normalization metric WITHOUT re-decompiling.

Resumable (per (opt,project,binary,dec) checkpoint JSON) and parallel via the
'spawn' context (fork deadlocks once angr's threads are live). Output:
``<results>/byte_match_new.json`` mapping ``opt::project::binary::dec::func`` ->
{"value": float, "compilable": bool}.

Usage:  python scripts/reeval_bytematch.py results/sailr_full [workers]
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import sys
from pathlib import Path

from decbench.utils.results_tree import OPT_LEVELS, resolve_binary, split_functions

DECOMPILERS = ("angr", "phoenix", "ghidra", "ida", "binja", "kuna")


def eval_one(task: tuple[str, str, str, str, str, str]) -> tuple[str, dict]:
    """Worker: recompute byte_match for every function of one (binary, dec).

    ``task`` = (opt, project, binary_stem, dec, binary_path, c_path).
    Returns (checkpoint_key, {func: {value, compilable}}).
    """
    opt, project, stem, dec, binary_path, c_path = task
    from decbench.metrics.byte_match import ByteMatchMetric
    from decbench.models.decompilation import FunctionDecompilation

    metric = ByteMatchMetric()
    binary = Path(binary_path)
    out: dict[str, dict] = {}
    for name, (addr, code) in split_functions(Path(c_path)).items():
        fd = FunctionDecompilation(
            name=name,
            address=addr,
            decompiled_code=code,
            line_count=code.count("\n") + 1,
        )
        try:
            mv = metric.compute_for_function(fd, original_binary_path=binary)
        except Exception as e:  # noqa: BLE001
            out[name] = {"value": 0.0, "compilable": False, "error": str(e)[:120]}
            continue
        md = mv.metadata or {}
        out[name] = {"value": float(mv.value), "compilable": bool(md.get("compilable", False))}
    key = f"{opt}::{project}::{stem}::{dec}"
    return key, out


def build_tasks(
    root: Path, only: set[str] | None = None
) -> list[tuple[str, str, str, str, str, str]]:
    tasks = []
    for opt in OPT_LEVELS:
        odir = root / opt
        if not odir.is_dir():
            continue
        for proj in sorted(p for p in odir.iterdir() if p.is_dir()):
            if only and proj.name not in only:
                continue
            comp, dec_dir = proj / "compiled", proj / "decompiled"
            if not (comp.is_dir() and dec_dir.is_dir()):
                continue
            for dec in DECOMPILERS:
                for cf in sorted(dec_dir.glob(f"{dec}_*.c")):
                    stem = cf.name[len(dec) + 1 : -2]  # strip "dec_" and ".c"
                    binary = resolve_binary(comp, stem)
                    if binary is not None:
                        tasks.append((opt, proj.name, stem, dec, str(binary), str(cf)))
    return tasks


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/sailr_full")
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    # Optional trailing project stems restrict the reeval (e.g. only the ARM/PE
    # projects when recomputing byte_match in the cross-toolchain container).
    only = {a for a in sys.argv[3:] if not a.lstrip("-").isdigit()} or None
    ckpt_dir = root / "reeval_bm"
    ckpt_dir.mkdir(exist_ok=True)

    tasks = build_tasks(root, only=only)
    pending = []
    for t in tasks:
        key = f"{t[0]}::{t[1]}::{t[2]}::{t[3]}"
        if not (ckpt_dir / (key.replace("::", "__") + ".json")).exists():
            pending.append(t)
    print(
        f"[reeval] {len(tasks)} tasks total, {len(pending)} pending, {workers} workers", flush=True
    )

    ctx = mp.get_context("spawn")
    done = 0
    with ctx.Pool(processes=workers) as pool:
        for key, result in pool.imap_unordered(eval_one, pending):
            (ckpt_dir / (key.replace("::", "__") + ".json")).write_text(json.dumps(result))
            done += 1
            if done % 25 == 0 or done == len(pending):
                print(f"[reeval] {done}/{len(pending)} binaries done", flush=True)

    # Merge all checkpoints into one map.
    merged: dict[str, dict] = {}
    for cp in ckpt_dir.glob("*.json"):
        key = cp.stem.replace("__", "::")
        data = json.loads(cp.read_text())
        for func, v in data.items():
            merged[f"{key}::{func}"] = v
    out_path = root / "byte_match_new.json"
    out_path.write_text(json.dumps(merged))
    comp = sum(1 for v in merged.values() if v.get("compilable"))
    print(
        f"[reeval] wrote {out_path} ({len(merged)} funcs, {comp} compilable "
        f"= {100*comp/max(1,len(merged)):.1f}%)",
        flush=True,
    )


if __name__ == "__main__":
    os.environ.setdefault("PYTHONWARNINGS", "ignore")
    main()
