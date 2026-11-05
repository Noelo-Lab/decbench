"""The fixup agent's workbench: score a candidate fixup module on a dataset.

Run from a fixup workspace (built by ``scripts/fixup_agent.py``)::

    python -m decbench.metrics.fixups.workbench eval [--quick]
    python -m decbench.metrics.fixups.workbench errors [--match REGEX | --compiled]
    python -m decbench.metrics.fixups.workbench show ID

``eval`` compiles every function in ``data/dev.jsonl`` through ``fixup.py``
with the same harness, flags, and scoring as the byte_match metric, then
prints the compile rate, the byte-match mean, the perfect-match rate,
regressions against the raw (no-fixup) baseline, and the most common remaining
gcc errors. A full eval also snapshots ``fixup.py`` under ``snapshots/``.
``show`` adds a diff of the original and recompiled instructions.

Dataset format (one JSON object per line, one line per binary)::

    {"group": "O0/bash/bash", "compiler": "gcc", "flags": [...], "cs": [arch, mode],
     "siblings": {name: code, ...},
     "funcs": [{"name", "address", "orig": hex, "raw_ok": bool, "raw_bm": float}, ...]}
"""

from __future__ import annotations

import argparse
import difflib
import gzip
import hashlib
import json
import multiprocessing as mp
import os
import re
import shutil
import sys
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

CHUNK = 48
QUICK_MODULUS = 8

_ERROR_LINE = re.compile(r"^[^\n:]*:\d+:\d+: (?:fatal )?error: (.+)$", re.M)
_QUOTED = re.compile(r"'[^'\n]*'")
_NUMBER = re.compile(r"\b\d+\b")


def open_dataset(path: Path) -> Iterator[dict[str, Any]]:
    """Yield binary groups from a ``.jsonl`` or ``.jsonl.gz`` dataset."""
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def func_id(group: str, name: str) -> str:
    return f"{group}/{name}"


def in_quick(fid: str) -> bool:
    return int(hashlib.sha1(fid.encode()).hexdigest(), 16) % QUICK_MODULUS == 0


def error_cluster(stderr: str, error: str | None) -> tuple[str, str]:
    """``(cluster, token)``: the first gcc error with quoted names and numbers blanked,
    and the first quoted name it mentioned."""
    if error and not error.startswith("compiler diagnostics"):
        return error, ""
    m = _ERROR_LINE.search(stderr or "")
    if not m:
        return error or "unknown", ""
    quoted = _QUOTED.findall(m.group(1))
    return _NUMBER.sub("N", _QUOTED.sub("'…'", m.group(1))).strip(), (quoted or [""])[0]


_MODULE: tuple[str, float, ModuleType | None] | None = None


def _load_candidate(path: str) -> ModuleType | None:
    global _MODULE
    from decbench.metrics import fixups

    mtime = os.stat(path).st_mtime if os.path.exists(path) else -1.0
    if _MODULE is None or _MODULE[0] != path or _MODULE[1] != mtime:
        _MODULE = (path, mtime, fixups.load_path(Path(path)) if mtime >= 0 else None)
    return _MODULE[2]


def _asm_diff(obj_path: Path | None, fn: dict[str, Any], arch_mode: tuple) -> str:
    """Unified diff of the original's and the recompile's normalized instructions."""
    from decbench.metrics.byte_match import _disassemble_bytes
    from decbench.utils import binfmt

    if obj_path is None:
        return ""
    recompiled = binfmt.object_text_bytes(obj_path, fn["name"])
    if recompiled is None:
        return "(could not read the recompiled function)"
    original = _disassemble_bytes(bytes.fromhex(fn["orig"]), fn["address"], arch_mode)
    rebuilt = _disassemble_bytes(recompiled, 0, arch_mode)
    diff = difflib.unified_diff(original, rebuilt, "original", "recompiled", lineterm="", n=2)
    return "\n".join(diff) or "(identical)"


def _score_chunk(task: tuple[str, dict[str, Any], list[dict[str, Any]], bool]) -> list[dict]:
    module_path, group, funcs, keep_source = task
    from decbench.metrics import fixup as harness
    from decbench.metrics import fixups
    from decbench.metrics.byte_match import score_compiled

    module = _load_candidate(module_path)
    siblings = group["siblings"]
    bkey = fixups.binary_key(siblings)
    arch_mode = tuple(group["cs"])
    out = []
    for fn in funcs:
        code = siblings[fn["name"]]
        fid = func_id(group["group"], fn["name"])
        start = time.perf_counter()
        res = harness.compile_with_fixup(
            code,
            fn["name"],
            group["compiler"],
            group["flags"],
            fixup=module,
            siblings=siblings,
            binary_key=bkey,
        )
        if keep_source:
            asm = _asm_diff(res.obj_path, fn, arch_mode)
            mv = score_compiled(
                res, fn["name"], fn["address"], bytes.fromhex(fn["orig"]), arch_mode
            )
            out.append(
                {
                    "id": fid,
                    "code": code,
                    "source": res.source,
                    "stderr": res.stderr,
                    "ok": res.compilable,
                    "iterations": res.iterations,
                    "error": res.error,
                    "bm": float(mv.value),
                    "asm": asm,
                }
            )
            continue
        mv = score_compiled(res, fn["name"], fn["address"], bytes.fromhex(fn["orig"]), arch_mode)
        ok = bool((mv.metadata or {}).get("compilable"))
        cluster, token = ("", "") if ok else error_cluster(res.stderr, res.error)
        out.append(
            {
                "id": fid,
                "ok": ok,
                "bm": float(mv.value),
                "raw_ok": fn["raw_ok"],
                "raw_bm": fn["raw_bm"],
                "cluster": cluster,
                "token": token,
                "secs": time.perf_counter() - start,
            }
        )
    return out


def _tasks(
    dataset: Path, module: Path, quick: bool, only: set[str] | None = None, keep: bool = False
) -> Iterator[tuple[str, dict[str, Any], list[dict[str, Any]], bool]]:
    for group in open_dataset(dataset):
        funcs = [
            fn
            for fn in group["funcs"]
            if (not quick or in_quick(func_id(group["group"], fn["name"])))
            and (only is None or func_id(group["group"], fn["name"]) in only)
        ]
        for i in range(0, len(funcs), CHUNK):
            yield str(module), group, funcs[i : i + CHUNK], keep


def evaluate(dataset: Path, module: Path, workers: int, quick: bool = False) -> list[dict]:
    """Score every function of ``dataset`` through ``module``; one row per function."""
    from decbench.metrics import fixups

    if module.exists():
        fixups.load_path(module)
    rows: list[dict] = []
    tasks = _tasks(dataset, module, quick)
    if workers <= 1:
        for chunk in map(_score_chunk, tasks):
            rows.extend(chunk)
    else:
        with mp.get_context("spawn").Pool(workers) as pool:
            for chunk in pool.imap_unordered(_score_chunk, tasks):
                rows.extend(chunk)
    rows.sort(key=lambda r: r["id"])
    return rows


def summarize(rows: list[dict]) -> dict[str, Any]:
    """Headline numbers for one evaluation."""
    n = len(rows) or 1
    both = [r for r in rows if r["ok"] and r["raw_ok"]]
    return {
        "functions": len(rows),
        "compile_rate": sum(r["ok"] for r in rows) / n,
        "raw_compile_rate": sum(r["raw_ok"] for r in rows) / n,
        "bytematch_mean": sum(r["bm"] for r in rows) / n,
        "raw_bytematch_mean": sum(r["raw_bm"] for r in rows) / n,
        "perfect_rate": sum(r["bm"] >= 1.0 for r in rows) / n,
        "raw_perfect_rate": sum(r["raw_bm"] >= 1.0 for r in rows) / n,
        "regressions": sum(1 for r in rows if r["raw_ok"] and not r["ok"]),
        "both_compiled": len(both),
        "both_bytematch_mean": sum(r["bm"] for r in both) / (len(both) or 1),
        "both_raw_bytematch_mean": sum(r["raw_bm"] for r in both) / (len(both) or 1),
        "fixup_raised": sum(1 for r in rows if r["cluster"].startswith("fixup raised")),
        "ms_per_function": 1000 * sum(r["secs"] for r in rows) / n,
    }


def _print_summary(summary: dict[str, Any], rows: list[dict], top: int) -> None:
    s = summary
    print(f"functions            {s['functions']}")
    print(
        f"compile rate         {100 * s['compile_rate']:.2f}%  "
        f"(raw {100 * s['raw_compile_rate']:.2f}%)"
    )
    print(f"bytematch mean       {s['bytematch_mean']:.4f}  (raw {s['raw_bytematch_mean']:.4f})")
    print(
        f"perfect matches      {100 * s['perfect_rate']:.2f}%  "
        f"(raw {100 * s['raw_perfect_rate']:.2f}%)"
    )
    print(
        f"  on {s['both_compiled']} compiled both ways: {s['both_bytematch_mean']:.4f} "
        f"(raw {s['both_raw_bytematch_mean']:.4f})"
    )
    print(f"regressions          {s['regressions']}  (compiled raw, fail with fixup)")
    print(f"fixup raised         {s['fixup_raised']}")
    print(f"ms per function      {s['ms_per_function']:.1f}")
    failing = [r for r in rows if not r["ok"]]
    clusters = Counter(r["cluster"] for r in failing)
    print(f"\ntop {top} remaining errors (count  first gcc error  [most common names]):")
    for msg, count in clusters.most_common(top):
        names = Counter(r["token"] for r in failing if r["cluster"] == msg and r["token"])
        common = ", ".join(f"{n} {c}" for n, c in names.most_common(6))
        print(f"{count:7d}  {msg[:150]}" + (f"\n           [{common}]" if common else ""))


def _remaining(workspace: Path) -> str:
    try:
        deadline = float((workspace / ".deadline").read_text())
    except (OSError, ValueError):
        return ""
    return f"\ntime remaining: {max(0.0, (deadline - time.time()) / 60):.0f} min"


def cmd_eval(args: argparse.Namespace) -> int:
    ws = Path(args.workspace)
    dataset = ws / args.dataset
    module = ws / "fixup.py"
    rows = evaluate(dataset, module, args.workers, quick=args.quick)
    summary = summarize(rows)
    _print_summary(summary, rows, args.top)
    out = ws / "eval"
    out.mkdir(exist_ok=True)
    (out / "last.json").write_text(json.dumps({"summary": summary, "rows": rows}))
    if not args.quick and module.exists():
        snaps = ws / "snapshots"
        snaps.mkdir(exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        dest = snaps / f"{stamp}_{100 * summary['compile_rate']:.2f}.py"
        shutil.copy2(module, dest)
        with open(snaps / "index.jsonl", "a") as f:
            f.write(json.dumps({"file": dest.name, **summary}) + "\n")
    print(_remaining(ws))
    return 0


def cmd_errors(args: argparse.Namespace) -> int:
    last = json.loads((Path(args.workspace) / "eval" / "last.json").read_text())
    if args.compiled:
        built = sorted(
            (r for r in last["rows"] if r["ok"] and r["bm"] < 1.0), key=lambda r: r["bm"]
        )
        for r in built[: args.limit]:
            print(f"{r['id']}\tbytematch {r['bm']:.3f}")
        print(f"\n{len(built)} compiled functions are not a perfect match")
        return 0
    pattern = re.compile(args.match) if args.match else None
    hits = [
        r for r in last["rows"] if not r["ok"] and (pattern is None or pattern.search(r["cluster"]))
    ]
    for r in hits[: args.limit]:
        print(f"{r['id']}\t{r['cluster'][:140]}\t{r['token']}")
    print(f"\n{len(hits)} failing functions match")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    ws = Path(args.workspace)
    rows: list[dict] = []
    for task in _tasks(ws / args.dataset, ws / "fixup.py", False, only=set(args.ids), keep=True):
        rows.extend(_score_chunk(task))
    if not rows:
        print("no such function id", file=sys.stderr)
        return 1
    for r in rows:
        print(
            f"===== {r['id']}  ok={r['ok']} bytematch={r['bm']:.3f} "
            f"attempts={r['iterations']} error={r['error']}"
        )
        print("----- decompiled code")
        print(r["code"])
        print("----- translation unit after fixup")
        print(r["source"])
        print("----- gcc stderr (last attempt)")
        print(r["stderr"])
        if r["asm"]:
            print("----- instructions, original vs recompiled (normalized as scored)")
            print(r["asm"])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="workbench", description=__doc__.split("\n")[0])
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--dataset", default="data/dev.jsonl.gz")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("eval", help="score fixup.py on the dataset")
    p.add_argument("--quick", action="store_true", help=f"only 1/{QUICK_MODULUS} of functions")
    p.add_argument("--workers", type=int, default=int(os.environ.get("FIXUP_WORKERS", "8")))
    p.add_argument("--top", type=int, default=30)
    p = sub.add_parser("errors", help="list failing function ids from the last eval")
    p.add_argument("--match", default="")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--compiled", action="store_true", help="compiled but not a perfect match")
    p = sub.add_parser("show", help="code, translation unit, gcc stderr, and asm diff for ids")
    p.add_argument("ids", nargs="+")
    args = parser.parse_args(argv)
    return {"eval": cmd_eval, "errors": cmd_errors, "show": cmd_show}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
