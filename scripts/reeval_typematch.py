"""Re-evaluate type_match from run checkpoints (no re-decompile) and compare to
the old stored scores. Checkpoints carry FunctionDecompilation.variables +
binary_path, so type_match (which only needs those + DWARF) can be recomputed.

Usage: python reeval_typematch.py <results_dir> [proj1 proj2 ...]
Prints per-decompiler OLD vs NEW aggregate over functions present in
function_results.json, and writes type_match_new.json when --emit is passed.
"""

from __future__ import annotations

import json
import pickle
import sys
from collections import defaultdict
from pathlib import Path

import decbench.decompilers  # noqa: F401 (register backends so pickles load)
from decbench.metrics.type_match import TypeMatchMetric

root = Path(sys.argv[1])
args = [a for a in sys.argv[2:] if not a.startswith("--")]
emit = "--emit" in sys.argv

# old stored type_match, keyed (project, opt, binary, function, dec)
with open(root / "function_results.json") as _fh:
    fd = json.load(_fh)
old = {}
for g in fd["groups"]:
    for f in g["functions"]:
        for d, v in (f.get("values") or {}).items():
            if v and v.get("type_match") is not None:
                old[(g["project"], g["opt_level"], g["binary"], f["function"], d)] = v["type_match"]

ckpt_dir = root / "checkpoints"
projects = args or sorted(p.stem for p in ckpt_dir.glob("*.pkl"))

metric = TypeMatchMetric()
agg = defaultdict(lambda: {"o": 0.0, "n": 0.0, "c": 0, "imp": 0, "wor": 0})
new_scores: dict = {}

for proj in projects:
    pk = ckpt_dir / f"{proj}.pkl"
    if not pk.is_file():
        continue
    with open(pk, "rb") as _pf:
        data = pickle.load(_pf)
    dec_tree = data.get("decompile", {})
    for opt, bins in dec_tree.items():
        optn = getattr(opt, "value", str(opt))
        for binn, decs in bins.items():
            for dname, dr in decs.items():
                # dname here is the decompiler id used in the run; normalize to
                # the unversioned name used in function_results (angr/ida/...).
                try:
                    mr = metric.compute_for_binary(dr)
                except Exception as e:  # noqa: BLE001
                    print(f"  ! {proj}/{optn}/{binn}/{dname}: {e}")
                    continue
                for fn, mv in mr.function_results.items():
                    key = (proj, optn, binn, fn, dname)
                    if key not in old:
                        continue
                    o = old[key]
                    n = mv.value
                    a = agg[dname]
                    a["o"] += o
                    a["n"] += n
                    a["c"] += 1
                    if n > o + 1e-9:
                        a["imp"] += 1
                    elif n < o - 1e-9:
                        a["wor"] += 1
                    if emit:
                        md = mv.metadata or {}
                        dist = int(md.get("fp", 0)) + int(md.get("fn", 0))
                        new_scores.setdefault(dname, {})[f"{proj}::{optn}::{binn}::{fn}"] = {
                            "value": n,
                            "dist": dist,
                        }

print(f"\n{'dec':9} {'n':>7} {'OLD mean':>9} {'NEW mean':>9} {'improved':>9} {'worse':>7}")
for d in sorted(agg):
    a = agg[d]
    c = a["c"] or 1
    print(f"{d:9} {a['c']:>7} {a['o']/c:>9.3f} {a['n']/c:>9.3f} {a['imp']:>9} {a['wor']:>7}")

if emit:
    with open(root / "type_match_new.json", "w") as _of:
        json.dump(new_scores, _of)
    print("\nwrote", root / "type_match_new.json")
