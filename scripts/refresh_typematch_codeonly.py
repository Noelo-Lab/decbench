"""Recompute type_match for the CODE-ONLY decompilers (no structured variables)
and merge the fresh values into the published type_match_new.json overlay.

The type_match metric parses a code-only decompiler's C signature into arguments
(matched by ABI position) + locals; before that fix these backends were scored by
a name-only regex fallback that never credited arguments, so a function whose only
variables are its arguments scored 0 despite perfect types. Structured decompilers
(angr/ghidra/ida/binja/kuna/phoenix) expose real variables and are UNTOUCHED here —
their overlay entries are preserved exactly so their published numbers do not move.

Usage: python scripts/refresh_typematch_codeonly.py <results_dir>
Writes: <results_dir>/type_match_new.json (backing up the previous one).
"""

from __future__ import annotations

import json
import pickle
import shutil
import sys
from pathlib import Path

import decbench.decompilers  # noqa: F401  (register backends so pickles load)
from decbench.metrics.type_match import TypeMatchMetric

CODE_ONLY = {"codex", "claude-code", "dewolf", "r2dec"}

root = Path(sys.argv[1])
overlay_path = root / "type_match_new.json"
overlay = json.loads(overlay_path.read_text()) if overlay_path.exists() else {}
if overlay_path.exists():
    shutil.copy2(overlay_path, overlay_path.with_suffix(".json.bak_pretypefix"))

metric = TypeMatchMetric()
ckpt_dir = root / "checkpoints"
updated = {d: 0 for d in CODE_ONLY}

for pk in sorted(ckpt_dir.glob("*.pkl")):
    proj = pk.stem
    data = pickle.loads(pk.read_bytes())
    for opt, bins in data.get("decompile", {}).items():
        optn = getattr(opt, "value", str(opt))
        for binn, decs in bins.items():
            for dname, dr in decs.items():
                if dname not in CODE_ONLY:
                    continue
                try:
                    mr = metric.compute_for_binary(dr)
                except Exception as e:  # noqa: BLE001
                    print(f"  ! {proj}/{optn}/{binn}/{dname}: {e}", flush=True)
                    continue
                bucket = overlay.setdefault(dname, {})
                for fn, mv in mr.function_results.items():
                    md = mv.metadata or {}
                    dist = int(md.get("fp", 0)) + int(md.get("fn", 0))
                    bucket[f"{proj}::{optn}::{binn}::{fn}"] = {"value": mv.value, "dist": dist}
                    updated[dname] += 1
    print(f"[{proj}] done", flush=True)

overlay_path.write_text(json.dumps(overlay))
print("\nupdated entries:", updated, flush=True)
print("wrote", overlay_path, flush=True)
print("TYPEFIX_DONE", flush=True)
