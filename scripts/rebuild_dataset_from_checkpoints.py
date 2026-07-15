"""Rebuild function_results.json from ALL per-project checkpoints.

The per-function dataset can silently lose a whole project if that project falls
out of the ``all_evaluate`` accumulator during an incremental re-run (observed:
coreutils dropped even though its checkpoint holds full decompile + evaluate for
all 6 decompilers). The checkpoints are the source of truth, so this rebuilds the
dataset directly from every ``checkpoints/*.pkl`` — restoring any missing project.

It writes function_results.json with the checkpoints' INLINE-eval metrics; run the
downstream reeval merges (``rebuild_function_data.py --ged / --type-match /
default``) afterward to layer the authoritative header-stripped GED, calibrated
type_match, and v2 byte_match back on top for every project uniformly.

Usage:  python scripts/rebuild_dataset_from_checkpoints.py results/full_run
"""

from __future__ import annotations

import pickle
import sys
from pathlib import Path

import decbench.decompilers  # noqa: F401  (register backends so checkpoints unpickle)
from decbench.models.project import Project
from decbench.scoring.function_data_builder import build_function_data
from scripts.run_benchmark import gather_tomls


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/full_run")
    ck = root / "checkpoints"
    all_dec: dict = {}
    all_eval: dict = {}
    for pk in sorted(ck.glob("*.pkl")):
        data = pickle.loads(pk.read_bytes())
        all_dec[pk.stem] = data.get("decompile", {})
        all_eval[pk.stem] = data.get("evaluate", {})
    projects = [Project.from_toml(t) for t in gather_tomls()]
    fd = build_function_data(all_eval, projects, all_dec)

    from collections import Counter

    gper = Counter(g.project for g in fd.groups)
    fper = Counter()
    for g in fd.groups:
        fper[g.project] += len(g.functions)
    print(
        f"[rebuild-ckpt] {len(gper)} projects, {sum(gper.values())} binary-groups, "
        f"{sum(fper.values())} functions",
        flush=True,
    )
    for p in sorted(gper):
        print(f"    {p:20} {gper[p]:>4} groups  {fper[p]:>7} functions", flush=True)

    out = root / "function_results.json"
    fd.to_json(out)
    print(f"[rebuild-ckpt] wrote {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
