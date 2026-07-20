"""Assemble the complete function_results.json + scoreboard.toml from checkpoints.

The authoritative, no-re-decompile finalize: read every ``checkpoints/*.pkl``
(the source of truth — they carry per-function metrics, the byte_match
``compilable`` flag, variables, and decompiled code), build the per-function
dataset, overlay the reeval'd GED / type_match / byte_match where those files
cover a decompiler, attach the report extras (difficulty-tiered View samples,
hardest, per-decompiler compile rates), fold in the historical-Ghidra points,
and build the scoreboard from the finished dataset so ``scoreboard.toml`` matches
what the site renders.

The metric overlays are SCOPED by their ``covered`` set (see
``rebuild_function_data.update_*``): a decompiler added after the reeval
(r2dec/dewolf) has no entries in ``*_new.json`` and keeps its own checkpoint
values; only the decompilers the reeval covered are rewritten to the
authoritative header-stripped GED / calibrated type_match / v2 byte_match.

Usage:  python scripts/finalize_full_run.py results/full_run [history_run_dir]
"""

from __future__ import annotations

import glob
import json
import pickle
import sys
from pathlib import Path

# Same-repo scripts.
from ingest_history import build_points
from rebuild_function_data import update_byte_match, update_ged, update_type_match

import decbench.decompilers  # noqa: F401  (register backends so checkpoints unpickle)
import decbench.metrics  # noqa: F401  (register metrics for perfect-value lookups)
from decbench.models.project import Project
from decbench.scoring.function_data_builder import build_function_data
from decbench.scoring.report_extras import attach_extras
from decbench.scoring.scoreboard import build_scoreboard_from_function_data

# All eight backends a full run supports (phoenix stays in the data; the site
# hides it at render time). Order is display order.
DECOMPILERS = ["angr", "phoenix", "ghidra", "ida", "binja", "kuna", "r2dec", "dewolf"]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/full_run")
    history_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("results/ghidra_history")

    print(f"[finalize] loading checkpoints from {root}/checkpoints ...", flush=True)
    all_dec: dict = {}
    all_eval: dict = {}
    for pk in sorted(glob.glob(str(root / "checkpoints" / "*.pkl"))):
        data = pickle.loads(Path(pk).read_bytes())
        stem = Path(pk).stem
        all_dec[stem] = data.get("decompile", {})
        all_eval[stem] = data.get("evaluate", {})
    print(f"[finalize] {len(all_dec)} project checkpoints loaded", flush=True)

    # gather_tomls() imports run_benchmark, which forces the 'spawn' start method
    # and imports angr; import it lazily so this stays a light finalize.
    from run_benchmark import gather_tomls

    projects = [Project.from_toml(t) for t in gather_tomls()]

    fd = build_function_data(all_eval, projects, all_dec)
    print(
        f"[finalize] dataset: {len(fd.decompilers)} decompilers, "
        f"{sum(len(g.functions) for g in fd.groups)} functions, {len(fd.groups)} groups",
        flush=True,
    )

    # Scoped metric overlays (authoritative reeval for covered decompilers only).
    for stem, apply_overlay in (("ged_new", update_ged), ("type_match_new", update_type_match)):
        path = root / f"{stem}.json"
        if path.exists():
            n = apply_overlay(fd, json.loads(path.read_text()))
            print(f"[finalize] overlaid {stem}: {n} entries", flush=True)
    bm_path = root / "byte_match_new.json"
    if bm_path.exists():
        tally = update_byte_match(fd, json.loads(bm_path.read_text()))
        print(f"[finalize] overlaid byte_match for {len(tally)} decompilers", flush=True)

    # Historical Ghidra points (GED across versions) -> the Historical view.
    history = build_points(history_dir, "ghidra", ["ged"]) if history_dir.is_dir() else None
    if history:
        print(f"[finalize] history: {len(history)} ghidra version points", flush=True)

    # Difficulty-tiered View samples + hardest + compile rates + dataset presets,
    # all from the checkpoint eval (which carries code + the compilable flag).
    attach_extras(
        fd,
        evaluation_results=all_eval,
        decompile_results=all_dec,
        projects=projects,
        history_inputs=history,
    )
    print(
        f"[finalize] extras: {len(fd.samples)} samples, {len(fd.hardest)} hardest, "
        f"{len(fd.compile_rates)} compile-rates, {len(fd.history)} history",
        flush=True,
    )

    # Scoreboard from the FINISHED dataset (post-overlay) so it matches the site.
    scoreboard = build_scoreboard_from_function_data(fd)
    scoreboard.decompilers = [d for d in DECOMPILERS if d in fd.decompilers] + [
        d for d in fd.decompilers if d not in DECOMPILERS
    ]

    fd.to_json(root / "function_results.json")
    scoreboard.to_toml(root / "scoreboard.toml")
    print(
        f"[finalize] wrote {root}/function_results.json + scoreboard.toml "
        f"(decompilers: {fd.decompilers})",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
