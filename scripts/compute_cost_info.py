"""Compute the data page's cost FACTS and store them in function_results.json.

Mirrors scripts/compute_dataset_info.py: loads the tree's FunctionData, fills one
top-level blob (here ``FunctionData.cost_info``), and writes it back through the
guarded results-store path. The blob is FACTS ONLY — seconds and token counts —
gathered by decbench.scoring.cost:

- decompile_time: per-decompiler batch times from the decompiled/*.toml headers
  (binary wall time / function count — an amortized rate, basis "batch").
- llm: per-backend per-function times + token sums, from the structured
  FunctionDecompilation fields when present (new runs), else from the trace tree
  (<llm_traces>/<backend>/*.md + *.session.jsonl — the historical path).

Dollar amounts are NOT computed here: prices live in
decbench/rendering/content/pricing.toml and are applied at render time
(rendering/aggregate._cost_block), so a price fix needs only a re-render.

Usage:  python scripts/compute_cost_info.py results/full_run [llm_traces]
"""

from __future__ import annotations

import sys
from pathlib import Path

from decbench.models.function_data import FunctionData
from decbench.scoring.cost import build_cost_info


def _fmt_secs(value: object) -> str:
    return f"{value:8.2f}s" if isinstance(value, (int, float)) else "       -"


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/full_run")
    traces_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    fd = FunctionData.from_json(root / "function_results.json")
    opt_levels = sorted({g.opt_level for g in fd.groups})
    print(f"[cost] scanning {root} over opt levels {opt_levels}", flush=True)

    fd.cost_info = build_cost_info(root, traces_dir, opt_levels)

    batch = fd.cost_info["decompile_time"]
    llm = fd.cost_info["llm"]
    print(f"[cost] {'decompiler':<14} {'basis':<12} {'mean/fn':>9} {'median/fn':>9}  n_functions")
    for dec, entry in sorted(batch.items()):
        print(
            f"[cost] {dec:<14} {'batch':<12} {_fmt_secs(entry['per_fn_mean_s'])} "
            f"{_fmt_secs(entry['per_fn_median_s'])}  {entry['functions']}"
        )
    for dec, entry in sorted(llm.items()):
        elapsed = entry.get("elapsed") or {}
        tokens = entry.get("tokens")
        note = f"tokens x{tokens['sessions']}" if tokens else "no token data"
        print(
            f"[cost] {dec:<14} {'per-function':<12} {_fmt_secs(elapsed.get('mean_s'))} "
            f"{_fmt_secs(elapsed.get('median_s'))}  {entry['functions']} ({note})"
        )

    # Guarded write (decbench.results_store): this script only ADDS cost_info, so
    # any coverage regression the guard reports means the file changed under us.
    from decbench.results_store import write_function_data_guarded

    write_function_data_guarded(fd, root)
    print("[cost] wrote cost_info into function_results.json", flush=True)


if __name__ == "__main__":
    main()
