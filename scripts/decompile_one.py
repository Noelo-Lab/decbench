#!/usr/bin/env python
"""Decompile ONE binary with ONE decompiler, pickling the result.

Run as a short-lived subprocess so the orchestrator can impose a hard wall-clock
timeout and SIGKILL it (angr's decompiler runs native at 100% CPU and ignores
in-process signals, so an external kill is the only reliable bound). Process
isolation also sidesteps the fork-after-threads deadlock and any JVM/angr state
leakage.

Usage: decompile_one.py <binary> <decompiler> <out_dir> <pickle_out> [names_json]

names_json (optional): path to a JSON list of source function names. When given
and non-empty, decompilation is restricted to those functions (skips bundled
gnulib/static filler), a large speedup for slow decompilers.
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

import decbench.decompilers  # noqa: F401  (registers raw + declib + dockerized backends)
from decbench.pipeline.decompile import decompile_binary


def main() -> int:
    binary, dec_name, out_dir, pkl_out = sys.argv[1:5]
    # The binary handed to us is a STRIPPED copy (no symbols), so the filter is a
    # JSON list of target ADDRESSES (DWARF low_pc), not names.
    target_addrs: set[int] | None = None
    if len(sys.argv) > 5 and sys.argv[5] not in ("", "NONE"):
        try:
            loaded = json.loads(Path(sys.argv[5]).read_text())
            target_addrs = {int(a) for a in loaded} or None
        except Exception:
            target_addrs = None
    # Write partial progress straight to the output pickle, so if the
    # orchestrator kills this process on timeout, the functions completed so far
    # are still recoverable. The final write below replaces it atomically.
    result = decompile_binary(
        Path(binary),
        dec_name,
        Path(out_dir),
        function_names=target_addrs,
        progress_path=Path(pkl_out),
    )
    Path(pkl_out).write_bytes(pickle.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
