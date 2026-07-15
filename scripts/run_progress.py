#!/usr/bin/env python
"""Show progress of a decompiler re-run driven by ``rerun_angr_binja.py``.

The re-run has several stages (snapshot -> decompile -> restore -> reeval GED ->
reeval type_match -> reeval byte_match -> rebuild -> render). The orchestrator
writes a small status file (``<root>/rerun_ab_status.json``) recording the stage
timeline; this viewer combines it with on-disk artifact counts to render a live
picture of how far along the (multi-hour) run is:

* Decompile stage: per-decompiler ``decompiled/{dec}_*.c`` files freshly
  rewritten this run (mtime >= the stage start) vs the total that exist, plus a
  projects-checkpointed count (out of all gathered projects) and an ETA from the
  observed rate.
* Each reeval stage: the per-``(binary,dec)`` checkpoint JSONs recomputed for the
  refreshed decompilers vs the number of decompiled ``.c`` for those decompilers.
* rebuild / render: taken straight from the stage timeline.

Usage:
    python scripts/run_progress.py [results_dir] [--watch [secs]]

With no results_dir it defaults to ``results/full_run``. ``--watch`` refreshes
every N seconds (default 15) until the run reports ``done``.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

OPT_LEVELS = ("O0", "O2", "O2-noinline")
STATUS_NAME = "rerun_ab_status.json"
STAGE_ORDER = [
    "snapshot",
    "decompile",
    "restore",
    "reeval_ged",
    "reeval_typematch",
    "reeval_bytematch",
    "rebuild",
    "render",
    "done",
]


def _fmt_dur(secs: float) -> str:
    secs = int(max(0, secs))
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def _bar(done: int, total: int, width: int = 32) -> str:
    total = max(total, 0)
    frac = (done / total) if total else 0.0
    frac = min(max(frac, 0.0), 1.0)
    filled = int(round(frac * width))
    return "[" + "#" * filled + "-" * (width - filled) + f"] {100*frac:5.1f}%"


def _count_c(root: Path, dec: str, since: float | None) -> tuple[int, int]:
    """(fresh, total) count of ``decompiled/{dec}_*.c`` across all opt levels.

    ``fresh`` = files whose mtime is >= ``since`` (i.e. rewritten this run).
    """
    total = 0
    fresh = 0
    for opt in OPT_LEVELS:
        odir = root / opt
        if not odir.is_dir():
            continue
        for cf in odir.glob(f"*/decompiled/{dec}_*.c"):
            total += 1
            if since is not None and cf.stat().st_mtime >= since:
                fresh += 1
    return fresh, total


def _count_ckpt(dirpath: Path, dec: str) -> int:
    """Number of reeval checkpoint JSONs for one decompiler (keys end __<dec>)."""
    if not dirpath.is_dir():
        return 0
    return sum(1 for _ in dirpath.glob(f"*__{dec}.json"))


def _projects_done(root: Path, since: float | None) -> tuple[int, int]:
    ck = root / "checkpoints"
    if not ck.is_dir():
        return 0, 0
    pkls = list(ck.glob("*.pkl"))
    if since is None:
        return 0, len(pkls)
    done = sum(1 for p in pkls if p.stat().st_mtime >= since)
    return done, len(pkls)


def _stage_bounds(status: dict, name: str) -> tuple[float | None, float | None]:
    st = (status.get("stages") or {}).get(name) or {}
    return st.get("start"), st.get("end")


def render(root: Path) -> bool:
    """Print one progress snapshot. Returns True if the run is done."""
    status_path = root / STATUS_NAME
    now = time.time()
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append(f"  DecBench re-run progress   {root}")
    lines.append("=" * 70)

    if not status_path.exists():
        lines.append("  (no status file yet — orchestrator has not started)")
        print("\n".join(lines), flush=True)
        return False

    status = json.loads(status_path.read_text())
    decs = status.get("decompilers", ["angr", "binja"])
    current = status.get("current", "?")
    run_start = status.get("run_start")
    elapsed = now - run_start if run_start else 0
    lines.append(
        f"  decompilers: {', '.join(decs)}    current stage: {current.upper()}"
        f"    elapsed: {_fmt_dur(elapsed)}"
    )
    lines.append("-" * 70)

    # Per-stage one-liners with timing.
    stages = status.get("stages") or {}
    for name in STAGE_ORDER:
        st = stages.get(name)
        if not st:
            mark = "·"
            when = "pending"
        elif st.get("end"):
            mark = "✓"
            when = f"done in {_fmt_dur(st['end'] - st['start'])}"
        else:
            mark = "»"
            when = f"running {_fmt_dur(now - st['start'])}"
        lines.append(f"   {mark} {name:18} {when}")
    lines.append("-" * 70)

    # Decompile detail (the long stage).
    dstart, dend = _stage_bounds(status, "decompile")
    if dstart is not None:
        pd, pt = _projects_done(root, dstart)
        lines.append(f"  DECOMPILE   projects checkpointed: {pd}/{pt}")
        for dec in decs:
            fresh, total = _count_c(root, dec, dstart)
            rate = fresh / (dend - dstart) if dend else (fresh / max(1e-9, now - dstart))
            remain = total - fresh
            eta = remain / rate if rate > 0 and not dend else 0
            eta_s = "" if dend else (f"  eta {_fmt_dur(eta)}" if rate > 0 else "")
            lines.append(f"    {dec:7} {_bar(fresh, total)}  {fresh}/{total} .c{eta_s}")

    # Reeval details (per refreshed decompiler; total target = that dec's .c count).
    for stage, sub in (
        ("reeval_ged", "reeval_ged"),
        ("reeval_bytematch", "reeval_bm"),
    ):
        sstart, _ = _stage_bounds(status, stage)
        if sstart is None:
            continue
        lines.append(f"  {stage.upper()}")
        for dec in decs:
            _, total = _count_c(root, dec, None)
            done = _count_ckpt(root / sub, dec)
            lines.append(f"    {dec:7} {_bar(done, total)}  {done}/{total} rescored")

    # type_match reeval is a single monolithic pass (no per-task checkpoints).
    tstart, tend = _stage_bounds(status, "reeval_typematch")
    if tstart is not None and tend is None:
        lines.append("  REEVAL_TYPEMATCH  (single pass over checkpoints — no per-task counter)")

    if status.get("log"):
        lines.append("-" * 70)
        lines.append(f"  log: {status['log']}")
    lines.append("=" * 70)
    print("\n".join(lines), flush=True)
    return current == "done"


def main() -> int:
    args = [a for a in sys.argv[1:]]
    watch = False
    interval = 15
    positional: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--watch":
            watch = True
            if i + 1 < len(args) and args[i + 1].isdigit():
                interval = int(args[i + 1])
                i += 1
        else:
            positional.append(a)
        i += 1
    root = Path(positional[0]) if positional else Path("results/full_run")

    if not watch:
        render(root)
        return 0
    try:
        while True:
            print("\033[2J\033[H", end="")  # clear screen
            done = render(root)
            if done:
                return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
