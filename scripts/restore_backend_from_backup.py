"""Restore specific decompilers' results in a results tree from a checkpoint backup.

Used to revert ONE decompiler's re-decompile (e.g. an experimental force-decompile
pass) while preserving every OTHER decompiler's current data. For each project it
replaces the named decompilers' entries in BOTH the ``decompile`` and ``evaluate``
sections of the live checkpoint with the backup's, and regenerates their
``decompiled/{dec}_{stem}.c`` artifacts from the restored results, so a subsequent
reeval + rebuild reflects the restored (backup) decompilation.

Usage:
  python scripts/restore_backend_from_backup.py <results_root> <backup_ckpt_dir> \
      <dec1,dec2> [project ...]

If no projects are given, every project present in the backup is restored.
Prints which (project, opt, binary, dec) were restored.
"""

from __future__ import annotations

import pickle
import sys
from pathlib import Path

import decbench.decompilers  # noqa: F401  (register backends so checkpoints unpickle)


def main() -> int:
    root = Path(sys.argv[1])
    backup = Path(sys.argv[2])
    decs = [d for d in sys.argv[3].split(",") if d]
    only = set(sys.argv[4:]) or None
    ck_dir = root / "checkpoints"

    restored = 0
    changed_projects: list[str] = []
    for bpk in sorted(backup.glob("*.pkl")):
        proj = bpk.stem
        if only and proj not in only:
            continue
        live_pk = ck_dir / f"{proj}.pkl"
        if not live_pk.exists():
            print(f"  ! {proj}: no live checkpoint, skipping")
            continue
        bdata = pickle.loads(bpk.read_bytes())
        ldata = pickle.loads(live_pk.read_bytes())
        bdec = bdata.get("decompile", {})
        bev = bdata.get("evaluate", {})
        ldec = ldata.setdefault("decompile", {})
        lev = ldata.setdefault("evaluate", {})
        proj_restored = 0
        for opt, bins in bdec.items():
            for stem, bdecs in bins.items():
                ldecs = ldec.setdefault(opt, {}).setdefault(stem, {})
                for dec in decs:
                    if dec in bdecs:
                        res = bdecs[dec]
                        ldecs[dec] = res
                        proj_restored += 1
                        restored += 1
                        # regenerate the .c artifact from the restored result
                        cf = root / getattr(opt, "value", str(opt)) / proj / "decompiled" / f"{dec}_{stem}.c"
                        try:
                            if res is not None and getattr(res, "functions", None):
                                res.to_c_file(cf)
                        except Exception as e:  # noqa: BLE001
                            print(f"  ! {proj}/{stem}/{dec}: to_c_file {e}")
                # restore evaluate section for the decs too
                bev_bin = bev.get(opt, {}).get(stem, {})
                lev_bin = lev.setdefault(opt, {}).setdefault(stem, {})
                for dec in decs:
                    if dec in bev_bin:
                        lev_bin[dec] = bev_bin[dec]
        if proj_restored:
            live_pk.write_bytes(pickle.dumps(ldata))
            changed_projects.append(proj)
            print(f"  {proj}: restored {proj_restored} (opt,bin,dec) for {decs}")
    print(f"\nRestored {restored} entries across: {changed_projects}")
    print("PROJECTS_CHANGED=" + ",".join(changed_projects))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
