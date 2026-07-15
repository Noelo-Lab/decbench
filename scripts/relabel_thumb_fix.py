"""Repair ARM/Thumb function naming for angr + phoenix in an existing results tree.

angr (and the angr-based phoenix) report a Thumb function's entry with the Thumb
bit set (odd address, e.g. 0x8008001); DWARF low_pc is the even address. The run's
``_relabel_to_dwarf`` looked the name up by the exact (odd) address, missed, and
left the function named ``sub_...`` — so it never matched a source function and was
dropped from GED / type_match. Ghidra/IDA report even addresses and were fine.

This re-applies relabeling to the ALREADY-DECOMPILED angr/phoenix results (no
re-decompile): for every function it retries the DWARF lookup with the Thumb LSB
cleared, renames it in the decompiled code + function key, rewrites the
``decompiled/{dec}_{stem}.c`` artifact, and updates the per-project checkpoint.
Auto-detects affected binaries (only functions whose masked address hits the DWARF
map get renamed), so it is a no-op on x86 where names already resolved.

Usage:  python scripts/relabel_thumb_fix.py results/full_run [proj1 proj2 ...]
Prints the projects/binaries changed; run the scoped GED/type/byte reeval + rebuild
afterwards to fold the recovered functions into the scoreboard.
"""

from __future__ import annotations

import pickle
import re
import sys
from pathlib import Path

import decbench.decompilers  # noqa: F401  (register backends so checkpoints unpickle)
from decbench.utils.results_tree import resolve_binary
from scripts.run_benchmark import project_source_functions

DECS = ("angr", "phoenix")


def relabel_result(result, addr2name: dict[int, str]) -> int:
    """Retry DWARF naming with the Thumb LSB cleared; returns # functions renamed."""
    renamed = 0
    new_funcs: dict[str, object] = {}
    for fd in list(result.functions.values()):
        addr = int(fd.address)
        dn = addr2name.get(addr) or addr2name.get(addr & ~1)
        if dn and dn != fd.name:
            fd.decompiled_code = re.sub(
                r"\b" + re.escape(fd.name) + r"\b", dn, fd.decompiled_code
            )
            fd.name = dn
            renamed += 1
        new_funcs[fd.name] = fd
    result.functions = new_funcs
    return renamed


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/full_run")
    only = set(sys.argv[2:]) or None
    ck_dir = root / "checkpoints"

    total_renamed = 0
    changed_projects: list[str] = []
    for pk in sorted(ck_dir.glob("*.pkl")):
        proj = pk.stem
        if only and proj not in only:
            continue
        data = pickle.loads(pk.read_bytes())
        dec_tree = data.get("decompile", {})
        proj_renamed = 0
        for opt, bins in dec_tree.items():
            optn = getattr(opt, "value", str(opt))
            comp = root / optn / proj / "compiled"
            src_stems = {i.stem for i in comp.glob("*.i")} if comp.is_dir() else set()
            if not src_stems:
                continue
            for stem, decs in bins.items():
                if not any(d in decs for d in DECS):
                    continue
                binary = resolve_binary(comp, stem)
                if binary is None:
                    continue
                addr2name = project_source_functions(binary, src_stems)
                if not addr2name:
                    continue
                for dec in DECS:
                    res = decs.get(dec)
                    if res is None or not res.functions:
                        continue
                    n = relabel_result(res, addr2name)
                    if n:
                        proj_renamed += n
                        cf = root / optn / proj / "decompiled" / f"{dec}_{stem}.c"
                        try:
                            res.to_c_file(cf)
                        except Exception as e:  # noqa: BLE001
                            print(f"  ! {optn}/{proj}/{stem}/{dec}: to_c_file {e}")
                        print(f"  {optn}/{proj}/{stem}/{dec}: renamed {n} functions")
        if proj_renamed:
            pk.write_bytes(pickle.dumps(data))
            changed_projects.append(proj)
            total_renamed += proj_renamed
    print(f"\nTotal renamed: {total_renamed} functions across projects: {changed_projects}")
    print("PROJECTS_CHANGED=" + ",".join(changed_projects))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
