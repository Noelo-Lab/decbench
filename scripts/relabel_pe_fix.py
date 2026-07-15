"""Repair PE + ARM/Thumb function naming for ALL decompilers in a results tree.

Generalises ``relabel_thumb_fix.py`` (which only re-relabeled angr/phoenix for the
ARM Thumb T-bit) to also fix the PE ImageBase mismatch, for every decompiler:

  - PE: decompiles produced before the ``elf_min_vaddr`` PE fix stored function
    addresses as bare RVAs (0x1110) because ``elf_min_vaddr`` returned 0 for PE;
    DWARF ``low_pc`` is the linked VA (ImageBase + RVA = 0x401110). So the run's
    ``_relabel_to_dwarf`` never matched and the function kept its ``sub_401110``
    name, becoming a phantom universe row every other decompiler "failed" on.
  - ARM/Thumb: angr/phoenix report a Thumb entry at an odd address; DWARF is even.

This re-applies relabeling to the ALREADY-DECOMPILED results (no re-decompile):
for every function it retries the DWARF lookup with the Thumb LSB cleared AND the
ImageBase added, renames it in the decompiled code + function key, rewrites the
``decompiled/{dec}_{stem}.c`` artifact, and updates the per-project checkpoint.
Idempotent (already-correct names are a no-op) and a no-op on x86 (base 0, names
already resolved).

Usage:  python scripts/relabel_pe_fix.py results/full_run [proj1 proj2 ...]
Run the GED/type/byte reeval + rebuild_function_data afterwards so the recovered
names fold into the scoreboard, and run rebuild with the universe phantom-row
guard (function_data_builder) so the now-orphaned sub_* rows drop out.
"""

from __future__ import annotations

import pickle
import re
import sys
from pathlib import Path

import decbench.decompilers  # noqa: F401  (register backends so checkpoints unpickle)
from decbench.decompilers.raw import common
from decbench.utils.results_tree import resolve_binary
from scripts.run_benchmark import project_source_functions


def relabel_result(result, addr2name: dict[int, str], base: int) -> int:
    """Retry DWARF naming with Thumb-LSB + ImageBase candidates; returns # renamed."""
    renamed = 0
    new_funcs: dict[str, object] = {}
    for fd in list(result.functions.values()):
        addr = int(fd.address)
        dn = (
            addr2name.get(addr)
            or addr2name.get(addr & ~1)
            or addr2name.get(addr + base)
            or addr2name.get((addr + base) & ~1)
        )
        if dn and dn != fd.name:
            fd.decompiled_code = re.sub(
                r"\b" + re.escape(fd.name) + r"\b", dn, fd.decompiled_code
            )
            fd.name = dn
            renamed += 1
        prev = new_funcs.get(fd.name)
        if prev is None or len(fd.decompiled_code or "") >= len(
            getattr(prev, "decompiled_code", "") or ""
        ):
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
                binary = resolve_binary(comp, stem)
                if binary is None:
                    continue
                addr2name = project_source_functions(binary, src_stems)
                if not addr2name:
                    continue
                base = common.elf_min_vaddr(binary)
                for dec, res in decs.items():
                    if res is None or not getattr(res, "functions", None):
                        continue
                    n = relabel_result(res, addr2name, base)
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
