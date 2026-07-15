"""Explain WHY each decompiler 'failed' a function, from an existing results tree.

`function_results.json` records only a boolean ``decompiled[dec]`` per function.
This tool reads that PLUS the run checkpoints (``checkpoints/<project>.pkl``, which
carry each decompiler's produced functions + addresses + ``failed_functions`` +
timeout metadata) and the on-disk decompiled ``.c`` files, and categorises every
failure into an actionable reason:

  timeout           the binary decompilation timed out / crashed (no per-func credit)
  duplicate_relabel SPURIOUS: the decompiler DID decompile this function, but under
                    a different address/name so it shows as a separate 'failed' row.
                    The dominant cause is the ARM Thumb T-bit (a function at low_pc
                    0xX0 reported by one tool as 0xX1) and the PE image-base offset,
                    which `_relabel_to_dwarf` does not normalise -> phantom rows.
  unparsable        the decompiler ENUMERATED the function but decompile() failed on
                    it (it is in ``failed_functions``)
  not_identified    the decompiler never produced a function at the address at all
                    (auto-analysis did not discover it; common for pointer-table
                    functions on stripped firmware)
  unknown           could not resolve the failure's address to categorise it

It also flags, among SUCCESSES, functions whose decompiled body is effectively
``empty`` (a quality signal, not a failure).

Usage:
  python scripts/analyze_failures.py results/full_run [--decompiler ida]
      [--json failure_reasons.json] [--examples N]
"""
from __future__ import annotations

import argparse
import json
import pickle
import re
from collections import defaultdict
from pathlib import Path

# Projects cross-compiled for ARM firmware / built as PE (the rest are x86 ELF).
_ARM = {
    "betaflight", "cleanflight", "crazyflie", "chibios", "freertos",
    "libopencm3", "nuttx", "riot-os", "u-boot",
}
_PE = {"mirai-win", "mydoom", "x0r-usb", "minipig", "dexter"}

_SUB = re.compile(r"(?:sub_|FUN_|fcn_|loc_|j_)([0-9a-fA-F]+)")
_HEXTAIL = re.compile(r"([0-9a-fA-F]{3,})$")
# A decompiled body with no real content: only braces/returns/comments/whitespace.
_TRIVIAL_LINE = re.compile(r"^\s*(\{|\}|return\s*;?|//.*|/\*.*|\*.*|;)?\s*$")


def arch_of(project: str) -> str:
    if project in _ARM:
        return "ARM"
    if project in _PE:
        return "PE"
    return "x86"


def _addr_from_name(name: str) -> int | None:
    m = _SUB.search(name) or _HEXTAIL.search(name)
    return int(m.group(1), 16) if m else None


def _is_empty_body(code: str) -> bool:
    body = code.split("{", 1)[1] if "{" in code else code
    meaningful = [ln for ln in body.splitlines() if not _TRIVIAL_LINE.match(ln)]
    return len(meaningful) == 0


def _iter_opt_bins(data: dict):
    for opt, bins in data.get("decompile", {}).items():
        optn = getattr(opt, "value", str(opt))
        for binn, decs in bins.items():
            yield optn, binn, decs


def analyze(root: Path, only_dec: str | None, n_examples: int) -> dict:
    with open(root / "function_results.json") as f:
        fd = json.load(f)
    decompilers = [d for d in fd["decompilers"] if (only_dec is None or d == only_dec)]

    # universe + per-decompiler decompiled flags, keyed (project,opt,binary)
    universe: dict[tuple, list[tuple[str, dict]]] = defaultdict(list)
    for g in fd["groups"]:
        key = (g["project"], g["opt_level"], g["binary"])
        for fn in g["functions"]:
            universe[key].append((fn["function"], fn.get("decompiled", {})))

    # tallies: dec -> arch -> category -> count
    tally: dict = {d: defaultdict(lambda: defaultdict(int)) for d in decompilers}
    examples: dict = {d: defaultdict(list) for d in decompilers}

    ckpt = root / "checkpoints"
    for pk in sorted(ckpt.glob("*.pkl")):
        project = pk.stem
        arch = arch_of(project)
        with open(pk, "rb") as fh:
            data = pickle.load(fh)
        for optn, binn, decs in _iter_opt_bins(data):
            key = (project, optn, binn)
            uni = universe.get(key)
            if not uni:
                continue
            # address for every universe function: from ANY decompiler's produced
            # functions (even-normalised), else parsed from a sub_/FUN_ name.
            addr_by_name: dict[str, int] = {}
            for dr in decs.values():
                for nm, fdc in getattr(dr, "functions", {}).items():
                    a = getattr(fdc, "address", None)
                    if a is not None:
                        addr_by_name.setdefault(nm, int(a) & ~1)
            for nm, _flags in uni:
                if nm not in addr_by_name:
                    a = _addr_from_name(nm)
                    if a is not None:
                        addr_by_name[nm] = a & ~1

            for dec in decompilers:
                dr = decs.get(dec)
                if dr is None:
                    continue
                meta = dr.decompiler
                extra = getattr(meta, "extra", {}) or {}
                ff = list(getattr(meta, "failed_functions", []) or [])
                bin_timeout = ff == ["all"] or bool(extra.get("timed_out")) or bool(
                    extra.get("recovered_partial")
                ) or len(getattr(dr, "functions", {})) == 0
                # this decompiler's produced + failed address sets (even-normalised)
                produced = {int(v.address) & ~1: k for k, v in dr.functions.items()}
                failed_a = set()
                for n in ff:
                    a = _addr_from_name(n)
                    if a is not None:
                        failed_a.add(a & ~1)

                for nm, flags in uni:
                    if flags.get(dec) is not False:  # ok / empty handled below
                        continue
                    addr = addr_by_name.get(nm)
                    if bin_timeout:
                        cat = "timeout"
                    elif addr is not None and addr in produced:
                        cat = "duplicate_relabel"
                    elif addr is not None and addr in failed_a:
                        cat = "unparsable"
                    elif addr is None:
                        cat = "unknown"
                    else:
                        cat = "not_identified"
                    tally[dec][arch][cat] += 1
                    if len(examples[dec][cat]) < n_examples:
                        examples[dec][cat].append(
                            {"project": project, "opt": optn, "binary": binn,
                             "function": nm, "addr": hex(addr) if addr else None}
                        )

                # empty-body quality flag among SUCCESSES (read the .c once)
                for nm, fdc in dr.functions.items():
                    code = getattr(fdc, "decompiled_code", "") or ""
                    if code and _is_empty_body(code):
                        tally[dec][arch]["empty(success)"] += 1
                        if len(examples[dec]["empty(success)"]) < n_examples:
                            examples[dec]["empty(success)"].append(
                                {"project": project, "opt": optn, "binary": binn, "function": nm}
                            )

    return {"decompilers": decompilers, "tally": tally, "examples": examples}


CATS = ["timeout", "duplicate_relabel", "unparsable", "not_identified", "unknown"]


def render(result: dict) -> None:
    tally = result["tally"]
    for dec in result["decompilers"]:
        per_arch = tally[dec]
        total_fail = sum(per_arch[a][c] for a in per_arch for c in CATS)
        empty = sum(per_arch[a].get("empty(success)", 0) for a in per_arch)
        print(f"\n### {dec}  —  {total_fail} failures  (+{empty} empty successful bodies)")
        header = f"  {'arch':5}" + "".join(f"{c[:16]:>17}" for c in CATS) + f"{'TOTAL':>8}"
        print(header)
        agg = defaultdict(int)
        for arch in ("x86", "ARM", "PE"):
            row = per_arch.get(arch)
            if not row:
                continue
            t = sum(row[c] for c in CATS)
            print(f"  {arch:5}" + "".join(f"{row.get(c,0):>17}" for c in CATS) + f"{t:>8}")
            for c in CATS:
                agg[c] += row.get(c, 0)
        gt = sum(agg[c] for c in CATS) or 1
        print(f"  {'ALL':5}" + "".join(f"{agg[c]:>17}" for c in CATS) + f"{gt:>8}")
        print("  " + " " * 5 + "".join(f"{100*agg[c]/gt:>16.0f}%" for c in CATS) + f"{'100%':>8}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results_root")
    ap.add_argument("--decompiler", default=None, help="analyze just this decompiler")
    ap.add_argument("--json", default=None, help="write full per-category detail here")
    ap.add_argument("--examples", type=int, default=5)
    args = ap.parse_args()

    result = analyze(Path(args.results_root), args.decompiler, args.examples)
    render(result)
    if args.json:
        out = {
            "decompilers": result["decompilers"],
            "tally": {d: {a: dict(cs) for a, cs in arches.items()}
                      for d, arches in result["tally"].items()},
            "examples": {d: {c: ex for c, ex in cs.items()}
                         for d, cs in result["examples"].items()},
        }
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
