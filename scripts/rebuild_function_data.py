"""Rebuild function_results.json + scoreboard.toml from an existing results tree.

Used after :mod:`scripts.reeval_bytematch` recomputes byte_match: this merges the
fresh byte_match values into the per-function dataset, attaches the report's
code-carrying extras (side-by-side **samples** with original source, the
**hardest** functions, per-decompiler **compile rates**), and recomputes the
scoreboard aggregates — all WITHOUT re-decompiling.

byte_match policy: a function's byte_match is replaced with the freshly computed
value when its decompiled artifact still exists on disk; where the artifact is
gone (whole projects were pruned from the snapshot) byte_match is *dropped* for
that function so the column is uniformly the new metric (per-metric denominators
already differ, and such functions are simply excluded from Overall).

Usage:  python scripts/rebuild_function_data.py results/sailr_full
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

from decbench.models.function_data import FunctionData, HardestEntry, SampleEntry
from decbench.models.scoreboard import Scoreboard
from decbench.scoring.datasets import assign_datasets
from decbench.scoring.report_extras import (
    _log_exclusions,
    malware_projects,
    publish_malware_allowed,
)
from decbench.scoring.scoreboard import build_scoreboard_from_function_data
from decbench.scoring.view_samples import DIFFICULTY_TIERS, select_view_functions
from decbench.utils.results_tree import resolve_binary
from decbench.utils.source_extract import function_source, function_source_ex

MARKER = re.compile(r"^// Function: (\S+) @ (0x[0-9a-fA-F]+)\s*$", re.M)
PERFECT = {"ged": 0.0, "type_match": 1.0, "byte_match": 1.0}
PER_TIER = 100  # View-page samples per difficulty tier
HARDEST_PER = 12


def split_functions(c_path: Path) -> dict[str, str]:
    """name -> decompiled block for one decompiled .c (code only)."""
    text = c_path.read_text(errors="replace")
    out: dict[str, str] = {}
    ms = list(MARKER.finditer(text))
    for i, m in enumerate(ms):
        start = m.end()
        end = ms[i + 1].start() if i + 1 < len(ms) else len(text)
        out[m.group(1)] = text[start:end].strip()
    return out


class DiskReader:
    """Lazily reads decompiled blocks and resolves original binaries on disk."""

    def __init__(self, root: Path):
        self.root = root
        self._dec_cache: dict[tuple, dict[str, str]] = {}
        self._bin_cache: dict[tuple, Path | None] = {}

    def binary(self, opt: str, proj: str, stem: str) -> Path | None:
        key = (opt, proj, stem)
        if key in self._bin_cache:
            return self._bin_cache[key]
        found = resolve_binary(self.root / opt / proj / "compiled", stem)
        self._bin_cache[key] = found
        return found

    def decompiled(self, opt: str, proj: str, stem: str, dec: str) -> dict[str, str]:
        key = (opt, proj, stem, dec)
        if key not in self._dec_cache:
            cf = self.root / opt / proj / "decompiled" / f"{dec}_{stem}.c"
            self._dec_cache[key] = split_functions(cf) if cf.exists() else {}
        return self._dec_cache[key]


def update_byte_match(
    fd: FunctionData, new: dict[str, dict], add_only: bool = False
) -> dict[str, dict]:
    """Merge freshly recomputed byte_match into the dataset.

    For every (function, decompiler) that was decompiled (``values[dec]`` exists):
    SET byte_match to the new value when one exists. When ``add_only`` is False
    (default), also DROP any stale value with no fresh replacement so the column
    is uniformly the new metric. When ``add_only`` is True, keep existing values
    untouched and only ADD where ``new`` has a value — used to fold in a partial
    reeval (e.g. the Docker ARM/PE recompile) without dropping the host-computed
    x86 byte_match.
    Returns per-dec compile tallies (over the newly merged values).

    Like :func:`update_ged`, the stale-value drop is scoped to the decompilers
    the reeval covered: one added after the reeval (r2dec/dewolf) has no fresh
    entries at all, and an unscoped drop would wipe its whole healthy column.
    """
    covered = {key.split("::", 4)[3] for key in new}
    tally = {d: {"comp": 0, "tot": 0} for d in fd.decompilers}
    for g in fd.groups:
        for f in g.functions:
            for dec, mv in list(f.values.items()):
                key = f"{g.opt_level}::{g.project}::{g.binary}::{dec}::{f.function}"
                rec = new.get(key)
                if rec is None:
                    if not add_only and dec in covered:
                        # No fresh value (artifact gone / abstained): drop any
                        # stale value, distance, perfect and compile flag.
                        mv.pop("byte_match", None)
                        f.perfects.get(dec, {}).pop("byte_match", None)
                        f.distances.get(dec, {}).pop("byte_match", None)
                        f.compiles.pop(dec, None)
                    continue
                val = float(rec["value"])
                mv["byte_match"] = val
                f.perfects.setdefault(dec, {})["byte_match"] = val >= PERFECT["byte_match"]
                compilable = bool(rec.get("compilable"))
                f.compiles[dec] = compilable
                if rec.get("dist") is not None:
                    f.distances.setdefault(dec, {})["byte_match"] = float(rec["dist"])
                else:
                    # Non-compiling (or extract-failed): no fresh distance. Clear
                    # any stale one so the distance view + a compile proxy can't
                    # read a value left over from a prior computation.
                    f.distances.get(dec, {}).pop("byte_match", None)
                t = tally.setdefault(dec, {"comp": 0, "tot": 0})
                t["tot"] += 1
                if compilable:
                    t["comp"] += 1
    return tally


def build_samples(fd: FunctionData, reader: DiskReader) -> list[SampleEntry]:
    """Difficulty-tiered side-by-side samples for the View page.

    Selection (which functions, which tier) is shared with
    :func:`decbench.scoring.report_extras.build_samples` via
    :mod:`decbench.scoring.view_samples`; this script only differs in reading
    code from the on-disk ``decompiled/*.c`` artifacts. Malware projects never
    enter a tier pool — this script is the *other* writer of these payloads, so
    the filter has to hold here too or a rebuild would put the malware back.
    """
    out: list[SampleEntry] = []
    excluded = set() if publish_malware_allowed() else malware_projects(fd)
    tiers = select_view_functions(fd, per_tier=PER_TIER, excluded=excluded)
    for tier in DIFFICULTY_TIERS:
        built = 0
        for g, f in tiers.get(tier, []):
            if built >= PER_TIER:
                break
            binary = reader.binary(g.opt_level, g.project, g.binary)
            decompiled: dict[str, str] = {}
            for dec in fd.decompilers:
                code = reader.decompiled(g.opt_level, g.project, g.binary, dec).get(f.function)
                if code:
                    decompiled[dec] = code
            if not decompiled:
                continue  # nothing to compare
            source, source_status = function_source_ex(binary, f.function)
            out.append(
                SampleEntry(
                    project=g.project,
                    opt_level=g.opt_level,
                    binary=g.binary,
                    function=f.function,
                    size=f.size,
                    labels=f.labels,
                    difficulty=tier,
                    source_code=source,
                    source_status=source_status,
                    decompiled=decompiled,
                    values=f.values,
                    perfects=f.perfects,
                )
            )
            built += 1
    return out


def build_hardest(fd: FunctionData, reader: DiskReader) -> list[HardestEntry]:
    """Worst N per (metric, decompiler), with decompiled + source code.

    Malware groups are skipped *before* the worst-N cut, so the next-worst
    non-malware function takes the slot and the list keeps its length.
    """
    excluded = set() if publish_malware_allowed() else malware_projects(fd)
    dropped: Counter[str] = Counter()
    buckets: dict[tuple[str, str], list] = {}
    for g in fd.groups:
        if g.project in excluded:
            dropped[g.project] += len(g.functions)
            continue
        for f in g.functions:
            for dec, mv in f.values.items():
                for metric, val in mv.items():
                    perfect = PERFECT.get(metric, 0.0)
                    dist = abs(val - perfect)
                    if dist == 0.0:
                        continue
                    buckets.setdefault((metric, dec), []).append((dist, val, g, f))

    out: list[HardestEntry] = []
    for (metric, dec), cands in buckets.items():
        cands.sort(key=lambda c: (c[0], c[1]), reverse=True)
        kept = 0
        for _dist, val, g, f in cands:
            if kept >= HARDEST_PER:
                break
            code = reader.decompiled(g.opt_level, g.project, g.binary, dec).get(f.function)
            if not code:
                continue
            binary = reader.binary(g.opt_level, g.project, g.binary)
            out.append(
                HardestEntry(
                    metric=metric,
                    decompiler=dec,
                    project=g.project,
                    opt_level=g.opt_level,
                    binary=g.binary,
                    function=f.function,
                    value=val,
                    perfect_value=PERFECT.get(metric, 0.0),
                    size=f.size,
                    labels=f.labels,
                    decompiled_code=code,
                    source_code=function_source(binary, f.function) if binary else None,
                )
            )
            kept += 1
    _log_exclusions("hardest", dropped)
    return out


def recompute_scoreboard(fd: FunctionData, old: Scoreboard) -> Scoreboard:
    """Recompute per-metric + overall aggregates from the updated dataset.

    Delegates to the shared :func:`build_scoreboard_from_function_data` so the
    persisted ``scoreboard.toml`` uses the SAME shared per-metric universe
    denominators as the HTML report (identical across decompilers; a
    decompile/metric failure is a not-perfect miss, not an exclusion).
    """
    return build_scoreboard_from_function_data(
        fd,
        name=old.name or "DecBench Scoreboard",
        description=old.description,
        version=old.version,
    )


def update_ged(fd: FunctionData, new: dict[str, dict]) -> int:
    """Replace the GED column with the freshly recomputed values, per decompiler.

    The reeval (``scripts/reeval_ged.py``) DROPS unmeasurable functions
    (empty-prototype/degenerate source) and pairs each binary against its own
    translation unit, so its output is the authoritative, collision-free GED set
    for every decompiler it COVERS. Scoping matters: a decompiler evaluated
    *after* the reeval (r2dec/dewolf added by an additive resume) has healthy
    fresh values and NO ``ged_new.json`` entries — a blanket clear would wipe its
    whole column (and an un-overlaid finalize did the inverse: it reverted the
    covered six to the stale inline values; see the 2026-07-19 GED-collapse
    post-mortem). So: covered decompilers are cleared then rewritten; uncovered
    ones keep their values except non-finite entries, which are dropped for the
    same excluded-from-the-denominator policy the reeval applies. Returns the
    number of (function, decompiler) entries set.
    """
    covered = {key.split("::", 4)[3] for key in new}
    for g in fd.groups:
        for f in g.functions:
            for dec, mv in f.values.items():
                if dec in covered:
                    mv.pop("ged", None)
                elif not math.isfinite(mv.get("ged", 0.0)):
                    mv.pop("ged", None)
                    (f.perfects.get(dec) or {}).pop("ged", None)
                    (f.distances.get(dec) or {}).pop("ged", None)
            for dec in covered:
                (f.perfects.get(dec) or {}).pop("ged", None)
                (f.distances.get(dec) or {}).pop("ged", None)
    n = 0
    for g in fd.groups:
        for f in g.functions:
            for dec in fd.decompilers:
                key = f"{g.opt_level}::{g.project}::{g.binary}::{dec}::{f.function}"
                rec = new.get(key)
                if rec is None:
                    continue
                val = float(rec["value"])
                f.values.setdefault(dec, {})["ged"] = val
                f.perfects.setdefault(dec, {})["ged"] = bool(rec.get("perfect", val == 0.0))
                # GED distance IS the graph edit distance (the value itself).
                f.distances.setdefault(dec, {})["ged"] = val
                n += 1
    return n


def update_type_match(fd: FunctionData, new: dict[str, dict[str, float]]) -> int:
    """Merge freshly recomputed type_match (from run checkpoints) in.

    ``new`` is ``{decompiler: {"proj::opt::bin::fn": value}}`` (the shape emitted
    by ``scripts/reeval_typematch.py``). For every covered (function, decompiler)
    SET type_match + its perfect flag; entries with no fresh value are kept (the
    reeval covers every checkpoint, so this is rare). Returns the number of
    (function, decompiler) entries set. ged / byte_match / compile_rates are left
    untouched.
    """
    n = 0
    for g in fd.groups:
        for f in g.functions:
            for dec in fd.decompilers:
                per = new.get(dec)
                if not per:
                    continue
                rec = per.get(f"{g.project}::{g.opt_level}::{g.binary}::{f.function}")
                if rec is None:
                    continue
                # Back-compat: older type_match_new.json stored a bare float; the
                # new form is {"value": accuracy, "dist": type-flips (fp+fn)}.
                if isinstance(rec, dict):
                    val = float(rec["value"])
                    dist = rec.get("dist")
                else:
                    val = float(rec)
                    dist = None
                f.values.setdefault(dec, {})["type_match"] = val
                f.perfects.setdefault(dec, {})["type_match"] = val >= PERFECT["type_match"]
                if dist is not None:
                    f.distances.setdefault(dec, {})["type_match"] = float(dist)
                n += 1
    return n


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "results/sailr_full")
    # --add-only: fold a PARTIAL byte_match_new (e.g. the Docker ARM/PE recompile)
    # into an already-complete dataset without dropping existing (x86) values, and
    # keep the existing compile_rates.
    add_only = "--add-only" in sys.argv[2:]
    # --ged: merge ged_new.json (header-stripped source CFGs) instead of byte_match;
    # keeps byte_match + compile_rates untouched.
    ged_mode = "--ged" in sys.argv[2:]
    # --type-match: merge type_match_new.json (recomputed from checkpoints after a
    # calibration fix) instead of byte_match; keeps byte_match/ged/compile_rates.
    tm_mode = "--type-match" in sys.argv[2:]
    fd = FunctionData.from_json(root / "function_results.json")
    reader = DiskReader(root)

    print(
        f"[rebuild] {sum(len(g.functions) for g in fd.groups)} functions, "
        f"{len(fd.groups)} binaries, decompilers={fd.decompilers}, "
        f"add_only={add_only}, ged={ged_mode}, type_match={tm_mode}",
        flush=True,
    )

    if tm_mode:
        new = json.loads((root / "type_match_new.json").read_text())
        n = update_type_match(fd, new)
        print(f"[rebuild] merged type_match for {n} (function,decompiler) entries", flush=True)
    elif ged_mode:
        new = json.loads((root / "ged_new.json").read_text())
        n = update_ged(fd, new)
        print(f"[rebuild] merged GED for {n} (function,decompiler) entries", flush=True)
    else:
        new = json.loads((root / "byte_match_new.json").read_text())
        tally = update_byte_match(fd, new, add_only=add_only)
        if not add_only:
            fd.compile_rates = {d: (t["comp"] / t["tot"]) for d, t in tally.items() if t["tot"]}
        rates_str = ", ".join(f"{d}={100*r:.1f}%" for d, r in (fd.compile_rates or {}).items())
        print(f"[rebuild] compile rates: {rates_str}", flush=True)

    assign_datasets(fd)
    fd.samples = build_samples(fd, reader)
    fd.hardest = build_hardest(fd, reader)
    src = sum(1 for s in fd.samples if s.source_code)
    print(
        f"[rebuild] {len(fd.samples)} samples ({src} with source), " f"{len(fd.hardest)} hardest",
        flush=True,
    )

    old_sb = Scoreboard.from_toml(root / "scoreboard.toml")
    sb = recompute_scoreboard(fd, old_sb)

    fd.to_json(root / "function_results.json")
    sb.to_toml(root / "scoreboard.toml")
    print("[rebuild] wrote function_results.json + scoreboard.toml", flush=True)
    for d in sb.decompilers:
        ds = sb.decompiler_scores[d]
        bm = ds.metric_scores.get("byte_match")
        if bm:
            print(
                f"  {d} byte_match: {bm.perfect_percentage:.2f}% perfect, "
                f"mean {bm.mean:.3f} over {bm.total_count}",
                flush=True,
            )


if __name__ == "__main__":
    main()
