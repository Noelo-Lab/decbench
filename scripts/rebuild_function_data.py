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
import re
import sys
from collections import Counter
from pathlib import Path

from decbench.models.function_data import FunctionData, HardestEntry, SampleEntry
from decbench.models.scoreboard import Scoreboard

# The overlay merges live in decbench.results_store now (slice-scoped clears; see
# its docstrings) — this script keeps its historical role of an overlay remerge
# over an existing function_results.json, without touching checkpoints.
from decbench.results_store import (
    load_sample_manifest,
    read_ged_overlay,
    update_byte_match,
    update_ged,
    update_type_match,
    write_function_data_guarded,
)
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
    # --allow-drops: let the coverage guard's regressions through (see
    # decbench.results_store.write_function_data_guarded).
    allow_drops = "--allow-drops" in sys.argv[2:]
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
        payload, covered = read_ged_overlay(root)
        if payload is None:
            raise SystemExit(f"error: no ged_new.json in {root}")
        n = update_ged(fd, payload, covered=covered)
        print(f"[rebuild] merged GED for {n} (function,decompiler) entries", flush=True)
    else:
        new = json.loads((root / "byte_match_new.json").read_text())
        tally = update_byte_match(fd, new, add_only=add_only)
        if not add_only:
            fd.compile_rates = {d: (t["comp"] / t["tot"]) for d, t in tally.items() if t["tot"]}
        rates_str = ", ".join(f"{d}={100*r:.1f}%" for d, r in (fd.compile_rates or {}).items())
        print(f"[rebuild] compile rates: {rates_str}", flush=True)

    # The frozen manifest (when the tree has one) is the single source of truth
    # for sample-set membership; the seeded draw only runs on manifest-less trees.
    assign_datasets(fd, sample_members=load_sample_manifest(root))
    fd.samples = build_samples(fd, reader)
    fd.hardest = build_hardest(fd, reader)
    src = sum(1 for s in fd.samples if s.source_code)
    print(
        f"[rebuild] {len(fd.samples)} samples ({src} with source), " f"{len(fd.hardest)} hardest",
        flush=True,
    )

    old_sb = Scoreboard.from_toml(root / "scoreboard.toml")
    sb = recompute_scoreboard(fd, old_sb)

    write_function_data_guarded(fd, root, allow_drops=allow_drops)
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
