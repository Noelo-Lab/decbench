"""Canonical derivation of ``function_results.json`` from a results tree's fragments.

A published results tree is layered:

* **Raw inputs** — ``checkpoints/<project>.pkl`` (one pickle per project holding the
  decompile + inline-evaluate results) and the on-disk ``<opt>/<proj>/{compiled,
  decompiled}`` artifacts.
* **Corrected metric overlays** — ``ged_new.json`` / ``type_match_new.json`` /
  ``byte_match_new.json`` written by the ``scripts/reeval_*.py`` passes; these carry the
  published metric values. ``ged_new.slices.json`` is a sidecar listing every
  ``(opt, project, binary, decompiler)`` slice the GED reeval actually evaluated
  (including empty ones), so the merge can tell "evaluated, found nothing" from
  "never evaluated".
* **Frozen sample membership** — ``sample_set_manifest.json`` (the LLM cost gate).
* **Derived** — ``function_results.json`` (+ one rotating ``function_results.prev.json``
  backup) and ``scoreboard.toml``. Derived files are pure projections of the layers
  above and are only ever produced by :func:`finalize_tree` / the guarded writer here.

Why this module exists: the derived file used to have four independent writers and the
overlay merges cleared whole decompiler columns before rewriting them, so a reeval that
covered only part of a decompiler's slices silently erased the rest (the 2026-07-22
kuna@betaflight O2-noinline wipe: 1716 published perfects vanished with no error, and
before that the 2026-07-19 GED collapse). :func:`finalize_tree` always rebuilds from
EVERY checkpoint in the tree, the ``update_*`` merges are scoped to the exact slices an
overlay covers, and :func:`write_function_data_guarded` refuses to shrink published
coverage unless explicitly allowed.
"""

from __future__ import annotations

import json
import math
import os
import pickle
import shutil
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from decbench.models.function_data import FunctionData, HistoryPoint
from decbench.models.scoreboard import Scoreboard

#: (opt_level, project, binary_stem, decompiler) — the granularity every overlay merge,
#: guard counter and audit row works at.
Slice = tuple[str, str, str, str]
#: (project, opt_level, binary_stem, function) — a single function's identity, the shape
#: used by ``sample_set_manifest.json``.
FnKey = tuple[str, str, str, str]
Log = Callable[[str], None]

PERFECT = {"ged": 0.0, "type_match": 1.0, "byte_match": 1.0}

# All benchmark project dirs (top-level *.toml only; cps/disabled/ excluded).
# sailr = x86, cps = ARM firmware, malware = ARM/PE. Anchored to the repo root
# (this file is <repo>/decbench/results_store.py) rather than the cwd: a finalize
# run from the wrong directory must NOT silently find zero projects — that would
# drop every project label (malware/cps/arch), and losing the `malware` label
# would let the code-carrying report extras embed real malware source (the leak
# `decbench-malware-publishing-guard` closed). finalize_tree hard-fails on empty.
_REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_DIRS = [
    _REPO_ROOT / "projects/sailr",
    _REPO_ROOT / "projects/cps",
    _REPO_ROOT / "projects/malware",
]

GUARD_PRINT_CAP = 100  # max aggregated regression lines printed before "... and N more"


class CoverageRegressionError(RuntimeError):
    """Raised when a guarded write would shrink published coverage."""


def gather_project_tomls() -> list[Path]:
    """Every benchmark project TOML, sorted by stem (the project name)."""
    out: list[Path] = []
    for d in PROJECT_DIRS:
        out.extend(sorted(d.glob("*.toml")))
    return sorted(out, key=lambda p: p.stem)


# --------------------------------------------------------------------------- #
# Raw layer: checkpoints.
# --------------------------------------------------------------------------- #
def load_checkpoints(
    root: Path, exclude_projects: Collection[str] = (), log: Log = print
) -> tuple[dict[str, dict], dict[str, dict]]:
    """Load EVERY ``checkpoints/*.pkl`` in the tree — never a scoped subset.

    Returns ``(all_decompile, all_evaluate)`` keyed by project name, the accumulator
    shape ``build_function_data`` consumes. A corrupt/empty checkpoint is reported and
    skipped (its project then legitimately drops, which the guard will surface unless
    it is in ``exclude_projects``).
    """
    # Register model/metric modules so the pickles resolve their classes.
    import decbench.decompilers  # noqa: F401
    import decbench.metrics  # noqa: F401

    all_decompile: dict[str, dict] = {}
    all_evaluate: dict[str, dict] = {}
    excluded = set(exclude_projects)
    for ckpt in sorted((root / "checkpoints").glob("*.pkl")):
        name = ckpt.stem
        if name in excluded:
            log(f"[store] excluding project {name} (checkpoint present, skipped)")
            continue
        try:
            data = pickle.loads(ckpt.read_bytes())
        except Exception as e:  # noqa: BLE001
            log(f"[store] WARNING: unreadable checkpoint {ckpt.name}: {e} — skipped")
            continue
        all_decompile[name] = data.get("decompile", {}) or {}
        all_evaluate[name] = data.get("evaluate", {}) or {}
    return all_decompile, all_evaluate


# --------------------------------------------------------------------------- #
# Overlay merges (moved from scripts/rebuild_function_data.py, with the clears
# scoped to SLICES instead of whole decompiler columns).
# --------------------------------------------------------------------------- #
def slices_from_overlay_keys(new: dict[str, Any]) -> set[Slice]:
    """The ``(opt, project, binary, dec)`` slices an overlay's entry keys cover."""
    covered: set[Slice] = set()
    for key in new:
        opt, proj, stem, dec, _fn = key.split("::", 4)
        covered.add((opt, proj, stem, dec))
    return covered


def read_ged_overlay(root: Path) -> tuple[dict[str, dict] | None, set[Slice] | None]:
    """Load ``ged_new.json`` plus the set of slices the GED reeval EVALUATED.

    Returns ``(payload, covered)``; ``payload`` is None when there is no overlay.
    ``covered`` is the union of three sources so an evaluated-but-empty slice
    still clears its stale inline values (the exact class that silently
    re-inflated 219 slices before this was hardened):

    * ``ged_new.slices.json`` — the authoritative list the new ``reeval_ged.py``
      writes (every evaluated slice, empty ones included);
    * every per-slice checkpoint filename under ``reeval_ged/`` — the reeval
      cache IS the evaluated-slice record, present even on trees whose overlay
      predates the sidecar (the same ``__``↔``::`` stem convention the reeval
      uses to build the sidecar);
    * the payload's own entry keys — a slice with entries is always covered.

    Only when NONE of these exist (a bare ``ged_new.json`` with no reeval cache)
    does coverage reduce to the entry keys — conservative: an unlisted empty
    slice then keeps its inline value.
    """
    path = root / "ged_new.json"
    if not path.exists():
        return None, None
    payload = json.loads(path.read_text())
    covered: set[Slice] = slices_from_overlay_keys(payload)
    sidecar = root / "ged_new.slices.json"
    if sidecar.exists():
        covered |= {tuple(k.split("::", 3)) for k in json.loads(sidecar.read_text())}  # type: ignore[misc]
    reeval_dir = root / "reeval_ged"
    if reeval_dir.is_dir():
        covered |= {
            tuple(cp.stem.replace("__", "::").split("::", 3)) for cp in reeval_dir.glob("*.json")
        }  # type: ignore[misc]
    return payload, covered


def update_ged(fd: FunctionData, new: dict[str, dict], covered: set[Slice] | None = None) -> int:
    """Replace the GED column with the freshly recomputed values, per SLICE.

    The reeval (``scripts/reeval_ged.py``) DROPS unmeasurable functions and pairs each
    binary against its own translation unit, so its output is authoritative for every
    ``(opt, project, binary, decompiler)`` slice it COVERS: covered slices are cleared
    then rewritten; uncovered slices keep their inline values (minus non-finite
    entries, which are dropped for the same excluded-from-the-denominator policy the
    reeval applies). This is the per-slice refinement of the old per-decompiler
    scoping, which wiped every slice of a covered decompiler even where the overlay
    had nothing to put back (the kuna@betaflight O2-noinline incident — see the module
    docstring). ``covered`` defaults to the slices inferred from ``new``'s keys; pass
    the sidecar set (:func:`read_ged_overlay`) so evaluated-but-empty slices clear
    their stale values too. Returns the number of (function, decompiler) entries set.
    """
    if covered is None:
        covered = slices_from_overlay_keys(new)
    for g in fd.groups:
        for f in g.functions:
            for dec in set(f.values) | set(f.perfects) | set(f.distances):
                mv = f.values.get(dec)
                if (g.opt_level, g.project, g.binary, dec) in covered:
                    if mv is not None:
                        mv.pop("ged", None)
                    (f.perfects.get(dec) or {}).pop("ged", None)
                    (f.distances.get(dec) or {}).pop("ged", None)
                elif mv is not None and not math.isfinite(mv.get("ged", 0.0)):
                    mv.pop("ged", None)
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


def update_byte_match(
    fd: FunctionData, new: dict[str, dict], add_only: bool = False
) -> dict[str, dict]:
    """Merge freshly recomputed byte_match into the dataset, scoped per SLICE.

    For every (function, decompiler) that was decompiled: SET byte_match to the new
    value when one exists. When ``add_only`` is False (default), also DROP any stale
    value with no fresh replacement — but only within the ``(opt, project, binary,
    decompiler)`` slices the reeval actually covered, so a slice it never touched
    (added later, or legitimately abstained-and-omitted ARM/PE) keeps its values.
    There is deliberately NO sidecar for byte_match: the host reeval omits ARM/PE
    slices it abstains on, so "no entries for a slice" does NOT mean "no data" and an
    evaluated-slices list would clear Docker-computed ARM values. Returns per-dec
    compile tallies (over the newly merged values).
    """
    covered = slices_from_overlay_keys(new)
    tally = {d: {"comp": 0, "tot": 0} for d in fd.decompilers}
    for g in fd.groups:
        for f in g.functions:
            for dec, mv in list(f.values.items()):
                key = f"{g.opt_level}::{g.project}::{g.binary}::{dec}::{f.function}"
                rec = new.get(key)
                if rec is None:
                    in_slice = (g.opt_level, g.project, g.binary, dec) in covered
                    if not add_only and in_slice:
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


def update_type_match(fd: FunctionData, new: dict[str, dict[str, Any]]) -> int:
    """Merge freshly recomputed type_match in (add-only; never clears).

    ``new`` is ``{decompiler: {"proj::opt::bin::fn": value}}`` (the shape emitted by
    ``scripts/reeval_typematch.py``). For every covered (function, decompiler) SET
    type_match + its perfect flag; entries with no fresh value are kept. Returns the
    number of (function, decompiler) entries set.
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


def merge_typematch_overlay(
    existing: dict[str, dict[str, Any]], fresh: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Merge a (possibly project-scoped) type_match reeval into the full overlay.

    Per decompiler, fresh per-function entries overwrite existing ones and everything
    else is kept — so a scoped ``reeval_typematch.py --emit`` run can no longer shrink
    ``type_match_new.json`` to just the projects it covered.
    """
    merged = {dec: dict(per) for dec, per in existing.items()}
    for dec, per in fresh.items():
        merged.setdefault(dec, {}).update(per)
    return merged


def apply_overlays(
    fd: FunctionData, root: Path, log: Log = print
) -> tuple[dict[str, int], dict[str, dict]]:
    """Apply the three corrected-metric overlays to ``fd`` with slice scoping.

    Returns ``(entry_counts_per_metric, byte_match_compile_tally)``. A missing overlay
    leaves that metric column on the raw inline checkpoint values (stale for any
    decompiler evaluated before the reeval fixes) — loudly warned, matching the
    long-standing finalize behaviour.
    """
    counts: dict[str, int] = {}
    bm_tally: dict[str, dict] = {}

    def _warn_missing(name: str) -> None:
        log(
            f"[store] WARNING: no {root / name} — that metric column is the raw inline "
            "checkpoint values (stale for any decompiler evaluated before the reeval "
            "fixes). Run the matching reeval script, then finalize again."
        )

    ged_payload, ged_covered = read_ged_overlay(root)
    if ged_payload is None:
        _warn_missing("ged_new.json")
    else:
        counts["ged"] = update_ged(fd, ged_payload, covered=ged_covered)

    tm_path = root / "type_match_new.json"
    if not tm_path.exists():
        _warn_missing("type_match_new.json")
    else:
        counts["type_match"] = update_type_match(fd, json.loads(tm_path.read_text()))

    bm_path = root / "byte_match_new.json"
    if not bm_path.exists():
        _warn_missing("byte_match_new.json")
    else:
        bm_tally = update_byte_match(fd, json.loads(bm_path.read_text()))
        counts["byte_match"] = sum(t["tot"] for t in bm_tally.values())

    for metric, n in counts.items():
        log(f"[store] overlaid {n} {metric} entries")
    return counts, bm_tally


# --------------------------------------------------------------------------- #
# Sample-set manifest (the frozen membership store).
# --------------------------------------------------------------------------- #
def load_sample_manifest(root: Path) -> set[FnKey] | None:
    """The frozen sample-set membership, or None when the tree has no manifest."""
    path = root / "sample_set_manifest.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text())
    return {(e["project"], e["opt"], e["binary"], e["function"]) for e in data.get("functions", [])}


# --------------------------------------------------------------------------- #
# Coverage-regression guard.
# --------------------------------------------------------------------------- #
def _iter_group_dicts(fd_or_raw: FunctionData | dict) -> Iterable[tuple[str, str, str, list]]:
    """Yield ``(project, opt, binary, functions)`` from a model OR a raw JSON dict.

    The previous ``function_results.json`` is counted from its raw ``json.load`` form
    (pydantic validation of a ~300 MB file is pure overhead here), while the new data
    arrives as a model — this normalizes both.
    """
    if isinstance(fd_or_raw, dict):
        for g in fd_or_raw.get("groups", []):
            yield g["project"], g["opt_level"], g["binary"], g["functions"]
    else:
        for g in fd_or_raw.groups:
            yield g.project, g.opt_level, g.binary, g.functions


def coverage_counts(fd_or_raw: FunctionData | dict) -> dict[str, dict[str, int]]:
    """Per-binary coverage counters: what the guard compares across a rewrite.

    Key: ``"project::opt::binary"``. Counters per key: ``"functions"`` (row count),
    ``"<dec>::<metric>"`` (finite value count) and ``"<dec>::decompiled"`` (True
    flags). Perfect-flag counts are deliberately NOT compared — a metric fix may
    legitimately change perfects without dropping coverage; the kuna incident was a
    value-count drop (3503 -> 0) and is exactly what these counters catch.
    """
    out: dict[str, dict[str, int]] = {}
    for project, opt, binary, functions in _iter_group_dicts(fd_or_raw):
        c: dict[str, int] = out.setdefault(f"{project}::{opt}::{binary}", {})
        c["functions"] = c.get("functions", 0) + len(functions)
        for f in functions:
            # `.get`/`getattr` defaults so a pre-`decompiled`-field tree (older
            # function_results.json) counts cleanly instead of KeyError-ing.
            values = f.get("values") if isinstance(f, dict) else f.values
            decompiled = f.get("decompiled") if isinstance(f, dict) else f.decompiled
            for dec, mv in (values or {}).items():
                for metric, val in (mv or {}).items():
                    if isinstance(val, (int, float)) and math.isfinite(val):
                        k = f"{dec}::{metric}"
                        c[k] = c.get(k, 0) + 1
            for dec, flag in (decompiled or {}).items():
                if flag:
                    k = f"{dec}::decompiled"
                    c[k] = c.get(k, 0) + 1
    return out


def coverage_regressions(
    old: dict[str, dict[str, int]],
    new: dict[str, dict[str, int]],
    allowed_projects: Collection[str] = (),
    allowed_decompilers: Collection[str] = (),
) -> list[tuple[str, str, int, int]]:
    """Counters that shrank: ``(group_key, counter, old, new)`` rows.

    Groups whose project is in ``allowed_projects`` and counters whose decompiler is
    in ``allowed_decompilers`` are expected drops (an explicit exclusion) and skipped.
    """
    allowed_p = set(allowed_projects)
    allowed_d = set(allowed_decompilers)
    regressions: list[tuple[str, str, int, int]] = []
    for gkey, counters in old.items():
        if gkey.split("::", 1)[0] in allowed_p:
            continue
        new_counters = new.get(gkey, {})
        for counter, oval in counters.items():
            if "::" in counter and counter.split("::", 1)[0] in allowed_d:
                continue
            nval = new_counters.get(counter, 0)
            if nval < oval:
                regressions.append((gkey, counter, oval, nval))
    return regressions


def _print_regressions(regressions: list[tuple[str, str, int, int]], log: Log) -> None:
    """Aggregate per (group, decompiler) for readability and print (capped)."""
    agg: dict[tuple[str, str], list[int]] = {}
    for gkey, counter, oval, nval in regressions:
        dec = counter.split("::", 1)[0] if "::" in counter else counter
        entry = agg.setdefault((gkey, dec), [0, 0, 0])
        entry[0] += oval
        entry[1] += nval
        entry[2] += 1
    lines = sorted(agg.items(), key=lambda kv: kv[1][0] - kv[1][1], reverse=True)
    log(f"[guard] COVERAGE REGRESSIONS ({len(regressions)} counters, {len(lines)} slices):")
    for (gkey, dec), (o, n, c) in lines[:GUARD_PRINT_CAP]:
        log(f"[guard]   {gkey} {dec}: {o} -> {n} across {c} counter(s)")
    if len(lines) > GUARD_PRINT_CAP:
        log(f"[guard]   ... and {len(lines) - GUARD_PRINT_CAP} more slices")


def write_function_data_guarded(
    fd: FunctionData,
    root: Path,
    *,
    allow_drops: bool = False,
    allowed_projects: Collection[str] = (),
    allowed_decompilers: Collection[str] = (),
    old_counts: dict[str, dict[str, int]] | None = None,
    log: Log = print,
) -> None:
    """The ONE write path for ``function_results.json``: guarded + atomic.

    Compares coverage against the existing file (or ``old_counts`` precomputed from
    it) and raises :class:`CoverageRegressionError` — leaving the old file untouched —
    on any shrink not covered by an explicit exclusion, unless ``allow_drops``.
    On success the previous file rotates to ``function_results.prev.json`` (the one
    sanctioned backup; the ad-hoc ``.pre_*``/``.bak_*`` sprawl predates this module).
    """
    fd_path = root / "function_results.json"
    if old_counts is None and fd_path.exists():
        with open(fd_path) as fh:
            old_counts = coverage_counts(json.load(fh))
    new_counts = coverage_counts(fd)
    if old_counts is not None:
        regressions = coverage_regressions(
            old_counts, new_counts, allowed_projects, allowed_decompilers
        )
        if regressions:
            _print_regressions(regressions, log)
            if not allow_drops:
                raise CoverageRegressionError(
                    f"{len(regressions)} coverage counters would shrink "
                    f"(see the [guard] lines above); pass allow_drops/--allow-drops "
                    "only if every drop is intended"
                )
            log("[guard] allow_drops set: writing despite the regressions above")
        old_fns = sum(c.get("functions", 0) for c in old_counts.values())
        new_fns = sum(c.get("functions", 0) for c in new_counts.values())
        log(
            f"[guard] coverage: {len(old_counts)} -> {len(new_counts)} binaries, "
            f"{old_fns} -> {new_fns} function rows"
        )
    tmp = root / "function_results.json.tmp"
    fd.to_json(tmp)
    # COPY (not rename) the old file to .prev, then a single atomic replace: a
    # crash mid-write can never leave function_results.json absent (which would
    # disable the guard on the next run), only a stale tmp.
    if fd_path.exists():
        shutil.copy2(fd_path, root / "function_results.prev.json")
    os.replace(tmp, fd_path)
    log(f"[guard] wrote {fd_path}")


# --------------------------------------------------------------------------- #
# The canonical rebuild.
# --------------------------------------------------------------------------- #
def finalize_tree(
    root: Path,
    *,
    exclude_projects: Collection[str] = (),
    exclude_decompilers: Collection[str] = (),
    allow_drops: bool = False,
    seed: int | None = None,
    log: Log = print,
) -> tuple[FunctionData, Scoreboard]:
    """THE canonical rebuild: every checkpoint + overlays -> derived files.

    Always operates on ALL checkpoints in ``root/checkpoints`` (a scoped resume can
    no longer regenerate the dataset from a subset of projects), applies the three
    overlays with slice scoping, re-attaches the report extras, pins the sample-set
    tags to ``sample_set_manifest.json`` when present, carries forward the fields that
    exist nowhere else (``dataset_info``, ``history``), strips ``exclude_decompilers``
    and writes both derived files through the coverage guard (``exclude_projects`` /
    ``exclude_decompilers`` are the guard's expected drops).
    """
    from decbench.models.project import Project
    from decbench.publish.layout import strip_decompilers
    from decbench.scoring.datasets import assign_datasets
    from decbench.scoring.function_data_builder import build_function_data
    from decbench.scoring.report_extras import attach_extras
    from decbench.scoring.scoreboard import build_scoreboard_from_function_data

    root = Path(root)
    excluded_projects = set(exclude_projects)
    tomls = [t for t in gather_project_tomls() if t.stem not in excluded_projects]
    all_decompile, all_evaluate = load_checkpoints(root, excluded_projects, log=log)
    if not tomls and all_decompile:
        # No project TOMLs found but checkpoints exist -> almost certainly a
        # wrong-cwd / bad-install run. Refuse rather than rebuild label-less (which
        # would strip malware/cps labels and risk leaking malware source).
        raise RuntimeError(
            f"finalize_tree: no project TOMLs under {[str(d) for d in PROJECT_DIRS]} "
            f"but {len(all_decompile)} checkpoints present — refusing to rebuild "
            "without project metadata (labels/malware filter would be lost)."
        )
    projects = [Project.from_toml(t) for t in tomls]
    known = {p.name for p in projects}
    for orphan in sorted(set(all_decompile) - known):
        log(
            f"[store] NOTE: checkpoint {orphan}.pkl has no project TOML (removed "
            "project?) — its data is kept; pass exclude_projects to drop it"
        )
    log(f"[store] {len(all_decompile)} checkpoints loaded")

    fd = build_function_data(all_evaluate, projects, all_decompile)
    _counts, bm_tally = apply_overlays(fd, root, log=log)

    attach_extras(
        fd,
        evaluation_results=all_evaluate,
        decompile_results=all_decompile,
        projects=projects,
    )
    # attach_extras derives compile rates from the inline (checkpoint) byte_match;
    # for the overlaid decompilers the reeval tally is the published number.
    if bm_tally:
        fd.compile_rates.update({d: t["comp"] / t["tot"] for d, t in bm_tally.items() if t["tot"]})

    # Sample-set: the frozen manifest (minus excluded projects) is the single source
    # of truth for membership; the seeded draw only runs on manifest-less trees.
    members = load_sample_manifest(root)
    if members is not None:
        members = {m for m in members if m[0] not in excluded_projects}
        assign_datasets(fd, seed=seed, sample_members=members)
        log(f"[store] sample-set pinned to manifest ({len(members)} functions)")
    elif seed is not None:
        assign_datasets(fd, seed=seed)

    # Carry forward the fields that exist ONLY in the previous derived file, and
    # reuse its raw parse for the guard's old-coverage counts (parse once, not twice).
    old_counts: dict[str, dict[str, int]] | None = None
    prev_path = root / "function_results.json"
    if prev_path.exists():
        with open(prev_path) as fh:
            prev_raw = json.load(fh)
        fd.dataset_info = prev_raw.get("dataset_info") or {}
        fd.history = [HistoryPoint(**h) for h in prev_raw.get("history") or []]
        old_counts = coverage_counts(prev_raw)
        del prev_raw

    if exclude_decompilers:
        removed = strip_decompilers(fd, exclude_decompilers)
        log(f"[store] stripped decompilers: {removed or exclude_decompilers}")

    sb_path = root / "scoreboard.toml"
    old_sb = Scoreboard.from_toml(sb_path) if sb_path.exists() else None
    scoreboard = build_scoreboard_from_function_data(
        fd,
        name=(old_sb.name if old_sb else "DecBench Scoreboard"),
        description=(old_sb.description if old_sb else ""),
        version=(old_sb.version if old_sb else "1.0"),
    )
    write_function_data_guarded(
        fd,
        root,
        allow_drops=allow_drops,
        allowed_projects=excluded_projects,
        allowed_decompilers=exclude_decompilers,
        old_counts=old_counts,
        log=log,
    )
    scoreboard.raw_data_path = root / "function_results.json"
    scoreboard.to_toml(sb_path)
    log(f"[store] wrote {sb_path}")
    return fd, scoreboard


# --------------------------------------------------------------------------- #
# Audit: find silent coverage gaps across every layer.
# --------------------------------------------------------------------------- #
@dataclass
class CoverageGap:
    """One suspicious ``(opt, project, binary, decompiler)`` slice."""

    kind: str  # SILENT-DROP | OVERLAY-GAP | DECOMPILE-FAILURE | PARTIAL
    opt: str
    project: str
    binary: str
    decompiler: str
    checkpoint_fns: int = 0
    artifact_markers: int = 0
    overlay_entries: int = 0
    published_values: int = 0
    note: str = field(default="")

    def row(self) -> str:
        return (
            f"{self.kind:17} {self.opt:12} {self.project:16} {self.binary:20} "
            f"{self.decompiler:12} "
            f"ckpt={self.checkpoint_fns:<5} artifact={self.artifact_markers:<5} "
            f"overlay={self.overlay_entries:<5} published={self.published_values:<5} "
            f"{self.note}"
        )


_LLM_BASENAMES = {"codex", "claude-code", "kimi-code"}


def _artifact_marker_names(path: Path) -> set[str]:
    """The ``// Function: <name>`` marker names in a decompiled artifact."""
    if not path.is_file() or path.stat().st_size == 0:
        return set()
    names: set[str] = set()
    with open(path, errors="replace") as fh:
        for line in fh:
            if line.startswith("// Function: "):
                names.add(line[len("// Function: ") :].split(" ", 1)[0])
    return names


def audit_tree(root: Path, log: Log = print) -> list[CoverageGap]:
    """Compare every layer per slice and classify the gaps.

    * **SILENT-DROP** — the published dataset has NO values for a slice although the
      checkpoint, overlay or artifact has data: the regression class the guard exists
      to prevent, present in already-written data.
    * **OVERLAY-GAP** — artifact + checkpoint data but no GED overlay entries: the
      published GED for that slice rides on stale inline values; run the reeval.
    * **DECOMPILE-FAILURE** — empty artifact + empty checkpoint slice while the same
      (project, decompiler) succeeded at sibling opt levels (the kuna@betaflight
      case): re-decompile or accept as a recorded failure.
    * **PARTIAL** — published values < 50% of what checkpoint/artifact hold.

    The LLM sample-set backends are only audited on their manifest slice.
    """
    root = Path(root)
    fd_path = root / "function_results.json"
    published: dict[Slice, int] = {}
    published_names: dict[tuple[str, str, str], set[str]] = {}
    published_decs: set[str] = set()
    if fd_path.exists():
        with open(fd_path) as fh:
            raw = json.load(fh)
        published_decs = set(raw.get("decompilers") or [])
        for g in raw.get("groups", []):
            gkey = (g["opt_level"], g["project"], g["binary"])
            names = published_names.setdefault(gkey, set())
            for f in g.get("functions", []):
                names.add(f["function"])
                for dec, mv in (f.get("values") or {}).items():
                    if mv:
                        key = (g["opt_level"], g["project"], g["binary"], dec)
                        published[key] = published.get(key, 0) + 1
        del raw
    overlay: dict[Slice, int] = {}
    ged_payload, _ = read_ged_overlay(root)
    for k in ged_payload or {}:
        opt, proj, stem, dec, _fn = k.split("::", 4)
        overlay[(opt, proj, stem, dec)] = overlay.get((opt, proj, stem, dec), 0) + 1

    manifest = load_sample_manifest(root)
    llm_slices: set[tuple[str, str, str]] | None = None
    if manifest is not None:
        llm_slices = {(proj, opt, stem) for proj, opt, stem, _fn in manifest}

    import decbench.decompilers  # noqa: F401  (pickles resolve)
    import decbench.metrics  # noqa: F401

    gaps: list[CoverageGap] = []
    for ckpt in sorted((root / "checkpoints").glob("*.pkl")):
        project = ckpt.stem
        try:
            data = pickle.loads(ckpt.read_bytes())
        except Exception as e:  # noqa: BLE001
            gaps.append(
                CoverageGap("SILENT-DROP", "*", project, "*", note=f"unreadable checkpoint: {e}")
            )
            continue
        ckpt_names: dict[Slice, set[str]] = {}
        per_dec_opts: dict[tuple[str, str], dict[str, int]] = {}
        for opt, bins in (data.get("decompile") or {}).items():
            optn = getattr(opt, "value", str(opt))
            for stem, decs in (bins or {}).items():
                for dec, dr in (decs or {}).items():
                    names = set((getattr(dr, "functions", {}) or {}).keys())
                    ckpt_names[(optn, project, stem, dec)] = names
                    per_dec_opts.setdefault((stem, dec), {})[optn] = len(names)
        del data
        for (optn, proj, stem, dec), names in sorted(ckpt_names.items()):
            base_dec = dec.split("@", 1)[0]
            if published_decs and dec not in published_decs and base_dec not in published_decs:
                continue  # decompiler intentionally removed from the dataset (e.g. phoenix)
            if base_dec in _LLM_BASENAMES and (
                llm_slices is None or (proj, optn, stem) not in llm_slices
            ):
                continue  # off-slice LLM sparsity is by design
            key: Slice = (optn, proj, stem, dec)
            markers = _artifact_marker_names(root / optn / proj / "decompiled" / f"{dec}_{stem}.c")
            pubnames = published_names.get((optn, proj, stem))
            ov = overlay.get(key, 0)
            pub = published.get(key, 0)
            sibling_ok = any(
                n > 0 for o, n in per_dec_opts.get((stem, dec), {}).items() if o != optn
            )
            if pubnames is None:
                # The whole (opt, project, binary) group is absent from the
                # published data — the historical "coreutils vanished" class.
                if names or markers:
                    gaps.append(
                        CoverageGap(
                            "SILENT-DROP",
                            optn,
                            proj,
                            stem,
                            dec,
                            len(names),
                            len(markers),
                            ov,
                            pub,
                            note="whole group missing from published data",
                        )
                    )
                continue
            # Compare only functions that exist as published rows: a checkpoint
            # holds everything the tool decompiled (library/sub_* included), while
            # the dataset legitimately keeps only attributable source rows.
            ckpt_n = len(names & pubnames)
            art = len(markers & pubnames)
            if pub == 0 and ov > 0:
                # The corrected overlay HAS metric values for this slice, but the
                # published dataset has none — a real merge drop. (A decompiled
                # artifact with NO overlay entry is not a drop: the function may be
                # legitimately unmeasurable — ARM byte_match abstains, no source
                # CFG for GED — so it falls to OVERLAY-GAP below, not here.)
                gaps.append(CoverageGap("SILENT-DROP", optn, proj, stem, dec, ckpt_n, art, ov, pub))
            elif len(names) == 0 and len(markers) == 0 and sibling_ok:
                gaps.append(
                    CoverageGap(
                        "DECOMPILE-FAILURE",
                        optn,
                        proj,
                        stem,
                        dec,
                        ckpt_n,
                        art,
                        ov,
                        pub,
                        note="empty artifact+checkpoint; sibling opts have data",
                    )
                )
            elif ov == 0 and ckpt_n > 0 and art > 0:
                note = (
                    "GED riding on inline values"
                    if pub > 0
                    else "no overlay coverage (unmeasurable: ARM byte_match / no source CFG)"
                )
                gaps.append(
                    CoverageGap(
                        "OVERLAY-GAP", optn, proj, stem, dec, ckpt_n, art, ov, pub, note=note
                    )
                )
            elif (basis := [x for x in (ckpt_n, art) if x > 0]) and 0 < pub < 0.5 * min(basis):
                gaps.append(CoverageGap("PARTIAL", optn, proj, stem, dec, ckpt_n, art, ov, pub))
    for gap in gaps:
        log(gap.row())
    by_kind: dict[str, int] = {}
    for gap in gaps:
        by_kind[gap.kind] = by_kind.get(gap.kind, 0) + 1
    log(f"[audit] {len(gaps)} gaps: " + ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items())))
    return gaps
