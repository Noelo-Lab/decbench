"""Curated dataset *presets* for the report's single dataset selector.

Rather than exposing dozens of label/binary toggles, the report offers five
fixed, meaningful views. This module tags every :class:`FunctionRecord` with the
presets it belongs to (``FunctionRecord.datasets``) and records the preset
metadata on the :class:`FunctionData`:

* **unoptimized** — O0 functions only, to surface simple structural differences
  without optimization noise. The selector's default view.
* **optimized** — optimized **without** inlining (O2-noinline). Inlining is an
  outlier optimization that destroys function boundaries, so the plain
  "optimized" view keeps it off.
* **inlined** — optimized **with** inlining (plain O2).
* **large** — optimized (no inlining, O2-noinline), **large** functions only.
  This is the upper tail of the size bell curve — the genuinely hard cases.
  (Previously named ``hard``; membership is unchanged.)
* **sample-set** — ~250 functions total, evenly sampled from five categories
  (unoptimized=O0, optimized=O2-noinline, inlined=O2, large, and
  ARM-unoptimized=O0 on a non-x86 target), spread evenly across projects,
  and — while there are enough distinct binaries — taking **at most one
  function per binary**, so it is a fast, representative slice. The sample is a
  **seeded random** selection — stable across runs for a given seed, but
  changeable via ``DECBENCH_SAMPLE_SEED`` (or ``assign_datasets(seed=...)``).

"Large" is the upper tail of the function-size bell curve (``mean + k·std`` over
decompiled line counts), matching :mod:`decbench.scoring.subset`. The majority
of functions are small, so this surfaces the genuinely hard, large ones.

**Scope**: this module owns preset *names* and *membership rules* only — never how
a preset is presented. The button label, the one-line description and which preset
the report opens on live in ``decbench/rendering/content/datasets.toml`` and are
joined onto these names at render time
(:func:`decbench.rendering.aggregate.resolve_presets`). Scoring is the lower layer
and must not import rendering; keeping the text out of here is what lets a
maintainer reword a preset without re-running a multi-hour benchmark.
"""

from __future__ import annotations

import os
import random
import statistics
from collections import OrderedDict
from typing import TYPE_CHECKING

from decbench.models.function_data import DatasetPreset

if TYPE_CHECKING:
    from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord

__all__ = [
    "assign_datasets",
    "topup_sample_members",
    "large_threshold",
    "PRESETS",
    "DEFAULT_SAMPLE_SEED",
]

DEFAULT_SAMPLE_SEED = 1337


def _resolve_seed(seed: int | None) -> int:
    """Resolve the sample-set seed: explicit arg > env var > default.

    ``DECBENCH_TINY_SEED`` (the preset's pre-rename spelling) is still honoured
    so existing run scripts keep reproducing the same slice.
    """
    if seed is not None:
        return seed
    for var in ("DECBENCH_SAMPLE_SEED", "DECBENCH_TINY_SEED"):
        env = os.environ.get(var)
        if env:
            try:
                return int(env)
            except ValueError:
                pass
    return DEFAULT_SAMPLE_SEED


PRESETS: list[DatasetPreset] = [
    DatasetPreset(name="unoptimized"),
    DatasetPreset(name="optimized"),
    DatasetPreset(name="inlined"),
    DatasetPreset(name="large"),
    DatasetPreset(name="sample-set"),
]

_O2 = "O2"
_O2_NOINLINE = "O2-noinline"
_O0 = "O0"

_ARM_LABELS = frozenset({"cps", "arm", "armv7", "aarch64", "arm64", "bare-metal", "embedded-linux"})


def _is_arm(group: BinaryGroup) -> bool:
    """Whether a binary group was cross-compiled for a non-x86 (ARM) target."""
    labels = group.labels or []
    return any(label in _ARM_LABELS or label.startswith("cortex-") for label in labels)


def large_threshold(function_data: FunctionData, k: float = 1.0) -> float | None:
    """Upper-tail size cutoff (``mean + k·std``) over decompiled line counts.

    Returns ``None`` when no function has a recorded size (then the ``large``
    auto-label is used as a fallback by :func:`assign_datasets`).
    """
    sizes = [f.size for g in function_data.groups for f in g.functions if f.size is not None]
    if not sizes:
        return None
    mean = statistics.fmean(sizes)
    std = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
    return mean + k * std


def _binkey(g: BinaryGroup) -> tuple[str, str, str]:
    """Identity of a single compiled binary: (project, opt level, binary)."""
    return (g.project, g.opt_level, g.binary)


def _scoreable(f: FunctionRecord) -> bool:
    """Whether a record can contribute to ANY metric — i.e. is worth sampling.

    A record with no metric value from any decompiler is a wasted sample-set
    slot: it joins no denominator (``any_measurable`` is False for it) and the
    gated LLM run cannot even attempt it when its name is a decompiler-invented
    one with no DWARF anchor. The real corpus contains a few hundred such rows —
    relabel-duplicate phantoms of CRT/TLS-callback code (the same function
    counted once per decompiler naming style: ``tls_callback_1`` /
    ``TlsCallback_1`` / ``_TLS_Entry_1``) plus a handful of genuinely
    unmeasurable functions. Five phantoms were sampled into the published
    2026-07 sample-set this way, showing up as "missing data" for every backend.

    Checked during the draw (not by pre-filtering the candidate pool) so the
    shuffles — and therefore every already-published valid pick — are unchanged
    for a given seed: skipping an ineligible record just advances the scan to
    the next candidate in the same shuffled order.
    """
    return any(f.values.values())


def _sample_even(
    items: list[tuple[BinaryGroup, FunctionRecord]],
    quota: int,
    chosen_fns: set[int],
    used_bins: set[tuple[str, str, str]],
    rng: random.Random,
    exclude_projects: frozenset[str] = frozenset(),
    exclude_members: frozenset[tuple[str, str, str, str]] = frozenset(),
) -> list[tuple[BinaryGroup, FunctionRecord]]:
    """Pick up to ``quota`` records as a *seeded random*, evenly-spread sample.

    Evenness on two axes:

    * **projects** — candidates are grouped by project and drawn round-robin so
      no project dominates.
    * **binaries** — *at most one function is taken from any one binary* while
      distinct binaries remain (a first pass enforces this); only if there are
      not enough binaries to meet ``quota`` does a second pass relax the rule
      and allow a second function from a binary.

    The member order within each project and the project visitation order are
    shuffled with ``rng`` (random but fully reproducible for a given seed).
    ``chosen_fns`` (``id(record)``) and ``used_bins`` (:func:`_binkey`) are
    shared across the five category buckets and **mutated** here, so the rules
    hold across the whole ``sample-set`` sample, not just within one bucket.

    Records that are not :func:`_scoreable` are skipped during the scan (not
    pre-filtered from ``items``), so the shuffles — and every scoreable pick a
    prior run of the same seed made — stay identical.

    ``exclude_projects`` skips an excluded project's candidates during the scan.
    It is used ONLY by :func:`topup_sample_members` for the refill pass, whose
    ``chosen_fns``/``used_bins`` already pin the surviving picks — so exclusion
    there cannot perturb them. ``exclude_members`` is the per-function analogue
    (same refill-only caveat): it stops the refill from re-picking a member that
    was explicitly dropped from the base manifest. It must NOT be used for a
    full fresh draw across all five buckets: ``chosen_fns``/``used_bins`` are shared and two bucket
    pairs overlap (``unoptimized-arm`` ⊂ ``unoptimized``; ``large`` ⊂
    ``optimized``), so excluding a project mid-draw diverges the rng for the
    overlapping bucket and loses unrelated picks.
    """
    by_project: OrderedDict[str, list[tuple[BinaryGroup, FunctionRecord]]] = OrderedDict()
    ordered = sorted(
        items,
        key=lambda gf: (gf[0].project, gf[0].opt_level, gf[0].binary, gf[1].function),
    )
    for g, f in ordered:
        if id(f) in chosen_fns:
            continue
        by_project.setdefault(g.project, []).append((g, f))

    for lst in by_project.values():
        rng.shuffle(lst)
    projects = list(by_project.keys())
    rng.shuffle(projects)

    picked: list[tuple[BinaryGroup, FunctionRecord]] = []

    def pass_once(one_per_binary: bool) -> None:
        advanced = True
        while len(picked) < quota and advanced:
            advanced = False
            for proj in projects:
                if len(picked) >= quota:
                    break
                lst = by_project[proj]
                idx = None
                for j, (g, f) in enumerate(lst):
                    if id(f) in chosen_fns:
                        continue
                    if g.project in exclude_projects:
                        continue
                    if (g.project, g.opt_level, g.binary, f.function) in exclude_members:
                        continue
                    if not _scoreable(f):
                        continue
                    if one_per_binary and _binkey(g) in used_bins:
                        continue
                    idx = j
                    break
                if idx is not None:
                    g, f = lst.pop(idx)
                    picked.append((g, f))
                    chosen_fns.add(id(f))
                    used_bins.add(_binkey(g))
                    advanced = True

    pass_once(one_per_binary=True)
    pass_once(one_per_binary=False)
    return picked


def _apply_opt_presets(
    function_data: FunctionData, k: float
) -> list[tuple[BinaryGroup, FunctionRecord]]:
    """Tag the rule-based presets (unoptimized/optimized/inlined/large) and
    return the ``(group, record)`` list. The sample-set tag is added separately."""
    threshold = large_threshold(function_data, k=k)

    def is_large(f: FunctionRecord) -> bool:
        if f.size is not None and threshold is not None:
            return f.size >= threshold
        return "large" in (f.labels or [])

    records: list[tuple[BinaryGroup, FunctionRecord]] = [
        (g, f) for g in function_data.groups for f in g.functions
    ]
    for g, f in records:
        ds = []
        if g.opt_level == _O0:
            ds.append("unoptimized")
        elif g.opt_level == _O2_NOINLINE:
            ds.append("optimized")
            if is_large(f):
                ds.append("large")
        elif g.opt_level == _O2:
            ds.append("inlined")
        f.datasets = ds
    return records


def _sample_buckets(
    records: list[tuple[BinaryGroup, FunctionRecord]], k_threshold: float | None
) -> OrderedDict[str, list[tuple[BinaryGroup, FunctionRecord]]]:
    """The five sample-set category buckets, in draw order.

    ``k_threshold`` is the precomputed ``large`` cutoff (``None`` -> fall back to
    the ``large`` label). Kept a pure function of ``records`` so the top-up refill
    builds the identical buckets the original draw used.
    """

    def is_large(f: FunctionRecord) -> bool:
        if f.size is not None and k_threshold is not None:
            return f.size >= k_threshold
        return "large" in (f.labels or [])

    return OrderedDict(
        [
            ("unoptimized", [(g, f) for g, f in records if g.opt_level == _O0]),
            ("optimized", [(g, f) for g, f in records if g.opt_level == _O2_NOINLINE]),
            ("inlined", [(g, f) for g, f in records if g.opt_level == _O2]),
            ("large", [(g, f) for g, f in records if g.opt_level == _O2_NOINLINE and is_large(f)]),
            ("unoptimized-arm", [(g, f) for g, f in records if g.opt_level == _O0 and _is_arm(g)]),
        ]
    )


def assign_datasets(
    function_data: FunctionData,
    sample_total: int = 250,
    k: float = 1.0,
    seed: int | None = None,
    sample_members: set[tuple[str, str, str, str]] | None = None,
) -> FunctionData:
    """Tag every record with its dataset presets and set ``dataset_presets``.

    The ``sample-set`` sample is a **seeded random** selection: deterministic
    for a given seed (so the chosen targets are stable across runs), but
    changeable. Seed resolution: ``seed`` arg > ``DECBENCH_SAMPLE_SEED`` env
    var > :data:`DEFAULT_SAMPLE_SEED`.

    ``sample_members`` — the frozen membership, as ``(project, opt, binary,
    function)`` keys (the ``sample_set_manifest.json`` shape; see
    :func:`decbench.results_store.load_sample_manifest`): when given, the draw
    is skipped entirely and exactly these functions are tagged ``sample-set``.
    The manifest is the single source of truth wherever one exists — the seeded
    draw is only the bootstrap for manifest-less trees. To remove a project from
    an existing manifest, use :func:`topup_sample_members` (NOT a fresh draw with
    an exclusion — that would perturb the seed and lose unrelated picks).

    Idempotent: re-running with the same inputs re-derives identical membership.
    """
    records = _apply_opt_presets(function_data, k)

    if sample_members is not None:
        matched: set[tuple[str, str, str, str]] = set()
        for g, f in records:
            key = (g.project, g.opt_level, g.binary, f.function)
            if key in sample_members:
                if "sample-set" not in f.datasets:
                    f.datasets.append("sample-set")
                matched.add(key)
        if len(matched) < len(sample_members):
            print(
                f"[datasets] WARNING: {len(sample_members) - len(matched)} sample-set "
                "manifest entries have no matching record (renamed/removed data?)",
                flush=True,
            )
        function_data.dataset_presets = [p.model_copy() for p in PRESETS]
        return function_data

    rng = random.Random(_resolve_seed(seed))
    buckets = _sample_buckets(records, large_threshold(function_data, k=k))
    per_bucket = max(1, sample_total // len(buckets))
    chosen: set[int] = set()
    used_bins: set[tuple[str, str, str]] = set()
    for _name, items in buckets.items():
        for _g, f in _sample_even(items, per_bucket, chosen, used_bins, rng):
            if "sample-set" not in f.datasets:
                f.datasets.append("sample-set")

    function_data.dataset_presets = [p.model_copy() for p in PRESETS]
    return function_data


def topup_sample_members(
    function_data: FunctionData,
    base_members: set[tuple[str, str, str, str]],
    exclude_projects: frozenset[str],
    sample_total: int = 250,
    k: float = 1.0,
    seed: int | None = None,
    exclude_members: frozenset[tuple[str, str, str, str]] = frozenset(),
) -> set[tuple[str, str, str, str]]:
    """Return a full sample-set membership that KEEPS the surviving base picks
    and deterministically refills the slots freed by ``exclude_projects`` /
    ``exclude_members``.

    The frozen manifest (``base_members``) is the source of truth for every pick
    that is not from an excluded project — those are preserved verbatim, drift or
    not. Only the freed slots are re-drawn, per category bucket, from the same
    buckets, excluding the removed projects and every already-kept function/binary
    (so the one-function-per-binary rule still holds). Deterministic for a given
    seed; idempotent. This avoids the seed-perturbation that a fresh draw with an
    exclusion would cause across the overlapping buckets (see :func:`_sample_even`).

    ``exclude_members`` drops specific base picks (rather than whole projects) —
    the repair path for the five valueless phantom picks frozen into the
    published 2026-07 manifest (see :func:`_scoreable`): each dropped pick frees
    its slot in its first-owning bucket and is refilled from that same bucket.
    """
    records = _apply_opt_presets(function_data, k)
    kept = {m for m in base_members if m[0] not in exclude_projects and m not in exclude_members}
    removed = {m for m in base_members if m[0] in exclude_projects or m in exclude_members}

    buckets = _sample_buckets(records, large_threshold(function_data, k=k))

    # Most-specific bucket wins: the buckets overlap and each is quota-limited, so
    # crediting the broadest match would zero the specific buckets' refill counts
    # and shrink the sub-quota they exist to guarantee.
    refill_per_bucket: dict[str, int] = {name: 0 for name in buckets}
    assigned: set[tuple[str, str, str, str]] = set()
    chosen: set[int] = set()
    used_bins: set[tuple[str, str, str]] = set()
    for name in reversed(list(buckets)):
        for g, f in buckets[name]:
            key = (g.project, g.opt_level, g.binary, f.function)
            if key in assigned:
                continue
            if key in kept:
                assigned.add(key)
                chosen.add(id(f))
                used_bins.add(_binkey(g))
            elif key in removed:
                assigned.add(key)
                refill_per_bucket[name] += 1

    # A removed pick whose record is gone entirely appears in no bucket, so charge
    # it to its opt level's bucket or its slot silently vanishes.
    _OPT_BUCKET = {_O0: "unoptimized", _O2_NOINLINE: "optimized", _O2: "inlined"}
    for key in sorted(removed - assigned):
        bucket = _OPT_BUCKET.get(key[1])
        if bucket is not None:
            refill_per_bucket[bucket] += 1

    rng = random.Random(_resolve_seed(seed))
    refilled: set[tuple[str, str, str, str]] = set()
    for name, items in buckets.items():
        need = refill_per_bucket[name]
        if need <= 0:
            continue
        for g, f in _sample_even(
            items, need, chosen, used_bins, rng, exclude_projects, exclude_members
        ):
            refilled.add((g.project, g.opt_level, g.binary, f.function))
    return kept | refilled
