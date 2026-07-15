"""Build-time aggregation of the per-function dataset into the site's JSON.

The report used to ship every :class:`~decbench.models.function_data.FunctionRecord`
(~98 MB for the full run) so the browser could recompute the same handful of tables
on every click. Every aggregate the site renders is a pure function of exactly two
selectors — the dataset **preset** and the **normalize-failures** toggle — so there
are only ``len(presets) x 2`` distinct answers. This module computes all of them
once, here, into ~22 KB of JSON (see ``docs/SITE_DATA_SCHEMA.md``).

The aggregation semantics are ported verbatim from the client-side ``recompute()``,
``buildDistance()`` and ``buildDataset()`` in :mod:`decbench.rendering.html`. They
are not incidental — they are the benchmark's **fairness contract**, and the
docstrings below say why each rule exists. Two consequences worth stating up front:

* Denominators are *shared*: for a given metric, every decompiler is scored over the
  same set of functions. A decompiler that failed on a function the metric could
  measure counts as a **miss**, never as an exclusion. Only functions no decompiler
  could be scored on (our tooling's fault, not theirs) leave the denominator, and
  they leave it for everyone at once.
* Where the JS is quirky, this port is quirky the same way, on purpose. A "fix" here
  would silently change published numbers. The quirks are marked ``JS parity``.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from decbench.models.function_data import FunctionData, FunctionRecord
from decbench.models.scoreboard import Scoreboard
from decbench.rendering.content import Category, Content, load_content

__all__ = [
    "build_aggregates",
    "build_dataset_page",
    "build_payloads",
    "combo_key",
    "resolve_presets",
]

#: Preset name for the synthetic all-functions combo emitted when a run carries no
#: dataset presets at all. Reserved: no real preset may use it. The client falls back
#: to this key when it has no preset to select (``app.js``'s ``FALLBACK_PRESET``), so
#: a preset-less run renders every number with no dataset selector instead of an
#: error banner. Kept in sync by ``docs/SITE_DATA_SCHEMA.md`` and tests.
ALL_PRESET = "__all__"

#: Floats are emitted EXACTLY as computed — deliberately unrounded. Rounding used to
#: happen here (3dp) and was documented as "lossless"; it was not. The client
#: re-renders some values at FEWER places than it stored (``toFixed(2)`` for Compare
#: values, ``toFixed(1)`` for distance means), so pre-rounding to 3dp manufactures an
#: exact 2dp/1dp half-boundary and the second rounding then breaks the tie the other
#: way: 0.45454... renders "0.45", but stored as 0.455 it renders "0.46". That moved
#: 13 Compare cells and 1 distance cell, in BOTH directions. The old proof only ever
#: covered means and perfect flags, never the raw per-function values the Compare view
#: prints. Rounding bought 0.087% of payload bytes (6.4 KB of 7.3 MB; 2.1 KB of 935 KB
#: gzipped) — the payloads are dominated by embedded C source, not float digits — so
#: the whole double-rounding hazard is simply deleted rather than re-proved. Do not
#: reintroduce it: any rounding here is only safe at >= the most precise rendering the
#: client does, and that is a coupling across the Python/JS boundary that no test in
#: this repo can see.


def combo_key(preset: str, normalize: bool) -> str:
    """Key one precomputed combo: ``"<preset>|0"`` or ``"<preset>|1"``."""
    return f"{preset}|{'1' if normalize else '0'}"


def _js_is_finite(value: float | None) -> bool:
    """Mirror JavaScript's **global** ``isFinite``, not ``Number.isFinite``.

    JS parity: the client calls the global ``isFinite``, which coerces its argument
    first, so ``isFinite(null) === true``. The measurability checks therefore treat a
    ``null`` metric value as *measurable*, while ``buildDistance`` guards ``v != null``
    before its own ``isFinite`` and skips it. The two paths genuinely disagree.

    It is latent on the real data (every value is a finite number), so keeping the
    quirk costs nothing and "fixing" it would move published denominators.
    """
    if value is None:
        return True  # isFinite(null) === true — Number(null) is 0.
    return math.isfinite(value)


def _decompiled_by(func: FunctionRecord, dec: str) -> bool:
    """Did ``dec`` produce output for this function?

    Back-compat with datasets written before ``FunctionRecord.decompiled`` existed:
    fall back to inferring attempt-and-success from the presence of a per-metric
    perfects map.

    JS parity: the fallback is ``!!func.perfects[d]``, and in JS *every* object —
    including ``{}`` — is truthy, so it is a **presence** test. ``bool(dict)`` would
    be wrong: Python's empty dict is falsy, which would flip an empty perfects map
    from "decompiled" to "not decompiled" and quietly shrink the normalize=1 universe.
    """
    decompiled = func.decompiled
    if dec in decompiled:
        return decompiled[dec]
    return dec in func.perfects


def _has_ged(func: FunctionRecord, dec: str) -> bool:
    """Did ``dec`` obtain a finite GED for this function?

    A non-finite/degenerate result means our source front-end had no real CFG to
    compare against; that is unmeasurable, not a decompiler miss.
    """
    values = func.values.get(dec)
    if values is None:
        return False
    return "ged" in values and _js_is_finite(values["ged"])


def _source_parsed(func: FunctionRecord, decompilers: list[str], ged_present: bool) -> bool:
    """Did our source front-end (Joern) produce a CFG for this function's source?

    Source CFGs are decompiler-independent, so a function's source parsed iff *some*
    decompiler obtained a GED for it. When Joern fails on the SOURCE that is our
    tooling's fault, so the function is excluded from GED for everyone rather than
    counted against anyone. When Joern fails on a single decompiler's OUTPUT (source
    parsed, that decompiler has no GED) it still counts as that decompiler's miss.
    """
    if not ged_present:
        return True
    return any(_has_ged(func, dec) for dec in decompilers)


def _metric_measurable(
    func: FunctionRecord, metric: str, decompilers: list[str], ged_present: bool
) -> bool:
    """Is ``metric`` measurable for this function *at all*, for anyone?

    This is the per-metric universe filter and the heart of the fairness contract. A
    function no decompiler could be scored on for reasons outside every decompiler's
    control — GED with no source CFG, ``byte_match`` abstained (no recompile
    toolchain for the target's arch), ``type_match`` with no DWARF ground truth — is
    dropped from that metric's denominator **uniformly**, so denominators stay
    identical across decompilers. A function that IS measurable but which a given
    decompiler failed on is that decompiler's not-perfect miss and stays in.
    """
    if metric == "ged":
        return _source_parsed(func, decompilers, ged_present)
    for dec in decompilers:
        values = func.values.get(dec)
        if values is not None and metric in values and _js_is_finite(values[metric]):
            return True
    return False


@dataclass(frozen=True)
class _FunctionFacts:
    """Everything the combo accumulators need from one function.

    Every field here is **selector-independent** — measurability, perfection and
    distances do not depend on which preset is selected or whether normalize is on.
    That is what makes the single pass legal: a function is computed once and then
    added to each combo it is active under.

    All per-decompiler / per-metric fields are positional, indexed the same way as
    the ``decompilers`` / ``metrics`` lists they were built from.
    """

    datasets: frozenset[str]
    all_decompiled: bool
    err_scope: tuple[bool, ...]
    err_errored: tuple[bool, ...]
    measurable: tuple[bool, ...]
    all_measurable: bool
    perfect: tuple[tuple[bool, ...], ...]
    overall_perfect: tuple[bool, ...]
    distances: tuple[tuple[float | None, ...], ...]


def _function_facts(
    func: FunctionRecord,
    decompilers: list[str],
    metrics: list[str],
    distance_metrics: list[str],
    ged_present: bool,
) -> _FunctionFacts:
    """Reduce one function to its combo-independent contribution."""
    measurable = tuple(_metric_measurable(func, m, decompilers, ged_present) for m in metrics)

    err_scope: list[bool] = []
    err_errored: list[bool] = []
    perfect: list[tuple[bool, ...]] = []
    overall_perfect: list[bool] = []
    distances: list[tuple[float | None, ...]] = []
    all_decompiled = True

    for dec in decompilers:
        # Errors: a function is in scope for `dec` if it attempted it (present in the
        # decompiled map); errored if it produced nothing (failed / timed out).
        attempted = dec in func.decompiled
        err_scope.append(attempted)
        err_errored.append(attempted and not func.decompiled[dec])

        if not _decompiled_by(func, dec):
            all_decompiled = False

        fperf = func.perfects.get(dec) or {}
        flags = tuple(bool(fperf.get(m)) for m in metrics)
        perfect.append(flags)
        overall_perfect.append(all(flags))

        # JS parity: `const dm = dd[d]; if (!dm) continue;` — a missing distances map
        # yields no values, and so does an empty one (every lookup is undefined).
        dmap = func.distances.get(dec)
        if dmap is None:
            distances.append(tuple(None for _ in distance_metrics))
        else:
            distances.append(
                tuple(
                    value if (value := dmap.get(m)) is not None and _js_is_finite(value) else None
                    for m in distance_metrics
                )
            )

    return _FunctionFacts(
        datasets=frozenset(func.datasets),
        all_decompiled=all_decompiled,
        err_scope=tuple(err_scope),
        err_errored=tuple(err_errored),
        measurable=measurable,
        all_measurable=all(measurable),
        perfect=tuple(perfect),
        overall_perfect=tuple(overall_perfect),
        distances=tuple(distances),
    )


def _distance_stats(values: list[float]) -> dict[str, Any] | None:
    """Summarize one decompiler's edit distances for one metric.

    ``None`` when nothing under the combo had a finite distance for the metric.

    JS parity: ``median`` is ``sorted[len // 2]`` — the *upper*-middle element, never
    the average of the two middles. For the even-length arrays that dominate this
    dataset that is not a true median, and :func:`statistics.median` would disagree.
    It is reproduced deliberately: it is the number the published report shows.

    Unlike ``per_metric``, this applies no shared-denominator universe — ``n`` is
    whatever this decompiler actually produced, so it differs per decompiler and from
    the metric's ``total``. ``at0`` is likewise counted from the distances map, an
    independent source of truth from the perfects map behind ``per_metric``; for
    ``byte_match`` the two legitimately disagree, so neither is derived from the other.

    ``mean``/``median`` are emitted unrounded: the client renders the mean with
    ``toFixed(1)`` and the median by plain string coercion, so any rounding here is a
    *second* rounding of an already-rounded number (see the note by ``ALL_PRESET``).
    """
    if not values:
        return None
    ordered = sorted(values)
    # Plain left-to-right summation, as in the JS `reduce`; math.fsum would be more
    # accurate and therefore a different number.
    mean = sum(values) / len(values)
    return {
        "mean": mean,
        "median": ordered[len(ordered) // 2],
        "n": len(values),
        "at0": sum(1 for value in values if value == 0),
    }


class _ComboAccumulator:
    """Accumulates one ``(preset, normalize)`` combo's tables over the single pass."""

    def __init__(self, decompilers: list[str], metrics: list[str], distance_metrics: list[str]):
        self._decompilers = decompilers
        self._metrics = metrics
        self._distance_metrics = distance_metrics
        n_dec, n_met, n_dist = len(decompilers), len(metrics), len(distance_metrics)
        self.functions = 0
        self.binaries = 0
        self._group_active = False
        self._perfect = [[0] * n_met for _ in range(n_dec)]
        self._total = [[0] * n_met for _ in range(n_dec)]
        self._overall_perfect = [0] * n_dec
        self._overall_total = [0] * n_dec
        self._errored = [0] * n_dec
        self._scope = [0] * n_dec
        self._distances: list[list[list[float]]] = [
            [[] for _ in range(n_dist)] for _ in range(n_dec)
        ]

    def add(self, facts: _FunctionFacts) -> None:
        """Fold one active function into this combo."""
        self.functions += 1
        self._group_active = True
        for di in range(len(self._decompilers)):
            if facts.err_scope[di]:
                self._scope[di] += 1
                if facts.err_errored[di]:
                    self._errored[di] += 1
            dec_perfect = facts.perfect[di]
            dec_total = self._total[di]
            dec_perfect_counts = self._perfect[di]
            for mi in range(len(self._metrics)):
                if not facts.measurable[mi]:
                    continue  # Unmeasurable for everyone: excluded uniformly.
                dec_total[mi] += 1
                if dec_perfect[mi]:
                    dec_perfect_counts[mi] += 1
            if facts.all_measurable:
                self._overall_total[di] += 1
                if facts.overall_perfect[di]:
                    self._overall_perfect[di] += 1
            dec_distances = self._distances[di]
            for mi, value in enumerate(facts.distances[di]):
                if value is not None:
                    dec_distances[mi].append(value)

    def end_group(self) -> None:
        """Close a binary group: it counts iff at least one function was active."""
        if self._group_active:
            self.binaries += 1
            self._group_active = False

    def result(self) -> dict[str, Any]:
        """Emit this combo per the schema (counts as ``[numerator, denominator]``)."""
        return {
            "functions": self.functions,
            "binaries": self.binaries,
            "per_metric": {
                dec: {
                    metric: [self._perfect[di][mi], self._total[di][mi]]
                    for mi, metric in enumerate(self._metrics)
                }
                for di, dec in enumerate(self._decompilers)
            },
            "overall": {
                dec: [self._overall_perfect[di], self._overall_total[di]]
                for di, dec in enumerate(self._decompilers)
            },
            "errors": {
                dec: [self._errored[di], self._scope[di]]
                for di, dec in enumerate(self._decompilers)
            },
            "distance": {
                dec: {
                    metric: _distance_stats(self._distances[di][mi])
                    for mi, metric in enumerate(self._distance_metrics)
                }
                for di, dec in enumerate(self._decompilers)
            },
        }


def _active_combos(
    facts: _FunctionFacts, preset_names: Iterable[str], match_all: bool = False
) -> list[tuple[str, bool]]:
    """The combos one function is active under.

    Mirrors ``isActive()``: membership is the preset tag on the function, and
    ``normalize=1`` additionally restricts to functions **every** decompiler
    decompiled — so scores compare like with like instead of rewarding a decompiler
    for skipping what it found hard.

    ``match_all`` is the preset-less fallback: every function joins the synthetic
    :data:`ALL_PRESET` combo whatever its (absent) tags say. It restores the old
    client's ``if (!state.dataset) return true;`` — see :func:`build_aggregates`.

    JS parity: ``isActive(group, func)`` takes a ``group`` and ignores it entirely.
    """
    combos: list[tuple[str, bool]] = []
    for name in preset_names:
        if match_all or name in facts.datasets:
            combos.append((name, False))
            if facts.all_decompiled:
                combos.append((name, True))
    return combos


def build_aggregates(function_data: FunctionData, scoreboard: Scoreboard) -> dict[str, Any]:
    """Precompute every aggregate the site needs — ``data/aggregates.json``.

    One pass over the per-function records fills all ``len(presets) x 2`` combos:
    the presets are non-exclusive membership tags and every per-function fact is
    selector-independent, so a function is reduced once and folded into each combo it
    is active under. That is ~10x cheaper than re-scanning per combo, and this runs on
    every site build.

    ``scoreboard`` supplies only the run's identity (name/version/timestamp/projects);
    every count comes from ``function_data``, which is the same source the scoreboard
    itself was aggregated from.

    A run with **no dataset presets** still gets numbers: presets are membership tags
    applied after the benchmark (``scoring.datasets.assign_datasets``), and tagging is
    best-effort — ``cli.py``'s ``report`` swallows any failure there. When there are
    none, emit one synthetic :data:`ALL_PRESET` combo over the whole corpus. The
    ``presets`` list stays empty, so no dataset selector renders and the client falls
    back to that combo: the site shows the full corpus with no selector, which is what
    the pre-aggregation client did (``isActive()`` began ``if (!state.dataset) return
    true;``). Without it every view renders an error banner and zero numbers.
    """
    content = load_content()
    decompilers = function_data.decompilers
    metrics = function_data.metrics
    distance_metrics = content.ordered_metrics(metrics)
    presets = function_data.dataset_presets
    preset_names = [preset.name for preset in presets]
    ged_present = "ged" in metrics

    # No presets: one synthetic combo that every function is active under.
    match_all = not preset_names
    combo_names = [ALL_PRESET] if match_all else preset_names

    accumulators: dict[tuple[str, bool], _ComboAccumulator] = {
        (name, normalize): _ComboAccumulator(decompilers, metrics, distance_metrics)
        for name in combo_names
        for normalize in (False, True)
    }

    total_functions = 0
    for group in function_data.groups:
        for func in group.functions:
            total_functions += 1
            facts = _function_facts(func, decompilers, metrics, distance_metrics, ged_present)
            for combo in _active_combos(facts, combo_names, match_all):
                accumulators[combo].add(facts)
        for accumulator in accumulators.values():
            accumulator.end_group()

    return {
        "name": scoreboard.name,
        "version": scoreboard.version,
        "generated_at": scoreboard.generated_at.isoformat(),
        "projects_evaluated": scoreboard.projects_evaluated
        or sorted({group.project for group in function_data.groups}),
        "decompilers": decompilers,
        "decompiler_versions": function_data.decompiler_versions,
        "metrics": metrics,
        # How to name and order those metrics on screen. `metrics` above is the run's
        # raw order (whatever the metrics happened to be registered in); the site sorts
        # and labels by this registry, which comes from content/metrics.toml. Without
        # it the columns would read "byte_match | ged | type_match" instead of
        # "Structure | Types | Recompile".
        "metric_registry": {
            spec.name: {
                "display_name": spec.display_name,
                "short_name": spec.short_name,
                "order": spec.order,
            }
            for spec in content.metrics
            if spec.name in metrics
        },
        "presets": resolve_presets(function_data, content),
        # Which view the site opens on, from views.toml's `default = true`. The
        # skeleton already marks that section `active`, so this is the schema's
        # record of the choice rather than the client's routing input (routing
        # happens before this file lands).
        "default_view": content.default_view,
        # Corpus-wide, selector-independent: `binaries` here counts BUILDS (one per
        # binary x opt level), the same population each combo's `binaries` is a
        # subset of. It can exceed every combo's count — a group whose function list
        # is empty is never active anywhere.
        "totals": {"functions": total_functions, "binaries": len(function_data.groups)},
        "combos": {
            combo_key(name, normalize): accumulator.result()
            for (name, normalize), accumulator in accumulators.items()
        },
    }


def _default_preset_name(content: Content, preset_names: list[str]) -> str | None:
    """Which preset the site opens on.

    The content registry marks its default explicitly, because the default used to be
    positional and reordering ``datasets.toml`` silently changed the landing view. If
    the run carries a preset set the registry doesn't know about, fall back to the
    first one so the site always opens on something.
    """
    default = content.default_dataset
    if default is not None and default.name in preset_names:
        return default.name
    return preset_names[0] if preset_names else None


def resolve_presets(
    function_data: FunctionData, content: Content | None = None
) -> list[dict[str, Any]]:
    """Join the run's preset **names** with the registry's **presentation**.

    This is the seam between two layers that must not know about each other.
    :mod:`decbench.scoring.datasets` owns which functions are in ``hard`` — a
    membership rule, baked into ``function_results.json`` at benchmark time.
    ``content/datasets.toml`` owns what the button says and which one is
    preselected. The two used to both carry label and description, and two copies
    of a string drift.

    The payoff: **editing ``content/datasets.toml`` and re-rendering changes the
    site's preset text without re-running the benchmark** — a ~day of decompiling
    is no longer the cost of a typo fix.

    A preset the registry has never heard of (an older ``function_results.json``,
    or a name added to scoring before its text was written) keeps whatever label
    and description were stored with it, so old data still renders.
    """
    content = content or load_content()
    specs = {spec.name: spec for spec in content.dataset_presets}
    names = [preset.name for preset in function_data.dataset_presets]
    default_name = _default_preset_name(content, names)

    out: list[dict[str, Any]] = []
    for preset in function_data.dataset_presets:
        spec = specs.get(preset.name)
        entry: dict[str, Any] = {
            "name": preset.name,
            "label": spec.label if spec else (preset.label or preset.name),
            "description": spec.description if spec else preset.description,
        }
        if preset.name == default_name:
            entry["default"] = True
        out.append(entry)
    return out


def build_payloads(function_data: FunctionData, scoreboard: Scoreboard) -> dict[str, Any]:
    """Build every data payload the site needs, keyed by data-file stem.

    The keys are the split tree's ``data/<key>.json`` filenames *and* the keys of
    ``window.__DECBENCH_INLINE__`` in the single-file report, so both delivery modes
    hand the client one shape and it never learns which it is running under.

    ``samples``/``hardest``/``history`` are serialized straight through: their metric
    values are what the Compare and Hardest views print, so they are emitted exactly as
    measured (see the note by ``ALL_PRESET`` for why they are not rounded).

    This is also the last gate before malware code reaches a published payload.
    ``samples``/``hardest`` are normally filtered where they are *built*
    (:func:`decbench.scoring.report_extras.attach_extras`), but both ``decbench
    report`` and ``decbench site build`` read a ``function_results.json`` straight
    from disk — and a file written before that filter existed still has the malware
    code baked in. Filtering here too means an old results tree cannot republish it.
    Only the two code-carrying payloads are touched: ``aggregates`` (the
    leaderboard / metrics / distance numbers) still counts every malware function.
    """
    from decbench.scoring.report_extras import drop_malware_entries, malware_projects

    excluded = malware_projects(function_data)
    samples = drop_malware_entries(function_data.samples, excluded, "samples")
    hardest = drop_malware_entries(function_data.hardest, excluded, "hardest")

    return {
        "aggregates": build_aggregates(function_data, scoreboard),
        "dataset": build_dataset_page(function_data),
        "samples": [s.model_dump(mode="json") for s in samples],
        "hardest": [h.model_dump(mode="json") for h in hardest],
        "history": [h.model_dump(mode="json") for h in function_data.history],
    }


@dataclass
class _ProjectStats:
    """Per-project rollup for the Dataset page."""

    labels: set[str] = field(default_factory=set)
    binaries: set[str] = field(default_factory=set)
    functions: int = 0


@dataclass(frozen=True)
class _ProjectRow:
    """One row of the Dataset page's project table."""

    name: str
    cats: list[str]
    loc: int
    binaries: int
    functions: int

    def as_dict(self) -> dict[str, Any]:
        """Emit this row per the schema."""
        return {
            "name": self.name,
            "cats": self.cats,
            "loc": self.loc,
            "binaries": self.binaries,
            "functions": self.functions,
        }


def _project_stats(function_data: FunctionData) -> dict[str, _ProjectStats]:
    """Roll the binary groups up per project (labels, distinct binaries, functions)."""
    stats: dict[str, _ProjectStats] = {}
    for group in function_data.groups:
        entry = stats.get(group.project)
        if entry is None:
            entry = stats[group.project] = _ProjectStats()
        entry.labels.update(group.labels)
        entry.binaries.add(group.binary)
        entry.functions += len(group.functions)
    return stats


def _categories_of(labels: set[str], categories: tuple[Category, ...]) -> list[str]:
    """The software types a project belongs to, in taxonomy order.

    A project is in a category when ANY of that category's labels appears on ANY of
    its binaries, so a project can span several categories.
    """
    return [cat.name for cat in categories if any(label in labels for label in cat.labels)]


def build_dataset_page(function_data: FunctionData) -> dict[str, Any]:
    """Precompute the Dataset page — ``data/dataset.json``.

    Corpus-wide and selector-independent: this page describes what was benchmarked,
    not how anyone scored, so neither the preset nor the normalize toggle applies.

    Note the Joern block is a *tooling health* report, not a score. ``source.lost`` is
    the share of functions GED cannot score because our own source front-end failed —
    charged to us, not to any decompiler — and ``output[dec]`` is how often Joern
    failed on that decompiler's output, which does count as its GED miss but is
    surfaced here so a reader can tell tooling loss from decompiler loss.
    """
    content = load_content()
    decompilers = function_data.decompilers
    ged_present = "ged" in function_data.metrics
    info = function_data.dataset_info or {}
    loc_by_project = info.get("loc_by_project") or {}

    stats = _project_stats(function_data)
    projects = [
        _ProjectRow(
            name=name,
            cats=_categories_of(stats[name].labels, content.categories),
            loc=loc_by_project.get(name) or 0,
            binaries=len(stats[name].binaries),
            functions=stats[name].functions,
        )
        for name in sorted(stats)
    ]
    categories = [
        {"name": cat.name, "count": sum(1 for p in projects if cat.name in p.cats)}
        for cat in content.categories
    ]

    # `unique_binaries` sums each project's distinct binary names — binaries are
    # unique within a project, not across the corpus (many projects ship a `main`).
    summary = {
        "projects": len(projects),
        "unique_binaries": sum(p.binaries for p in projects),
        "builds": len(function_data.groups),  # binary x opt-level instances
        "functions": sum(p.functions for p in projects),
        "total_loc": info.get("total_loc") or 0,
    }

    source_total = 0
    source_lost = 0
    output_failed = [0] * len(decompilers)
    output_scope = [0] * len(decompilers)
    for group in function_data.groups:
        for func in group.functions:
            attempted = [_decompiled_by(func, dec) for dec in decompilers]
            parsed = _source_parsed(func, decompilers, ged_present)
            if any(attempted):
                source_total += 1
                if not parsed:
                    source_lost += 1
            if not parsed:
                continue
            for di, dec in enumerate(decompilers):
                if not attempted[di]:
                    continue
                output_scope[di] += 1
                if not _has_ged(func, dec):
                    output_failed[di] += 1

    spot_check = info.get("joern") or {}
    return {
        "summary": summary,
        "categories": categories,
        # Table order: biggest project first (stable, so equal-LOC projects keep
        # their name order). Sorted AFTER the totals above are summed.
        "projects": [p.as_dict() for p in sorted(projects, key=lambda p: -p.loc)],
        "joern": {
            "source": {"lost": source_lost, "total": source_total},
            "output": {
                dec: [output_failed[di], output_scope[di]] for di, dec in enumerate(decompilers)
            },
            "spot_check": {
                "files_sampled": spot_check.get("files_sampled") or 0,
                "files_failed": spot_check.get("files_failed") or 0,
                "files_timed_out": spot_check.get("files_timed_out") or 0,
            },
        },
    }
