"""Builders for the HTML report's v2 extras: hardest functions and history.

These are pure functions consumed by the WEB cluster's renderer
(``decbench/rendering/html.py``). They turn the pipeline's nested evaluation /
decompilation results into the bounded, code-carrying ``HardestEntry`` list and
the ``HistoryPoint`` list embedded in :class:`FunctionData`.

Design goals:
- Pure & defensive. ``attach_extras`` must never raise (each section is wrapped
  in try/except), so a malformed corner of the results never sinks a report.
- Read decompiled code from
  ``decompile_results[proj][opt_level][binary][dec].functions[fn].decompiled_code``.
- "Worst" = farthest from the metric's ``perfect_value`` (pulled from the
  :class:`MetricRegistry`).
- **Never emit malware code.** See :data:`MALWARE_LABEL` below.
"""

from __future__ import annotations

import logging
import os
import random
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, Any

from decbench.models.function_data import HardestEntry, HistoryPoint

if TYPE_CHECKING:
    from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
    from decbench.models.metrics import MetricResult
    from decbench.models.project import OptimizationLevel, Project

logger = logging.getLogger(__name__)

#: Label carried by every :class:`BinaryGroup` built from an ``is_malware``
#: project (see ``projects/malware/*.toml``). It is the render-time signal that
#: a function's code is REAL MALWARE source.
MALWARE_LABEL = "malware"

#: Opt-OUT switch: set ``DECBENCH_PUBLISH_MALWARE=1`` to put malware code back
#: into the report payloads. Default is to EXCLUDE.
PUBLISH_MALWARE_ENV = "DECBENCH_PUBLISH_MALWARE"


def publish_malware_allowed() -> bool:
    """Whether malware code may be embedded in report payloads (default: NO).

    WHY THIS EXISTS — do not "simplify" this away:

    ``build_samples`` / ``build_hardest`` lift **source and decompiled C** out of
    ``results/`` and into ``samples``/``hardest``, which are committed to the repo
    (``site/data/*.json``) and published by ``.github/workflows/pages.yml``. Six
    benchmark targets (mirai, mirai-win, mydoom, x0r-usb, minipig, dexter) are REAL
    MALWARE compiled from theZoo — Mirai being the most notorious IoT botnet source
    in existence.

    Three reasons the default must stay EXCLUDE:

    1. **The published site is public.** GitHub Pages access control is
       Enterprise-Cloud-only; on Pro/Team a *private* repo still publishes a
       *public* site. No auth, no referrer check.
    2. **It breaks the project's containment invariant.** ``is_malware`` is
       enforced at COMPILE time (``pipeline/compile.py`` refuses to build outside a
       container) and the binaries never leave ``results/`` — but nothing stopped
       the *code* from being republished at render time. This closes that gap.
    3. **Republishing Mirai on an org's github.io is a GitHub Acceptable-Use /
       takedown risk.**

    Set the env var only for a LOCAL-ONLY report you will not commit or publish.
    """
    return os.environ.get(PUBLISH_MALWARE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def malware_projects(
    function_data: FunctionData | None = None,
    projects: Sequence[Project] | None = None,
) -> set[str]:
    """Names of projects whose code must never be published.

    Unions two independent signals so a gap in either still fails closed:

    * every :class:`BinaryGroup` from a malware target carries
      :data:`MALWARE_LABEL` (verified across the full run: all 6 malware projects
      labeled, no false positives) — this is the only signal available at render
      time, when the project TOMLs are long gone; and
    * ``ProjectConfig.is_malware``, when the caller happens to have the
      :class:`Project` objects to hand.
    """
    names: set[str] = set()
    try:
        for group in getattr(function_data, "groups", None) or []:
            if MALWARE_LABEL in (group.labels or []):
                names.add(group.project)
    except Exception:
        pass
    try:
        for project in projects or []:
            config = getattr(project, "config", None)
            if getattr(config, "is_malware", False):
                names.add(getattr(config, "name", None) or getattr(project, "name", ""))
    except Exception:
        pass
    names.discard("")
    return names


def _log_exclusions(kind: str, dropped: Counter[str]) -> None:
    """Make an exclusion visible rather than silent.

    WARNING (not info) on purpose: dropping content from a published artifact is
    something a maintainer should see without opting into debug logging. Python's
    last-resort handler puts it on stderr even when nothing configures logging, so
    this needs no ``print`` — adding one would just double-report.
    """
    if not dropped:
        return
    detail = ", ".join(f"{project}={count}" for project, count in sorted(dropped.items()))
    logger.warning(
        "excluded %d malware function(s) from `%s` (%s); code payloads are not "
        "published. Set %s=1 for a local-only report.",
        sum(dropped.values()),
        kind,
        detail,
        PUBLISH_MALWARE_ENV,
    )


def drop_malware_entries(entries: Sequence[Any], excluded: set[str], kind: str) -> list[Any]:
    """Filter already-built ``samples``/``hardest`` entries by project name.

    The publication-time counterpart to the generation-time filtering in
    :func:`build_samples` / :func:`build_hardest`: a ``function_results.json``
    written before this filter existed still carries malware code, and
    ``decbench site build`` / ``decbench report`` read that file straight from
    disk without ever calling :func:`attach_extras`. Without this, an old results
    tree would republish the payload.
    """
    if not entries:
        return list(entries or [])
    if not excluded or publish_malware_allowed():
        return list(entries)
    kept: list[Any] = []
    dropped: Counter[str] = Counter()
    for entry in entries:
        project = getattr(entry, "project", None)
        if project is None and isinstance(entry, dict):
            project = entry.get("project")
        if project in excluded:
            dropped[str(project)] += 1
            continue
        kept.append(entry)
    _log_exclusions(kind, dropped)
    return kept


def _perfect_value_for(metric_name: str) -> float:
    """Return a metric's perfect value, tolerating an unregistered metric."""
    try:
        from decbench.metrics.registry import MetricRegistry

        return MetricRegistry.get(metric_name).perfect_value
    except Exception:
        return 0.0


def _opt_value(opt_level: Any) -> str:
    """Normalize an OptimizationLevel enum (or string) to its string value."""
    return opt_level.value if hasattr(opt_level, "value") else str(opt_level)


def _lookup_decompiled(
    decompile_results: Any,
    project: str,
    opt_level: Any,
    binary: str,
    dec_name: str,
    func_name: str,
) -> str | None:
    """Best-effort lookup of decompiled C for one function.

    ``decompile_results`` is ``proj -> OptimizationLevel -> binary -> dec ->
    DecompilationResult``. The opt-level key may be an enum or a string, so we
    try both.
    """
    if not decompile_results:
        return None
    try:
        opt_results = decompile_results.get(project)
        if not opt_results:
            return None
        binary_results = opt_results.get(opt_level)
        if binary_results is None:
            # Fall back to matching by string value of the opt key.
            ov = _opt_value(opt_level)
            for key, val in opt_results.items():
                if _opt_value(key) == ov:
                    binary_results = val
                    break
        if not binary_results:
            return None
        dec_results = binary_results.get(binary)
        if not dec_results:
            return None
        dec_result = dec_results.get(dec_name)
        if dec_result is None:
            return None
        func = dec_result.functions.get(func_name)
        if func is None:
            return None
        return func.decompiled_code
    except Exception:
        return None


def _lookup_binary_path(
    decompile_results: Any,
    project: str,
    opt_level: Any,
    binary: str,
) -> Any:
    """Best-effort path to the original binary for a (project, opt, binary)."""
    if not decompile_results:
        return None
    try:
        opt_results = decompile_results.get(project) or {}
        binary_results = opt_results.get(opt_level)
        if binary_results is None:
            ov = _opt_value(opt_level)
            for key, val in opt_results.items():
                if _opt_value(key) == ov:
                    binary_results = val
                    break
        if not binary_results:
            return None
        dec_results = binary_results.get(binary) or {}
        for dec_result in dec_results.values():
            bp = getattr(dec_result, "binary_path", None)
            if bp is not None:
                return bp
    except Exception:
        return None
    return None


def _lookup_source(
    decompile_results: Any,
    project: str,
    opt_level: Any,
    binary: str,
    func_name: str,
) -> str | None:
    """Best-effort original source text for one function (for side-by-side view)."""
    bp = _lookup_binary_path(decompile_results, project, opt_level, binary)
    if bp is None:
        return None
    try:
        from pathlib import Path

        from decbench.utils.source_extract import function_source

        return function_source(Path(bp), func_name)
    except Exception:
        return None


def _lookup_line_count(
    decompile_results: Any,
    project: str,
    opt_level: Any,
    binary: str,
    dec_name: str,
    func_name: str,
) -> int | None:
    """Best-effort decompiled line count for one function (the 'size')."""
    if not decompile_results:
        return None
    try:
        opt_results = decompile_results.get(project) or {}
        binary_results = opt_results.get(opt_level)
        if binary_results is None:
            ov = _opt_value(opt_level)
            for key, val in opt_results.items():
                if _opt_value(key) == ov:
                    binary_results = val
                    break
        if not binary_results:
            return None
        dec_result = (binary_results.get(binary) or {}).get(dec_name)
        if dec_result is None:
            return None
        func = dec_result.functions.get(func_name)
        if func is None:
            return None
        return func.line_count
    except Exception:
        return None


def _count_candidate_functions(opt_results: Any) -> int:
    """Distinct function names under one project's evaluation results (for logging)."""
    names: set[str] = set()
    try:
        for binary_results in (opt_results or {}).values():
            for dec_results in (binary_results or {}).values():
                for metric_results in (dec_results or {}).values():
                    for result in (metric_results or {}).values():
                        names.update(getattr(result, "function_results", None) or {})
    except Exception:
        return 0
    return len(names)


def build_hardest(
    evaluation_results: dict[
        str,
        dict[OptimizationLevel, dict[str, dict[str, dict[str, MetricResult]]]],
    ],
    decompile_results: Any,
    projects: list[Project] | None = None,
    per_metric_per_dec: int = 15,
    excluded_projects: Iterable[str] | None = None,
) -> list[HardestEntry]:
    """Pick the worst N functions per (metric, decompiler).

    "Worst" = the largest absolute distance from the metric's ``perfect_value``.
    Only functions that have decompiled code are included (no code → skipped).

    Args:
        evaluation_results: Nested
            ``project -> OptimizationLevel -> binary -> decompiler -> metric ->
            MetricResult`` mapping, where ``MetricResult.function_results`` maps
            function name to a ``MetricValue`` (with ``.value``).
        decompile_results: Nested decompilation results used to pull the
            decompiled (and best-effort source) code for each entry.
        projects: Used (with ``excluded_projects``) to identify malware targets
            whose code must not be published; see :func:`publish_malware_allowed`.
        per_metric_per_dec: How many worst functions to keep for each
            (metric, decompiler) pair.
        excluded_projects: Project names whose code must never be embedded.
            Defaults to the malware targets. Entries are dropped *before* the
            worst-N cut, so excluding them does not shorten the list — the next
            worst non-excluded function takes the slot.

    Returns:
        A flat list of :class:`HardestEntry`, grouped implicitly by
        (metric, decompiler) and ordered worst-first within each group.
    """
    excluded = set(excluded_projects or ()) or malware_projects(None, projects)
    if publish_malware_allowed():
        excluded = set()
    dropped: Counter[str] = Counter()

    # (metric, dec) -> list of candidate dicts
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    perfect_cache: dict[str, float] = {}

    for project, opt_results in (evaluation_results or {}).items():
        if project in excluded:
            dropped[str(project)] += _count_candidate_functions(opt_results)
            continue
        for opt_level, binary_results in (opt_results or {}).items():
            opt_str = _opt_value(opt_level)
            for binary, dec_results in (binary_results or {}).items():
                for dec_name, metric_results in (dec_results or {}).items():
                    for metric_name, result in (metric_results or {}).items():
                        if metric_name not in perfect_cache:
                            perfect_cache[metric_name] = _perfect_value_for(metric_name)
                        perfect = perfect_cache[metric_name]
                        fr = getattr(result, "function_results", None) or {}
                        for func_name, mv in fr.items():
                            try:
                                value = float(mv.value)
                            except Exception:
                                continue
                            distance = abs(value - perfect)
                            if distance == 0.0:
                                continue  # perfect ⇒ not "hard"
                            buckets.setdefault((metric_name, dec_name), []).append(
                                {
                                    "metric": metric_name,
                                    "decompiler": dec_name,
                                    "project": project,
                                    "opt_level": opt_str,
                                    "opt_key": opt_level,
                                    "binary": binary,
                                    "function": func_name,
                                    "value": value,
                                    "perfect_value": perfect,
                                    "distance": distance,
                                }
                            )

    entries: list[HardestEntry] = []
    for (metric_name, dec_name), candidates in buckets.items():
        # Worst first: farthest from perfect, then larger raw value as tiebreak.
        candidates.sort(key=lambda c: (c["distance"], c["value"]), reverse=True)
        kept = 0
        for c in candidates:
            if kept >= per_metric_per_dec:
                break
            code = _lookup_decompiled(
                decompile_results,
                c["project"],
                c["opt_key"],
                c["binary"],
                dec_name,
                c["function"],
            )
            if not code:
                continue  # require code to be worth showing
            size = _lookup_line_count(
                decompile_results,
                c["project"],
                c["opt_key"],
                c["binary"],
                dec_name,
                c["function"],
            )
            entries.append(
                HardestEntry(
                    metric=metric_name,
                    decompiler=dec_name,
                    project=c["project"],
                    opt_level=c["opt_level"],
                    binary=c["binary"],
                    function=c["function"],
                    value=c["value"],
                    perfect_value=c["perfect_value"],
                    size=size,
                    labels=[],
                    decompiled_code=code,
                    source_code=_lookup_source(
                        decompile_results,
                        c["project"],
                        c["opt_key"],
                        c["binary"],
                        c["function"],
                    ),
                )
            )
            kept += 1

    _log_exclusions("hardest", dropped)
    return entries


def _large_predicate(function_data: FunctionData) -> Any:
    """Return ``is_large(record)`` using the same rule as :mod:`decbench.scoring.datasets`."""
    from decbench.scoring.datasets import large_threshold

    threshold = large_threshold(function_data)

    def is_large(f: FunctionRecord) -> bool:
        if f.size is not None and threshold is not None:
            return f.size >= threshold
        return "large" in (f.labels or [])

    return is_large


def _topup_samples(
    function_data: FunctionData,
    removed: list[tuple[BinaryGroup, FunctionRecord]],
    kept: list[tuple[BinaryGroup, FunctionRecord]],
    excluded: set[str],
    headroom: int = 4,
) -> list[tuple[BinaryGroup, FunctionRecord]]:
    """Replace excluded ``tiny`` records with non-excluded ones of the same shape.

    The ``tiny`` slice is a deliberately even sample (see
    :mod:`decbench.scoring.datasets`): balanced across the inlined / optimized /
    unoptimized / large categories, spread across projects, at most one function
    per binary. Dropping the malware members without replacing them would both
    shorten the Compare view and skew that balance, so each dropped record is
    replaced by one drawn from the same ``(opt_level, is_large)`` bucket, reusing
    the same even-spread sampler and honouring the binaries already taken.

    ``tiny`` *membership itself is left untouched* — it feeds the report's
    client-side aggregates, and re-sampling it would move published numbers.
    ``headroom`` over-draws so replacements that turn out to have no decompiled
    code can be skipped without shortening the result.
    """
    # Same-package internals: the tiny slice's own sampler, reused so the
    # replacements obey the identical spread rules.
    from decbench.scoring.datasets import _resolve_seed, _sample_even

    is_large = _large_predicate(function_data)
    want: Counter[tuple[str, bool]] = Counter((g.opt_level, is_large(f)) for g, f in removed)

    chosen_ids: set[int] = {id(f) for _g, f in kept}
    used_bins: set[tuple[str, str, str]] = {(g.project, g.opt_level, g.binary) for g, _f in kept}

    pools: dict[tuple[str, bool], list[tuple[BinaryGroup, FunctionRecord]]] = defaultdict(list)
    for g in function_data.groups:
        if g.project in excluded:
            continue
        for f in g.functions:
            if id(f) in chosen_ids:
                continue
            key = (g.opt_level, is_large(f))
            if key in want:
                pools[key].append((g, f))

    rng = random.Random(_resolve_seed(None))
    primary: list[tuple[BinaryGroup, FunctionRecord]] = []
    extras: list[tuple[BinaryGroup, FunctionRecord]] = []
    for key, count in sorted(want.items()):
        drawn = _sample_even(pools.get(key, []), count * headroom, chosen_ids, used_bins, rng)
        primary.extend(drawn[:count])  # the balanced replacements...
        extras.extend(drawn[count:])  # ...and spares, used only if code is missing
    return primary + extras


def build_samples(
    function_data: FunctionData,
    decompile_results: Any,
    max_samples: int = 140,
    excluded_projects: Iterable[str] | None = None,
) -> list[Any]:
    """Curated side-by-side samples (source + each decompiler's output).

    Prefers the ``tiny`` representative slice (so it spans projects/opt levels at
    one function per binary); falls back to any function with decompiled code.
    Requires datasets to be assigned first (see :func:`attach_extras`).

    Functions from ``excluded_projects`` (by default the malware targets — see
    :func:`publish_malware_allowed`) are dropped and *replaced* by equivalent
    non-malware functions, so the slice keeps its size and spread.
    """
    from decbench.models.function_data import SampleEntry

    samples: list[SampleEntry] = []
    groups = function_data.groups

    def opt_key_for(group_opt: str) -> Any:
        return group_opt  # _lookup_* tolerate string opt keys via _opt_value

    tiny = [(g, f) for g in groups for f in g.functions if "tiny" in (f.datasets or [])]
    candidates = tiny or [(g, f) for g in groups for f in g.functions]
    # Publish no more than the unfiltered slice would have — and, thanks to the
    # top-up below, no fewer.
    limit = min(max_samples, len(candidates))

    excluded = set(excluded_projects or ()) or malware_projects(function_data)
    if publish_malware_allowed():
        excluded = set()
    if excluded:
        kept = [(g, f) for g, f in candidates if g.project not in excluded]
        removed = [(g, f) for g, f in candidates if g.project in excluded]
        if removed:
            _log_exclusions("samples", Counter(g.project for g, _f in removed))
            if tiny:
                kept += _topup_samples(function_data, removed, kept, excluded)
        candidates = kept

    for g, f in candidates:
        if len(samples) >= limit:
            break
        decompiled: dict[str, str] = {}
        for dec in function_data.decompilers:
            code = _lookup_decompiled(
                decompile_results,
                g.project,
                opt_key_for(g.opt_level),
                g.binary,
                dec,
                f.function,
            )
            if code:
                decompiled[dec] = code
        if not decompiled:
            continue
        source = _lookup_source(
            decompile_results, g.project, opt_key_for(g.opt_level), g.binary, f.function
        )
        samples.append(
            SampleEntry(
                project=g.project,
                opt_level=g.opt_level,
                binary=g.binary,
                function=f.function,
                size=f.size,
                labels=f.labels,
                source_code=source,
                decompiled=decompiled,
                values=f.values,
                perfects=f.perfects,
            )
        )
    return samples


def compute_compile_rates(evaluation_results: Any) -> dict[str, float]:
    """decompiler -> fraction of byte_match functions whose code recompiled.

    Reads the ``compilable`` flag the byte_match metric records per function.
    """
    comp: dict[str, int] = {}
    tot: dict[str, int] = {}
    for _project, opt_results in (evaluation_results or {}).items():
        for _opt, binary_results in (opt_results or {}).items():
            for _binary, dec_results in (binary_results or {}).items():
                for dec_name, metric_results in (dec_results or {}).items():
                    bm = (metric_results or {}).get("byte_match")
                    if bm is None:
                        continue
                    for mv in getattr(bm, "function_results", {}).values():
                        meta = getattr(mv, "metadata", None) or {}
                        if "compilable" not in meta:
                            continue
                        tot[dec_name] = tot.get(dec_name, 0) + 1
                        if meta.get("compilable"):
                            comp[dec_name] = comp.get(dec_name, 0) + 1
    return {d: comp.get(d, 0) / n for d, n in tot.items() if n}


def build_history(
    history_inputs: Iterable[Any] | None,
) -> list[HistoryPoint]:
    """Build ``HistoryPoint`` records from loosely-typed inputs.

    Accepts an iterable of either:
    - dicts with keys ``decompiler``, ``version``, optional ``date``,
      ``scores`` (metric -> pct), ``overall``; or
    - tuples/lists ``(decompiler, version, date, scores, overall)`` (trailing
      items optional).

    Anything that can't be coerced is skipped. The lead supplies inputs.
    """
    points: list[HistoryPoint] = []
    if not history_inputs:
        return points

    for item in history_inputs:
        try:
            if isinstance(item, HistoryPoint):
                points.append(item)
                continue
            if isinstance(item, dict):
                decompiler = item.get("decompiler")
                version = item.get("version")
                if decompiler is None or version is None:
                    continue
                points.append(
                    HistoryPoint(
                        decompiler=str(decompiler),
                        version=str(version),
                        date=item.get("date"),
                        scores={str(k): float(v) for k, v in (item.get("scores") or {}).items()},
                        overall=float(item.get("overall", 0.0) or 0.0),
                    )
                )
                continue
            # Tuple / list form.
            seq = list(item)
            if len(seq) < 2:
                continue
            decompiler = seq[0]
            version = seq[1]
            date = seq[2] if len(seq) > 2 else None
            scores = seq[3] if len(seq) > 3 else {}
            overall = seq[4] if len(seq) > 4 else 0.0
            points.append(
                HistoryPoint(
                    decompiler=str(decompiler),
                    version=str(version),
                    date=str(date) if date is not None else None,
                    scores={str(k): float(v) for k, v in (scores or {}).items()},
                    overall=float(overall or 0.0),
                )
            )
        except Exception:
            continue

    return points


def attach_extras(
    function_data: FunctionData,
    *,
    evaluation_results: Any,
    decompile_results: Any,
    projects: list[Project] | None = None,
    history_inputs: Iterable[Any] | None = None,
    per_metric_per_dec: int = 15,
) -> FunctionData:
    """Populate ``function_data.hardest`` (and ``history`` if inputs given).

    Code-carrying sections (``hardest``, ``samples``) exclude malware targets by
    default — see :func:`publish_malware_allowed`. The score/aggregate path is
    deliberately untouched: malware functions still count in every metric.
    """
    # Derived once from the label signal (+ is_malware when projects are given)
    # and shared by both code-carrying builders.
    excluded = malware_projects(function_data, projects)

    try:
        function_data.hardest = build_hardest(
            evaluation_results,
            decompile_results,
            projects,
            per_metric_per_dec=per_metric_per_dec,
            excluded_projects=excluded,
        )
    except Exception:
        function_data.hardest = []

    if history_inputs is not None:
        try:
            function_data.history = build_history(history_inputs)
        except Exception:
            function_data.history = []

    # Tag each function with its dataset presets (full/hard/hard-inlined/tiny)
    # so the report shows a single dataset selector instead of many toggles.
    # Must run BEFORE build_samples (which prefers the `tiny` slice).
    try:
        from decbench.scoring.datasets import assign_datasets

        assign_datasets(function_data)
    except Exception:
        pass

    # Side-by-side Compare samples (original source vs each decompiler's output).
    # Runs after assign_datasets so the `tiny` slice (and its malware-replacement
    # top-up) is available.
    try:
        function_data.samples = build_samples(
            function_data, decompile_results, excluded_projects=excluded
        )
    except Exception:
        function_data.samples = []

    # Per-decompiler recompilation (compilability) rate for the Metrics page.
    try:
        function_data.compile_rates = compute_compile_rates(evaluation_results)
    except Exception:
        function_data.compile_rates = {}

    return function_data
