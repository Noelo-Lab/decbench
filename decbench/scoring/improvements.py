"""Find per-function *improvement cases* between two decompilers.

A decompiler developer wants to know: *where does another decompiler (the base)
beat mine (the target) on a given metric?* Each such function is a concrete,
actionable place to improve the target. This module reads an already-computed
:class:`~decbench.models.function_data.FunctionData` (the ``function_results.json``
persisted next to a scoreboard) and returns the functions where ``base`` scores
strictly better than ``target`` on one metric, respecting the metric's direction
(GED is lower-is-better with a perfect value of 0; byte_match/type_match are
higher-is-better with a perfect value of 1).

The comparison is per function; each :class:`ImprovementCase` carries enough to
locate the function on disk — the binary name, the resolved path to the compiled
binary, the function symbol, and (best effort) its address — by walking the
results tree with :mod:`decbench.utils.results_tree`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path

from decbench.models.function_data import FunctionData
from decbench.utils import results_tree


@dataclass
class ImprovementCase:
    """One function where ``base`` beats ``target`` on ``metric``."""

    project: str
    opt_level: str
    binary: str
    function: str
    base: str
    target: str
    metric: str

    base_value: float
    # None when the target produced no value for this metric on this function
    # (e.g. it failed to decompile it) and ``include_target_missing`` is set.
    target_value: float | None
    base_perfect: bool
    # Base's advantage magnitude (>= 0), always oriented "higher = base wins by
    # more"; ``inf`` when the target is missing entirely.
    margin: float
    target_missing: bool

    labels: list[str] = field(default_factory=list)
    binary_path: Path | None = None
    address: int | None = None

    def to_dict(self) -> dict:
        """JSON-friendly representation (paths as strings, address as hex)."""
        return {
            "project": self.project,
            "opt_level": self.opt_level,
            "binary": self.binary,
            "binary_path": str(self.binary_path) if self.binary_path else None,
            "function": self.function,
            "address": self.address,
            "address_hex": (f"0x{self.address:x}" if self.address is not None else None),
            "base": self.base,
            "target": self.target,
            "metric": self.metric,
            "base_value": self.base_value,
            "base_perfect": self.base_perfect,
            "target_value": self.target_value,
            "target_missing": self.target_missing,
            "margin": (None if math.isinf(self.margin) else self.margin),
            "labels": list(self.labels),
        }


def metric_direction(metric: str, fd: FunctionData) -> tuple[bool, float]:
    """Return ``(lower_is_better, perfect_value)`` for ``metric``.

    Prefers the registered metric's own attributes; falls back to the perfect
    value recorded in the dataset (treating a perfect value of 0 as
    lower-is-better) so the function still works for metrics not importable here.
    """
    perfect = fd.perfect_values.get(metric)
    try:
        import decbench.metrics  # noqa: F401  (register built-in metrics)
        from decbench.metrics.registry import MetricRegistry

        m = MetricRegistry.get(metric)
        return bool(m.lower_is_better), (perfect if perfect is not None else m.perfect_value)
    except Exception:
        if perfect is None:
            perfect = 0.0
        return (perfect == 0.0), perfect


def _base_beats_target(
    base_value: float,
    target_value: float | None,
    lower_is_better: bool,
) -> tuple[bool, float]:
    """Whether base wins and by how much (margin >= 0; inf if target missing)."""
    if target_value is None:
        return True, math.inf
    if lower_is_better:
        return base_value < target_value, target_value - base_value
    return base_value > target_value, base_value - target_value


def find_improvement_cases(
    fd: FunctionData,
    base: str,
    target: str,
    metric: str = "ged",
    *,
    perfect_only: bool = False,
    include_target_missing: bool = False,
    results_root: Path | None = None,
) -> list[ImprovementCase]:
    """Return functions where ``base`` beats ``target`` on ``metric``.

    Args:
        fd: The per-function dataset (``function_results.json``).
        base: Decompiler id whose wins we look for.
        target: Decompiler id being improved (the loser).
        metric: Metric to compare on (default ``ged``).
        perfect_only: Only include functions where ``base`` is a *perfect* match
            on the metric (GED == 0, byte/type_match == 1).
        include_target_missing: Also include functions ``base`` scored but for
            which ``target`` has no usable score — either no value at all (a
            decompile failure) or a non-finite error value (e.g. a GED of ``inf``
            when the target decompiled the function but GED could not be
            computed). Off by default so the result is strictly a metric win.
        results_root: Root of the results tree. When given, each case is resolved
            to its compiled-binary path and function address on disk.

    Returns:
        Cases sorted by margin (largest base advantage first; target-missing
        first), then by project / binary / function for a stable order.
    """
    if base not in fd.decompilers:
        raise ValueError(f"base decompiler {base!r} not in dataset {fd.decompilers}")
    if target not in fd.decompilers:
        raise ValueError(f"target decompiler {target!r} not in dataset {fd.decompilers}")
    if base == target:
        raise ValueError("base and target decompilers must differ")
    if metric not in fd.metrics:
        raise ValueError(f"metric {metric!r} not in dataset {fd.metrics}")

    lower_is_better, perfect_value = metric_direction(metric, fd)
    cases: list[ImprovementCase] = []

    for group in fd.groups:
        group_cases: list[ImprovementCase] = []
        for rec in group.functions:
            base_value = rec.values.get(base, {}).get(metric)
            if base_value is None or not math.isfinite(base_value):
                continue  # base must actually have a (finite) score to be winning
            base_perfect = bool(rec.perfects.get(base, {}).get(metric, False))
            if perfect_only and not base_perfect:
                continue

            target_value = rec.values.get(target, {}).get(metric)
            # A non-finite target score (e.g. GED's ``inf`` error sentinel) is a
            # tooling failure, not a place the target is genuinely worse — treat
            # it exactly like a missing value so it is gated behind
            # ``include_target_missing`` and never ranked as a real metric win.
            if target_value is not None and not math.isfinite(target_value):
                target_value = None
            target_missing = target_value is None
            if target_missing and not include_target_missing:
                continue

            won, margin = _base_beats_target(base_value, target_value, lower_is_better)
            if not won:
                continue

            group_cases.append(
                ImprovementCase(
                    project=group.project,
                    opt_level=group.opt_level,
                    binary=group.binary,
                    function=rec.function,
                    base=base,
                    target=target,
                    metric=metric,
                    base_value=base_value,
                    target_value=target_value,
                    base_perfect=base_perfect,
                    margin=margin,
                    target_missing=target_missing,
                    labels=list(rec.labels),
                )
            )

        if group_cases and results_root is not None:
            _resolve_locations(group_cases, results_root, base, target, fd.decompilers)
        cases.extend(group_cases)

    # Largest base advantage first (target-missing → inf sorts first), then a
    # stable secondary order so equal-margin rows are deterministic.
    cases.sort(
        key=lambda c: (
            -c.margin if math.isfinite(c.margin) else float("-inf"),
            c.project,
            c.opt_level,
            c.binary,
            c.function,
        )
    )
    return cases


def _artifact_name(decompiler_id: str) -> str:
    """The unversioned name a decompiler writes its artifacts under.

    Decompiler ids may be ``name@version`` (e.g. ``ghidra@12.1``) but
    ``DecompilationResult.to_c_file`` names the artifact by the bare ``name``
    (``ghidra_<stem>.c``), so map ids back to that.
    """
    return decompiler_id.split("@", 1)[0]


def _resolve_locations(
    group_cases: list[ImprovementCase],
    results_root: Path,
    base: str,
    target: str,
    all_decompilers: list[str],
) -> None:
    """Fill in ``binary_path`` and ``address`` for one binary's cases in place."""
    g = group_cases[0]
    comp = results_tree.compiled_dir(results_root, g.opt_level, g.project)
    binary_path = results_tree.resolve_binary(comp, g.binary)

    # Addresses are decompiler-emitted (in the .c header). Any decompiler that
    # decompiled the function has the same file-space address, so try the base
    # first, then the target, then any other decompiler's artifact for this
    # binary until every function is located.
    addr_map: dict[str, int] = {}
    tried: set[str] = set()
    wanted = {c.function for c in group_cases}

    def merge(decompiler_id: str) -> bool:
        """Parse one decompiler's artifact; return True once all funcs are found."""
        art = _artifact_name(decompiler_id)
        if art not in tried:
            tried.add(art)
            c_path = results_tree.decompiled_c_path(
                results_root, g.opt_level, g.project, art, g.binary
            )
            for name, addr in results_tree.function_addresses(c_path).items():
                addr_map.setdefault(name, addr)
        return wanted.issubset(addr_map)

    done = merge(base) or merge(target)
    if not done:
        for dec in all_decompilers:
            if merge(dec):
                break

    for c in group_cases:
        c.binary_path = binary_path
        c.address = addr_map.get(c.function)


def _fmt_value(v: float | None) -> str:
    if v is None:
        return "(no score)"
    if math.isinf(v):
        return "inf"
    return f"{v:g}"


def render_text(
    cases: list[ImprovementCase],
    fd: FunctionData,
    *,
    base: str,
    target: str,
    metric: str,
    total: int,
    perfect_only: bool = False,
) -> str:
    """Render (a possibly-truncated) list of cases as an aligned text report.

    ``cases`` is what to display (already limited); ``total`` is the full count
    before any limit was applied.
    """
    lower_is_better, perfect_value = metric_direction(metric, fd)
    direction = "lower is better" if lower_is_better else "higher is better"

    lines: list[str] = []
    flag = "  [base-perfect only]" if perfect_only else ""
    lines.append(f"{base} beats {target} on '{metric}' — {total} case(s){flag}")
    lines.append(f"metric: {metric}  ({direction}, perfect = {perfect_value:g})")
    if not cases:
        lines.append("(no functions matched)")
        return "\n".join(lines)
    if len(cases) < total:
        lines.append(f"showing {len(cases)} of {total}, largest margin first")
    else:
        lines.append(f"showing all {total}, largest margin first")
    lines.append("")

    addr_w = max((len(f"0x{c.address:x}") for c in cases if c.address is not None), default=1)
    addr_w = max(addr_w, 3)
    func_w = min(max(len(c.function) for c in cases), 48)

    # Group consecutive cases by (project, opt, binary) preserving margin order.
    last_key: tuple[str, str, str] | None = None
    for c in cases:
        key = (c.project, c.opt_level, c.binary)
        if key != last_key:
            last_key = key
            path = str(c.binary_path) if c.binary_path else "(binary not found)"
            lines.append(f"── {c.project} / {c.opt_level} / {c.binary} ──  {path}")
        addr = f"0x{c.address:x}" if c.address is not None else "?"
        star = "*" if c.base_perfect else " "
        margin = "—" if math.isinf(c.margin) else f"{c.margin:g}"
        lines.append(
            f"   {addr:<{addr_w}}  {c.function[:func_w]:<{func_w}}  "
            f"{base}={_fmt_value(c.base_value)}{star}  "
            f"{target}={_fmt_value(c.target_value)}  Δ{margin}"
        )

    binaries = {(c.project, c.opt_level, c.binary) for c in cases}
    projects = {c.project for c in cases}
    lines.append("")
    lines.append(f"{len(cases)} shown across {len(binaries)} binaries, {len(projects)} projects")
    return "\n".join(lines)
