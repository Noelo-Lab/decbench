"""Render-time hiding of specific decompilers from the site.

Some decompilers are benchmarked and kept in ``function_results.json`` but should
not appear on the published site (e.g. an experimental backend whose numbers are
not ready to show). Rather than delete their results or re-run the benchmark
without them, this module produces *filtered copies* of the
:class:`~decbench.models.function_data.FunctionData` and
:class:`~decbench.models.scoreboard.Scoreboard` with the hidden decompilers
stripped from every list, map, and code-carrying payload. The two rendering entry
points (:func:`decbench.rendering.html.render_html_report` and
:func:`decbench.rendering.site.build_site`) pass their inputs through
:func:`apply_hidden_decompilers` first, so the whole rendering stack below them
only ever sees the visible decompilers.

The hidden set lives in ``content/site.toml`` (``[decompilers] hidden``). A name
matches a decompiler id exactly OR by its base name before ``@``, so hiding
``"phoenix"`` also hides any ``"phoenix@<version>"``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from decbench.models.function_data import FunctionData
from decbench.models.scoreboard import Scoreboard
from decbench.rendering.content import Content, load_content

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["apply_hidden_decompilers", "is_hidden"]


def _base_name(dec: str) -> str:
    """A decompiler id's base name (``ghidra@12.1`` -> ``ghidra``)."""
    return dec.split("@", 1)[0]


def is_hidden(dec: str, hidden: Iterable[str]) -> bool:
    """Whether decompiler id ``dec`` is hidden by exact id or base name."""
    hidden_set = set(hidden)
    return dec in hidden_set or _base_name(dec) in hidden_set


def _visible(decompilers: Iterable[str], hidden: Iterable[str]) -> list[str]:
    """The visible decompilers, order preserved."""
    hidden_set = set(hidden)
    return [d for d in decompilers if not is_hidden(d, hidden_set)]


def _filter_function_data(function_data: FunctionData, hidden: set[str]) -> FunctionData:
    """A deep copy of ``function_data`` with hidden decompilers stripped everywhere."""
    fd = function_data.model_copy(deep=True)
    keep = set(_visible(fd.decompilers, hidden))

    fd.decompilers = [d for d in fd.decompilers if d in keep]
    fd.decompiler_versions = {d: v for d, v in fd.decompiler_versions.items() if d in keep}
    fd.compile_rates = {d: r for d, r in fd.compile_rates.items() if d in keep}

    for group in fd.groups:
        for record in group.functions:
            record.values = {d: v for d, v in record.values.items() if d in keep}
            record.perfects = {d: v for d, v in record.perfects.items() if d in keep}
            record.distances = {d: v for d, v in record.distances.items() if d in keep}
            record.decompiled = {d: v for d, v in record.decompiled.items() if d in keep}

    for sample in fd.samples:
        sample.decompiled = {d: c for d, c in sample.decompiled.items() if d in keep}
        sample.values = {d: v for d, v in sample.values.items() if d in keep}
        sample.perfects = {d: v for d, v in sample.perfects.items() if d in keep}
    # A sample whose only shown output was a hidden decompiler has nothing left.
    fd.samples = [s for s in fd.samples if s.decompiled]

    fd.hardest = [h for h in fd.hardest if not is_hidden(h.decompiler, hidden)]
    fd.history = [h for h in fd.history if not is_hidden(h.decompiler, hidden)]
    return fd


def _filter_scoreboard(scoreboard: Scoreboard, hidden: set[str]) -> Scoreboard:
    """A deep copy of ``scoreboard`` with hidden decompilers stripped."""
    sb = scoreboard.model_copy(deep=True)
    keep = set(_visible(sb.decompilers, hidden))
    sb.decompilers = [d for d in sb.decompilers if d in keep]
    sb.decompiler_scores = {d: s for d, s in sb.decompiler_scores.items() if d in keep}
    return sb


def apply_hidden_decompilers(
    scoreboard: Scoreboard,
    function_data: FunctionData | None,
    content: Content | None = None,
) -> tuple[Scoreboard, FunctionData | None]:
    """Return copies with the site's hidden decompilers removed everywhere.

    A no-op (returns the inputs unchanged) when nothing is hidden, so the common
    case pays no copy cost. Otherwise both objects are deep-copied and filtered,
    leaving the on-disk results untouched.
    """
    content = content or load_content()
    hidden = set(content.site.hidden_decompilers)
    if not hidden:
        return scoreboard, function_data
    filtered_sb = _filter_scoreboard(scoreboard, hidden)
    filtered_fd = (
        _filter_function_data(function_data, hidden) if function_data is not None else None
    )
    return filtered_sb, filtered_fd
