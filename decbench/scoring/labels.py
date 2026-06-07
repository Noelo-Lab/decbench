"""Label derivation for binaries and functions.

Pure functions that derive the set of labels applied to binaries and
functions. Labels drive the interactive filtering in the HTML report. The
function-level derivation is the extension hook for future auto labels
(e.g. heuristics that inspect decompiled code).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decbench.models.project import ProjectConfig


DEFAULT_LARGE_LINE_THRESHOLD = 100


def opt_level_labels(opt_level: str) -> list[str]:
    """Return labels derived purely from the optimization level.

    Args:
        opt_level: Optimization level string (e.g. "O0", "O2").

    Returns:
        The opt level itself plus an "unoptimized"/"optimized" label.
    """
    return [opt_level, "unoptimized" if opt_level == "O0" else "optimized"]


def binary_labels_for(
    project_config: ProjectConfig,
    opt_level: str,
    binary_name: str,
) -> list[str]:
    """Return the de-duplicated label list for a single binary.

    Combines optimization-level labels, project-wide labels, and per-binary
    label additions in a stable order with duplicates removed.

    Args:
        project_config: Configuration for the owning project.
        opt_level: Optimization level string (e.g. "O0", "O2").
        binary_name: Binary name (stem) used to look up per-binary labels.

    Returns:
        Ordered, de-duplicated list of labels for the binary.
    """
    combined: list[str] = []
    combined.extend(opt_level_labels(opt_level))
    combined.extend(project_config.labels)
    combined.extend(project_config.binary_labels.get(binary_name, []))

    seen: set[str] = set()
    result: list[str] = []
    for label in combined:
        if label not in seen:
            seen.add(label)
            result.append(label)
    return result


def function_labels_for(
    binary_label_list: list[str],
    line_count: int | None,
    large_threshold: int = DEFAULT_LARGE_LINE_THRESHOLD,
) -> list[str]:
    """Return the labels for a single function.

    Functions inherit all of their binary's labels and gain additional
    auto-derived labels. This is the extension hook for future automatic
    function labels.

    Args:
        binary_label_list: Labels inherited from the owning binary.
        line_count: Number of lines in the decompiled function, if known.
        large_threshold: Line count at or above which "large" is applied.

    Returns:
        Ordered, de-duplicated list of labels for the function.
    """
    seen: set[str] = set()
    result: list[str] = []
    for label in binary_label_list:
        if label not in seen:
            seen.add(label)
            result.append(label)

    is_large = line_count is not None and line_count >= large_threshold
    if is_large and "large" not in seen:
        seen.add("large")
        result.append("large")

    return result
