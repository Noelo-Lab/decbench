"""Decompiler *spec* parsing and version configuration.

A decompiler is selected by a **spec string** that is either a bare name
(``"ghidra"``) or a name pinned to a version (``"ghidra@12.1"``). The version
suffix lets the benchmark run *several versions of the same decompiler* as
distinct, comparable entries — which is what powers the report's historical
view (e.g. ``ghidra@11.3`` vs ``ghidra@12.1``).

How a version is *realized* is backend-specific (for Ghidra it is which
install directory ``pyghidra`` launches; for a Dockerized backend it is the
image tag). That mapping lives in an optional TOML config:

    # ~/.config/decbench/decompilers.toml  (or $DECBENCH_DECOMPILERS_CONFIG)
    [ghidra.versions."11.3"]
    install_dir = "/home/user/bin/ghidra_11.3"
    [ghidra.versions."12.1"]
    install_dir = "/home/user/bin/ghidra_12.1"

    [retdec.versions."5.0"]
    image = "decbench/retdec:5.0"

Backends call :func:`version_settings` to fetch their per-version settings and
fall back to environment defaults (e.g. ``GHIDRA_INSTALL_DIR``) when no config
is present, so the unversioned case keeps working with zero configuration.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

__all__ = [
    "parse_spec",
    "make_id",
    "config_path",
    "load_versions_config",
    "version_settings",
]


def parse_spec(spec: str) -> tuple[str, str | None]:
    """Split a decompiler spec into ``(name, version)``.

    ``"ghidra@12.1"`` -> ``("ghidra", "12.1")``;  ``"angr"`` -> ``("angr", None)``.
    """
    spec = spec.strip()
    if "@" in spec:
        name, _, version = spec.partition("@")
        name = name.strip()
        version = version.strip() or None
        return name, version
    return spec, None


def make_id(name: str, version: str | None) -> str:
    """Canonical decompiler id used as the key in results/scoreboards."""
    return f"{name}@{version}" if version else name


def config_path() -> Path:
    """Path to the decompiler versions config (may not exist)."""
    env = os.environ.get("DECBENCH_DECOMPILERS_CONFIG")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".config" / "decbench" / "decompilers.toml"


@lru_cache(maxsize=1)
def load_versions_config() -> dict[str, Any]:
    """Load the decompiler versions config, or ``{}`` if absent/unreadable."""
    path = config_path()
    if not path.is_file():
        return {}
    try:
        import toml

        return toml.load(path)
    except Exception:
        return {}


def version_settings(name: str, version: str | None) -> dict[str, Any]:
    """Return the per-version settings dict for ``name@version``.

    Returns an empty dict when no config entry exists. Backends merge this
    with their own environment-based defaults.
    """
    if version is None:
        return {}
    cfg = load_versions_config()
    try:
        return dict(cfg[name]["versions"][version])
    except (KeyError, TypeError):
        return {}
