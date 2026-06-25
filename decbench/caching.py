"""Content-addressed on-disk caching for DecBench.

Two things are expensive and perfectly deterministic in a DecBench run:

* **Metric computation** — a metric value is a pure function of a small set of
  inputs (for GED: the two CFG structures; for type_match: the decompiled
  variables + DWARF ground truth + calibration shift; for byte_match: the
  decompiled code + original function bytes). If we have *seen the same inputs
  before* we never need to recompute the metric. See :mod:`decbench.metrics`.

* **Compiled binaries** — the binary dataset store (:mod:`decbench.dataset`)
  is content-addressed by the same hashing primitives.

This module provides the shared primitives: a stable content hash and a
process-safe, sharded, JSON-backed key/value cache. Writes are idempotent
(the key is derived from the content, so any two writers store identical
bytes), so concurrent access from the evaluation ``ProcessPoolExecutor`` is
safe without locking — we still write atomically via tmp-file + ``replace``.

Configuration (environment):
    DECBENCH_CACHE_DIR   cache root (default: ~/.cache/decbench)
    DECBENCH_NO_CACHE    if set to a truthy value, all gets miss and puts no-op
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

__all__ = [
    "stable_hash",
    "cache_enabled",
    "default_cache_dir",
    "ContentCache",
    "get_cache",
]


def _is_truthy(val: str | None) -> bool:
    return bool(val) and val.lower() not in ("0", "false", "no", "off", "")


def cache_enabled() -> bool:
    """Whether caching is enabled (disabled via DECBENCH_NO_CACHE)."""
    return not _is_truthy(os.environ.get("DECBENCH_NO_CACHE"))


def default_cache_dir() -> Path:
    """Cache root directory (DECBENCH_CACHE_DIR or ~/.cache/decbench)."""
    env = os.environ.get("DECBENCH_CACHE_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".cache" / "decbench"


def _canonical(obj: Any) -> bytes:
    """Canonical, deterministic JSON encoding of ``obj`` for hashing.

    Keys are sorted and separators are tight so equal logical content always
    produces identical bytes. ``default=str`` lets us hash Paths/sets/etc.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")


def _json_default(o: Any) -> Any:
    if isinstance(o, (set, frozenset)):
        return sorted(o, key=lambda x: (str(type(x)), str(x)))
    if isinstance(o, bytes):
        return o.hex()
    if isinstance(o, Path):
        return str(o)
    return str(o)


def stable_hash(*parts: Any) -> str:
    """Return a stable hex digest of the given parts.

    Each part is canonically JSON-encoded; bytes parts are hashed directly.
    The result is stable across processes and Python runs (unlike ``hash()``).
    """
    h = hashlib.sha256()
    for part in parts:
        if isinstance(part, bytes):
            h.update(b"\x00b")
            h.update(part)
        else:
            h.update(b"\x00j")
            h.update(_canonical(part))
    return h.hexdigest()


class ContentCache:
    """A simple sharded, JSON-backed, process-safe content cache.

    Namespaces keep unrelated caches (e.g. ``metric``, ``binary``) apart.
    Values must be JSON-serializable.
    """

    def __init__(self, root: Path | None = None, namespace: str = "default") -> None:
        self.root = (root or default_cache_dir()) / namespace
        self.namespace = namespace
        self._enabled = cache_enabled()
        self._mem: dict[str, Any] = {}
        self.hits = 0
        self.misses = 0

    def _path_for(self, key: str) -> Path:
        # Shard by the first two hex chars to avoid huge flat directories.
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str) -> Any | None:
        """Return the cached value for ``key`` or None on miss."""
        if not self._enabled:
            return None
        if key in self._mem:
            self.hits += 1
            return self._mem[key]
        path = self._path_for(key)
        try:
            with open(path) as f:
                value = json.load(f)
        except (FileNotFoundError, ValueError, OSError):
            self.misses += 1
            return None
        self._mem[key] = value
        self.hits += 1
        return value

    def put(self, key: str, value: Any) -> None:
        """Store ``value`` under ``key`` (idempotent, atomic)."""
        if not self._enabled:
            return
        self._mem[key] = value
        path = self._path_for(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".json.tmp.{os.getpid()}")
            with open(tmp, "w") as f:
                json.dump(value, f, separators=(",", ":"), default=_json_default)
            os.replace(tmp, path)
        except OSError:
            # Cache is best-effort; never fail the run because of it.
            pass

    def stats(self) -> dict[str, int]:
        return {"hits": self.hits, "misses": self.misses}


# Process-global cache instances, keyed by namespace, so repeated lookups in a
# single worker share the in-memory layer.
_CACHES: dict[str, ContentCache] = {}


def get_cache(namespace: str = "default") -> ContentCache:
    """Return the process-global :class:`ContentCache` for ``namespace``."""
    cache = _CACHES.get(namespace)
    if cache is None:
        cache = ContentCache(namespace=namespace)
        _CACHES[namespace] = cache
    return cache
