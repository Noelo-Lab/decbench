"""External eval-kit: run OUTSIDE decompilers on DecBench's frozen sample-set.

The flow has three legs:

1. **Export** (maintainer, :mod:`decbench.evalkit.export`): ``decbench evalkit
   export <tree>`` builds a self-contained kit — stripped + anonymized
   binaries, a ``functions.json`` mapping anonymous names to target function
   addresses (public) and back to their original identities (private), a
   ``results/`` template, and a standalone ``package.py``.
2. **Package** (contributor, :mod:`decbench.evalkit.kit_package`, shipped in
   the kit as ``package.py``): validates the contributor's per-binary ``.c``
   files + ``results.json`` and emits a de-anonymized ``results.zip``.
3. **Ingest** (maintainer, :mod:`decbench.evalkit.ingest`): ``decbench evalkit
   ingest results.zip <tree> --id <dec>`` turns the submission into a
   sample-set-only decompiler column (checkpoints + artifacts + evaluation).
"""

from __future__ import annotations


class EvalKitError(Exception):
    """A contract violation anywhere in the eval-kit export/package/ingest flow."""


__all__ = ["EvalKitError"]
