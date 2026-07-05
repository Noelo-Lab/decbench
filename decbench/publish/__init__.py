"""Publish a completed DecBench results tree as a HuggingFace-style dataset.

This package implements *component 2* of the dataset-publishing contract
(``docs/DATASET_PUBLISHING.md``): it reads a results tree (e.g.
``results/full_run``) anchored on its ``function_results.json`` and lays the
data out into a dataset-repo root:

* ``binaries/<opt>/<project>/<file>`` — the compiled binaries (real filenames).
* ``sources/<project>/<tu>.c`` — header-stripped, content-deduplicated sources.
* ``results/<decompiler>/<opt>/<project>/<stem>.c`` — decompiled C, reorganized
  so each decompiler is its own folder.
* ``pipeline_data/source_cfgs/<opt>/<project>/<stem>.json`` — the source CFGs the
  GED metric consumed, serialized topologically (see :mod:`cfg_export`).
* ``configs/<name>/manifest.json`` + filtered ``function_results.json`` and the
  top-level ``dataset.toml`` index.

:mod:`decbench.publish.layout` builds everything except the CFG JSONs;
:mod:`decbench.publish.cfg_export` builds the (compute-heavy, resumable) CFGs.
The thin CLI lives in ``scripts/publish_dataset.py``.
"""

from __future__ import annotations

from decbench.publish import cfg_export, layout

__all__ = ["layout", "cfg_export"]
