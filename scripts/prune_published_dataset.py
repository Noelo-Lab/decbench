"""Prune orphaned files from the published dataset repo after a re-publish.

The publisher (:mod:`scripts.publish_dataset`) is additive: it never deletes
files that an earlier publish wrote but the current one no longer references
(removed configs, excluded decompilers' ``results/<dec>/`` trees, renamed or
pruned binaries/sources). This script reconciles the dataset repo against the
freshly written manifests: every *tracked* file (``git ls-files``) that is not
referenced by the current publish is ``git rm``'d.

The expected set is built from:
- repo infrastructure: README/dataset.toml/.gitattributes/.gitignore/
  pyproject.toml + everything under ``decbench_data/``;
- ``configs/<cfg>/manifest.json`` (+ ``function_results.json``) for every
  config listed in ``dataset.toml``;
- ``results/function_results.json`` + ``results/scoreboard.toml``;
- every path referenced by the ``full`` config manifest: binaries, source
  CFGs, per-decompiler results (``.c`` and the sibling ``.toml`` variable
  files), and per-project sources.

Dry-run by default (prints what would be removed); ``--apply`` runs
``git rm --quiet`` on the orphans (staged, not committed).

Usage:  python scripts/prune_published_dataset.py [dataset_repo] [--apply]
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import toml

INFRA = {
    "README.md",
    "dataset.toml",
    ".gitattributes",
    ".gitignore",
    "pyproject.toml",
}
INFRA_PREFIXES = ("decbench_data/",)


def expected_paths(repo: Path) -> set[str]:
    """Every repo-relative path the current publish references."""
    expected: set[str] = set(INFRA)
    index = toml.load(repo / "dataset.toml")
    expected.update({"results/function_results.json", "results/scoreboard.toml"})

    full_manifest: Path | None = None
    for cfg, entry in index.get("configs", {}).items():
        manifest_rel = entry["manifest"]
        expected.add(manifest_rel)
        scores_rel = entry.get("scores")
        if scores_rel:
            expected.add(scores_rel)
        if cfg == "full":
            full_manifest = repo / manifest_rel

    if full_manifest is None or not full_manifest.is_file():
        raise SystemExit("dataset.toml has no 'full' config manifest — refusing to prune")

    manifest = json.loads(full_manifest.read_text())
    for project in manifest.get("projects", {}).values():
        expected.update(project.get("sources", []))
    for entry in manifest.get("binaries", []):
        expected.add(entry["binary_path"])
        if entry.get("source_cfg_path"):
            expected.add(entry["source_cfg_path"])
        for rel in entry.get("results", {}).values():
            expected.add(rel)
            # The publisher also copies the sibling variables .toml when present.
            if rel.endswith(".c"):
                expected.add(rel[:-2] + ".toml")
    return expected


def tracked_files(repo: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files"], check=True, capture_output=True, text=True
    )
    return [line for line in out.stdout.splitlines() if line]


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--apply"]
    apply = "--apply" in sys.argv[1:]
    repo = Path(args[0]) if args else Path.home() / "github" / "decbench-dataset"

    expected = expected_paths(repo)
    orphans = [
        path
        for path in tracked_files(repo)
        if path not in expected and not path.startswith(INFRA_PREFIXES)
    ]
    if not orphans:
        print("[prune] no orphans — repo matches the current publish")
        return 0

    by_top: dict[str, int] = {}
    for path in orphans:
        top = "/".join(path.split("/")[:2])
        by_top[top] = by_top.get(top, 0) + 1
    print(f"[prune] {len(orphans)} orphaned tracked file(s):")
    for top, count in sorted(by_top.items()):
        print(f"  {top:50s} {count:>6}")

    if not apply:
        print("[prune] dry run — re-run with --apply to git rm these")
        return 0

    # git rm in batches to stay under argv limits. -f: orphans often carry
    # working-tree drift (hardlinks shared with the results tree), and git rm
    # refuses locally-modified files without it; the manifest reconciliation,
    # not content, is what decides deletion.
    for i in range(0, len(orphans), 500):
        batch = orphans[i : i + 500]
        subprocess.run(["git", "-C", str(repo), "rm", "--quiet", "-f", "--", *batch], check=True)
    print(f"[prune] git rm'd {len(orphans)} file(s) (staged; commit is up to you)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
