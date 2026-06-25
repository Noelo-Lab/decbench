"""Content-addressed binary dataset store.

Compiling the benchmark targets is by far the slowest part of a DecBench run
(autotools storms, many opt levels). A *binary dataset* captures the compiled
artifacts — the linked ELF binaries plus their preprocessed ``.i`` sources —
into a stable, content-addressed store so subsequent runs can be replayed
**without recompiling**.

Layout in the store::

    <store_root>/<name>/manifest.json
    <store_root>/<name>/<opt>/<project>/<binary>
    <store_root>/<name>/<opt>/<project>/<source>.i

``materialize`` lays this tree back out under
``<dest>/<opt>/<project>/compiled/`` — exactly the layout
:meth:`PipelineExecutor._discover_existing_binaries` (and ``decbench run
--skip-compile``) expects — so a re-run finds the binaries and skips
compilation entirely.

The module is intentionally pure-python (``shutil`` + ``hashlib`` + ``json``)
and has no heavy dependencies.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import struct
from pathlib import Path

from pydantic import BaseModel, Field

__all__ = [
    "BinaryEntry",
    "BinaryDatasetManifest",
    "default_store_root",
    "save_dataset",
    "load_dataset",
    "list_datasets",
    "materialize",
]


def default_store_root() -> Path:
    """Default dataset store root (``DECBENCH_DATASET_DIR`` or XDG data dir)."""
    env = os.environ.get("DECBENCH_DATASET_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".local" / "share" / "decbench" / "datasets"


class BinaryEntry(BaseModel):
    """A single compiled binary plus its preprocessed sources in the store."""

    project: str = Field(..., description="Project name")
    opt: str = Field(..., description="Optimization level (e.g. 'O0', 'O2')")
    stem: str = Field(..., description="Binary file name (stem)")
    sha256: str = Field(..., description="SHA-256 of the binary content")
    size: int = Field(..., description="Binary size in bytes")
    binary_relpath: str = Field(..., description="Path to the binary relative to the dataset root")
    source_relpaths: list[str] = Field(
        default_factory=list,
        description="Paths to sibling .i sources relative to the dataset root",
    )


class BinaryDatasetManifest(BaseModel):
    """Manifest describing all binaries captured in a dataset."""

    name: str = Field(..., description="Dataset name")
    created: str | None = Field(default=None, description="ISO timestamp the dataset was created")
    binaries: list[BinaryEntry] = Field(default_factory=list, description="Captured binary entries")

    def compile_sets(self) -> list[tuple[str, str]]:
        """Return the distinct (project, opt) pairs present in this dataset."""
        seen: list[tuple[str, str]] = []
        for entry in self.binaries:
            pair = (entry.project, entry.opt)
            if pair not in seen:
                seen.append(pair)
        return seen

    def to_json(self, path: Path) -> None:
        """Serialize the manifest to ``path``."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.model_dump(mode="json"), f, indent=2)

    @classmethod
    def from_json(cls, path: Path) -> BinaryDatasetManifest:
        """Load a manifest from ``path``."""
        with open(path) as f:
            data = json.load(f)
        return cls(**data)


def _is_elf_executable(path: Path) -> bool:
    """Whether ``path`` is a linked ELF executable or shared object.

    Mirrors :meth:`PipelineExecutor._is_elf_executable` (e_type 2/3).
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return False
            f.seek(16)
            raw = f.read(2)
            if len(raw) < 2:
                return False
            e_type = struct.unpack("<H", raw)[0]
            return e_type in (2, 3)
    except (OSError, struct.error):
        return False


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy(src: Path, dst: Path) -> None:
    """Copy ``src`` to ``dst``, trying a hardlink first to save space/time."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def save_dataset(
    results_dir: Path,
    name: str,
    store_root: Path | None = None,
) -> BinaryDatasetManifest:
    """Capture compiled artifacts under ``results_dir`` into the dataset store.

    Scans ``results_dir/<opt>/<project>/compiled/`` for ELF binaries and
    sibling ``.i`` preprocessed sources, copies them into
    ``store_root/<name>/<opt>/<project>/`` (preserving names), records a
    SHA-256 and size per binary, and writes ``store_root/<name>/manifest.json``.

    Args:
        results_dir: A pipeline output directory (e.g. ``results/sailr_full``).
        name: Dataset name (becomes the store subdirectory).
        store_root: Store root (defaults to :func:`default_store_root`).

    Returns:
        The written :class:`BinaryDatasetManifest`.
    """
    results_dir = Path(results_dir)
    store_root = Path(store_root) if store_root is not None else default_store_root()
    dataset_root = store_root / name

    entries: list[BinaryEntry] = []

    if not results_dir.is_dir():
        raise FileNotFoundError(f"results_dir does not exist: {results_dir}")

    for opt_dir in sorted(p for p in results_dir.iterdir() if p.is_dir()):
        opt = opt_dir.name
        for project_dir in sorted(p for p in opt_dir.iterdir() if p.is_dir()):
            project = project_dir.name
            compiled_dir = project_dir / "compiled"
            if not compiled_dir.is_dir():
                continue

            for entry_path in sorted(compiled_dir.iterdir()):
                if not entry_path.is_file() or not _is_elf_executable(entry_path):
                    continue

                stem = entry_path.name
                rel_dir = Path(opt) / project
                binary_relpath = rel_dir / stem
                _copy(entry_path, dataset_root / binary_relpath)

                # Sibling .i sources for this binary (same compiled dir).
                source_relpaths: list[str] = []
                for src in sorted(compiled_dir.glob("*.i")):
                    src_rel = rel_dir / src.name
                    _copy(src, dataset_root / src_rel)
                    source_relpaths.append(str(src_rel))

                entries.append(
                    BinaryEntry(
                        project=project,
                        opt=opt,
                        stem=stem,
                        sha256=_sha256_of(entry_path),
                        size=entry_path.stat().st_size,
                        binary_relpath=str(binary_relpath),
                        source_relpaths=source_relpaths,
                    )
                )

    manifest = BinaryDatasetManifest(
        name=name,
        created=datetime.datetime.now().isoformat(timespec="seconds"),
        binaries=entries,
    )
    manifest.to_json(dataset_root / "manifest.json")
    return manifest


def load_dataset(
    name: str,
    store_root: Path | None = None,
) -> BinaryDatasetManifest:
    """Load the manifest for dataset ``name`` from the store."""
    store_root = Path(store_root) if store_root is not None else default_store_root()
    manifest_path = store_root / name / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"No dataset '{name}' under {store_root}")
    return BinaryDatasetManifest.from_json(manifest_path)


def list_datasets(store_root: Path | None = None) -> list[dict]:
    """List datasets in the store with a summary of each.

    Returns:
        A list of dicts ``{name, binaries, compile_sets}`` (compile_sets is the
        count of distinct (project, opt) pairs).
    """
    store_root = Path(store_root) if store_root is not None else default_store_root()
    out: list[dict] = []
    if not store_root.is_dir():
        return out
    for child in sorted(store_root.iterdir()):
        if not child.is_dir():
            continue
        manifest_path = child / "manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = BinaryDatasetManifest.from_json(manifest_path)
        except Exception:
            continue
        out.append(
            {
                "name": manifest.name,
                "binaries": len(manifest.binaries),
                "compile_sets": len(manifest.compile_sets()),
            }
        )
    return out


def materialize(
    name: str,
    dest: Path,
    store_root: Path | None = None,
) -> BinaryDatasetManifest:
    """Lay a stored dataset out under ``dest`` as a pipeline output tree.

    Recreates ``dest/<opt>/<project>/compiled/`` with the stored binaries and
    ``.i`` sources, so ``decbench run --skip-compile`` (via
    :meth:`PipelineExecutor._discover_existing_binaries`) discovers them.

    Args:
        name: Dataset name in the store.
        dest: Destination pipeline output directory.
        store_root: Store root (defaults to :func:`default_store_root`).

    Returns:
        The dataset manifest that was materialized.
    """
    store_root = Path(store_root) if store_root is not None else default_store_root()
    dataset_root = store_root / name
    manifest = load_dataset(name, store_root=store_root)
    dest = Path(dest)

    for entry in manifest.binaries:
        compiled_dir = dest / entry.opt / entry.project / "compiled"
        src_bin = dataset_root / entry.binary_relpath
        _copy(src_bin, compiled_dir / entry.stem)
        for src_rel in entry.source_relpaths:
            src = dataset_root / src_rel
            _copy(src, compiled_dir / Path(src_rel).name)

    return manifest
