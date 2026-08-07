"""Source-language vocabulary shared by the compiler, CFG, and source-extract paths.

gcc names its ``-save-temps`` output after the LANGUAGE, not the flag: a C
translation unit yields ``<name>.i`` and a C++ one ``<name>.ii``. Joern picks
its frontend the same way — from the extension — and its C frontend returns
zero functions for C++ input. So the ``.i``/``.ii`` distinction has to be
carried end-to-end, and every site that used to hard-code ``.i`` speaks these
tuples instead.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path

_l = logging.getLogger(__name__)

C_SOURCE_EXTS = (".c",)
CXX_SOURCE_EXTS = (".cc", ".cpp", ".cxx", ".c++", ".C")
SOURCE_EXTS = (*C_SOURCE_EXTS, *CXX_SOURCE_EXTS)

C_PREPROC_EXTS = (".i",)
CXX_PREPROC_EXTS = (".ii",)
PREPROC_EXTS = (*C_PREPROC_EXTS, *CXX_PREPROC_EXTS)

SOURCE_AND_PREPROC_EXTS = (*SOURCE_EXTS, *PREPROC_EXTS)


def preprocessed_ext(source_path: Path | str) -> str:
    """The ``-save-temps`` preprocessed extension for a translation unit."""
    return ".ii" if Path(source_path).suffix in CXX_SOURCE_EXTS else ".i"


def is_cxx_preprocessed(path: Path | str) -> bool:
    """True for a preprocessed C++ translation unit (``.ii``)."""
    return Path(path).suffix in CXX_PREPROC_EXTS


def strip_source_ext(name: str) -> str:
    """Drop a trailing C/C++ *source* extension from ``name``.

    Used to compare a DWARF ``DW_AT_decl_file`` basename against a preprocessed
    translation-unit stem, which differ in shape between C and C++: gcc emits
    ``foo.i`` for ``foo.c`` (stem ``foo``) but CMake's object naming makes it
    ``foo.cc.ii`` for ``foo.cc`` (stem ``foo.cc``). Header extensions are
    deliberately NOT stripped, so header-defined functions stay outside the
    "project's own translation units" filter exactly as before.
    """
    stem, ext = os.path.splitext(name)
    return stem if ext in SOURCE_EXTS else name


def preprocessed_by_stem(directory: Path | str) -> dict[str, Path]:
    """Every preprocessed translation unit in ``directory``, keyed by file stem.

    Globs BOTH extensions. A collection site that hard-codes ``*.i`` finds
    nothing at all in a C++ project's ``compiled/`` (which holds ``*.ii``) and
    then reports "no sources" instead of an error, so every source-side metric
    silently abstains. Collisions (``parser.i`` beside ``parser.ii``, both stem
    ``parser``) keep the first in ``PREPROC_EXTS`` order and warn.
    """
    directory = Path(directory)
    out: dict[str, Path] = {}
    if not directory.is_dir():
        return out
    for ext in PREPROC_EXTS:
        for path in sorted(directory.glob(f"*{ext}")):
            if path.stem in out:
                _l.warning(
                    "preprocessed stem collision in %s: %s is shadowed by %s",
                    directory,
                    path.name,
                    out[path.stem].name,
                )
                continue
            out[path.stem] = path
    return out


def build_stem_index(stems: Iterable[str]) -> dict[str, str]:
    """``{strip_source_ext(stem): stem}``, warning on any collision.

    ``main.cc`` and ``main.cpp`` both strip to ``main``, so a naive dict
    comprehension drops one translation unit and every function defined in it
    is silently excluded from the run. No shipped project mixes languages in
    one directory, so this is a guard rather than a fix: the first stem in
    sorted order wins and the loss is logged instead of being invisible.
    """
    index: dict[str, str] = {}
    for stem in sorted(stems):
        key = strip_source_ext(stem)
        if key in index:
            _l.warning(
                "source-stem collision on %r: %r is shadowed by %r; functions "
                "declared in it will not be matched",
                key,
                stem,
                index[key],
            )
            continue
        index[key] = stem
    return index
