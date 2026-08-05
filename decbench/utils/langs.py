"""Source-language vocabulary shared by the compiler, CFG, and source-extract paths.

gcc names its ``-save-temps`` output after the LANGUAGE, not the flag: a C
translation unit yields ``<name>.i`` and a C++ one ``<name>.ii``. Joern picks
its frontend the same way — from the extension — and its C frontend returns
zero functions for C++ input. So the ``.i``/``.ii`` distinction has to be
carried end-to-end, and every site that used to hard-code ``.i`` speaks these
tuples instead.
"""

from __future__ import annotations

import os
from pathlib import Path

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
