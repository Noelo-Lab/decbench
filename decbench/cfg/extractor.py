"""CFG extractor contract used by the benchmark pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from decbench.cfg.models import CfgExtraction, CfgLanguage


class CfgExtractor(Protocol):
    """In-process provider boundary; the fork implements Cindergraph only."""

    name: str
    version: str
    supported_languages: frozenset[CfgLanguage]

    def extract_source(
        self,
        path: Path,
        text: str,
        language: CfgLanguage,
    ) -> CfgExtraction: ...

    def extract_decompiled(
        self,
        text: str,
        language: CfgLanguage = "c",
    ) -> CfgExtraction: ...
