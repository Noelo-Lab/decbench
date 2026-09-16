"""Provider-neutral control-flow graph extraction records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

CfgLanguage = Literal["c", "c++"]
ExtractionStatus = Literal["ok", "unsupported-language", "failed"]
PreprocessingStatus = Literal["not-needed", "succeeded", "unavailable", "failed", "timed-out"]


@dataclass(frozen=True)
class ExtractedCfg:
    """Durable, graph-library-independent topology for one function."""

    nodes: tuple[int, ...]
    edges: tuple[tuple[int, int], ...]
    entry: tuple[int, ...]
    exit: tuple[int, ...]
    degenerate: bool


@dataclass(frozen=True)
class CfgDiagnostic:
    """Machine-readable evidence produced while extracting CFGs."""

    code: str
    message: str
    function: str | None = None
    recovery_qualified: bool = False


@dataclass(frozen=True)
class PreprocessingEvidence:
    """Observable outcome of preparing generated C for extraction."""

    status: PreprocessingStatus
    compiler: str | None = None
    command: tuple[str, ...] = ()
    stderr: str = ""
    includes_removed: bool = False


@dataclass(frozen=True)
class CfgExtraction:
    """Complete result of one provider invocation.

    Unsupported languages and provider failures are typed outcomes rather than
    empty mappings, so callers cannot accidentally count an abstention as an
    empty translation unit.
    """

    functions: dict[str, ExtractedCfg]
    provider: str
    provider_version: str
    cfg_schema: int
    extraction_policy: int
    language: CfgLanguage
    status: ExtractionStatus = "ok"
    diagnostics: tuple[CfgDiagnostic, ...] = ()
    preprocessing: PreprocessingEvidence | None = None
    partial_recovery: bool = False

    @property
    def supported(self) -> bool:
        """Whether the provider supports this input language."""
        return self.status != "unsupported-language"
