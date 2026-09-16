"""Cindergraph implementation of DecBench's CFG extraction contract."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from decbench.cfg.models import (
    CfgDiagnostic,
    CfgExtraction,
    CfgLanguage,
    ExtractedCfg,
    ExtractionStatus,
    PreprocessingEvidence,
)

CFG_SCHEMA_VERSION = 1
EXTRACTION_POLICY_VERSION = 1


def _package_version() -> str:
    try:
        return version("cindergraph")
    except PackageNotFoundError:
        return "unknown"


def _record(serialized: dict[str, Any]) -> ExtractedCfg:
    return ExtractedCfg(
        nodes=tuple(int(node) for node in serialized["nodes"]),
        edges=tuple((int(source), int(target)) for source, target in serialized["edges"]),
        entry=tuple(int(node) for node in serialized.get("entry", ())),
        exit=tuple(int(node) for node in serialized.get("exit", ())),
        degenerate=bool(serialized["degenerate"]),
    )


class CindergraphCfgExtractor:
    """Extract deterministic C CFG topology without a server or subprocess."""

    name = "cindergraph"
    version = _package_version()
    supported_languages: frozenset[CfgLanguage] = frozenset({"c"})

    def _base(
        self,
        *,
        language: CfgLanguage,
        functions: dict[str, ExtractedCfg] | None = None,
        status: ExtractionStatus = "ok",
        diagnostics: tuple[CfgDiagnostic, ...] = (),
        preprocessing: PreprocessingEvidence | None = None,
        partial_recovery: bool = False,
    ) -> CfgExtraction:
        return CfgExtraction(
            functions=functions or {},
            provider=self.name,
            provider_version=self.version,
            cfg_schema=CFG_SCHEMA_VERSION,
            extraction_policy=EXTRACTION_POLICY_VERSION,
            language=language,
            status=status,
            diagnostics=diagnostics,
            preprocessing=preprocessing,
            partial_recovery=partial_recovery,
        )

    def _unsupported(self, language: CfgLanguage) -> CfgExtraction:
        return self._base(
            language=language,
            status="unsupported-language",
            diagnostics=(
                CfgDiagnostic(
                    code="unsupported-language",
                    message=f"Cindergraph CFG extraction supports C, not {language.upper()}",
                ),
            ),
        )

    def extract_source(
        self,
        path: Path,
        text: str,
        language: CfgLanguage,
    ) -> CfgExtraction:
        """Extract topology from one source translation unit."""
        del path  # Included in the provider contract for diagnostic-capable providers.
        if language not in self.supported_languages:
            return self._unsupported(language)
        from cindergraph import source_cfg

        serialized = source_cfg.parity_cfgs(text)
        return self._base(
            language=language,
            functions={name: _record(cfg) for name, cfg in serialized.items()},
        )

    def extract_decompiled(
        self,
        text: str,
        language: CfgLanguage = "c",
    ) -> CfgExtraction:
        """Extract generated-C topology and preserve preprocessing evidence."""
        if language not in self.supported_languages:
            return self._unsupported(language)
        from cindergraph import source_cfg

        analysis = source_cfg.analyze_decompiled(text)
        serialized = source_cfg.parity_cfgs(analysis.preprocessing.text)
        diagnostics = tuple(
            CfgDiagnostic(
                code=str(item.get("code", "parser-diagnostic")),
                message=str(item.get("message", item)),
                function=item.get("function"),
                recovery_qualified=bool(item.get("recovery_qualified", False)),
            )
            for item in analysis.diagnostics
        )
        partial_recovery = bool(diagnostics) or any(
            provenance.recovery_qualified for provenance in analysis.provenance.values()
        )
        report = analysis.preprocessing
        preprocessing = PreprocessingEvidence(
            status=report.status,
            compiler=report.compiler,
            command=tuple(report.command),
            stderr=report.stderr,
            includes_removed=report.includes_removed,
        )
        return self._base(
            language=language,
            functions={name: _record(cfg) for name, cfg in serialized.items()},
            diagnostics=diagnostics,
            preprocessing=preprocessing,
            partial_recovery=partial_recovery,
        )


def extractor_info() -> dict[str, object]:
    """Serializable identity of the fork's sole CFG provider."""
    return {
        "name": CindergraphCfgExtractor.name,
        "version": CindergraphCfgExtractor.version,
        "cfg_schema": CFG_SCHEMA_VERSION,
        "extraction_policy": EXTRACTION_POLICY_VERSION,
    }
