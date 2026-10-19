"""Opt-in C++ policy proposal; deliberately separate from type_match / Union."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from decbench.decompilers.provenance import NativeProvenanceContext, sanitize_native_provenance
from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.cpp_recovered_types import RecoveredTypeContext
from decbench.metrics.cpp_type_graph import dwarf_graph, pdb_graph, recovered_graph
from decbench.metrics.cpp_types import (
    POLICY_VERSION,
    UnsupportedType,
    dwarf_location_supported,
)
from decbench.metrics.type_evidence import PreprocessedSourceContext, build_source_evidence
from decbench.metrics.type_match import _get_location
from decbench.metrics.variable_match import (
    VariableEvidence,
    extract_decompiler_evidence,
    match_variables,
)
from decbench.models.decompilation import DecompilationResult, FunctionDecompilation
from decbench.models.metrics import MetricResult, MetricValue
from decbench.utils import binfmt
from decbench.utils.native_code import die_ranges, entry_address_candidates
from decbench.utils.pdb_info import PdbFormatError
from decbench.utils.producer_validation import inspect_producer


class CppOracleContext:
    """One immutable image's debug index shared across producer/view comparisons.

    This is in-memory oracle preparation, not a score or decompilation cache.
    A changed file invalidates the context instead of serving stale evidence.
    """

    def __init__(self, path: Path):
        self.path = path.resolve()
        self.signature = self._signature()
        self.info = binfmt.detect(self.path)
        self.dwarf = binfmt.dwarf_info(self.path)
        self.pdb = binfmt.pdb_info(self.path) if self.dwarf is None else None
        self.native = NativeProvenanceContext(self.path)
        self.index: dict[int, list[Any]] = {}
        if self.dwarf is not None:
            for cu in self.dwarf.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    ranges = die_ranges(die, self.dwarf)
                    if ranges:
                        self.index.setdefault(min(a for a, _ in ranges), []).append(die)

    def _signature(self) -> tuple[int, int, int]:
        stat = self.path.stat()
        return stat.st_ino, stat.st_size, stat.st_mtime_ns

    def validate(self, path: Path) -> None:
        if path.resolve() != self.path or self._signature() != self.signature:
            raise ValueError("C++ oracle context does not match immutable input")


class CppTypeMatchMetric(Metric):
    name = "cpp_type_match"
    display_name = "C++ Types (proposal, supported subset)"
    lower_is_better = False
    perfect_value = 1.0
    cache_version = "5"

    def __init__(self, config: MetricConfig | None = None):
        super().__init__(config)
        options = self.config.extra_options
        self.view = options.get("view", "source")
        self.data_model = str(options.get("data_model"))
        if self.view not in {"source", "abi"}:
            raise ValueError("C++ view must be source or abi")
        if self.data_model not in {"LP64", "LLP64", "ILP32"}:
            raise ValueError("C++ proposal requires an explicit data_model: LP64/LLP64/ILP32")
        if set(options) - {"view", "data_model"}:
            raise ValueError("unknown C++ type policy option")

    def compute_for_function(
        self, decompiled: FunctionDecompilation, source_cfg=None, decompiled_cfg=None, **kwargs: Any
    ) -> MetricValue:
        gt = kwargs.get("ground_truth_vars")
        if not gt:
            raise ValueError("C++ policy requires complete typed ground truth")
        evidence = kwargs.get("source_evidence")
        if evidence is None:
            raise ValueError("C++ policy requires type-blind source evidence")
        inspection = inspect_producer(decompiled.decompiled_code, decompiled.metadata)
        if inspection.invalid:
            return MetricValue(
                value=0.0,
                raw_value=len(gt),
                metadata={
                    "policy": POLICY_VERSION,
                    "view": self.view,
                    "data_model": self.data_model,
                    "ground_truth_count": len(gt),
                    "correct_count": 0,
                    "matched_count": 0,
                    "producer_failure": "invalid_producer_output",
                    "producer_validation": inspection.evidence(),
                    "official_score": False,
                    "decisions": [
                        {
                            "identity": row["identity"],
                            "matched_identity": None,
                            "expected": asdict(row["descriptor"].project(self.view)),
                            "actual": None,
                            "verdict": "invalid_producer_output",
                        }
                        for row in gt
                    ],
                },
            )
        recovered = extract_decompiler_evidence(
            decompiled, backend="decompiler", identity_prefix="decompiler", include_unnamed=True
        )
        match = match_variables(evidence, recovered, min_overlap=0.1, ambiguity_margin=0.03)
        by_id = {f"decompiler:{i}": v for i, v in enumerate(decompiled.variables)}
        mapping = {m.source_id: m.decompiled_id for m in match.matches}
        decisions = []
        recovered_types = RecoveredTypeContext(decompiled.decompiled_code, self.data_model)
        for row in gt:
            expected = row["descriptor"].project(self.view)
            variable = by_id.get(mapping.get(row["identity"], ""))
            actual = None
            reason = "unmatched"
            if variable is not None:
                try:
                    actual = recovered_graph(
                        variable.type, self.data_model, decompiled.metadata, recovered_types
                    ).project(self.view)
                    reason = "correct" if actual == expected else "type_mismatch"
                    if variable.size is not None and variable.size != actual.byte_size():
                        reason = "inconsistent_recovered_storage_width"
                except UnsupportedType:
                    reason = "unsupported_recovered_type"
            decisions.append(
                {
                    "identity": row["identity"],
                    "matched_identity": mapping.get(row["identity"]),
                    "expected": asdict(expected),
                    "actual": asdict(actual) if actual else None,
                    "verdict": reason,
                }
            )
        correct = sum(d["verdict"] == "correct" for d in decisions)
        return MetricValue(
            value=correct / len(gt),
            raw_value=len(gt) - correct,
            metadata={
                "policy": POLICY_VERSION,
                "view": self.view,
                "data_model": self.data_model,
                "ground_truth_count": len(gt),
                "correct_count": correct,
                "matched_count": len(match.matches),
                "unmatched_source": match.unmatched_source,
                "unobservable_source": match.unobservable_source,
                "decisions": decisions,
                "official_score": False,
                "producer_validation": inspection.evidence(),
            },
        )

    def _dwarf_rows(
        self, dwarf: Any, address_candidates: tuple[int, ...], oracle_index: dict[int, list[Any]]
    ) -> list[dict]:
        candidates = {
            die.offset: die
            for address in address_candidates
            for die in oracle_index.get(address, [])
        }
        if len(candidates) != 1:
            raise UnsupportedType("DWARF function missing or entry identity ambiguous")
        function_die = next(iter(candidates.values()))
        # Aggregate returns do not prove ordinary ABI formal ordinals.
        return_type = dwarf_graph(function_die, self.data_model)
        formal_ordinals_proven = return_type.nodes[return_type.root].kind not in {
            "record",
            "union",
            "array",
        }
        rows = []
        arg_index = 0

        def walk(parent: Any) -> None:
            nonlocal arg_index
            for child in parent.iter_children():
                if child.tag == "DW_TAG_inlined_subroutine":
                    # Nested inline locals and split/abstract identities require
                    # their own source correspondence contract.
                    raise UnsupportedType("inline variable identity policy unsupported")
                if child.tag == "DW_TAG_lexical_block":
                    walk(child)
                    continue
                if child.tag not in {"DW_TAG_formal_parameter", "DW_TAG_variable"}:
                    continue
                is_arg = child.tag == "DW_TAG_formal_parameter" and parent is function_die
                ordinal = arg_index if is_arg and formal_ordinals_proven else None
                if is_arg:
                    arg_index += 1
                offsets, observable = _get_location(child, dwarf)
                dwarf_location_supported(child, dwarf)
                if not observable:
                    # Optimized-out oracle variables are excluded uniformly.
                    continue
                descriptor = dwarf_graph(child, self.data_model)
                if descriptor.nodes[descriptor.root].kind == "void":
                    raise UnsupportedType("missing variable type")
                rows.append(
                    {
                        "identity": f"dwarf:0x{child.offset:x}",
                        "descriptor": descriptor,
                        "rbp_offset": sorted(set(offsets)),
                        "arg_index": ordinal,
                        "name": binfmt.die_str_attr(
                            child, "DW_AT_name", follow_abstract_origin=True
                        )
                        or "",
                    }
                )

        walk(function_die)
        return rows

    def compute_for_binary(
        self,
        decompilation: DecompilationResult,
        source_cfgs=None,
        decompiled_cfgs=None,
        **kwargs: Any,
    ) -> MetricResult:
        # Do not mutate reused producer output when removing unverifiable PCs.
        working = decompilation.model_copy(deep=True)
        requested = kwargs.get("requested_functions")
        if requested is not None:
            addresses = {address for _, address in requested}
            if len(addresses) != len(requested):
                raise ValueError("duplicate requested function entry")
            working.functions = {
                key: f for key, f in working.functions.items() if f.address in addresses
            }
        # Evaluation plans own the population. A missing producer result is an
        # empty recovery at the requested entry, not a new oracle exclusion.
        producer_addresses = [f.address for f in working.functions.values()]
        if len(producer_addresses) != len(set(producer_addresses)):
            raise ValueError("ambiguous producer records at one requested address")
        returned = set(producer_addresses)
        for name, address in requested or []:
            if address not in returned:
                working.add_function(
                    FunctionDecompilation(
                        name=name,
                        address=address,
                        decompiled_code="",
                    )
                )
                returned.add(address)
        oracle_context = kwargs.get("oracle_context") or CppOracleContext(working.binary_path)
        oracle_context.validate(working.binary_path)
        sanitizer = sanitize_native_provenance(working, context=oracle_context.native)
        info, dwarf, pdb = oracle_context.info, oracle_context.dwarf, oracle_context.pdb
        oracle_index = oracle_context.index
        values, errors = {}, []
        context = PreprocessedSourceContext(
            tuple(Path(p) for p in kwargs.get("preprocessed_sources", [])), working.binary_name
        )
        try:
            for key, function in working.functions.items():
                try:
                    if dwarf is not None:
                        gt = self._dwarf_rows(
                            dwarf,
                            entry_address_candidates(function.address, info.arch if info else ""),
                            oracle_index,
                        )
                        evidence = list(
                            build_source_evidence(
                                working.binary_path, function.name, function.address, gt, context
                            ).variables
                        )
                    elif pdb is not None:
                        from decbench.utils.pdb_info import ground_truth_variables

                        oracle = pdb.at_address(function.address)
                        if oracle is None or not oracle.measurable:
                            raise UnsupportedType(
                                "PDB identity/storage/formal classification incomplete"
                            )
                        raw = ground_truth_variables(working.binary_path, oracle)
                        gt = []
                        evidence = []
                        for row in raw:
                            # The oracle graph is independent of the selected view.
                            if pdb.types is None:
                                raise UnsupportedType("PDB type graph context unavailable")
                            variable = next(
                                v for v in oracle.variables if v.identity == row["identity"]
                            )
                            descriptor = pdb_graph(pdb.types, variable.type_index, self.data_model)
                            if descriptor.byte_size() != row["size"]:
                                raise UnsupportedType("PDB width disagrees with data model")
                            gt.append({**row, "descriptor": descriptor})
                            evidence.append(
                                VariableEvidence(row["identity"], frozenset(row["addresses"]))
                            )
                    else:
                        raise UnsupportedType("no readable debug oracle")
                    if not gt:
                        raise UnsupportedType("no observable variable ground truth")
                    if any(
                        not (v.addresses or v.stack_offsets or v.arg_index is not None)
                        for v in evidence
                    ):
                        raise UnsupportedType("oracle variable correspondence unavailable")
                except (UnsupportedType, PdbFormatError) as exc:
                    errors.append(f"{key}: {exc}")
                    continue
                value = self.compute_for_function(
                    function, ground_truth_vars=gt, source_evidence=evidence
                )
                value.metadata.update(
                    ground_truth_format="dwarf" if dwarf else "pdb", native_provenance=sanitizer
                )
                values[key] = value
        finally:
            context.close()
        result = MetricResult(
            metric_name=self.name,
            decompiler_name=working.decompiler.decompiler_name,
            binary_name=working.binary_name,
            function_results=values,
            errors=errors,
        )
        result.compute_aggregates(perfect_value=self.perfect_value)
        return result
