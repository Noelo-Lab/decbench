#!/usr/bin/env python3
"""Run the local-variable edit-distance experiment on testing/grep::main."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from collections import defaultdict
from dataclasses import replace
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from decbench.decompilers.raw import common
from decbench.experimental.local_variable_distance import (
    FunctionEvidence,
    VariableEvidence,
    extract_ida_evidence,
    extract_source_evidence,
    instruction_addresses,
    mask_elf_metadata,
    match_variables,
)
from decbench.metrics.type_match import parse_c_variables


IDA_CANDIDATES = (
    Path("/Applications/IDA Professional 9.2.app/Contents/MacOS"),
    Path("/home/mahaloz/ctf/tools/idapro_9.2"),
)
DEFAULT_IDA = next((path for path in IDA_CANDIDATES if path.exists()), IDA_CANDIDATES[0])
ORACLE = {
    "argc": "a1",
    "argv": "a2",
    "keycc": "v131",
    "keyalloc": "v132",
    "default_context": "v133",
    "filename_option": "v127",
    "num_operands": "v59",
    "psize": "v61",
}
NEGATIVE_ORACLE = {
    "num_operands": {"v61"},
    "psize": {"v59"},
}


def _load_ida(ida_dir: Path) -> Any:
    for path in (ida_dir / "idalib/python", ida_dir / "python"):
        if path.exists() and str(path) not in sys.path:
            sys.path.insert(0, str(path))
    import idapro

    return idapro


def _provided_main(path: Path) -> str:
    text = path.read_text(errors="replace")
    marker = text.find("\n// Function:", 1)
    return text if marker < 0 else text[:marker]


def _provided_variable_names(code: str, function_name: str) -> set[str]:
    names = {
        var.name
        for var in parse_c_variables(code, function_name)
        if var.kind == "arg" and var.name
    }
    declaration = re.compile(
        r"^\s+.*?(?:\(\*(?P<function_pointer>[A-Za-z_]\w*)\)\s*\([^;]*\)|"
        r"(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?)\s*;\s*//"
    )
    for line in code.splitlines():
        match = declaration.match(line)
        if match:
            names.add(match.group("function_pointer") or match.group("name"))
    return names


def _match_name_pairs(
    source: FunctionEvidence,
    decompiled: FunctionEvidence,
    result: Any,
) -> list[dict[str, Any]]:
    source_by_id = {var.identity: var for var in source.variables}
    decompiled_by_id = {var.identity: var for var in decompiled.variables}
    rows = []
    for match in result.matches:
        source_var = source_by_id[match.source_id]
        decompiled_var = decompiled_by_id[match.decompiled_id]
        rows.append(
            {
                **match.to_dict(),
                "source_name": source_var.name,
                "decompiled_name": decompiled_var.name,
                "source_stack_offsets": list(source_var.stack_offsets),
                "decompiled_stack_offsets": list(decompiled_var.stack_offsets),
            }
        )
    return rows


def _oracle_checks(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actual = {row["source_name"]: row["decompiled_name"] for row in matches}
    return [
        {
            "source": source_name,
            "expected_decompiled": decompiled_name,
            "actual_decompiled": actual.get(source_name),
            "passed": actual.get(source_name) == decompiled_name,
        }
        for source_name, decompiled_name in ORACLE.items()
    ]


def _negative_oracle_checks(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actual = {(row["source_name"], row["decompiled_name"]) for row in matches}
    return [
        {
            "source": source_name,
            "forbidden_decompiled": decompiled_name,
            "passed": (source_name, decompiled_name) not in actual,
        }
        for source_name, decompiled_names in NEGATIVE_ORACLE.items()
        for decompiled_name in sorted(decompiled_names)
    ]


def _unresolved_source(
    source: FunctionEvidence,
    decompiled: FunctionEvidence,
    result: Any,
) -> list[dict[str, Any]]:
    source_by_id = {var.identity: var for var in source.variables}
    decompiled_by_id = {var.identity: var for var in decompiled.variables}
    return [
        {
            "source": source_by_id[source_id].name,
            "candidates": [
                {
                    "decompiled": decompiled_by_id[decompiled_id].name,
                    "score": score,
                }
                for decompiled_id, score in result.candidates.get(source_id, [])[:3]
            ],
        }
        for source_id in result.unmatched_source
    ]


def _correspondence_checks(
    source: FunctionEvidence,
    decompiled: FunctionEvidence,
) -> list[dict[str, Any]]:
    source_by_name = {var.name: var for var in source.variables}
    decompiled_by_name = {var.name: var for var in decompiled.variables}
    expected = {
        "source num_operands": (
            source_by_name["num_operands"].addresses,
            {0x5DDF, 0x5DF6, 0x5E23, 0x5E9B, 0x5E9D},
        ),
        "source psize": (
            source_by_name["psize"].addresses,
            {0x5E1E, 0x5E29, 0x5E2E, 0x5E31, 0x5E35, 0x5E3F, 0x5E42, 0x5E4F},
        ),
        "IDA v59 overlap": (
            decompiled_by_name["v59"].addresses
            & source_by_name["num_operands"].addresses,
            {0x5DF6, 0x5E9B, 0x5E9D},
        ),
        "IDA v61 overlap": (
            decompiled_by_name["v61"].addresses & source_by_name["psize"].addresses,
            {0x5E29, 0x5E2E, 0x5E31, 0x5E35, 0x5E3F, 0x5E42, 0x5E4F},
        ),
    }
    return [
        {
            "label": label,
            "actual": [f"0x{address:x}" for address in sorted(actual)],
            "expected": [f"0x{address:x}" for address in sorted(wanted)],
            "passed": actual == wanted,
        }
        for label, (actual, wanted) in expected.items()
    ]


def _alias_groups(decompiled: FunctionEvidence) -> list[dict[str, Any]]:
    groups: dict[int, list[VariableEvidence]] = defaultdict(list)
    for var in decompiled.variables:
        for offset in var.stack_offsets:
            groups[offset].append(var)
    return [
        {
            "stack_offset": offset,
            "sizes": sorted({var.size for var in variables if var.size is not None}),
            "variables": [var.name for var in sorted(variables, key=lambda item: item.identity)],
        }
        for offset, variables in sorted(groups.items())
        if len(variables) > 1
    ]


def _controls(
    source: FunctionEvidence,
    decompiled: FunctionEvidence,
    baseline: Any,
) -> dict[str, Any]:
    renamed_source = [
        replace(var, name=f"source_{index}") for index, var in enumerate(source.variables)
    ]
    renamed_decompiled = [
        replace(var, name=f"decompiled_{index}")
        for index, var in enumerate(decompiled.variables)
    ]
    renamed = match_variables(renamed_source, renamed_decompiled)
    baseline_pairs = {(row.source_id, row.decompiled_id) for row in baseline.matches}
    renamed_pairs = {(row.source_id, row.decompiled_id) for row in renamed.matches}

    disjoint_decompiled = [
        replace(
            var,
            addresses=frozenset(address + 0x1000000 for address in var.addresses),
        )
        for var in decompiled.variables
    ]
    disjoint = match_variables(source.variables, disjoint_decompiled)
    fake = VariableEvidence(identity="ida:fake", name="fake_local")
    with_fake = match_variables(source.variables, [*decompiled.variables, fake])
    return {
        "rename_invariant": baseline_pairs == renamed_pairs,
        "baseline_overlap_matches": sum(
            match.stage == "overlap" for match in baseline.matches
        ),
        "disjoint_overlap_matches": sum(
            match.stage == "overlap" for match in disjoint.matches
        ),
        "fake_local_distance_delta": with_fake.distance - baseline.distance,
    }


def _render_markdown(data: dict[str, Any]) -> str:
    summary = data["summary"]
    lines = [
        "# Local-variable edit distance: `grep::main` proof",
        "",
        "This is an experimental, unregistered metric. Matching never uses variable names.",
        "Arguments are matched by ABI position; unambiguous stack slots are locked after",
        "frame-offset calibration; remaining variables are peeled by inverse-frequency",
        "weighted address overlap.",
        "",
        "## Result",
        "",
        "| quantity | value |",
        "|---|---:|",
        f"| source-owned DWARF variables | {summary['source_total']} |",
        f"| observable source variables | {summary['source_observable']} |",
        f"| IDA variables | {summary['decompiled_total']} |",
        f"| accepted matches | {summary['matched']} |",
        f"| unresolved source variables | {summary['unmatched_source']} |",
        f"| unmatched IDA variables | {summary['unmatched_decompiled']} |",
        f"| LVED | {summary['distance']} |",
        f"| recovery accuracy | {summary['accuracy']:.3f} |",
        f"| calibrated stack shift | {summary['stack_shift']} |",
        f"| IDA mapped pseudocode lines | {summary['mapped_decompiled_lines']} |",
        "",
        "LVED is `|source| + |decompiled| - 2|matches|`; accuracy is",
        "`2|matches| / (|source| + |decompiled|)`. Source variables with neither",
        "compiled-use addresses nor stack/argument evidence are reported separately.",
        "",
        "## Independently inspectable oracle checks",
        "",
        "| source | expected IDA | actual | pass |",
        "|---|---|---|---|",
    ]
    for row in data["oracle_checks"]:
        lines.append(
            f"| `{row['source']}` | `{row['expected_decompiled']}` | "
            f"`{row['actual_decompiled']}` | {'yes' if row['passed'] else 'no'} |"
        )

    lines.extend(
        [
            "",
            "Negative oracle pairs are also rejected: "
            + ", ".join(
                f"`{row['source']} ↛ {row['forbidden_decompiled']}`"
                for row in data["negative_oracle_checks"]
                if row["passed"]
            )
            + ".",
        ]
    )

    lines.extend(
        [
            "",
            "Direct source-line and IDA-line address checks:",
            "",
            "| evidence | addresses | pass |",
            "|---|---|---|",
        ]
    )
    for row in data["correspondence_checks"]:
        lines.append(
            f"| {row['label']} | {', '.join(row['actual'])} | "
            f"{'yes' if row['passed'] else 'no'} |"
        )

    lines.extend(
        [
            "",
            "The oracle names are used only after matching to evaluate the result.",
            "`num_operands ↔ v59` and `psize ↔ v61` are the register-only proof cases;",
            "the earlier rows are independently checkable from DWARF and IDA stack comments.",
            "",
            "## Accepted matches",
            "",
            "| stage | source | IDA | score | shared addresses |",
            "|---|---|---|---:|---|",
        ]
    )
    for row in data["matches"]:
        shared = ", ".join(row["intersection"][:8])
        lines.append(
            f"| {row['stage']} | `{row['source_name']}` | "
            f"`{row['decompiled_name']}` | {row['score']:.3f} | {shared} |"
        )

    lines.extend(
        [
            "",
            "## Unresolved source variables",
            "",
            "| source | leading candidates |",
            "|---|---|",
        ]
    )
    for row in data["unresolved_source"]:
        candidates = ", ".join(
            f"`{candidate['decompiled']}` ({candidate['score']:.3f})"
            for candidate in row["candidates"]
        )
        lines.append(f"| `{row['source']}` | {candidates or 'none'} |")

    lines.extend(
        [
            "",
            "## Stack aliases deliberately not treated as exact",
            "",
            "| IDA stack offset | sizes | aliases |",
            "|---:|---:|---|",
        ]
    )
    for row in data["stack_aliases"]:
        aliases = ", ".join(f"`{name}`" for name in row["variables"])
        lines.append(
            f"| {row['stack_offset']} | {row['sizes']} | {aliases} |"
        )

    controls = data["controls"]
    lines.extend(
        [
            "",
            "## Negative controls",
            "",
            f"- Renaming every source and IDA variable leaves all pairs unchanged: "
            f"`{controls['rename_invariant']}`.",
            f"- Moving IDA address sets into a disjoint address space changes overlap matches from "
            f"`{controls['baseline_overlap_matches']}` to "
            f"`{controls['disjoint_overlap_matches']}`.",
            f"- Injecting one fake IDA local changes LVED by "
            f"`{controls['fake_local_distance_delta']}`.",
            "",
            "## Artifact checks",
            "",
            f"- Supplied/generated IDA text similarity: "
            f"`{data['artifact_checks']['ida_text_similarity']:.3f}`.",
            f"- Supplied IDA declaration names recovered by the live extraction: "
            f"`{data['artifact_checks']['provided_name_coverage']:.3f}` "
            f"({data['artifact_checks']['shared_declared_names']}/"
            f"{data['artifact_checks']['provided_declared_names']}).",
            f"- Every emitted address lies inside `main` and on a decoded instruction: "
            f"`{data['artifact_checks']['addresses_valid']}`.",
            f"- The IDA input contains no debug or static symbol-table sections: "
            f"`{data['artifact_checks']['decompiler_input_metadata_hidden']}`.",
            f"- The preprocessed fixture contains the expected logical `main`: "
            f"`{data['artifact_checks']['preprocessed_contains_main']}`.",
            "",
            "The source use sets come from identifier tokens on source lines expanded to",
            "instruction starts through DWARF line data. DWARF location lists are used only",
            "for storage/lifetime constraints; treating their full ranges as uses would make",
            "long-lived variables overlap nearly everything.",
            "This first prototype uses token-boundary source occurrences; an AST-backed",
            "identifier resolver is the main hardening step before metric registration.",
            "",
            "Regenerate with:",
            "",
            "```bash",
            "python scripts/demo_local_variable_distance.py --check",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("testing/grep"))
    parser.add_argument("--source", type=Path, default=Path("testing/grep.c"))
    parser.add_argument("--preprocessed", type=Path, default=Path("testing/grep.i"))
    parser.add_argument("--ida-output", type=Path, default=Path("testing/ida_grep.c"))
    parser.add_argument("--ida-dir", type=Path, default=DEFAULT_IDA)
    parser.add_argument("--function", default="main")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("docs/experiments/local_variable_distance_grep_main"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    source = extract_source_evidence(
        args.binary,
        args.source,
        args.function,
        preprocessed_path=args.preprocessed,
    )
    idapro = _load_ida(args.ida_dir)
    with tempfile.TemporaryDirectory(prefix="decbench-lved-") as temp:
        stripped = Path(temp) / args.binary.name
        mask_elf_metadata(args.binary, stripped)
        from elftools.elf.elffile import ELFFile

        with stripped.open("rb") as stream:
            section_names = {
                section.name for section in ELFFile(stream).iter_sections()
            }
        metadata_hidden = not any(
            name.startswith(".debug") or name in {".symtab", ".strtab"}
            for name in section_names
        )
        idapro.open_database(str(stripped), run_auto_analysis=True)
        try:
            import ida_hexrays
            import idaapi

            cfunc = ida_hexrays.decompile(source.start)
            if cfunc is None:
                raise RuntimeError(f"IDA failed to decompile 0x{source.start:x}")
            decompiled = extract_ida_evidence(
                cfunc,
                elf_base=common.elf_min_vaddr(args.binary),
                image_base=int(idaapi.get_imagebase()),
                function_name=args.function,
            )
        finally:
            idapro.close_database(save=False)

    result = match_variables(source.variables, decompiled.variables)
    matches = _match_name_pairs(source, decompiled, result)
    provided = _provided_main(args.ida_output)
    provided_names = _provided_variable_names(provided, args.function)
    generated_names = {var.name for var in decompiled.variables if var.name}
    with args.binary.open("rb") as stream:
        instructions = set(
            instruction_addresses(
                ELFFile(stream),
                source.start,
                source.end,
            )
        )
    emitted_addresses = {
        address
        for var in [*source.variables, *decompiled.variables]
        for address in var.addresses
    }
    addresses_valid = all(
        source.start <= address < source.end and address in instructions
        for address in emitted_addresses
    )
    artifact_checks = {
        "ida_text_similarity": SequenceMatcher(
            None, provided, decompiled.code
        ).ratio(),
        "provided_name_coverage": (
            len(provided_names & generated_names) / len(provided_names)
            if provided_names
            else 1.0
        ),
        "provided_declared_names": len(provided_names),
        "generated_named_variables": len(generated_names),
        "shared_declared_names": len(provided_names & generated_names),
        "addresses_valid": addresses_valid,
        "decompiler_input_metadata_hidden": metadata_hidden,
        "preprocessed_contains_main": "main (int argc, char **argv)"
        in args.preprocessed.read_text(errors="replace"),
    }
    controls = _controls(source, decompiled, result)
    data = {
        "summary": {
            "function": args.function,
            "start": f"0x{source.start:x}",
            "end": f"0x{source.end:x}",
            "source_total": len(source.variables),
            "source_observable": result.source_count,
            "decompiled_total": result.decompiled_count,
            "matched": len(result.matches),
            "unmatched_source": len(result.unmatched_source),
            "unmatched_decompiled": len(result.unmatched_decompiled),
            "distance": result.distance,
            "strict_distance": result.strict_distance,
            "accuracy": result.accuracy,
            "stack_shift": result.stack_shift,
            "mapped_decompiled_lines": len(decompiled.line_addresses),
        },
        "matches": matches,
        "oracle_checks": _oracle_checks(matches),
        "negative_oracle_checks": _negative_oracle_checks(matches),
        "correspondence_checks": _correspondence_checks(source, decompiled),
        "unresolved_source": _unresolved_source(source, decompiled, result),
        "stack_aliases": _alias_groups(decompiled),
        "controls": controls,
        "artifact_checks": artifact_checks,
        "distance": result.to_dict(),
        "source": source.to_dict(),
        "decompiled": decompiled.to_dict(),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "evidence.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n"
    )
    (args.output_dir / "README.md").write_text(_render_markdown(data))
    print(json.dumps(data["summary"], indent=2))
    print(args.output_dir / "README.md")
    print(args.output_dir / "evidence.json")
    if args.check:
        checks = [
            all(row["passed"] for row in data["oracle_checks"]),
            all(row["passed"] for row in data["negative_oracle_checks"]),
            all(row["passed"] for row in data["correspondence_checks"]),
            controls["rename_invariant"],
            controls["disjoint_overlap_matches"] == 0,
            controls["fake_local_distance_delta"] == 1,
            artifact_checks["addresses_valid"],
            artifact_checks["decompiler_input_metadata_hidden"],
            artifact_checks["preprocessed_contains_main"],
            artifact_checks["provided_name_coverage"] == 1.0,
            artifact_checks["provided_declared_names"]
            == artifact_checks["generated_named_variables"],
            artifact_checks["ida_text_similarity"] >= 0.9,
        ]
        if not all(checks):
            raise SystemExit("local-variable-distance proof checks failed")


if __name__ == "__main__":
    main()
