#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from decbench.decompilers.raw.ghidra_raw import RawGhidraDecompiler
from decbench.experimental.local_variable_distance import (
    extract_decompiler_evidence,
    extract_source_evidence,
    mask_elf_metadata,
    match_variables,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("testing/grep"))
    parser.add_argument("--source", type=Path, default=Path("testing/grep.c"))
    parser.add_argument("--preprocessed", type=Path, default=Path("testing/grep.i"))
    parser.add_argument("--function", default="main")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ghidra-install-dir", type=Path)
    parser.add_argument("--keep-debug", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.ghidra_install_dir is not None:
        os.environ["GHIDRA_INSTALL_DIR"] = str(args.ghidra_install_dir)

    source = extract_source_evidence(
        args.binary,
        args.source,
        args.function,
        preprocessed_path=args.preprocessed,
    )
    with tempfile.TemporaryDirectory(prefix="decbench_lved_ghidra_") as temp_dir:
        decompiler_input = args.binary
        if not args.keep_debug:
            decompiler_input = Path(temp_dir) / args.binary.name
            mask_elf_metadata(args.binary, decompiler_input)

        decompiler = RawGhidraDecompiler()
        targets = [
            item
            for item in decompiler.discover_functions(decompiler_input)
            if item[1] == source.start
        ]
        if len(targets) != 1:
            raise RuntimeError(f"expected one Ghidra function at 0x{source.start:x}, got {targets}")
        result = decompiler.decompile_binary(decompiler_input, functions=targets)
        function = result.functions.get(targets[0][0])
        if function is None:
            raise RuntimeError(f"Ghidra did not decompile {targets[0][0]}")
        decompiled = extract_decompiler_evidence(
            function,
            backend="ghidra",
            function_name=args.function,
            function_end=source.end,
        )

    distance = match_variables(source.variables, decompiled.variables)
    payload = {
        "summary": {
            "function": args.function,
            "start": f"0x{source.start:x}",
            "end": f"0x{source.end:x}",
            "source_total": distance.source_count,
            "decompiled_total": distance.decompiled_count,
            "matched": len(distance.matches),
            "unmatched_source": len(distance.unmatched_source),
            "unmatched_decompiled": len(distance.unmatched_decompiled),
            "distance": distance.distance,
            "strict_distance": distance.strict_distance,
            "accuracy": distance.accuracy,
            "stack_shift": distance.stack_shift,
            "mapped_decompiled_lines": len(decompiled.line_addresses),
            "variables_with_addresses": sum(
                bool(variable.addresses) for variable in decompiled.variables
            ),
            "debug_masked": not args.keep_debug,
        },
        "decompiler": {
            "name": result.decompiler.decompiler_name,
            "version": result.decompiler.decompiler_version,
        },
        "source": source.to_dict(),
        "decompiled": decompiled.to_dict(),
        "matching": distance.to_dict(),
    }
    if args.check:
        assert decompiled.line_addresses
        assert all(variable.addresses for variable in decompiled.variables)
        code_lines = decompiled.code.splitlines()
        assert all(
            re.search(r"\b" + re.escape(variable.name) + r"\b", code_lines[line - 1])
            for variable in decompiled.variables
            for line in variable.lines
        )
        assert all(
            source.start <= address < source.end
            for addresses in decompiled.line_addresses.values()
            for address in addresses
        )
        assert any(match.stage == "overlap" for match in distance.matches)
        assert any(match.stage == "stack" for match in distance.matches)

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2) + "\n")

    for key, value in payload["summary"].items():
        print(f"{key} {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
