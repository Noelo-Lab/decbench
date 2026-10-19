#!/usr/bin/env python3
"""Compile an explicit fixture without linking/executing it; never emit C++ scores."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from decbench.utils.binfmt import BinInfo, object_info

TARGETS = ("aarch64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "arm64-apple-macos13")
OPTIMIZATIONS = (("O0", ("-O0",)), ("O2", ("-O2",)), ("O2-noinline", ("-O2", "-fno-inline")))


def run(command: list[str]) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=120).stdout


def text_sections(path: Path) -> list[tuple[str, str]]:
    import lief

    binary: Any = lief.parse(str(path))
    if isinstance(binary, lief.MachO.FatBinary):
        binary = binary.at(0)
    if binary is None:
        raise ValueError("compiler output is not a readable object")
    return [
        (section.name, hashlib.sha256(bytes(section.content)).hexdigest())
        for section in binary.sections
        if section.name in {".text", "__text"} and section.content
    ]


def audit(compiler: str, source: Path, output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    source = source.resolve()
    report: dict[str, Any] = {
        "profile": "cpp-toolchain-fixture-v1-diagnostic",
        "official_score": False,
        "compiler": str(Path(compiler).resolve()),
        "version": run([compiler, "--version"]),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "source": str(source),
        "executed_programs": False,
        "cells": [],
        "bounds": [
            "Explicit fixture only, not corpus qualification or recovered-code recompilation",
            "Clang cross-target output does not qualify GCC or native MSVC equivalence",
            "No standard-library, runtime linking, or execution parity qualification",
        ],
    }
    for target in TARGETS:
        for name, optimization in OPTIMIZATIONS:
            cell = output / target / name
            cell.mkdir(parents=True, exist_ok=True)
            flags = [
                "-target",
                target,
                "-std=c++17",
                "-g",
                "-fexceptions",
                "-fcxx-exceptions",
                *optimization,
            ]
            original, preprocessed, replay = (
                cell / "original.o",
                cell / "unit.ii",
                cell / "replay.o",
            )
            commands = [
                [compiler, *flags, "-c", str(source), "-o", str(original)],
                [compiler, *flags, "-E", str(source), "-o", str(preprocessed)],
                [
                    compiler,
                    *flags,
                    "-x",
                    "c++-cpp-output",
                    "-c",
                    str(preprocessed),
                    "-o",
                    str(replay),
                ],
                [compiler, *flags, "-S", "-emit-llvm", str(source), "-o", str(cell / "unit.ll")],
                [compiler, *flags, "-Xclang", "-ast-dump=json", "-fsyntax-only", str(source)],
            ]
            for command in commands[:-1]:
                run(command)
            ast_text = run(commands[-1])
            (cell / "ast.json").write_text(ast_text)
            ast = json.loads(ast_text)
            kinds: dict[str, int] = {}

            pending = [ast]
            while pending:
                node = pending.pop()
                kind = node.get("kind", "")
                kinds[kind] = kinds.get(kind, 0) + 1
                pending.extend(node.get("inner", []))
            ir = (cell / "unit.ll").read_text()
            identity = object_info(original)
            expected = {
                "aarch64-unknown-linux-gnu": BinInfo("elf", "aarch64", 64),
                "x86_64-pc-windows-msvc": BinInfo("pe", "x86-64", 64),
                "arm64-apple-macos13": BinInfo("macho", "aarch64", 64),
            }[target]
            if identity != expected or object_info(replay) != expected:
                raise ValueError("compiler objects do not match the requested target")
            first, second = text_sections(original), text_sections(replay)
            if not first or first != second:
                raise ValueError("preprocessing roundtrip changes code sections")
            if not all(
                kinds.get(k)
                for k in [
                    "FunctionTemplateDecl",
                    "TemplateArgument",
                    "CXXConstructExpr",
                    "CXXThrowExpr",
                ]
            ):
                raise ValueError("required C++ AST witnesses absent")
            cleanup = "cleanuppad" if "windows" in target else "landingpad"
            if "invoke " not in ir or "personality" not in ir or cleanup not in ir:
                raise ValueError("required exceptional cleanup IR absent")
            report["cells"].append(
                {
                    "target": target,
                    "optimization": name,
                    "object_identity": vars(identity),
                    "commands": commands,
                    "text_sections_identical": True,
                    "text_sections": first,
                    "ast_kinds": kinds,
                    "exception_ir_present": True,
                    "cleanup_ir_present": True,
                    "preprocessed_sha256": hashlib.sha256(preprocessed.read_bytes()).hexdigest(),
                    "ir_sha256": hashlib.sha256(ir.encode()).hexdigest(),
                    "ast_sha256": hashlib.sha256(ast_text.encode()).hexdigest(),
                }
            )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default=shutil.which("clang++"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.compiler is None:
        parser.error("clang++ or --compiler required")
    report = audit(args.compiler, args.source, args.output)
    (args.output / "REPORT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(report['cells'])} fixture cells verified; no corpus score produced")


if __name__ == "__main__":
    main()
