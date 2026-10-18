"""Recorded compilation-unit provenance; never execute compile database commands."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shlex
from dataclasses import dataclass
from pathlib import Path


def compilation_path(path: str, directory: str | None = None) -> str:
    path = path.replace("\\", "/")
    if directory is not None and not (path.startswith("/") or re.match(r"^[a-zA-Z]:/", path)):
        path = directory.replace("\\", "/") + "/" + path
    path = posixpath.normpath(path)
    return path.casefold() if re.match(r"^[a-zA-Z]:/", path) else path


@dataclass(frozen=True)
class CompilationUnitBinding:
    native_unit: str
    source_file: str
    directory: str
    command_sha256: str


def saved_temp_units(database: Path) -> dict[str, CompilationUnitBinding]:
    """Connect object-relative compiler unit names to recorded original inputs.

    With -save-temps=obj, the compiler can record the object output without its
    final .o as the DWARF CU name. Only exact native-unit matches consume these
    bindings. Reused outputs with conflicting commands are deliberately omitted.
    """
    entries = json.loads(database.read_text())
    if not isinstance(entries, list):
        raise ValueError("compilation database must be a JSON list")
    candidates: dict[str, set[CompilationUnitBinding]] = {}
    for entry in entries:
        arguments = entry.get("arguments")
        if arguments is None:
            command = entry.get("command", "")
            if "-save-temps=obj" not in command:
                continue
            arguments = shlex.split(command)
        if "-save-temps=obj" not in arguments or "-c" not in arguments or "-o" not in arguments:
            continue
        directory = entry["directory"].replace("\\", "/")
        if not (directory.startswith("/") or re.match(r"^[a-zA-Z]:/", directory)):
            raise ValueError("recorded compilation directory must be absolute")
        source = compilation_path(entry["file"], directory)
        inputs = {
            compilation_path(argument, directory)
            for argument in arguments
            if not argument.startswith("-")
        }
        if source not in inputs:
            raise ValueError("compilation database source is absent from recorded arguments")
        output_position = arguments.index("-o") + 1
        if output_position >= len(arguments):
            raise ValueError("recorded -o has no output")
        output = compilation_path(arguments[output_position], directory)
        if not output.endswith(".o"):
            continue
        native_unit = output[:-2]
        command_sha256 = hashlib.sha256(json.dumps(arguments).encode()).hexdigest()
        binding = CompilationUnitBinding(
            native_unit, source, compilation_path(directory), command_sha256
        )
        candidates.setdefault(native_unit, set()).add(binding)
    return {key: next(iter(rows)) for key, rows in candidates.items() if len(rows) == 1}
