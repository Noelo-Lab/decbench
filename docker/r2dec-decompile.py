#!/usr/bin/env python3
"""In-container r2dec driver: decompile (filtered) functions to a JSON file.

Invoked by ``docker/r2dec.Dockerfile``'s ENTRYPOINT as:

    python3 r2dec-decompile.py /in/<binary> /work/out.json [/work/targets.json]

It runs radare2 over the (possibly stripped) binary — ``aaa`` for analysis,
``aflj`` for discovery — and decompiles each function with the r2dec ``pdd``
command (the real decompiler), falling back to radare2's built-in ``pdc``
pseudo-decompiler only if the r2dec plugin is missing. Discovery is from
radare2's OWN analysis, so it works on fully stripped ELF/PE and on ARM firmware.

``targets.json`` (optional) is a JSON list of ELF-file-space ADDRESSES (DWARF
low_pc) the host wants; when present, only functions whose radare2 address
matches (Thumb-bit tolerant) are decompiled. radare2 loads the binary at its own
``baddr`` (== the ELF's min PT_LOAD vaddr / PE ImageBase), so a function's r2
address already equals the ELF-file-space address the host filters by.

Output is a JSON list containing the function identity and C plus optional raw
r2-space line mappings and variable metadata. The host validates and rebases all
addresses with ``addr - baddr + elf_min_vaddr``; each entry is already one
function.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import r2pipe

_R2_FLAGS = ["-2", "-e", "bin.relocs.apply=true", "-e", "scr.color=0"]
_SCHEMA_VERSION = 1

_ENTRY_NAMES = frozenset({"entry0", "entry1", "entry.init0", "entry.fini0", "entry.preinit0"})


def _probe_cmd(r: r2pipe.open) -> str:
    """Prefer the real r2dec ``pdd``; fall back to the built-in ``pdc``."""
    try:
        out = r.cmd("pdd @ entry0")
    except Exception:  # noqa: BLE001
        out = ""
    if out and "install the plugin" not in out and "Cannot find" not in out:
        return "pdd"
    return "pdc"


def _is_import(name: str) -> bool:
    """Whether an r2 function flag names an import / PLT / reloc stub."""
    return (
        name.startswith("sym.imp.")
        or name.startswith("imp.")
        or name.startswith("reloc.")
        or ".imp." in name
    )


def _addr_matches(addr: int, targets: set[int]) -> bool:
    """Address membership, tolerating the ARM Thumb T-bit (odd vs even)."""
    return addr in targets or (addr & ~1) in targets or (addr | 1) in targets


def _as_int(value: Any, default: int | None = None) -> int | None:
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _cmdj(r: r2pipe.open, command: str, default: object) -> object:
    try:
        payload = r.cmdj(command)
    except Exception:  # noqa: BLE001
        return default
    return default if payload is None else payload


def _json_code(payload: object) -> tuple[str, list[dict[str, object]]] | None:
    rows = payload.get("lines") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows:
        return None

    rendered: list[tuple[str, int | None]] = []
    for row in rows:
        if not isinstance(row, dict) or "str" not in row:
            continue
        text = str(row.get("str") or "")
        pieces = text.splitlines() or [""]
        offset = _as_int(row.get("offset"))
        rendered.extend((piece, offset) for piece in pieces)
    while rendered and not rendered[0][0].strip():
        rendered.pop(0)
    while rendered and not rendered[-1][0].strip():
        rendered.pop()
    if not rendered:
        return None

    return "\n".join(text for text, _offset in rendered), [
        {"line_number": line_number, "addresses": [offset]}
        for line_number, (_text, offset) in enumerate(rendered, 1)
        if offset is not None
    ]


def _annotated_code(payload: object) -> tuple[str, list[dict[str, object]]] | None:
    if not isinstance(payload, dict):
        return None
    raw_code = str(payload.get("code") or "")
    code = raw_code.strip()
    annotations = payload.get("annotations")
    if not code or not isinstance(annotations, list):
        return None
    code_start = raw_code.find(code)
    mappings: list[dict[str, object]] = []
    for annotation in annotations:
        if not isinstance(annotation, dict):
            continue
        offset = _as_int(annotation.get("offset"))
        position = _as_int(annotation.get("start"))
        if offset is None or position is None or position < code_start:
            continue
        adjusted = min(position - code_start, len(code))
        mappings.append(
            {
                "line_number": code.count("\n", 0, adjusted) + 1,
                "addresses": [offset],
            }
        )
    return code, mappings


def _variables(
    r: r2pipe.open,
    addr: int,
    line_mappings: list[dict[str, object]],
) -> list[dict[str, object]]:
    metadata = _cmdj(r, f"afvj @ {addr}", {})
    if not isinstance(metadata, dict):
        return []

    accesses: dict[str, set[int]] = {}
    for command in ("afvRj", "afvWj"):
        records = _cmdj(r, f"{command} @ {addr}", [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            name = str(record.get("name") or "")
            if not name:
                continue
            for value in record.get("addrs") or []:
                address = _as_int(value)
                if address is not None:
                    accesses.setdefault(name, set()).add(address)

    signature = _cmdj(r, f"afcfj @ {addr}", [])
    signature_args: list[str] = []
    if isinstance(signature, list) and signature and isinstance(signature[0], dict):
        signature_args = [
            str(arg.get("name") or "")
            for arg in signature[0].get("args") or []
            if isinstance(arg, dict) and arg.get("name")
        ]
    lines_by_address: dict[int, set[int]] = {}
    for mapping in line_mappings:
        line_number = _as_int(mapping.get("line_number"))
        if line_number is None:
            continue
        for value in mapping.get("addresses") or []:
            address = _as_int(value)
            if address is not None:
                lines_by_address.setdefault(address, set()).add(line_number)

    ordered: list[tuple[str, dict[str, object]]] = []
    for group in ("reg", "sp", "bp"):
        records = metadata.get(group) or []
        if isinstance(records, list):
            ordered.extend((group, record) for record in records if isinstance(record, dict))

    fallback_args = list(
        dict.fromkeys(
            str(record.get("name") or "")
            for group, record in ordered
            if (group == "reg" or str(record.get("kind") or "") == "arg") and record.get("name")
        )
    )
    signature_positions = {name: index for index, name in enumerate(signature_args)}
    arg_positions = {
        name: signature_positions.get(name, index) for index, name in enumerate(fallback_args)
    }

    variables: list[dict[str, object]] = []
    seen: set[tuple[str, str, int | None]] = set()
    for group, record in ordered:
        name = str(record.get("name") or "")
        if not name:
            continue
        ref = record.get("ref")
        stack_offset = _as_int(ref.get("offset")) if isinstance(ref, dict) else None
        identity = (group, name, stack_offset)
        if identity in seen:
            continue
        seen.add(identity)
        addresses = sorted(accesses.get(name, set()))
        variables.append(
            {
                "name": name,
                "type": str(record.get("type") or ""),
                "stack_offset": stack_offset,
                "size": _as_int(record.get("size")),
                "kind": "arg" if name in arg_positions else "stack",
                "arg_index": arg_positions.get(name),
                "line_numbers": sorted(
                    {
                        line_number
                        for address in addresses
                        for line_number in lines_by_address.get(address, set())
                    }
                ),
                "addresses": addresses,
            }
        )
    return variables


def _decompile(r: r2pipe.open, cmd: str, addr: int, architecture: str) -> dict[str, object] | None:
    code = ""
    line_mappings: list[dict[str, object]] = []
    if cmd in {"pdd", "pdc"}:
        payload = _cmdj(r, f"{cmd}j @ {addr}", None)
        parsed = _json_code(payload) if cmd == "pdd" else _annotated_code(payload)
        if parsed is not None:
            code, line_mappings = parsed
    if not code:
        try:
            code = str(r.cmd(f"{cmd} @ {addr}") or "").strip()
        except Exception:  # noqa: BLE001
            code = ""
    if not code or "install the plugin" in code:
        return None

    function_info = _cmdj(r, f"afij @ {addr}", [])
    info = (
        function_info[0]
        if isinstance(function_info, list) and function_info and isinstance(function_info[0], dict)
        else {}
    )
    is_thumb = architecture.startswith("arm") and (
        (_as_int(info.get("bits"), 0) or 0) == 16 or bool(addr & 1)
    )
    return {
        "code": code,
        "size": _as_int(info.get("size"), 0) or 0,
        "is_thumb": is_thumb,
        "line_mappings": line_mappings,
        "variables": _variables(r, addr, line_mappings),
    }


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: r2dec-decompile.py <binary> [out.json] [targets.json]", file=sys.stderr)
        return 2
    binary = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "/work/out.json"

    targets: set[int] | None = None
    if len(sys.argv) > 3 and sys.argv[3] not in ("", "NONE"):
        try:
            with open(sys.argv[3]) as f:
                targets = {int(a) for a in json.load(f)} or None
        except Exception:  # noqa: BLE001
            targets = None

    r = r2pipe.open(binary, flags=_R2_FLAGS)
    r.cmd("aaa")
    cmd = _probe_cmd(r)
    info = r.cmdj("ij") or {}
    baddr = int((info.get("bin") or {}).get("baddr") or 0)
    architecture = str((info.get("bin") or {}).get("arch") or "").lower()

    funcs = r.cmdj("aflj") or []
    out: list[dict[str, object]] = []
    for fn in funcs:
        name = fn.get("name") or ""
        addr = fn.get("addr")
        if addr is None:
            addr = fn.get("offset")
        if not name or addr is None:
            continue
        if _is_import(name) or name in _ENTRY_NAMES:
            continue
        addr = int(addr)
        if targets is not None and not _addr_matches(addr, targets):
            continue
        record = _decompile(r, cmd, addr, architecture)
        if record is None:
            continue
        out.append({"addr": addr, "baddr": baddr, "name": name, **record})

    r.quit()

    with open(out_path, "w") as f:
        json.dump({"schema_version": _SCHEMA_VERSION, "command": cmd, "functions": out}, f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
