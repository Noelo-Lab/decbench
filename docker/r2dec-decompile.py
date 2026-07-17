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

Output is a JSON list of ``{"addr": <r2 addr>, "baddr": <r2 baddr>,
"name": <r2 flag>, "code": <decompiled C>}`` — the host normalizes the address
(``addr - baddr + elf_min_vaddr``) and splits nothing (each entry is already one
function).
"""

from __future__ import annotations

import json
import sys

import r2pipe

_R2_FLAGS = ["-2", "-e", "bin.relocs.apply=true", "-e", "scr.color=0"]

# r2 names for the ELF/PE entry alias (== _start / CRT entry), not user code.
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
        try:
            code = r.cmd(f"{cmd} @ {addr}") or ""
        except Exception:  # noqa: BLE001
            code = ""
        if not code.strip():
            continue
        out.append({"addr": addr, "baddr": baddr, "name": name, "code": code})

    r.quit()

    with open(out_path, "w") as f:
        json.dump(out, f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
