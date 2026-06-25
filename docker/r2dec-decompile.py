#!/usr/bin/env python3
"""In-container r2dec driver: decompile every function to /work/out.c.

Invoked by docker/r2dec.Dockerfile's ENTRYPOINT as:

    python3 r2dec-decompile.py /in/<binary>

It runs radare2 (with the r2dec plugin) over the binary and writes a single
whole-program C file to /work/out.c. Each function is wrapped in a synthetic
``<name>(void) { ... }`` definition so decbench's ``split_c_functions`` can split
the file back into per-function snippets by symbol name (addresses are attached
on the host side from the ELF symbol table).

Prefers the real r2dec plugin (``pd:d``/``pdd``); falls back to radare2's
built-in ``pdc`` pseudo-decompiler when the plugin is unavailable.
"""

from __future__ import annotations

import sys

import r2pipe


def _probe_cmd(r: "r2pipe.open") -> str:
    for cmd in ("pd:d", "pdd"):
        try:
            out = r.cmd(f"{cmd} @ entry0")
        except Exception:
            out = ""
        if out and "install the plugin" not in out and "Cannot" not in out:
            return cmd
    return "pdc"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: r2dec-decompile.py <binary>", file=sys.stderr)
        return 2
    binary = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "/work/out.c"

    r = r2pipe.open(
        binary,
        flags=["-2", "-e", "bin.relocs.apply=true", "-e", "scr.color=0"],
    )
    r.cmd("aaa")
    cmd = _probe_cmd(r)

    funcs = r.cmdj("aflj") or []
    pieces: list[str] = []
    for fn in funcs:
        name = fn.get("name", "")
        addr = fn.get("offset")
        if not name or addr is None:
            continue
        # Normalize r2 flag name (sym.foo / dbg.foo / fcn.0x...) to a bare ident
        # so it matches the ELF symbol table on the host side.
        bare = name.split(".")[-1]
        try:
            body = r.cmd(f"{cmd} @ {addr}") or ""
        except Exception as e:  # noqa: BLE001
            body = f"// r2dec failed: {e}"
        # Wrap so split_c_functions sees a top-level definition for `bare`.
        commented = "\n".join("    // " + ln for ln in body.splitlines())
        pieces.append(f"void {bare}(void) {{\n{commented}\n}}\n")

    r.quit()

    with open(out_path, "w") as f:
        f.write("\n".join(pieces))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
