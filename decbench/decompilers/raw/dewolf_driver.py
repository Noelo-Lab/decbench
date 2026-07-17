#!/usr/bin/env python3
"""Out-of-process dewolf driver — runs in the dewolf virtualenv, not decbench's.

dewolf (github.com/fkie-cad/dewolf) is a Binary Ninja plugin pinned to
``z3-solver==4.8.10`` and Python 3.10, so it cannot be imported into the
decbench venv (Python 3.14). :class:`decbench.decompilers.raw.dewolf_raw.
RawDewolfDecompiler` therefore shells out to THIS script inside the dewolf venv
(``DECBENCH_DEWOLF_PYTHON`` / ``DECBENCH_DEWOLF_REPO``); it does the Binary Ninja
analysis and dewolf decompilation and streams one JSON object per function back
on stdout.

It drives Binary Ninja ONCE per binary (a single ``BinaryView`` shared across
every function — dewolf's own ``Decompiler.from_raw`` wraps it), which is far
cheaper than the per-function subprocess the ``decompile.py`` CLI would cost.

Protocol (all on stdout, one JSON object per line):
  {"type": "meta", "load_base": <int>, "count": <int>}          # first line
  {"type": "func", "name": str, "addr": <elf-file-space int>,
   "code": str, "seconds": float}                                # per success
  {"type": "fail", "name": str, "addr": <int>, "error": str}     # per failure
  {"type": "done"}                                               # last line

Args: ``dewolf_driver.py <binary> <elf_min_vaddr> [addrs_json]``. ``addrs_json``
is a JSON list of ELF-file-space addresses to restrict to (the project's source
functions); omit / "NONE" to decompile every function binja finds.
"""

from __future__ import annotations

import contextlib
import json
import sys
import time
from typing import Any


def _emit(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> int:
    binary = sys.argv[1]
    elf_base = int(sys.argv[2])
    target_addrs: set[int] | None = None
    if len(sys.argv) > 3 and sys.argv[3] not in ("", "NONE"):
        try:
            target_addrs = {int(a) for a in json.loads(sys.argv[3])} or None
        except Exception:  # noqa: BLE001
            target_addrs = None

    import binaryninja as bn
    from decompile import Decompiler
    from decompiler.util.options import Options

    bv = bn.load(binary)
    bv.update_analysis_and_wait()
    load_base = int(bv.start)

    # ELF-file-space address for a binja function start (mirrors binja_raw).
    def elf_addr(start: int) -> int:
        return (int(start) - load_base) + elf_base

    # Thumb functions (ARM) can carry the low bit set; compare with it cleared.
    def matches(addr: int) -> bool:
        if target_addrs is None:
            return True
        return addr in target_addrs or (addr & ~1) in target_addrs or (addr | 1) in target_addrs

    selected = []
    for func in bv.functions:
        try:
            if getattr(func, "is_thunk", False):
                continue
            addr = elf_addr(func.start)
            if matches(addr):
                selected.append((func, addr))
        except Exception:  # noqa: BLE001
            continue

    _emit({"type": "meta", "load_base": load_base, "count": len(selected)})

    options: Options = Decompiler.create_options()
    # Keep a single stubborn function from wedging the whole binary: bound the
    # logic-engine timeouts (dewolf's dominant slow path — sympy/z3 on complex
    # conditions). These are milliseconds.
    for key in ("logic.engine.dead_path_timeout", "logic.engine.dead_loop_timeout"):
        with contextlib.suppress(Exception):
            options.set(key, 2000)

    decompiler = Decompiler.from_raw(bv)
    for func, addr in selected:
        name = str(func.name or f"sub_{func.start:x}")
        started = time.time()
        try:
            # dewolf accepts a function identifier: the binja Function works
            # directly (its frontend resolves name/address/object).
            _task, code = decompiler.decompile(func, options)
            if code and code.strip():
                _emit(
                    {
                        "type": "func",
                        "name": name,
                        "addr": addr,
                        "code": code,
                        "seconds": time.time() - started,
                    }
                )
            else:
                _emit({"type": "fail", "name": name, "addr": addr, "error": "empty output"})
        except Exception as exc:  # noqa: BLE001
            _emit({"type": "fail", "name": name, "addr": addr, "error": str(exc)[:200]})

    _emit({"type": "done"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
