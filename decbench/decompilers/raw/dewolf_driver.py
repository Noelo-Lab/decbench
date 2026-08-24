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
   "code": str, "seconds": float, "variables": [                 # per success
     {"name": str, "type": str, "size": int | null,
      "kind": "arg" | "stack", "arg_index": int | null,
      "addresses": [<elf-file-space instruction address>, ...]}
   ]}
  {"type": "fail", "name": str, "addr": <int>, "error": str}     # per failure
  {"type": "done"}                                               # last line

Args: ``dewolf_driver.py <binary> <elf_min_vaddr> [addrs_json]``. ``addrs_json``
is a JSON list of ELF-file-space addresses to restrict to (the project's source
functions); omit / "NONE" to decompile every function binja finds.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any


def _emit(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


SSAKey = tuple[int, int]
SSADisplayKey = tuple[str, int]


def _configure_worker_threads(binaryninja: Any) -> int:
    """Apply the per-driver Binary Ninja worker cap and return it."""
    raw_count = os.environ.get("DECBENCH_DEWOLF_THREADS", "2")
    try:
        count = max(1, int(raw_count))
    except ValueError:
        count = 2
    binaryninja.set_worker_thread_count(count)
    return count


def _ssa_key(variable: Any) -> SSAKey | None:
    """Return a Binary Ninja SSA identity, including its stable variable ID."""
    source = getattr(variable, "var", None)
    version = getattr(variable, "version", None)
    identifier = getattr(source, "identifier", None)
    if identifier is None or version is None or isinstance(identifier, bool):
        return None
    try:
        return int(identifier), int(version)
    except (TypeError, ValueError, OverflowError):
        return None


def _ssa_display_key(variable: Any) -> SSADisplayKey | None:
    """Return the name/version pair retained in dewolf's pseudo variables."""
    source = getattr(variable, "var", None)
    version = getattr(variable, "version", None)
    if source is not None and version is not None:
        name = getattr(source, "name", None)
    else:
        name = getattr(variable, "name", None)
        version = getattr(variable, "ssa_label", None)
    if not name or version is None:
        return None
    try:
        return str(name), int(version)
    except (TypeError, ValueError, OverflowError):
        return None


def _instruction_at(mlil: Any, index: Any) -> Any | None:
    if index is None:
        return None
    if hasattr(index, "address") and hasattr(index, "operation"):
        return index
    try:
        return mlil[int(index)]
    except (TypeError, ValueError, OverflowError, IndexError, KeyError):
        return None


def _is_phi(instruction: Any) -> bool:
    operation = getattr(instruction, "operation", None)
    name = getattr(operation, "name", operation)
    return "PHI" in str(name).upper()


def _is_ssa_copy(instruction: Any) -> bool:
    operation = getattr(getattr(instruction, "operation", None), "name", "")
    source_operation = getattr(
        getattr(getattr(instruction, "src", None), "operation", None),
        "name",
        "",
    )
    return "SET_VAR" in str(operation) and str(source_operation) in {
        "MLIL_VAR",
        "MLIL_VAR_SSA",
        "MLIL_VAR_ALIASED",
    }


def _iter_mlil_instructions(mlil: Any) -> Iterable[Any]:
    try:
        for block in mlil:
            yield from block
    except (TypeError, AttributeError):
        return


def _ssa_address_index(
    function: Any,
) -> tuple[Any, dict[SSAKey, Any], dict[SSADisplayKey, set[SSAKey]], set[int]]:
    """Index SSA variables and real instruction starts for one Binary Ninja function."""
    mlil = function.medium_level_il.ssa_form
    variables: dict[SSAKey, Any] = {}
    display_keys: dict[SSADisplayKey, set[SSAKey]] = defaultdict(set)
    for instruction in _iter_mlil_instructions(mlil):
        for variable in list(getattr(instruction, "vars_read", ()) or ()) + list(
            getattr(instruction, "vars_written", ()) or ()
        ):
            if (key := _ssa_key(variable)) is not None:
                variables.setdefault(key, variable)
                if (display_key := _ssa_display_key(variable)) is not None:
                    display_keys[display_key].add(key)

    instruction_starts: set[int] = set()
    try:
        for item in function.instructions:
            try:
                address = item[1]
                if not isinstance(address, bool):
                    instruction_starts.add(int(address))
            except (TypeError, ValueError, IndexError, AttributeError):
                continue
    except (TypeError, AttributeError):
        pass
    return mlil, variables, display_keys, instruction_starts


def _resolve_ssa_origins(
    origins: set[SSADisplayKey],
    display_keys: dict[SSADisplayKey, set[SSAKey]],
) -> set[SSAKey]:
    """Resolve dewolf's name/version origins only when Binary Ninja makes them unique."""
    resolved: set[SSAKey] = set()
    for origin in origins:
        candidates = display_keys.get(origin, set())
        if len(candidates) == 1:
            resolved.update(candidates)
    return resolved


def _native_addresses_for_origins(
    mlil: Any,
    ssa_variables: dict[SSAKey, Any],
    origins: set[SSAKey],
    instruction_starts: set[int],
    blocked_origins: set[SSAKey] | None = None,
) -> set[int]:
    """Resolve final dewolf variable origins to native instruction starts.

    dewolf retains a Binary Ninja SSA variable in each final pseudo variable's
    ``ssa_name``. Binary Ninja then provides the native MLIL definition/use
    instruction for that identity. Phi nodes are not rendered C occurrences,
    so they contribute no address themselves; versions of the same Binary
    Ninja variable are followed to their real definitions and uses. Copies to
    a different Binary Ninja variable are uses, not identity evidence, so the
    destination is never followed.
    """
    if not instruction_starts:
        return set()

    blocked_origins = blocked_origins or set()
    pending = list(origins)
    visited: set[tuple[str, int]] = set()
    addresses: set[int] = set()
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        variable = ssa_variables.get(key)
        if variable is None:
            continue

        try:
            definition = _instruction_at(mlil, mlil.get_ssa_var_definition(variable))
        except Exception:  # noqa: BLE001
            definition = None
        if definition is not None:
            if _is_phi(definition):
                for operand in getattr(definition, "vars_read", ()) or ():
                    if (
                        (operand_key := _ssa_key(operand)) is not None
                        and operand_key[0] == key[0]
                        and operand_key not in blocked_origins
                    ):
                        pending.append(operand_key)
            else:
                with contextlib.suppress(TypeError, ValueError, OverflowError):
                    address = int(definition.address)
                    if address in instruction_starts:
                        addresses.add(address)
                if _is_ssa_copy(definition):
                    for source in getattr(definition, "vars_read", ()) or ():
                        if (
                            (source_key := _ssa_key(source)) is not None
                            and source_key[0] == key[0]
                            and source_key not in blocked_origins
                        ):
                            pending.append(source_key)

        try:
            uses = mlil.get_ssa_var_uses(variable) or ()
        except Exception:  # noqa: BLE001
            uses = ()
        for use in uses:
            instruction = _instruction_at(mlil, use)
            if instruction is None:
                continue
            if _is_phi(instruction):
                phi_variables = list(getattr(instruction, "vars_read", ()) or ()) + list(
                    getattr(instruction, "vars_written", ()) or ()
                )
                for phi_variable in phi_variables:
                    if (
                        (phi_key := _ssa_key(phi_variable)) is not None
                        and phi_key[0] == key[0]
                        and phi_key not in blocked_origins
                    ):
                        pending.append(phi_key)
                continue
            with contextlib.suppress(TypeError, ValueError, OverflowError):
                address = int(instruction.address)
                if address in instruction_starts:
                    addresses.add(address)
            if _is_ssa_copy(instruction):
                for destination in getattr(instruction, "vars_written", ()) or ():
                    if (
                        (destination_key := _ssa_key(destination)) is not None
                        and destination_key[0] == key[0]
                        and destination_key not in blocked_origins
                    ):
                        pending.append(destination_key)
    return addresses


def _type_size_bytes(variable_type: Any) -> int | None:
    """Convert dewolf's bit-sized pseudo type to bytes when it is well formed."""
    try:
        bits = int(variable_type.size)
    except (TypeError, ValueError, OverflowError, AttributeError):
        return None
    return bits // 8 if bits > 0 and bits % 8 == 0 else None


def _variable_records(
    task: Any,
    function: Any,
    to_file_address: Callable[[int], int],
) -> list[dict[str, Any]]:
    """Build structured final-variable records with Binary Ninja SSA provenance."""
    from decompiler.structures.pseudo import GlobalVariable, Variable

    parameters = list(getattr(task, "function_parameters", ()) or ())
    parameter_indices = {
        str(parameter.name): index
        for index, parameter in enumerate(parameters)
        if getattr(parameter, "name", None)
    }
    by_name: dict[str, dict[str, Any]] = {}
    origin_displays: dict[str, set[SSADisplayKey]] = defaultdict(set)

    def add(variable: Any) -> None:
        if not isinstance(variable, Variable) or isinstance(variable, GlobalVariable):
            return
        name = str(getattr(variable, "name", "") or "")
        if not name:
            return
        variable_type = getattr(variable, "type", None)
        entry = by_name.setdefault(
            name,
            {
                "name": name,
                "type": str(variable_type) if variable_type is not None else "",
                "size": _type_size_bytes(variable_type),
                "kind": "arg" if name in parameter_indices else "stack",
                "arg_index": parameter_indices.get(name),
                "addresses": [],
            },
        )
        if not entry["type"] and variable_type is not None:
            entry["type"] = str(variable_type)
        if entry["size"] is None:
            entry["size"] = _type_size_bytes(variable_type)

        origin = getattr(variable, "ssa_name", None)
        if (display_key := _ssa_display_key(origin) or _ssa_display_key(variable)) is not None:
            origin_displays[name].add(display_key)

    for parameter in parameters:
        add(parameter)
    ast = getattr(task, "ast", None)
    if ast is not None:
        for node in getattr(ast, "nodes", ()):
            for obj in node.get_dataflow_objets(ast.condition_map):
                for expression in obj.subexpressions():
                    add(expression)

    mlil, ssa_variables, display_keys, instruction_starts = _ssa_address_index(function)
    origins = {
        name: _resolve_ssa_origins(displays, display_keys)
        for name, displays in origin_displays.items()
    }
    all_origins = {origin for variable_origins in origins.values() for origin in variable_origins}
    for name, entry in by_name.items():
        blocked_origins = all_origins - origins.get(name, set())
        native = _native_addresses_for_origins(
            mlil,
            ssa_variables,
            origins.get(name, set()),
            instruction_starts,
            blocked_origins,
        )
        entry["addresses"] = sorted(to_file_address(address) for address in native)
    return list(by_name.values())


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

    worker_threads = _configure_worker_threads(bn)
    bv = bn.load(binary)
    bv.update_analysis_and_wait()
    load_base = int(bv.start)

    def elf_addr(start: int) -> int:
        return (int(start) - load_base) + elf_base

    # ARM Thumb functions can carry the low bit set; compare with it cleared.
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

    _emit(
        {
            "type": "meta",
            "load_base": load_base,
            "count": len(selected),
            "worker_threads": worker_threads,
        }
    )

    options: Options = Decompiler.create_options()
    # Bound dewolf's dominant slow path (sympy/z3 on complex conditions) so one
    # stubborn function cannot wedge the binary. In milliseconds.
    for key in ("logic.engine.dead_path_timeout", "logic.engine.dead_loop_timeout"):
        with contextlib.suppress(Exception):
            options.set(key, 2000)

    decompiler = Decompiler.from_raw(bv)
    for func, addr in selected:
        name = str(func.name or f"sub_{func.start:x}")
        started = time.time()
        try:
            task, code = decompiler.decompile(func, options)
            if code and code.strip():
                variables: list[dict[str, Any]] = []
                with contextlib.suppress(Exception):
                    variables = _variable_records(task, func, elf_addr)
                _emit(
                    {
                        "type": "func",
                        "name": name,
                        "addr": addr,
                        "code": code,
                        "seconds": time.time() - started,
                        "variables": variables,
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
