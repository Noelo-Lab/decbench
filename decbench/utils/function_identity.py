"""Collision-safe function identity helpers.

DecBench historically stores decompilation results and several DWARF-derived
maps by unqualified function name. That is sufficient for the current C corpus,
but it collapses C++ overloads and same-named functions in different scopes.

This module provides two small building blocks for migrating that behavior
without changing non-colliding results:

* :func:`dwarf_function_identities` extracts concrete DWARF subprograms keyed by
  binary-local address while retaining the human-readable and linkage names.
* :func:`insert_function` keeps the legacy plain-name key while it is unique,
  and upgrades every colliding entry to ``<name>@0x<address>`` only when a real
  same-name/different-address collision appears.

Address is the canonical identity primitive *within one binary*. Linkage names
are retained as a strong C++ source/oracle join key, but are not required (for
example ``main`` normally has no C++ linkage name).
"""

from __future__ import annotations

import re
from collections.abc import MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

from decbench.utils import binfmt


@dataclass(frozen=True, slots=True)
class FunctionIdentity:
    """Concrete function identity recovered from a binary's DWARF."""

    address: int
    name: str
    linkage_name: str | None = None

    @property
    def address_key(self) -> str:
        """Stable binary-local key suitable for serialization and diagnostics."""
        return f"0x{self.address:x}"


class _FunctionLike(Protocol):
    name: str
    address: int


_FunctionT = TypeVar("_FunctionT", bound=_FunctionLike)


def function_storage_key(function: _FunctionLike) -> str:
    """Collision-qualified storage key for one function."""
    return f"{function.name}@0x{function.address:x}"


def parse_function_storage_key(storage_key: str) -> tuple[str, int | None]:
    """Return ``(semantic_name, address)`` encoded by a benchmark storage key.

    Unique functions keep the historical plain-name key and therefore return
    ``None`` for the address. Collision-qualified keys are generated only by
    DecBench and use ``<semantic-name>@0x<canonical-low-pc>``.
    """
    match = re.fullmatch(r"(.+)@0x([0-9a-fA-F]+)", storage_key)
    if match is None:
        return storage_key, None
    return match.group(1), int(match.group(2), 16)


def insert_function(
    functions: MutableMapping[str, _FunctionT],
    function: _FunctionT,
) -> str:
    """Insert ``function`` without collapsing a same-name/different-address peer.

    The plain function name is retained while it is unique, preserving the
    historical representation for the C corpus and ordinary non-colliding
    binaries. On the first collision, the existing plain-name entry is re-keyed
    by address and all subsequent colliders use address-qualified keys as well.

    A repeated observation of the same ``(name, address)`` replaces the existing
    value rather than creating a duplicate.

    Returns the key under which ``function`` was stored.
    """
    same_name = [(key, value) for key, value in functions.items() if value.name == function.name]

    for key, value in same_name:
        if value.address == function.address:
            functions[key] = function
            return key

    if not same_name:
        functions[function.name] = function
        return function.name

    # The first time a collision is discovered, remove the ambiguous plain-name
    # slot before inserting the new function. Entries already qualified by
    # address are left untouched.
    for key, value in same_name:
        if key == function.name:
            del functions[key]
            functions[function_storage_key(value)] = value

    key = function_storage_key(function)
    functions[key] = function
    return key


def dwarf_function_identities(binary_path: Path) -> list[FunctionIdentity]:
    """Return concrete DWARF functions without collapsing C++ name collisions.

    Only ``DW_TAG_subprogram`` DIEs with a concrete ``DW_AT_low_pc`` are kept.
    Name/linkage attributes are read through DecBench's existing
    ``DW_AT_specification`` / C++ ``DW_AT_abstract_origin`` chase so out-of-line
    member definitions resolve the same way as the existing C++ support.

    Producers can emit more than one DIE description for one code address; those
    are deduplicated by address, preferring a row that carries a linkage name.
    """
    dwarf = binfmt.dwarf_info(binary_path)
    if dwarf is None:
        return []

    by_address: dict[int, FunctionIdentity] = {}
    for cu in dwarf.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                continue

            name = binfmt.die_str_attr(die, "DW_AT_name")
            if not name:
                continue

            address = int(die.attributes["DW_AT_low_pc"].value)
            if not binfmt.dwarf_low_pc_is_concrete(binary_path, address):
                continue

            linkage = binfmt.die_str_attr(die, "DW_AT_linkage_name")
            if linkage is None:
                linkage = binfmt.die_str_attr(die, "DW_AT_MIPS_linkage_name")

            identity = FunctionIdentity(
                address=address,
                name=name,
                linkage_name=linkage,
            )
            current = by_address.get(identity.address)
            if current is None or (current.linkage_name is None and linkage is not None):
                by_address[identity.address] = identity

    return sorted(by_address.values(), key=lambda identity: identity.address)


def identities_by_name(
    identities: list[FunctionIdentity],
) -> dict[str, list[FunctionIdentity]]:
    """Group identities by unqualified name without discarding collisions."""
    grouped: dict[str, list[FunctionIdentity]] = {}
    for identity in identities:
        grouped.setdefault(identity.name, []).append(identity)
    return grouped
