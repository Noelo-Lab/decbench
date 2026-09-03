"""The opt-in ``DW_AT_abstract_origin`` chase for C concrete out-of-line instances.

Builds the two-DIE shape gcc and clang emit for a C function that is both inlined
at some call site and still emitted out-of-line — an abstract instance root
(``DW_AT_name`` + ``DW_AT_inline``, no ``low_pc``) and a concrete instance
(``DW_AT_low_pc``, no name, only ``DW_AT_abstract_origin``) — and pins that the
concrete body is invisible by default and resolved only when the walk opts in.
"""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from decbench.utils import binfmt
from decbench.utils.dwarf_policy import dwarf_follow_abstract_origin

_ENV = "DECBENCH_DWARF_ABSTRACT_ORIGIN"


def _split_instance_cu(language: int | None = None) -> Any:
    """A CU holding one ordinary subprogram plus one abstract/concrete instance pair."""
    top_attrs: dict[str, Any] = {}
    if language is not None:
        top_attrs["DW_AT_language"] = SimpleNamespace(value=language)
    cu = SimpleNamespace(cu_offset=0, header={"version": 4})
    cu.get_top_DIE = lambda: SimpleNamespace(attributes=top_attrs)

    ordinary = SimpleNamespace(
        tag="DW_TAG_subprogram",
        cu=cu,
        attributes={
            "DW_AT_low_pc": SimpleNamespace(value=0x1000),
            "DW_AT_name": SimpleNamespace(value=b"gzopen"),
            "DW_AT_decl_file": SimpleNamespace(value=1),
        },
    )
    abstract = SimpleNamespace(
        tag="DW_TAG_subprogram",
        cu=cu,
        attributes={
            "DW_AT_name": SimpleNamespace(value=b"gz_read"),
            "DW_AT_inline": SimpleNamespace(value=1),
            "DW_AT_decl_file": SimpleNamespace(value=1),
        },
    )
    concrete = SimpleNamespace(
        tag="DW_TAG_subprogram",
        cu=cu,
        attributes={
            "DW_AT_low_pc": SimpleNamespace(value=0x2000),
            "DW_AT_abstract_origin": SimpleNamespace(value=abstract),
        },
    )
    concrete.get_DIE_from_attribute = lambda _name: abstract
    cu.iter_DIEs = lambda: iter((ordinary, abstract, concrete))
    return cu


@pytest.fixture
def dwarf_walk(monkeypatch: pytest.MonkeyPatch) -> Any:
    """``source_function_owners`` bound to the split-instance CU, decl-file ``gz.c``."""

    def _walk(*, language: int | None = None, follow: bool) -> dict[int, tuple[str, str]]:
        cu = _split_instance_cu(language)
        monkeypatch.setattr(
            binfmt, "dwarf_info", lambda _path: SimpleNamespace(iter_CUs=lambda: iter((cu,)))
        )
        monkeypatch.setattr(binfmt, "cu_file_table", lambda *_args: [None, "gz.c"])
        return binfmt.source_function_owners(Path("unused"), {"gz"}, follow_abstract_origin=follow)

    return _walk


def test_concrete_out_of_line_instance_is_invisible_by_default(dwarf_walk: Any) -> None:
    """Without the hop the concrete body has no name, so only the ordinary function resolves."""
    assert dwarf_walk(follow=False) == {0x1000: ("gzopen", "gz")}


def test_concrete_out_of_line_instance_resolves_when_the_walk_opts_in(dwarf_walk: Any) -> None:
    """The hop recovers the out-of-line body at its own ``low_pc``, adding to the default set."""
    assert dwarf_walk(follow=True) == {
        0x1000: ("gzopen", "gz"),
        0x2000: ("gz_read", "gz"),
    }


def test_cxx_units_take_the_hop_regardless_of_the_switch(dwarf_walk: Any) -> None:
    """C++ CUs already chase the origin, so the switch cannot move a C++ result."""
    cxx = 0x04
    assert dwarf_walk(language=cxx, follow=False) == dwarf_walk(language=cxx, follow=True)


def test_switch_is_off_unless_the_env_var_is_exactly_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only ``1`` enables the chase; unset, ``0`` and ``true`` all stay off."""
    monkeypatch.delenv(_ENV, raising=False)
    assert dwarf_follow_abstract_origin() is False
    for value in ("0", "true", "yes", ""):
        monkeypatch.setenv(_ENV, value)
        assert dwarf_follow_abstract_origin() is False, value
    monkeypatch.setenv(_ENV, "1")
    assert dwarf_follow_abstract_origin() is True
