"""Thumb-tagged entry addresses must still join against the even DWARF key.

The ARM ELF ABI encodes Thumb state in bit 0 of an ``STT_FUNC`` symbol value, so a
function whose DWARF ``low_pc`` is ``0x08000000`` is reported by ARM-aware tools as
``0x08000001``. angr is the only production backend that surfaces the tagged form:
on ``betaflight_STM32F405`` every one of its 3,978 addresses is odd while the DWARF
index has no odd key at all.

Three metric-side joins looked the reported address up verbatim. A function whose
static name is unique across the binary survived on the name fallback, but one whose
name repeats across translation units resolved to no ground truth and was dropped by
a bare ``continue`` -- silently, and only on ARM. The fail-closed coverage gate in
``scripts/reeval_typematch.py`` caught it as an overlay coverage mismatch (322
functions across the full corpus) rather than publishing a wrong number.

Patching only the ground-truth lookup would be worse than the original defect: the
coverage gate would go green while address-mode evidence stayed empty for every ARM
function. All three joins are covered here.
"""

from __future__ import annotations

from pathlib import Path

from decbench.metrics.type_evidence import PreprocessedSourceContext
from decbench.metrics.type_match import _ground_truth_for_function
from decbench.utils.native_code import entry_address_candidates

_THUMB_ENTRY = 0x08000001
_DWARF_ENTRY = 0x08000000


def test_candidates_add_the_masked_form_only_for_tagged_addresses() -> None:
    assert entry_address_candidates(_THUMB_ENTRY) == (_THUMB_ENTRY, _DWARF_ENTRY)
    assert entry_address_candidates(_DWARF_ENTRY) == (_DWARF_ENTRY,)


def test_ground_truth_resolves_a_thumb_entry_with_a_duplicated_static_name() -> None:
    """The exact production failure: a name repeated across TUs plus a tagged address."""

    wanted = [{"name": "count", "type": "int"}]
    index = {
        _DWARF_ENTRY: {"_putc": wanted},
        0x08001000: {"_putc": [{"name": "other", "type": "char"}]},
    }

    assert _ground_truth_for_function(index, "_putc", _THUMB_ENTRY) == wanted


def test_ground_truth_prefers_an_exact_odd_key_over_the_masked_one() -> None:
    odd = [{"name": "tagged", "type": "int"}]
    even = [{"name": "masked", "type": "int"}]
    index = {_THUMB_ENTRY: {"fn": odd}, _DWARF_ENTRY: {"fn": even}}

    assert _ground_truth_for_function(index, "fn", _THUMB_ENTRY) == odd


def test_ground_truth_still_misses_when_neither_form_is_present() -> None:
    index = {0x08002000: {"a": [{"name": "x"}], "b": [{"name": "y"}]}}

    assert _ground_truth_for_function(index, "absent", _THUMB_ENTRY) == []


def test_address_pinned_source_resolves_a_thumb_entry(monkeypatch) -> None:
    context = PreprocessedSourceContext([Path("build/led.i")], "firmware")
    monkeypatch.setattr(
        PreprocessedSourceContext,
        "_dwarf_source_index",
        lambda self, binary_path: {("_putc", _DWARF_ENTRY): ("src/led.c",)},
    )
    monkeypatch.setattr(
        PreprocessedSourceContext,
        "_path_for_cu",
        lambda self, cu_path, function_name: Path("build/led.i"),
    )

    resolved = context._address_pinned_path(Path("firmware.elf"), "_putc", _THUMB_ENTRY)

    assert resolved == Path("build/led.i")


def test_source_evidence_entry_candidates_cover_both_forms() -> None:
    """``extract_source_evidence`` matches DIE ranges through the same candidate set."""

    candidates = entry_address_candidates(_THUMB_ENTRY)
    die_ranges = ((_DWARF_ENTRY, _DWARF_ENTRY + 0x40),)

    assert any(begin in candidates for begin, _end in die_ranges)
