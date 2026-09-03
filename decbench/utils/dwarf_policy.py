"""Opt-in policy knobs for the DWARF function-discovery walk.

``DECBENCH_DWARF_ABSTRACT_ORIGIN=1`` makes the function-discovery walk
(:func:`decbench.utils.binfmt.source_function_owners` and the walks that mirror
it) resolve a C *concrete out-of-line instance* through its
``DW_AT_abstract_origin``.

Why it is a switch and not the default: gcc and clang split a C function that is
both inlined at some call site and still emitted out-of-line into an abstract
instance root (``DW_AT_name`` + ``DW_AT_inline``, no ``low_pc``) and a concrete
out-of-line instance (``DW_AT_low_pc``, no name, only ``DW_AT_abstract_origin``).
Neither half survives a walk that wants a ``low_pc`` and then a name, so the real
body is invisible. Taking the hop makes those bodies visible, and it also newly
surfaces functions in every already-published C result, which would move
historical scores. Default OFF keeps every existing result tree bit-identical; a
run that wants the bodies opts in.

Measured over the public corpus (``projects/{sailr,cps,malware}``, 40 projects,
288 binaries) at ``-O2``: DWARF-resolved source-function owners go 26,346 ->
29,956 (+13.7%; +19.0% on the sailr corpus alone), recovering real out-of-line
bodies such as zlib's ``gz_read`` and ``inflateReset``, bzip2's
``BZ2_bzWriteOpen``, grep's ``treenext`` and tar's ``chdir_do``. At ``-O0`` the
sailr and malware corpora are unchanged and three ``always_inline``-heavy
firmware targets move by 12 owners in total. ``O2-noinline`` still gains 4.8%,
because ``-fno-inline`` suppresses neither ``always_inline`` nor the
abstract-instance shape emitted for header-defined statics.

Scope: honoured by the run driver's target-set walk, ``pipeline.evaluate``, the
offline GED re-evaluation, the source-CFG export and the eval kit, so all of them
agree on one function set. Deliberately NOT applied to two name-keyed maps, for
two different reasons. :func:`decbench.metrics.type_match.extract_ground_truth_types`
has no ``low_pc`` requirement, so it already collects the abstract instance and its
parameters; taking the hop there would let the unnamed concrete instance overwrite
that entry and move type_match ground truth. :mod:`decbench.utils.source_extract`
does require ``low_pc``, so today it simply omits such a function — taking the hop
there would be additive rather than corrupting, but it is left out so this knob has
exactly one meaning, the function-discovery set, and nothing else shifts with it.
"""

from __future__ import annotations

import os

__all__ = ["dwarf_follow_abstract_origin"]


def dwarf_follow_abstract_origin() -> bool:
    """Whether the function-discovery DWARF walk chases ``DW_AT_abstract_origin`` in C."""
    return os.environ.get("DECBENCH_DWARF_ABSTRACT_ORIGIN") == "1"
