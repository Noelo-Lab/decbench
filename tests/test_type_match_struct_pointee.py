"""type_match credits any struct pointer against a pointer-to-struct ground truth."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from decbench.metrics.base import MetricConfig
from decbench.metrics.type_match import (
    TypeMatchMetric,
    aggregate_pointer_forms,
    extract_ground_truth_types,
)
from decbench.models.decompilation import FunctionDecompilation, VariableInfo

_SOURCE = """\
#include <stddef.h>
#include <stdio.h>
typedef struct Word { char *text; int length; } WORD;
typedef union Num { int i; float f; } NUM;
typedef struct Word *WordPtr;
typedef size_t count_t;
__attribute__((noinline)) int put_word(WORD *w, const struct Word **pp, NUM *n, char *s,
    void *v, count_t *c, WordPtr wp, struct Word byval, FILE *fp, int (*cb)(int)) {
  return w->length + (*pp)->length + n->i + s[0] + (v != 0) + (int)*c + wp->length
      + byval.length + (fp != 0) + cb(1);
}
static int id(int x) { return x; }
int main(void) {
  WORD w = {"hi", 2}; const struct Word *p = &w; NUM n = {1}; char s[2] = "x"; size_t c = 3;
  return put_word(&w, &p, &n, s, &c, &c, &w, w, stdout, id);
}
"""

_ANGR_PRELUDE = "typedef struct struct_0 { void* field_0; } struct_0;\n"


@pytest.fixture(autouse=True)
def _disable_metric_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECBENCH_NO_CACHE", "1")


@pytest.fixture(scope="module")
def put_word_truth(tmp_path_factory: pytest.TempPathFactory) -> list[dict[str, Any]]:
    if shutil.which("gcc") is None:
        pytest.skip("needs gcc")
    root = tmp_path_factory.mktemp("struct_pointee")
    src = root / "w.c"
    src.write_text(_SOURCE)
    binary = root / "w"
    subprocess.run(["gcc", "-g", "-O0", str(src), "-o", str(binary)], check=True)
    return extract_ground_truth_types(Path(binary))["put_word"]


def _forms(truth: list[dict[str, Any]]) -> dict[str, set[str]]:
    return {variable["name"]: set(variable["type"]) for variable in truth}


def _function(
    truth: list[dict[str, Any]], spellings: dict[str, str], prelude: str = _ANGR_PRELUDE
) -> FunctionDecompilation:
    """Decompiled ``put_word`` typing each named ground-truth argument at its ABI slot."""
    slots = {variable["arg_index"]: spellings[variable["name"]] for variable in truth}
    params = ", ".join(f"{slots[index]} a{index}" for index in sorted(slots))
    return FunctionDecompilation(
        name="put_word",
        address=0x1000,
        decompiled_code=f"{prelude}int put_word({params}) {{ return 0; }}\n",
        variables=[
            VariableInfo(name=f"a{index}", type=spelling, kind="arg", arg_index=index)
            for index, spelling in sorted(slots.items())
        ],
    )


def _score(function: FunctionDecompilation, truth: list[dict[str, Any]], backend: str) -> Any:
    return TypeMatchMetric(MetricConfig()).compute_for_function(
        function, ground_truth_vars=truth, backend=backend
    )


def test_ground_truth_marks_only_pointers_to_aggregates(
    put_word_truth: list[dict[str, Any]],
) -> None:
    forms = _forms(put_word_truth)
    assert {"<struct>*", "WORD*", "Word*"} <= forms["w"]
    assert "<struct>**" in forms["pp"] and "<struct>*" not in forms["pp"]
    assert "<union>*" in forms["n"] and "<struct>*" not in forms["n"]
    assert "<struct>*" in forms["wp"]
    assert "<struct>*" in forms["fp"]
    for name in ("s", "v", "c", "byval", "cb"):
        assert not any(form.startswith("<") for form in forms[name]), name


def test_cxx_class_pointers_and_references_are_struct_pointers(tmp_path: Path) -> None:
    if shutil.which("g++") is None:
        pytest.skip("needs g++")
    src = tmp_path / "c.cc"
    src.write_text(
        "class Node { public: int v; };\n"
        "int Take(Node *n, const Node &r) { return n->v + r.v; }\n"
        "int main() { Node a{1}; return Take(&a, a); }\n"
    )
    binary = tmp_path / "c"
    subprocess.run(["g++", "-g", "-O0", str(src), "-o", str(binary)], check=True)
    forms = _forms(extract_ground_truth_types(binary)["Take"])
    assert "<struct>*" in forms["n"]
    assert "<struct>*" in forms["r"]


def test_decompiled_kind_needs_a_keyword_or_a_declaration() -> None:
    spellings = [
        "struct_0 *",
        "struct_0 **",
        "struct stat *",
        "const struct termios *",
        "union pthread_mutex_t*",
        "astruct *",
        "FILE *",
        "struct_0",
        "char *",
        "void *",
    ]
    variables = [VariableInfo(type=spelling) for spelling in spellings]
    assert aggregate_pointer_forms(variables, _ANGR_PRELUDE) == [
        "<struct>*",
        "<struct>**",
        "<struct>*",
        "<struct>*",
        "<union>*",
        None,
        None,
        None,
        None,
        None,
    ]
    assert aggregate_pointer_forms(variables[:1], "") == [None]


@pytest.mark.parametrize("backend", ["angr", "external-text-decompiler"])
def test_any_struct_pointer_matches_at_the_same_depth(
    put_word_truth: list[dict[str, Any]], backend: str
) -> None:
    truth = [variable for variable in put_word_truth if variable["name"] in {"w", "pp", "n"}]

    def score(w: str, pp: str, n: str, prelude: str = _ANGR_PRELUDE) -> dict[str, Any]:
        function = _function(truth, {"w": w, "pp": pp, "n": n}, prelude)
        return dict(_score(function, truth, backend).metadata)

    kind_only = score("struct_0 *", "struct_0 **", "union U *")
    assert (kind_only["tp"], kind_only["tp_kind_only"]) == (3, 3)

    assert score("struct_0 **", "struct_0 *", "struct_0 *")["tp"] == 0

    named = score("WORD *", "struct_0 **", "long")
    assert (named["tp"], named["tp_kind_only"]) == (2, 1)

    assert score("struct_0 *", "struct_0 **", "U *", prelude="")["tp"] == 0


def test_typing_every_pointer_as_a_struct_loses_primitive_pointers(
    put_word_truth: list[dict[str, Any]],
) -> None:
    truth = [variable for variable in put_word_truth if variable["name"] in {"w", "s", "v", "c"}]
    everything_struct = _score(
        _function(truth, dict.fromkeys(("w", "s", "v", "c"), "struct_0 *")), truth, "angr"
    )
    faithful = _score(
        _function(truth, {"w": "long", "s": "char *", "v": "void *", "c": "size_t *"}),
        truth,
        "angr",
    )

    assert everything_struct.metadata["tp"] == 1
    assert everything_struct.metadata["fp"] == 3
    assert faithful.metadata["tp"] == 3
    assert everything_struct.value < faithful.value
