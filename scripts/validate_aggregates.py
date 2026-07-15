#!/usr/bin/env python3
"""Diff the Python aggregate port against the JS reference implementation.

``decbench/rendering/aggregate.py`` is a port of the report's client-side
``recompute()`` / ``buildDistance()`` / ``buildDataset()``. Those functions produce
the benchmark's published numbers, so the port has to agree with them exactly — not
approximately, and not "close enough on the headline figures".

The reference JSON was produced by running the CURRENT client-side JS verbatim (via
node) over the real ``function_results.json``. This script rebuilds the same data in
Python and compares it field by field, reporting every mismatch with its path and
both values.

Comparison rules:

* Integer counts (every numerator/denominator, ``n``, ``at0``) must match EXACTLY.
* Floats match EXACTLY too. They used to be compared with a ``5e-4`` tolerance,
  because the port rounded its output to 3dp while the reference (raw JS) did not.
  That tolerance is what let a real rendering bug through for a whole review cycle:
  it asserted on the STORED number, while the claim being made ("rounding moves no
  displayed value") was about the RENDERED string. A stored delta of 5e-4 is
  invisible here but flips ``0.45454...``'s ``toFixed(2)`` from ``0.45`` to ``0.46``.
  The port no longer rounds, so exact equality is both achievable and the right
  assertion — it subsumes every rendering.
* Rendered strings are additionally asserted at the precision the client actually
  uses (see :func:`check_rendered`), so a reintroduced rounding fails naming the
  cell and the hazard rather than as an opaque float diff.
* A few fields are skipped in the diff because the reference cannot contain them —
  they are not derivable from ``function_results.json``, which is all the JS harness
  had. Each is asserted against its real owner instead (see ``SKIP_PATHS``), so
  "skipped" never means "unchecked".

What this CANNOT catch: the reference only covers ``aggregates.json`` and
``dataset.json``. The Compare view's per-function values ship in ``samples.json``,
which has no JS reference (the old client read them straight out of the embedded
``FunctionData``) — so those are checked against the source records instead, in
:func:`check_payload_fidelity`, rather than against a reference.

Usage::

    python scripts/validate_aggregates.py [results_tree] [reference_dir]
"""

from __future__ import annotations

import json
import sys
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

from decbench.models.function_data import FunctionData
from decbench.models.scoreboard import Scoreboard
from decbench.rendering.aggregate import build_aggregates, build_dataset_page, build_payloads

DEFAULT_RESULTS = Path("results/full_run")
DEFAULT_REFERENCE = Path(
    "/tmp/claude-1000/-home-mahaloz-github-decbench/"
    "64a1722c-9f61-4b56-b96a-b51d0b54bc17/scratchpad"
)

#: Not derivable from function_results.json, so the JS harness — which had only that
#: file — could not produce them. Each is asserted against its real source in main()
#: instead of against the reference; skipping here is not "not checked".
#:
#: * name / version / generated_at: live on the Scoreboard (harness wrote nulls).
#: * metric_registry / default_view: presentation, resolved from content/*.toml. They
#:   postdate the reference capture and the harness never emitted them at all.
SKIP_PATHS = {"name", "version", "generated_at", "metric_registry", "default_view"}

#: Decimal places each client render site uses, from decbench/rendering/assets/app.js.
#: These are the precisions a stored value gets RE-rounded to, i.e. exactly where a
#: lossy transform on the way out turns into a wrong number on screen.
RENDER_PLACES = {
    "distance_mean": 1,  # app.js buildDistance: st.mean.toFixed(1)
    "sample_value": 2,  # app.js renderSample:  Number(vals[m]).toFixed(2)
    "hardest_value": 3,  # app.js buildHardest:  Number(e.value).toFixed(3)
}


def js_to_fixed(value: float, places: int) -> str:
    """Render ``value`` exactly as JavaScript's ``Number.prototype.toFixed`` would.

    ``Decimal(float)`` takes the double's exact binary value (no re-parse), and
    ECMA-262 breaks ties by picking the larger ``n`` after moving the sign out — i.e.
    half away from zero, which is ``ROUND_HALF_UP``. Python's ``round``/``format``
    would use banker's rounding and disagree on precisely the half-boundaries this
    script exists to police.
    """
    quantum = Decimal(1).scaleb(-places)
    return str(Decimal(value).quantize(quantum, rounding=ROUND_HALF_UP))


def js_number_to_string(value: float) -> str:
    """Render ``value`` as JavaScript's string coercion (``'' + n``) would.

    Needed because the distance median is printed with no ``toFixed`` at all. JS has
    no int/float distinction: an integral double prints WITHOUT a decimal point, so
    ``8.0`` renders ``"8"`` where Python's ``str`` gives ``"8.0"``. The wire format
    differs too (``json.dumps(8.0)`` is ``8.0``, ``JSON.stringify(8)`` is ``8``) but
    both parse to the same double, so the browser prints the same thing — comparing
    Python's ``str`` here would report that non-difference as a diff.

    Both languages print shortest-round-trip otherwise. They diverge only on
    exponential-notation thresholds (JS switches at >=1e21 / <1e-6); distances are
    small non-negative magnitudes, so that cannot arise here.
    """
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    return repr(float(value))


def child_path(path: str, key: str) -> str:
    """The dotted path of ``key`` under ``path`` (top-level keys have no leading dot)."""
    return f"{path}.{key}" if path else str(key)


def compare(path: str, got: Any, want: Any, out: list[str]) -> None:
    """Recursively diff ``got`` against ``want``, appending every mismatch to ``out``."""
    if path in SKIP_PATHS:
        return
    if isinstance(want, dict):
        if not isinstance(got, dict):
            out.append(f"{path}: type mismatch: got {type(got).__name__}, want dict")
            return
        # Presence is checked against SKIP_PATHS too: a skipped field is absent from
        # the reference BY CONSTRUCTION (the harness could not derive it), so without
        # this it reports as EXTRA and the skip never takes effect.
        for key in want:
            if key not in got and child_path(path, key) not in SKIP_PATHS:
                out.append(f"{path}.{key}: MISSING in port (reference has {want[key]!r})")
        for key in got:
            if key not in want and child_path(path, key) not in SKIP_PATHS:
                out.append(f"{path}.{key}: EXTRA in port (value {got[key]!r})")
        for key in want:
            if key in got:
                compare(child_path(path, key), got[key], want[key], out)
        return
    if isinstance(want, list):
        if not isinstance(got, list):
            out.append(f"{path}: type mismatch: got {type(got).__name__}, want list")
            return
        if len(got) != len(want):
            out.append(f"{path}: length {len(got)} != reference {len(want)}")
            return
        for i, (g, w) in enumerate(zip(got, want, strict=True)):
            compare(f"{path}[{i}]", g, w, out)
        return
    if want is None or got is None:
        if got is not want:
            out.append(f"{path}: got {got!r}, want {want!r}")
        return
    if isinstance(want, bool) or isinstance(got, bool):
        if got != want:
            out.append(f"{path}: got {got!r}, want {want!r}")
        return
    if isinstance(want, int) and isinstance(got, int):
        # Counts are exact: a single function landing in the wrong denominator is a bug.
        if got != want:
            out.append(f"{path}: got {got}, want {want} (delta {got - want:+d})")
        return
    if isinstance(want, (int, float)) and isinstance(got, (int, float)):
        # Exact: the port does the same arithmetic in the same order on the same
        # doubles, so anything else is a real divergence, not float noise.
        if got != want:
            out.append(f"{path}: got {got!r}, want {want!r} (delta {got - want:+.6g})")
        return
    if got != want:
        out.append(f"{path}: got {got!r}, want {want!r}")


def check_rendered(aggregates: dict[str, Any], reference: dict[str, Any], out: list[str]) -> None:
    """Assert the distance table RENDERS identically to the reference.

    Redundant while floats compare exactly — and that is the point. This asserts the
    property the reader actually experiences (the string on screen), so if someone
    reintroduces a lossy transform on the way out, the failure says which cell moved
    and at what precision, instead of showing a float diff that looks like noise and
    invites another tolerance.
    """
    places = RENDER_PLACES["distance_mean"]
    for key, combo in reference.get("combos", {}).items():
        for dec, metrics in (combo.get("distance") or {}).items():
            for metric, want in (metrics or {}).items():
                if not want:
                    continue
                got = (
                    (((aggregates.get("combos") or {}).get(key) or {}).get("distance") or {})
                    .get(dec, {})
                    .get(metric)
                )
                if not got:
                    continue  # Structural gap; the field-by-field diff reports it.
                gs, ws = js_to_fixed(got["mean"], places), js_to_fixed(want["mean"], places)
                if gs != ws:
                    out.append(
                        f"RENDERED combos.{key}.distance.{dec}.{metric}.mean: "
                        f"renders {gs!r}, reference renders {ws!r} "
                        f"(stored {got['mean']!r} vs {want['mean']!r}, toFixed({places}))"
                    )
                # The median is rendered by plain string coercion — no toFixed at all —
                # so ANY transform of it is visible verbatim on screen, at full
                # precision. (It survives rounding today only because every distance
                # is an integer edit count; a fractional median would print all 17
                # digits, and rounding it would silently truncate what is displayed.)
                gm, wm = js_number_to_string(got["median"]), js_number_to_string(want["median"])
                if gm != wm:
                    out.append(
                        f"RENDERED combos.{key}.distance.{dec}.{metric}.median: "
                        f"renders {gm!r}, reference renders {wm!r}"
                    )


def check_payload_fidelity(
    function_data: FunctionData, scoreboard: Scoreboard, out: list[str]
) -> None:
    """Assert Compare/Hardest values reach the client exactly as measured.

    These have no JS reference (the old client read them straight from the embedded
    ``FunctionData``), so the source records ARE the ground truth: the payload must
    render identically to the measurement. This is the check that would have caught
    the 3dp rounding moving 13 Compare cells.

    Entries are matched by identity, never by position: ``build_payloads`` drops
    malware-project entries, so the payload is a subsequence of the source records.
    An identity a record shares with another is skipped rather than guessed at.
    """
    payloads = build_payloads(function_data, scoreboard)

    def index(records: Any, key: Any) -> dict[Any, Any]:
        """Key records by identity, dropping any identity that is not unique."""
        found: dict[Any, Any] = {}
        for record in records:
            found.setdefault(key(record), []).append(record)
        return {k: v[0] for k, v in found.items() if len(v) == 1}

    places = RENDER_PLACES["sample_value"]
    samples = index(
        function_data.samples,
        lambda r: (r.project, r.opt_level, r.binary, r.function),
    )
    for emitted in payloads["samples"]:
        record = samples.get(
            (emitted["project"], emitted["opt_level"], emitted["binary"], emitted["function"])
        )
        if record is None:
            continue
        for dec, values in (record.values or {}).items():
            for metric, want in (values or {}).items():
                got = ((emitted.get("values") or {}).get(dec) or {}).get(metric)
                if want is None or got is None:
                    continue
                if js_to_fixed(got, places) != js_to_fixed(want, places):
                    out.append(
                        f"RENDERED samples {record.project}/{record.opt_level}/"
                        f"{record.binary} :: {record.function} | {dec} | {metric}: renders "
                        f"{js_to_fixed(got, places)!r}, measured {want!r} renders "
                        f"{js_to_fixed(want, places)!r} (toFixed({places}))"
                    )

    places = RENDER_PLACES["hardest_value"]
    hardest = index(
        function_data.hardest,
        lambda r: (r.metric, r.decompiler, r.project, r.opt_level, r.binary, r.function),
    )
    for emitted in payloads["hardest"]:
        record = hardest.get(
            (
                emitted["metric"],
                emitted["decompiler"],
                emitted["project"],
                emitted["opt_level"],
                emitted["binary"],
                emitted["function"],
            )
        )
        if record is None:
            continue
        for field in ("value", "perfect_value"):
            want, got = getattr(record, field, None), emitted.get(field)
            if want is None or got is None:
                continue
            if js_to_fixed(got, places) != js_to_fixed(want, places):
                out.append(
                    f"RENDERED hardest {record.function} | {record.metric} | "
                    f"{record.decompiler} | {field}: renders {js_to_fixed(got, places)!r}, "
                    f"measured {want!r} renders {js_to_fixed(want, places)!r} "
                    f"(toFixed({places}))"
                )


def main() -> int:
    """Build both files from the real run and diff them against the reference."""
    results = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_RESULTS
    reference = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_REFERENCE

    print(f"loading {results / 'function_results.json'} ...", file=sys.stderr)
    function_data = FunctionData.from_json(results / "function_results.json")
    scoreboard = Scoreboard.from_toml(results / "scoreboard.toml")
    print(f"loaded: {len(function_data.groups)} groups", file=sys.stderr)

    aggregates = build_aggregates(function_data, scoreboard)
    dataset = build_dataset_page(function_data)

    ref_aggregates = json.loads((reference / "reference_aggregates.json").read_text())
    ref_dataset = json.loads((reference / "reference_dataset.json").read_text())

    diffs: list[str] = []
    compare("", aggregates, ref_aggregates, diffs)
    compare("dataset", dataset, ref_dataset, diffs)
    check_rendered(aggregates, ref_aggregates, diffs)
    check_payload_fidelity(function_data, scoreboard, diffs)

    # The skipped fields still have to come from somewhere: assert the port sourced
    # each from its real owner rather than leaving it null.
    from decbench.rendering.content import load_content

    content = load_content()
    for key, want in (
        ("name", scoreboard.name),
        ("version", scoreboard.version),
        ("generated_at", scoreboard.generated_at.isoformat()),
        ("default_view", content.default_view),
    ):
        if aggregates.get(key) != want:
            diffs.append(f"{key}: got {aggregates.get(key)!r}, want {want!r} (from its source)")

    want_registry = {
        spec.name: {
            "display_name": spec.display_name,
            "short_name": spec.short_name,
            "order": spec.order,
        }
        for spec in content.metrics
        if spec.name in aggregates["metrics"]
    }
    if aggregates.get("metric_registry") != want_registry:
        diffs.append(
            f"metric_registry: got {aggregates.get('metric_registry')!r}, "
            f"want {want_registry!r} (from content/metrics.toml)"
        )

    combos = len(aggregates["combos"])
    print(
        f"compared {combos} combos + dataset page (floats exact, renders checked); "
        f"payload fidelity: {len(function_data.samples)} samples, "
        f"{len(function_data.hardest)} hardest",
        file=sys.stderr,
    )
    if diffs:
        print(f"\n{len(diffs)} MISMATCH(ES):")
        for line in diffs:
            print(f"  {line}")
        return 1
    print("\nEMPTY")
    return 0


if __name__ == "__main__":
    sys.exit(main())
