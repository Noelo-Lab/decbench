"""Tests for the site's build-time aggregation (:mod:`decbench.rendering.aggregate`).

These pin the benchmark's **fairness contract** — the denominator rules that decide
what counts against a decompiler and what is charged to our own tooling — plus the
display conventions the port reproduces from the client-side JS it replaces.

The full port is additionally diffed field-by-field against the reference JS
implementation over the real 91k-function run by ``scripts/validate_aggregates.py``.
These tests cover the rules in isolation, on data small enough to reason about by
hand, including the cases the real corpus happens not to exercise.
"""

from __future__ import annotations

import re
from pathlib import Path

from decbench.models.function_data import (
    BinaryGroup,
    DatasetPreset,
    FunctionData,
    FunctionRecord,
    SampleEntry,
)
from decbench.models.scoreboard import Scoreboard
from decbench.rendering.aggregate import (
    ALL_PRESET,
    build_aggregates,
    build_dataset_page,
    build_payloads,
    combo_key,
)

DECS = ["alpha", "beta"]
METRICS = ["byte_match", "ged", "type_match"]


def _func(
    name: str,
    values: dict[str, dict[str, float]],
    perfects: dict[str, dict[str, bool]],
    decompiled: dict[str, bool] | None = None,
    distances: dict[str, dict[str, float]] | None = None,
    datasets: list[str] | None = None,
) -> FunctionRecord:
    """One synthetic function; ``decompiled`` defaults to 'both succeeded'."""
    return FunctionRecord(
        function=name,
        values=values,
        perfects=perfects,
        decompiled=decompiled if decompiled is not None else dict.fromkeys(DECS, True),
        distances=distances or {},
        datasets=datasets if datasets is not None else ["full"],
    )


def _data(functions: list[FunctionRecord], labels: list[str] | None = None) -> FunctionData:
    """Wrap functions in a one-group dataset with the standard presets."""
    return FunctionData(
        decompilers=list(DECS),
        metrics=list(METRICS),
        groups=[
            BinaryGroup(
                project="proj",
                opt_level="O0",
                binary="bin",
                labels=labels or [],
                functions=functions,
            )
        ],
        dataset_presets=[
            DatasetPreset(name="full", label="full", description=""),
            DatasetPreset(name="tiny", label="tiny", description=""),
        ],
    )


def _build(function_data: FunctionData) -> dict:
    return build_aggregates(function_data, Scoreboard())


# -- the shared-denominator rule -------------------------------------------


def test_metric_unmeasurable_for_everyone_leaves_every_denominator() -> None:
    """A metric no decompiler could be scored on is our failure, not theirs.

    ``byte_match`` abstains here (no recompile toolchain for the target), so it must
    leave BOTH decompilers' denominators — uniformly, or the two would be scored over
    different populations.
    """
    scored = _func(
        "scored",
        values={d: {"byte_match": 0.5, "ged": 1.0, "type_match": 1.0} for d in DECS},
        perfects={d: {"byte_match": False, "ged": False, "type_match": True} for d in DECS},
    )
    abstained = _func(
        "abstained",
        values={d: {"ged": 1.0, "type_match": 1.0} for d in DECS},
        perfects={d: {"ged": False, "type_match": True} for d in DECS},
    )
    combo = _build(_data([scored, abstained]))["combos"][combo_key("full", False)]

    for dec in DECS:
        assert combo["per_metric"][dec]["byte_match"] == [0, 1], "abstained function must drop out"
        assert combo["per_metric"][dec]["ged"] == [0, 2]
        assert combo["per_metric"][dec]["type_match"] == [2, 2]
    # `overall` is the Union column: a function counts once ANY metric is measurable,
    # and both functions are type_match-perfect, so both land in the numerator.
    assert combo["overall"]["alpha"] == [2, 2]


def test_source_parse_failure_drops_ged_for_everyone() -> None:
    """No source CFG => GED unmeasurable. Joern failing on the SOURCE is our fault.

    A function's source parsed iff SOME decompiler got a finite GED for it, so a
    function nobody has a GED for leaves GED's denominator entirely.
    """
    no_source = _func(
        "no_source",
        values={d: {"byte_match": 1.0, "type_match": 1.0} for d in DECS},
        perfects={d: {"byte_match": True, "type_match": True} for d in DECS},
    )
    combo = _build(_data([no_source]))["combos"][combo_key("full", False)]

    for dec in DECS:
        assert combo["per_metric"][dec]["ged"] == [0, 0], "GED denominator must be empty"
        assert combo["per_metric"][dec]["byte_match"] == [1, 1]
        # Union: byte_match/type_match are still measurable (and perfect), so the
        # function stays in and scores despite GED being unmeasurable for everyone.
        assert combo["overall"][dec] == [1, 1]


def test_joern_failing_on_one_decompilers_output_is_that_decompilers_miss() -> None:
    """Source parsed but one decompiler has no GED: a miss for it, measurable for all.

    The mirror image of the rule above — the difference between "our tooling failed"
    and "this decompiler's output was unparseable" is exactly whether ANYONE got a
    value.
    """
    func = _func(
        "half",
        values={
            "alpha": {"byte_match": 1.0, "ged": 0.0, "type_match": 1.0},
            "beta": {"byte_match": 1.0, "type_match": 1.0},  # Joern choked on beta's C
        },
        perfects={
            "alpha": {"byte_match": True, "ged": True, "type_match": True},
            "beta": {"byte_match": True, "type_match": True},
        },
    )
    aggregates = _build(_data([func]))
    combo = aggregates["combos"][combo_key("full", False)]

    assert combo["per_metric"]["alpha"]["ged"] == [1, 1]
    assert combo["per_metric"]["beta"]["ged"] == [0, 1], "same denominator, counted as a miss"
    assert combo["overall"]["alpha"] == [1, 1]
    # Union: beta misses GED but is byte_match/type_match-perfect, so it scores.
    assert combo["overall"]["beta"] == [1, 1]

    # ...and it is reported as a tooling stat on the Dataset page.
    dataset = build_dataset_page(_data([func]))
    assert dataset["joern"]["source"] == {"lost": 0, "total": 1}
    assert dataset["joern"]["output"] == {"alpha": [0, 1], "beta": [1, 1]}


def test_measurable_metric_a_decompiler_failed_is_a_miss_not_an_exclusion() -> None:
    """A decompiler that failed a measurable metric stays in the denominator.

    This is the rule that stops a decompiler from scoring well by refusing the hard
    functions: failing to decompile is a miss, not an exemption.
    """
    func = _func(
        "beta_failed",
        values={"alpha": {"byte_match": 1.0, "ged": 0.0, "type_match": 1.0}},
        perfects={"alpha": {"byte_match": True, "ged": True, "type_match": True}},
        decompiled={"alpha": True, "beta": False},
    )
    combo = _build(_data([func]))["combos"][combo_key("full", False)]

    for metric in METRICS:
        assert combo["per_metric"]["alpha"][metric] == [1, 1]
        assert combo["per_metric"]["beta"][metric] == [0, 1], f"{metric}: miss, not dropped"
    assert combo["overall"]["beta"] == [0, 1], "union: failed everything, still counted"
    assert combo["errors"]["beta"] == [1, 1], "attempted and produced nothing"
    assert combo["errors"]["alpha"] == [0, 1]


def test_errors_scope_counts_only_attempts() -> None:
    """A decompiler never asked for a function is out of its error scope."""
    func = _func(
        "unattempted",
        values={"alpha": {"byte_match": 1.0, "ged": 0.0, "type_match": 1.0}},
        perfects={"alpha": {"byte_match": True, "ged": True, "type_match": True}},
        decompiled={"alpha": True},
    )
    combo = _build(_data([func]))["combos"][combo_key("full", False)]
    assert combo["errors"]["alpha"] == [0, 1]
    assert combo["errors"]["beta"] == [0, 0], "not attempted => not in scope"


# -- normalize -------------------------------------------------------------


def test_normalize_restricts_to_functions_every_decompiler_decompiled() -> None:
    """normalize=1 compares like with like: only functions everyone decompiled."""
    both = _func(
        "both",
        values={d: {"byte_match": 1.0, "ged": 0.0, "type_match": 1.0} for d in DECS},
        perfects={d: {"byte_match": True, "ged": True, "type_match": True} for d in DECS},
    )
    only_alpha = _func(
        "only_alpha",
        values={"alpha": {"byte_match": 0.0, "ged": 5.0, "type_match": 0.0}},
        perfects={"alpha": {"byte_match": False, "ged": False, "type_match": False}},
        decompiled={"alpha": True, "beta": False},
    )
    aggregates = _build(_data([both, only_alpha]))

    plain = aggregates["combos"][combo_key("full", False)]
    assert plain["functions"] == 2
    assert plain["per_metric"]["alpha"]["ged"] == [1, 2]

    normalized = aggregates["combos"][combo_key("full", True)]
    assert normalized["functions"] == 1, "only the function both decompiled"
    assert normalized["per_metric"]["alpha"]["ged"] == [1, 1]
    assert normalized["per_metric"]["beta"]["ged"] == [1, 1]
    assert normalized["binaries"] == 1


def test_normalize_can_empty_a_group() -> None:
    """A binary whose functions all drop out stops counting toward `binaries`."""
    func = _func(
        "only_alpha",
        values={"alpha": {"byte_match": 1.0, "ged": 0.0, "type_match": 1.0}},
        perfects={"alpha": {"byte_match": True, "ged": True, "type_match": True}},
        decompiled={"alpha": True, "beta": False},
    )
    aggregates = _build(_data([func]))
    assert aggregates["combos"][combo_key("full", False)]["binaries"] == 1
    assert aggregates["combos"][combo_key("full", True)]["binaries"] == 0
    assert aggregates["totals"]["binaries"] == 1, "totals are corpus-wide, not per-combo"


# -- presets ---------------------------------------------------------------


def test_presets_are_non_exclusive_membership_tags() -> None:
    """A function can be in several presets; each combo sees only its members."""
    both = _func("both", values={}, perfects={}, datasets=["full", "tiny"])
    full_only = _func("full_only", values={}, perfects={}, datasets=["full"])
    aggregates = _build(_data([both, full_only]))

    assert aggregates["combos"][combo_key("full", False)]["functions"] == 2
    assert aggregates["combos"][combo_key("tiny", False)]["functions"] == 1
    assert set(aggregates["combos"]) == {
        combo_key(p, n) for p in ("full", "tiny") for n in (False, True)
    }


def test_default_preset_is_explicit_not_positional() -> None:
    """The site's landing preset comes from the content registry's `default` flag."""
    aggregates = _build(_data([_func("f", values={}, perfects={})]))
    defaults = [p["name"] for p in aggregates["presets"] if p.get("default")]
    assert defaults == ["full"]


# -- the no-presets fallback -----------------------------------------------


def _presetless(functions: list[FunctionRecord]) -> FunctionData:
    """A run whose functions carry no preset tags at all.

    Not hypothetical: preset tagging happens after the benchmark and is best-effort —
    ``cli.py``'s ``report`` wraps ``assign_datasets`` in ``except Exception: pass``, so
    any failure there lands here, as does re-rendering a ``function_results.json``
    written before presets existed.
    """
    data = _data(functions)
    data.dataset_presets = []
    for group in data.groups:
        for func in group.functions:
            func.datasets = []
    return data


def test_no_presets_still_aggregates_every_function() -> None:
    """A preset-less run renders the full corpus, not an error banner.

    Regression: with no presets there were no combos, so `currentCombo()` returned
    null and the leaderboard / metrics / distance views each painted
    "no precomputed aggregates for dataset 'null'" — zero numbers. The pre-aggregation
    client rendered everything here (`isActive()` opened `if (!state.dataset) return
    true;`), so this is a fallback, not a new feature.
    """
    # Values on every metric, so `overall` (Union: perfect on >=1 metric) is a real
    # count over both functions.
    everywhere = dict.fromkeys(METRICS, 1.0)
    funcs = [
        _func(
            "f1",
            values={"alpha": everywhere, "beta": everywhere},
            perfects={
                "alpha": dict.fromkeys(METRICS, True),
                "beta": dict.fromkeys(METRICS, False),
            },
        ),
        _func(
            "f2",
            values={"alpha": everywhere, "beta": everywhere},
            perfects={
                "alpha": {"ged": False, "type_match": True, "byte_match": True},
                "beta": dict.fromkeys(METRICS, False),
            },
        ),
    ]
    aggregates = _build(_presetless(funcs))

    assert set(aggregates["combos"]) == {combo_key(ALL_PRESET, False), combo_key(ALL_PRESET, True)}

    combo = aggregates["combos"][combo_key(ALL_PRESET, False)]
    # The leaderboard's real counts: every function present, [perfect, total] pairs
    # populated — not an empty table and not zeros.
    assert combo["functions"] == 2, "every function is active under the fallback"
    assert combo["binaries"] == 1
    assert combo["per_metric"]["alpha"]["ged"] == [1, 2]
    assert combo["per_metric"]["alpha"]["type_match"] == [2, 2]
    assert combo["per_metric"]["beta"]["ged"] == [0, 2]
    assert combo["overall"]["alpha"] == [2, 2], "f1 perfect everywhere, f2 on two metrics"
    assert combo["overall"]["beta"] == [0, 2]


def test_no_presets_emits_no_dataset_selector() -> None:
    """The fallback combo must NOT masquerade as a user-selectable preset.

    `presets` stays empty, so the sidebar renders no selector (there is nothing to
    choose between) and `__all__` never appears on screen as a button.
    """
    aggregates = _build(_presetless([_func("f", values={}, perfects={})]))
    assert aggregates["presets"] == []


def test_client_fallback_preset_matches_the_builder() -> None:
    """`app.js`'s FALLBACK_PRESET and `ALL_PRESET` are one constant across a language
    boundary: if they drift, the client looks up a combo the builder never wrote and
    the error banner comes back. Nothing else can catch that — the site is only
    assembled at render time.
    """
    js = (Path(__file__).parent.parent / "decbench/rendering/assets/app.js").read_text()
    match = re.search(r'const FALLBACK_PRESET = "([^"]+)"', js)
    assert match, "app.js must define FALLBACK_PRESET"
    assert match.group(1) == ALL_PRESET


# -- distance --------------------------------------------------------------


def test_median_is_the_upper_middle_element_not_a_true_median() -> None:
    """JS parity: `sorted[len // 2]`, never the average of the two middles.

    For even-length arrays this is not a real median. It is reproduced deliberately —
    it is the number the published report shows — and it is load-bearing: on the real
    run, 9 of 90 (preset, decompiler, metric) cells disagree with a true median.
    """
    funcs = [
        _func(
            f"f{i}",
            values={"alpha": {"ged": 0.0}},
            perfects={"alpha": {"ged": False}},
            distances={"alpha": {"ged": float(v)}},
        )
        for i, v in enumerate([1, 2, 3, 4])
    ]
    stats = _build(_data(funcs))["combos"][combo_key("full", False)]["distance"]["alpha"]["ged"]
    assert stats["median"] == 3.0, "upper-middle of [1,2,3,4]; a true median would be 2.5"
    assert stats["mean"] == 2.5
    assert stats["n"] == 4


def test_distance_has_no_shared_denominator_and_at0_is_independent() -> None:
    """`distance.n` is per-decompiler, and `at0` is NOT derived from `per_metric`.

    Unlike `per_metric`, distance applies no measurability universe — `n` is whatever
    a decompiler actually produced. `at0` comes from the distances map while `perfect`
    comes from the perfects map; on the real run they legitimately disagree for
    byte_match (angr: at0=451 vs perfect=483), so neither may be derived from the other.
    """
    func = _func(
        "f",
        values={d: {"ged": 0.0} for d in DECS},
        # alpha is flagged perfect but carries a non-zero distance: two sources of truth.
        perfects={"alpha": {"ged": True}, "beta": {"ged": False}},
        distances={"alpha": {"ged": 2.0}},
    )
    combo = _build(_data([func]))["combos"][combo_key("full", False)]

    assert combo["per_metric"]["alpha"]["ged"] == [1, 1]
    assert combo["distance"]["alpha"]["ged"]["at0"] == 0, "at0 reads the distances map"
    assert combo["distance"]["alpha"]["ged"]["n"] == 1
    assert combo["distance"]["beta"]["ged"] is None, "no distances => null, not zeros"


def test_distance_floats_are_emitted_exactly_not_rounded() -> None:
    """Emitted floats are EXACT. Rounding here was a real bug, not a size win.

    The client re-renders the mean at fewer places than it stores
    (``st.mean.toFixed(1)``), so rounding on the way out is a *first* rounding whose
    result the client rounds again. 5/3 = 1.6666... renders "1.7" either way, but a
    value that rounding lands exactly on a rendered half-boundary flips — see
    ``test_rounding_would_move_a_rendered_value``.
    """
    funcs = [
        _func(
            f"f{i}",
            values={"alpha": {"ged": 0.0}},
            perfects={"alpha": {"ged": False}},
            distances={"alpha": {"ged": v}},
        )
        for i, v in enumerate([1.0, 2.0, 2.0])
    ]
    stats = _build(_data(funcs))["combos"][combo_key("full", False)]["distance"]["alpha"]["ged"]
    assert stats["mean"] == 5 / 3, "emitted exactly as computed, not rounded to 1.667"


def test_rounding_would_move_a_rendered_value() -> None:
    """Pin WHY the rounding is gone: it changes what the reader sees.

    Distances 4.0/5.0/5.0/5.0/5.0/5.0/5.0/4.749... are contrived so the mean lands on
    a 1dp half-boundary only AFTER a 3dp round. The client renders `toFixed(1)`:
    the exact mean renders "4.7", the 3dp-rounded one renders "4.8". This is the
    `full|1 phoenix type_match` cell from the real run, in miniature.
    """
    mean = 4.749873609706775
    exact = f"{mean:.1f}"
    rounded = f"{round(mean, 3):.1f}"
    assert exact == "4.7"
    assert rounded == "4.8", "3dp rounding manufactures a 1dp half-boundary"
    assert exact != rounded, "rounding is NOT lossless: it moves a displayed value"


def test_payload_values_reach_the_client_exactly_as_measured() -> None:
    """Compare renders raw per-function values (`toFixed(2)`), so they ship unrounded.

    0.45454... must render "0.45" as it always did; stored as 0.455 it would render
    "0.46". Guards the 13 Compare cells that the deleted 3dp rounding moved.
    """
    value = 0.45454545454545453
    data = _data([_func("f", values={"alpha": {"ged": 0.0}}, perfects={"alpha": {"ged": False}})])
    data.samples = [
        SampleEntry(
            project="proj",
            opt_level="O0",
            binary="bin",
            function="xstrdup",
            values={"alpha": {"byte_match": value}},
            perfects={"alpha": {"byte_match": False}},
            decompiled={"alpha": "code"},
        )
    ]
    emitted = build_payloads(data, Scoreboard())["samples"][0]["values"]["alpha"]["byte_match"]
    assert emitted == value, "shipped exactly as measured"
    assert f"{emitted:.2f}" == "0.45", "renders as the old report did"
    assert f"{round(value, 3):.2f}" == "0.46", "...which 3dp rounding would have broken"


def test_non_finite_values_are_not_distances() -> None:
    """A non-finite distance is skipped (JS `isFinite`), leaving no trace."""
    func = _func(
        "f",
        values={"alpha": {"ged": 0.0}},
        perfects={"alpha": {"ged": False}},
        distances={"alpha": {"ged": float("inf"), "type_match": float("nan")}},
    )
    combo = _build(_data([func]))["combos"][combo_key("full", False)]
    assert combo["distance"]["alpha"]["ged"] is None
    assert combo["distance"]["alpha"]["type_match"] is None


def test_non_finite_ged_is_unmeasurable_not_a_miss() -> None:
    """A degenerate (non-finite) GED means no real source CFG: nobody is charged."""
    func = _func(
        "f",
        values={d: {"ged": float("inf")} for d in DECS},
        perfects={d: {"ged": False} for d in DECS},
    )
    combo = _build(_data([func]))["combos"][combo_key("full", False)]
    for dec in DECS:
        assert combo["per_metric"][dec]["ged"] == [0, 0]


# -- decompiledBy back-compat ----------------------------------------------


def test_decompiled_by_falls_back_to_perfects_presence() -> None:
    """Datasets predating `FunctionRecord.decompiled` infer attempts from `perfects`.

    JS parity: the fallback is `!!func.perfects[d]`, and in JS every object — `{}`
    included — is truthy, so it is a PRESENCE test. `bool(dict)` would be wrong here:
    Python's empty dict is falsy, so an empty perfects map would flip to "not
    decompiled" and shrink the normalize=1 universe. The real corpus never takes this
    path (every record has a `decompiled` map), so only this test pins it.
    """
    func = _func(
        "legacy",
        values={d: {"byte_match": 1.0, "ged": 0.0, "type_match": 1.0} for d in DECS},
        perfects={"alpha": {"byte_match": True, "ged": True, "type_match": True}, "beta": {}},
        decompiled={},  # legacy record: no decompiled map at all
    )
    aggregates = _build(_data([func]))

    # An EMPTY perfects map still means "beta decompiled it", so normalize keeps it.
    assert aggregates["combos"][combo_key("full", True)]["functions"] == 1
    assert build_dataset_page(_data([func]))["joern"]["output"]["beta"] == [0, 1]


def test_decompiled_by_fallback_excludes_a_decompiler_with_no_perfects_entry() -> None:
    """No `decompiled` map and no `perfects` entry => that decompiler did not run."""
    func = _func(
        "legacy",
        values={"alpha": {"byte_match": 1.0, "ged": 0.0, "type_match": 1.0}},
        perfects={"alpha": {"byte_match": True, "ged": True, "type_match": True}},
        decompiled={},
    )
    aggregates = _build(_data([func]))
    assert aggregates["combos"][combo_key("full", False)]["functions"] == 1
    assert aggregates["combos"][combo_key("full", True)]["functions"] == 0


# -- dataset page ----------------------------------------------------------


def test_dataset_page_is_selector_independent() -> None:
    """The Dataset page describes the corpus, so presets/normalize do not apply."""
    in_full = _func("a", values={}, perfects={}, datasets=["full"])
    in_none = _func("b", values={}, perfects={}, datasets=[])
    dataset = build_dataset_page(_data([in_full, in_none]))
    assert dataset["summary"]["functions"] == 2, "counts every function, tagged or not"
    assert dataset["summary"]["builds"] == 1
    assert dataset["summary"]["projects"] == 1


def test_dataset_categories_come_from_the_taxonomy() -> None:
    """A project joins a category when any of that category's labels is on a binary."""
    data = _data([_func("f", values={}, perfects={})], labels=["parsing", "crypto"])
    dataset = build_dataset_page(data)
    assert dataset["projects"][0]["cats"] == ["parser", "cryptography"], "taxonomy order"
    counts = {c["name"]: c["count"] for c in dataset["categories"]}
    assert counts["parser"] == 1
    assert counts["cryptography"] == 1
    assert counts["firmware"] == 0


def test_dataset_projects_are_sorted_by_loc_descending_and_stably() -> None:
    """Biggest project first; ties keep name order (a non-stable sort would not)."""
    data = FunctionData(
        decompilers=list(DECS),
        metrics=list(METRICS),
        groups=[
            BinaryGroup(project=name, opt_level="O0", binary="bin", functions=[])
            for name in ("bravo", "alfa", "charlie")
        ],
        dataset_presets=[DatasetPreset(name="full", label="full", description="")],
        dataset_info={"loc_by_project": {"charlie": 10}},
    )
    dataset = build_dataset_page(data)
    assert [p["name"] for p in dataset["projects"]] == ["charlie", "alfa", "bravo"]


def test_dataset_joern_source_loss_is_scoped_to_decompiled_functions() -> None:
    """Source-CFG loss is measured over functions at least one decompiler produced."""
    lost = _func(
        "lost",
        values={d: {"byte_match": 1.0} for d in DECS},
        perfects={d: {"byte_match": True} for d in DECS},
    )
    never_decompiled = _func(
        "skipped", values={}, perfects={}, decompiled=dict.fromkeys(DECS, False)
    )
    dataset = build_dataset_page(_data([lost, never_decompiled]))
    assert dataset["joern"]["source"] == {"lost": 1, "total": 1}
