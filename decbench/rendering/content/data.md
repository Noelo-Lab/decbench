<!-- View template — see leaderboard.md for the shared conventions.

This is the DATA page (renamed from `distance` on 2026-07-23). It carries four
linkable sections, each headed by a RAW-HTML <h3 class="sub" id="..."> so the
anchor survives markdown rendering (a markdown `###` renders without an id):

  #distance         the per-metric edit-distance table (#distance-table)
  #compiles         the recompilation-rate table (#compile-table)
  #pipeline-health  Joern parse-health scaffolds (#joern-source /
                    #joern-output-table), moved here from about.md; filled by
                    app.js's buildPipelineHealth from data/dataset.json
  #cost             decompile time + estimated LLM API cost (#cost-table),
                    filled by app.js's buildCost from aggregates.json's `cost`
-->

# data

Benchmark-run data beyond the leaderboard's perfect rates:
[distance](#distance) from perfection per metric,
how often decompiled output [compiles](#compiles) again,
[pipeline health](#pipeline-health) (what our own tooling loses), and the
[cost](#cost) of producing each decompiler's output.

<h3 class="sub" id="distance">distance</h3>

When a decompiler can't yet achieve a perfect score on a function, it can be
helpful to understand the *distance* it is from perfection. For each
metric, we measure distance as the number of edits required to convert that
form of data into its source-code equivalent. For **GED**, that
is the number of edits to control-flow structures. For
**types**, that is the number of type-flips needed to reach
ground truth. For **recompilation**, that is the number of
assembly lines that must change to convert the recompiled assembly into the
ground-truth assembly.

Each cell shows the *mean*, the *median*, and how many functions
are already at distance 0 (perfect), averaged over the functions each
decompiler was scored on.

<p class="view-desc" id="distance-table-note">Over the selected dataset
    (mean &middot; median &middot; #at-0 / #measured).</p>

<table id="distance-table"><thead><tr></tr></thead><tbody></tbody></table>

<p class="view-desc subset-note" id="distance-subset-note" hidden>rows below the
break are <em>sample-set-only</em> backends (LLM coding agents): they are scored
only on the ~250-function sample-set slice, so on this dataset their numbers
cover just its overlap with that slice &mdash; not directly comparable to the
full-coverage rows above.</p>

<h3 class="sub" id="compiles">compiles</h3>

The share of each decompiler's byte_match-measured functions whose output
actually *recompiled* after the uniform compilability-fixup pass — a
fairness control, not a metric (type recovery is scored separately). The
denominator is per-decompiler: functions where byte_match was measurable, so
ARM / PE targets with no host recompiler never count against it. This rate moves
with the selected dataset, like the columns on the leaderboard.

<table id="compile-table"><thead><tr></tr></thead><tbody></tbody></table>

<p class="view-desc subset-note" id="compile-subset-note" hidden>rows below the
break: sample-set-only backends &mdash; their rate covers only this dataset's
overlap with the sample-set slice.</p>

<h3 class="sub" id="pipeline-health">pipeline health (our own tooling)</h3>

GED depends on Joern parsing both the source and the decompiler output.
When Joern fails on the **source**, that's our tooling — those
functions are excluded from GED for every decompiler (never counted against
them). When Joern fails on a single decompiler's **output**,
that's reported here (per decompiler), not folded into the headline score.

<div id="joern-source" class="goal"></div>
<table id="joern-output-table"><thead><tr></tr></thead><tbody></tbody></table>

<h3 class="sub" id="cost">cost</h3>

What each decompiler's output *costs* to produce. The two halves of the table
are **not directly comparable**: traditional decompilers are timed from
whole-binary batch decompilation (a binary's wall time divided by its function
count), while the LLM coding agents are timed per function — one agentic call
each, including all their tool use (objdump runs, reasoning, retries). The
dollar figures are **estimates**: recorded token usage from the sample-set run,
priced at public list prices at render time — not billed amounts. `-` means
not applicable or no data (traditional decompilers have no per-token cost;
an unpriced model shows n/a rather than $0.00).

<table id="cost-table"><thead><tr></tr></thead><tbody></tbody></table>
