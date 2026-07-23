<!-- View template — see leaderboard.md for the shared conventions. -->

# distance

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

### compiles

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
