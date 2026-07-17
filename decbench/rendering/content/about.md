<!--
The "about" page — NOT the page the site opens on.

If you came here to edit the text people see FIRST, you want leaderboard.md:
the site opens on the leaderboard (`default = true` in views.toml) and this page
is the LAST nav item. The starting-page prose is split between the two — the
short intro above the table lives in leaderboard.md, the long explainer is here.

This page absorbed the old `metrics` and `dataset` views, so it is the one
place that explains WHY the benchmark exists, WHAT the three metrics measure
(the `## [n]` goal cards below — the renderer turns each into a
<div class="goal"> card; see the conventions in leaderboard.md), and WHAT the
corpus is (the dataset scaffolds near the end, filled by app.js from
data/dataset.json).

GOAL CARDS. The `## [n] ...` sections are STRUCTURED:

  ## [n] <card title>              -> <div class="goal-head"><span class="num">[n]</span>...
  metric: <metric display name>    -> <div class="goal-metric">metric: ...
                                      Must match a `display_name` in metrics.toml.
  <body prose + markup>            -> <div class="goal-body">...
  **perfect =** <definition>       -> <span class="perfect">perfect = ...</span>
                                      Must repeat that metric's `perfect_definition`
                                      from metrics.toml verbatim; the test suite
                                      fails if the two drift apart.

Each card carries a <details class="metric-viz"> block: a collapsible, inline-SVG
visualization of how that metric works. They are hand-authored HTML — keep any
line inside them from starting with "# " or "## ", which the content parser
treats as section/card boundaries.

File name, view id, and nav label all agree: about / #about / "about".
-->

# decbench

a benchmark for decompilers. we compile real C projects at several optimization
levels, decompile every function of the resulting binaries with each decompiler,
and score the output against the source it came from &mdash; not against taste.

### why it exists

decompilers are graded by folklore: people eyeball a function or two and argue.
decbench was built to replace that with ground truth &mdash; we have the original
source, the debug info, and the exact toolchain for every binary we hand a
decompiler, so every claim a decompiler makes can be checked mechanically, at the
scale of tens of thousands of functions, and re-checked every time a decompiler
ships a new version.

### reading the leaderboard

<strong>Union</strong> is the summary column: the share of functions a
decompiler recovers perfectly on <em>at least one</em> metric &mdash; control
flow, types, or bytes. a function counts as long as one of its metrics could be
measured, so it is the broadest read of how often a decompiler gets
<em>something</em> exactly right.

every metric's denominator is shared: a function only counts if <em>some</em>
decompiler could be scored on it, so nobody is rewarded for skipping the hard
ones. failing a function you attempted is a miss, not an excuse. the
<strong>Errors</strong> column shows how often a decompiler produced nothing at
all. see <a href="#distance">distance</a> for how far off the imperfect results
are.

### the three metrics

decompilation has three separable goals, so we measure three things and report
how often a decompiler gets each <em>perfect</em> &mdash; because a
decompilation that is <em>nearly</em> right is still a thing you have to read
twice. expand the panel inside each card to see how the metric actually works.

## [1] Control-flow structure correctness
metric: Structural Correctness (GED)

Does the decompiled code branch and loop the same way the source does? We compare the control-flow graphs of the source and the decompilation with a Graph Edit Distance (GED) &mdash; the number of node/edge insertions, deletions, and substitutions needed to turn one CFG into the other.

<!-- VIZ:ged -->

**perfect =** GED of 0 (graph-isomorphic control flow).

## [2] Type correctness
metric: Type Correctness

Did the decompiler recover the right variable and argument types? We match the decompiled variables against DWARF ground truth (arguments by ABI position, stack variables by calibrated offset, the rest by name) and score the fraction recovered correctly.

<!-- VIZ:type_match -->

**perfect =** 1.0 (every recoverable variable typed correctly).

## [3] Recompilation correctness
metric: Recompilation Bytematch

Does the decompiled code recompile to the same machine code? We run a uniform compilability fixup (define decompiler pseudo-types, strip illegal symbol-version tokens, declare missing symbols) so every decompiler gets a fair shot at building, recompile each function with the original toolchain, and compare the resulting assembly &mdash; normalizing link-time-dependent operands (call/jump targets, PC-relative offsets) so only real differences count.

<!-- VIZ:byte_match -->

**perfect =** 1.0 (recompiled assembly matches the original).

# [outro]

<div class="recovered">
    [ = ] When a function is perfect on <strong>at least one</strong> metric,
    the decompiler has exactly recovered that aspect of the original source:
    the control flow, the types, or code that recompiles to the same bytes.
    That is the Union column on the leaderboard.
</div>

### how often each decompiler is perfect

<p class="view-desc" id="metrics-table-note">over the selected dataset.</p>

<table id="metrics-perfect-table"><thead><tr></tr></thead><tbody></tbody></table>

### the dataset

real software, not toy functions: coreutils-scale unix packages, drone and RTOS
firmware cross-compiled for ARM, and a handful of malware samples &mdash; every
project, its size, and how much of the GED pipeline is lost to our own tooling
(Joern source-parse failures) rather than to the decompilers. we count that
against ourselves.

### software types

click a type to highlight the projects it covers (a
project can span several).

<div class="controls" id="category-controls"></div>

### summary

<div id="dataset-summary" class="goal"></div>

### pipeline health (our own tooling)

GED depends on Joern parsing both the source and the decompiler output.
When Joern fails on the <strong>source</strong>, that's our tooling &mdash; those
functions are excluded from GED for every decompiler (never counted against
them). When Joern fails on a single decompiler's <strong>output</strong>,
that's reported here (per decompiler), not folded into the headline score.

<div id="joern-source" class="goal"></div>
<table id="joern-output-table"><thead><tr></tr></thead><tbody></tbody></table>

### projects

<table id="dataset-projects"><thead><tr></tr></thead><tbody></tbody></table>
