<!--
View template — see leaderboard.md for the shared conventions.

GOAL CARDS. The three `## [n] ...` sections below are STRUCTURED: the renderer
turns each into a <div class="goal"> card, so the shape matters.

  ## [1] <card title>              -> <div class="goal-head"><span class="num">[1]</span>...
  metric: <metric display name>    -> <div class="goal-metric">metric: ...
                                      Must match a `display_name` in metrics.toml.
  <one paragraph of body prose>    -> <div class="goal-body">...
  **perfect =** <definition>       -> <span class="perfect">perfect = ...</span>
                                      Must repeat that metric's `perfect_definition`
                                      from metrics.toml verbatim; the test suite
                                      fails if the two drift apart.

Card order is the order below. Everything outside the cards is ordinary view
prose: the text above them is the intro, the `# [outro]` section is emitted after
the cards, and the per-decompiler table is appended after that by the renderer.
-->

# metrics

Decompilation has three goals; DecBench measures each with one metric
and reports how often a decompiler gets it <em>perfect</em>.

## [1] Control-flow structure correctness
metric: Structural Correctness (GED)

Does the decompiled code branch and loop the same way the source does? We compare the control-flow graphs of the source and the decompilation with a Graph Edit Distance (GED) &mdash; the number of node/edge insertions, deletions, and substitutions needed to turn one CFG into the other.

**perfect =** GED of 0 (graph-isomorphic control flow).

## [2] Type correctness
metric: Type Correctness

Did the decompiler recover the right variable and argument types? We match the decompiled variables against DWARF ground truth (arguments by ABI position, stack variables by calibrated offset, the rest by name) and score the fraction recovered correctly.

**perfect =** 1.0 (every recoverable variable typed correctly).

## [3] Recompilation correctness
metric: Recompilation Bytematch

Does the decompiled code recompile to the same machine code? We run a uniform compilability fixup (define decompiler pseudo-types, strip illegal symbol-version tokens, declare missing symbols) so every decompiler gets a fair shot at building, recompile each function with the original toolchain, and compare the resulting assembly &mdash; normalizing link-time-dependent operands (call/jump targets, PC-relative offsets) so only real differences count.

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
