<!--
View template — see leaderboard.md for the shared conventions.

This page absorbed the old `compare` and `hardest` views: original source next
to ONE chosen decompiler's output, over three difficulty tiers of ~100 functions
each (tiers are assigned server-side from cross-decompiler GED agreement — see
decbench/scoring/view_samples.py). The element ids here (view-difficulty,
view-dec, view-metric, view-select, view-filter, view-counter, view-body) are
the contract with app.js's initView/renderView.
-->

# view

Original source next to a decompiler's output. **Difficulty** is
derived from structural (GED) agreement across decompilers:
**easy** — most decompilers recover the control flow
perfectly; **hard** — the functions farthest from perfect
for everyone (the old hall of shame); **medium** — in
between. Pick a difficulty, a decompiler, and a metric to highlight.

<div class="controls">
    <label for="view-difficulty">difficulty:</label>
    <select id="view-difficulty"></select>
    <label for="view-dec">decompiler:</label>
    <select id="view-dec"></select>
    <label for="view-metric">metric:</label>
    <select id="view-metric"></select>
</div>
<div class="controls">
    <label for="view-filter">filter:</label>
    <input type="text" id="view-filter" placeholder="function / project / binary" size="28">
    <label for="view-select">function:</label>
    <select id="view-select"></select>
    <span class="counter" id="view-counter"></span>
</div>
<div id="view-body"></div>

# [empty] view

No sample functions were attached to this report.
