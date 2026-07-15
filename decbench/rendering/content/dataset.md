<!-- View template — see leaderboard.md for the shared conventions. -->

# dataset

The benchmark corpus: the kinds of software it covers, every project,
its size, and how much of the GED pipeline is lost to our own tooling
(Joern source-parse failures) rather than to the decompilers.

### software types

click a type to highlight the projects it covers (a
project can span several).

<div class="controls" id="category-controls"></div>

### summary

<div id="dataset-summary" class="goal"></div>

### pipeline health (our own tooling)

GED depends on Joern parsing both the source and the decompiler output.
When Joern fails on the <strong>source</strong>, that's our tooling — those
functions are excluded from GED for every decompiler (never counted against
them). When Joern fails on a single decompiler's <strong>output</strong>,
that's reported here (per decompiler), not folded into the headline score.

<div id="joern-source" class="goal"></div>
<table id="joern-output-table"><thead><tr></tr></thead><tbody></tbody></table>

### projects

<table id="dataset-projects"><thead><tr></tr></thead><tbody></tbody></table>
