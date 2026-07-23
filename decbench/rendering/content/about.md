<!--
The "about" page — NOT the page the site opens on.

If you came here to edit the text people see FIRST, you want leaderboard.md:
the site opens on the leaderboard (`default = true` in views.toml) and this page
sits near the end of the nav (just before changelog). The starting-page prose is
split between the two — the
short intro above the table lives in leaderboard.md, the long explainer is here.

WRITE PLAIN MARKDOWN (the shared conventions live in leaderboard.md): prose is
**bold**/*italic*/[links](url)/`code` with literal unicode punctuation (— · ≥),
not <strong>/<em>/<a>/&mdash;. Raw HTML is only for the required scaffolds/hooks
below (elements with ids, the <div class="recovered"> callout) and the
hand-authored metric-viz "islands" — which markdown does NOT reach inside, so
their contents stay hand-written HTML (leave them exactly as they are).

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
  <body prose, plain markdown>     -> <div class="goal-body">...
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

Over the last 30 years, binary decompilers have made the steady march towards
_perfect decompilation_: where decompilers recover the exact source code.
However, that _perfect_ has yet to be measured meaningfully, and is often
defined across multiple axes.

DecBench is an experimental benchmark for comparing decompilers and modern LLMs
on the task of recovering _exact_ source code. This benchmark defines new
metrics and datasets that represent the various directions of exactness for
decompilers: structure, types, and precise recompilability. This benchmark is
also _living_: as new decompiler/LLMs are released, their scores will be added
to the leaderboard! Community feedback is welcome!

It is created by the [Noelo Lab at the University of Georgia](https://github.com/Noelo-Lab),
led by Dr. Zion Leonahenahe Basque. The project's
[code](https://github.com/noelo-lab/decbench) and
[data](https://huggingface.co/datasets/noelo-lab/decbench-dataset) are open
source. Email `decbench@mahaloz.re` to get your decompiler added to the public
site.

### why it exists

Other benchmarks have cropped up in the last two years. Many of these
evaluations use approaches that are often uninformative about perfect
decompilation, for example, "re-executability", which can often get full test
cases to pass but can still be incorrect.

DecBench uses metrics to quantify how often a decompiler recovers the exact
source code of a function. Since measuring this with pure strings is
inaccurate, we use multiple metrics described below.

### the three metrics

Decompilation has three separable goals, so we measure three things and report
how often a decompiler gets each *perfect* — because a
decompilation that is *nearly* right is still a thing you have to read
twice. Expand the panel inside each card to see how the metric actually works.

## [1] Control-flow structure correctness
metric: Structural Correctness (GED)

Does the decompiled code branch and loop the same way the source does? We compare the control-flow graphs of the source and the decompilation with a Graph Edit Distance (GED) — the number of node/edge insertions, deletions, and substitutions needed to turn one CFG into the other.

<details class="metric-viz" open>
<summary>how GED works: source &rarr; CFG &rarr; graph diff</summary>
<div class="viz-wrap">

<div class="viz-row">
<div class="viz-rowlabel">A &middot; lift the source to a control-flow graph</div>
<div class="viz-pipe">
<span class="viz-chip is-in">source .c</span>
<span class="viz-parrow">&mdash;<b>&nbsp;joern&nbsp;</b>&rarr;</span>
<span class="viz-chip is-out">control-flow graph</span>
<span class="viz-dim">&nbsp;(same lift is applied to every decompiler's C output)</span>
</div>
<div class="viz-grid">

<div class="viz-panel">
<div class="viz-panel-h is-src">source.c</div>
<pre class="viz-code" data-lang="c"><code>// sum of |x[i]|
int sum_abs(int *x, int n) {
    int i, s = 0;
    for (i = 0; i &lt; n; i++) {
        if (x[i] &lt; 0)
            s -= x[i];
        else
            s += x[i];
    }
    return s;
}</code></pre>
</div>

<div class="viz-panel">
<div class="viz-panel-h is-src">control-flow graph</div>
<svg viewBox="0 0 360 300" role="img" aria-label="control-flow graph of sum_abs" style="max-width:100%;height:auto;display:block">
<defs>
<marker id="ga-g" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--text-muted)"/></marker>
</defs>
<!-- edges -->
<line x1="180" y1="44" x2="180" y2="79" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#ga-g)"/>
<line x1="168" y1="110" x2="112" y2="156" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#ga-g)"/>
<line x1="192" y1="110" x2="248" y2="156" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#ga-g)"/>
<line x1="101" y1="188" x2="160" y2="240" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#ga-g)"/>
<line x1="259" y1="188" x2="200" y2="240" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#ga-g)"/>
<path d="M139,251 C78,250 22,238 22,180 C22,120 74,101 137,101" fill="none" stroke="var(--text-muted)" stroke-width="1.2" stroke-dasharray="4 3" marker-end="url(#ga-g)"/>
<text x="68" y="130" font-size="9.5" fill="var(--text-muted)" text-anchor="middle">loop</text>
<text x="104" y="139" font-size="9.5" fill="var(--text-muted)" text-anchor="end">&lt;0</text>
<text x="234" y="139" font-size="9.5" fill="var(--text-muted)">&ge;0</text>
<!-- nodes -->
<rect x="139" y="14"  width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="180" y="33"  font-size="12.5" fill="var(--text)" text-anchor="middle">entry</text>
<rect x="139" y="80"  width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="180" y="99"  font-size="12.5" fill="var(--text)" text-anchor="middle">cond</text>
<rect x="52"  y="158" width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="93"  y="177" font-size="12.5" fill="var(--text)" text-anchor="middle">then</text>
<rect x="226" y="158" width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="267" y="177" font-size="12.5" fill="var(--text)" text-anchor="middle">else</text>
<rect x="139" y="242" width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="180" y="261" font-size="12.5" fill="var(--text)" text-anchor="middle">exit</text>
</svg>
<div class="viz-cap">green = the reference shape (dashed edge = loop back-edge)</div>
</div>

</div>
</div>

<div class="viz-row">
<div class="viz-rowlabel">B &middot; the edit distance: reference vs a decompiler's CFG</div>
<div class="viz-grid">

<div class="viz-panel">
<div class="viz-panel-h is-src">source CFG</div>
<svg viewBox="0 0 360 300" role="img" aria-label="source control-flow graph" style="max-width:100%;height:auto;display:block">
<defs>
<marker id="gb-g" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--text-muted)"/></marker>
</defs>
<line x1="180" y1="44" x2="180" y2="79" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gb-g)"/>
<line x1="168" y1="110" x2="112" y2="156" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gb-g)"/>
<line x1="192" y1="110" x2="248" y2="156" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gb-g)"/>
<line x1="101" y1="188" x2="160" y2="240" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gb-g)"/>
<line x1="259" y1="188" x2="200" y2="240" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gb-g)"/>
<path d="M139,251 C78,250 22,238 22,180 C22,120 74,101 137,101" fill="none" stroke="var(--text-muted)" stroke-width="1.2" stroke-dasharray="4 3" marker-end="url(#gb-g)"/>
<text x="68" y="130" font-size="9.5" fill="var(--text-muted)" text-anchor="middle">loop</text>
<rect x="139" y="14"  width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="180" y="33"  font-size="12.5" fill="var(--text)" text-anchor="middle">entry</text>
<rect x="139" y="80"  width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="180" y="99"  font-size="12.5" fill="var(--text)" text-anchor="middle">cond</text>
<rect x="52"  y="158" width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="93"  y="177" font-size="12.5" fill="var(--text)" text-anchor="middle">then</text>
<rect x="226" y="158" width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="267" y="177" font-size="12.5" fill="var(--text)" text-anchor="middle">else</text>
<rect x="139" y="242" width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--green)" stroke-width="1.4"/><text x="180" y="261" font-size="12.5" fill="var(--text)" text-anchor="middle">exit</text>
</svg>
<div class="viz-cap">5 nodes &middot; 6 edges</div>
</div>

<div class="viz-panel">
<div class="viz-panel-h is-dec">decompiled CFG</div>
<svg viewBox="0 0 360 300" role="img" aria-label="decompiled control-flow graph with one inserted node" style="max-width:100%;height:auto;display:block">
<defs>
<marker id="gd-g" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--text-muted)"/></marker>
<marker id="gd-r" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--red)"/></marker>
</defs>
<!-- matched (grey) edges -->
<line x1="180" y1="44" x2="180" y2="79" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gd-g)"/>
<line x1="168" y1="110" x2="112" y2="156" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gd-g)"/>
<line x1="192" y1="110" x2="248" y2="156" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gd-g)"/>
<line x1="101" y1="188" x2="160" y2="240" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gd-g)"/>
<line x1="259" y1="188" x2="200" y2="240" stroke="var(--text-muted)" stroke-width="1.3" marker-end="url(#gd-g)"/>
<path d="M139,251 C78,250 22,238 22,180 C22,120 74,101 137,101" fill="none" stroke="var(--text-muted)" stroke-width="1.2" stroke-dasharray="4 3" marker-end="url(#gd-g)"/>
<text x="68" y="130" font-size="9.5" fill="var(--text-muted)" text-anchor="middle">loop</text>
<!-- RED inserted node + its 2 edges -->
<path d="M222,94 C332,102 332,182 302,214" fill="none" stroke="var(--red)" stroke-width="1.6" marker-end="url(#gd-r)"/>
<line x1="252" y1="234" x2="224" y2="250" stroke="var(--red)" stroke-width="1.6" marker-end="url(#gd-r)"/>
<rect x="252" y="214" width="70" height="28" rx="5" fill="var(--panel-red-tint)" stroke="var(--red)" stroke-width="1.5"/><text x="287" y="232" font-size="12" fill="var(--red)" text-anchor="middle">blk</text>
<!-- matched (grey) nodes -->
<rect x="139" y="14"  width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1.3"/><text x="180" y="33"  font-size="12.5" fill="var(--text)" text-anchor="middle">entry</text>
<rect x="139" y="80"  width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1.3"/><text x="180" y="99"  font-size="12.5" fill="var(--text)" text-anchor="middle">cond</text>
<rect x="52"  y="158" width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1.3"/><text x="93"  y="177" font-size="12.5" fill="var(--text)" text-anchor="middle">then</text>
<rect x="226" y="158" width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1.3"/><text x="267" y="177" font-size="12.5" fill="var(--text)" text-anchor="middle">else</text>
<rect x="139" y="242" width="82" height="30" rx="5" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1.3"/><text x="180" y="261" font-size="12.5" fill="var(--text)" text-anchor="middle">exit</text>
</svg>
<div class="viz-cap">matched nodes grey &middot; <span style="color:var(--red)">inserted node + 2 edges red</span></div>
</div>

</div>

<div class="viz-callout">
GED = <span class="n">3</span> &nbsp;&mdash;&nbsp; 1 node insertion + 2 edge insertions to align the two CFGs
</div>

<div class="viz-score">
<div><span class="viz-good big">GED = 0</span> <span class="viz-dim">&rarr; the two CFGs are graph-isomorphic &mdash; a perfect structural match.</span></div>
<div class="perfect">Only control-flow shape is scored; node labels are ignored, so the signal is fair across decompilers.</div>
</div>

</div>

<p class="viz-note">Structural Correctness (GED): Joern lifts both the original source and each decompiler's C output to control-flow graphs, then counts the fewest node/edge edits needed to make them isomorphic &mdash; <code>0</code> means an identical shape. Only control structure is scored, so the signal is fair across decompilers.</p>

</div>
</details>

**perfect =** GED of 0 (graph-isomorphic control flow).

## [2] Type correctness
metric: Type Correctness

Did the decompiler recover the right variable and argument types? We match the decompiled variables against DWARF ground truth (arguments by ABI position, stack variables by calibrated offset, the rest by name) and score the fraction recovered correctly.

<details class="metric-viz" open>
<summary>how type matching works: DWARF ground truth &harr; recovered variables</summary>
<div class="viz-wrap">

<svg viewBox="0 0 720 322" role="img" aria-label="stack-frame type matching between DWARF ground truth and decompiler output" style="max-width:100%;height:auto;display:block">
<defs>
<marker id="tm-g" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="var(--green)"/></marker>
<marker id="tm-a" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="var(--amber)"/></marker>
<marker id="tm-r" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="var(--red)"/></marker>
</defs>

<!-- panel headers -->
<text x="24"  y="26" font-size="12.5" fill="var(--text)">DWARF ground truth <tspan fill="var(--text-muted)">(from -g build)</tspan></text>
<text x="696" y="26" text-anchor="end" font-size="12.5" fill="var(--text)">decompiler output</text>
<line x1="24"  y1="34" x2="310" y2="34" stroke="var(--border-dim)" stroke-width="1" stroke-dasharray="4 3"/>
<line x1="410" y1="34" x2="696" y2="34" stroke="var(--border-dim)" stroke-width="1" stroke-dasharray="4 3"/>

<!-- band A label -->
<text x="360" y="54" text-anchor="middle" font-size="10.5" fill="var(--text-muted)"><tspan fill="var(--text)" font-weight="bold">[1]</tspan> arguments &mdash; matched by ABI position</text>

<!-- ==== argument slots ==== -->
<!-- A1 -->
<rect x="24" y="62" width="286" height="46" rx="3" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1"/>
<text x="34" y="80"  font-size="10" fill="var(--text-muted)">arg 0 &middot; %rdi</text>
<text x="34" y="99"  font-size="13" fill="var(--text)">char *<tspan fill="var(--text-muted)">path</tspan></text>
<rect x="410" y="62" width="286" height="46" rx="3" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1"/>
<text x="420" y="80"  font-size="10" fill="var(--text-muted)">param a1</text>
<text x="420" y="99"  font-size="13" fill="var(--green)">char *</text>
<text x="686" y="94"  text-anchor="end" font-size="15" fill="var(--green)">&#10003;</text>
<!-- A2 -->
<rect x="24" y="114" width="286" height="46" rx="3" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1"/>
<text x="34" y="132" font-size="10" fill="var(--text-muted)">arg 1 &middot; %esi</text>
<text x="34" y="151" font-size="13" fill="var(--text)">int <tspan fill="var(--text-muted)">mode</tspan></text>
<rect x="410" y="114" width="286" height="46" rx="3" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1"/>
<text x="420" y="132" font-size="10" fill="var(--text-muted)">param a2</text>
<text x="420" y="151" font-size="13" fill="var(--amber)">uint</text>
<text x="686" y="146" text-anchor="end" font-size="15" fill="var(--amber)">&#8800;</text>

<!-- band B label -->
<text x="360" y="188" text-anchor="middle" font-size="10.5" fill="var(--text-muted)"><tspan fill="var(--text)" font-weight="bold">[2]</tspan> stack locals &mdash; by frame offset, <tspan fill="var(--text)" font-weight="bold">[3]</tspan> then by name</text>

<!-- ==== local slots ==== -->
<!-- B1 -->
<rect x="24" y="196" width="286" height="46" rx="3" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1"/>
<text x="34" y="214" font-size="10" fill="var(--text-muted)">local @ rbp-0x18</text>
<text x="34" y="233" font-size="13" fill="var(--text)">size_t <tspan fill="var(--text-muted)">len</tspan></text>
<rect x="410" y="196" width="286" height="46" rx="3" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1"/>
<text x="420" y="214" font-size="10" fill="var(--text-muted)">var_28 @ rbp-0x28</text>
<text x="420" y="233" font-size="13" fill="var(--green)">ulong</text>
<text x="686" y="228" text-anchor="end" font-size="15" fill="var(--green)">&#10003;</text>
<!-- B2 -->
<rect x="24" y="248" width="286" height="46" rx="3" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1"/>
<text x="34" y="266" font-size="10" fill="var(--text-muted)">local @ rbp-0x20</text>
<text x="34" y="285" font-size="13" fill="var(--text)">struct stat <tspan fill="var(--text-muted)">st</tspan></text>
<rect x="410" y="248" width="286" height="46" rx="3" fill="var(--code-bg)" stroke="var(--code-border)" stroke-width="1"/>
<text x="420" y="266" font-size="10" fill="var(--text-muted)">var_30 @ rbp-0x30</text>
<text x="420" y="285" font-size="13" fill="var(--red)">undefined8</text>
<text x="686" y="280" text-anchor="end" font-size="15" fill="var(--red)">&#10007;</text>

<!-- ==== connectors (gap 310..410) ==== -->
<text x="360" y="80"  text-anchor="middle" font-size="9.5" fill="var(--green)"><tspan font-weight="bold">[1]</tspan> ABI 0</text>
<line x1="310" y1="85"  x2="406" y2="85"  stroke="var(--green)" stroke-width="1.6" marker-end="url(#tm-g)"/>

<text x="360" y="132" text-anchor="middle" font-size="9.5" fill="var(--amber)"><tspan font-weight="bold">[1]</tspan> int &#8800; uint</text>
<line x1="310" y1="137" x2="406" y2="137" stroke="var(--amber)" stroke-width="1.6" marker-end="url(#tm-a)"/>

<text x="360" y="214" text-anchor="middle" font-size="9.5" fill="var(--green)"><tspan font-weight="bold">[2]</tspan> offset +0x10</text>
<line x1="310" y1="219" x2="406" y2="219" stroke="var(--green)" stroke-width="1.6" marker-end="url(#tm-g)"/>

<text x="360" y="266" text-anchor="middle" font-size="9.5" fill="var(--red)"><tspan font-weight="bold">[3]</tspan> missed struct</text>
<line x1="310" y1="271" x2="406" y2="271" stroke="var(--red)" stroke-width="1.6" marker-end="url(#tm-r)"/>
</svg>

<div class="viz-legend">
<span class="pass"><span class="k">[1]</span> arguments by ABI position (name-independent)</span>
<span class="pass"><span class="k">[2]</span> stack vars by calibrated frame offset</span>
<span class="pass"><span class="k">[3]</span> remainder by exact name</span>
<span class="pass"><span style="color:var(--green)">&#10003;</span> correct type &middot; <span style="color:var(--amber)">&#8800;</span> type mismatch &middot; <span style="color:var(--red)">&#10007;</span> missed</span>
</div>

<div class="viz-score">
<div>score = <span class="viz-dim">matched-correct / recoverable</span> = <span class="viz-good">2</span> <span class="viz-dim">/</span> 4 = <span class="viz-warn big">0.50</span></div>
<div class="perfect"><span class="viz-good">1.0</span> &rarr; every recoverable variable typed correctly = perfect</div>
</div>

<p class="viz-note">Only variables carrying a DWARF location count as <em>recoverable</em> &mdash; fully optimized-out vars are dropped for everyone, so the denominator is identical across decompilers. Arguments match by ABI position (name-independent, so angr's <code>a1</code>/<code>a2</code> get fair credit), stack locals by an auto-calibrated frame-offset shift (here <code>+0x10</code>, so ground-truth <code>-0x18</code> aligns to the decompiler's <code>-0x28</code>), and the remainder by exact name.</p>

</div>
</details>

**perfect =** 1.0 (every recoverable variable typed correctly).

## [3] Recompilation correctness
metric: Recompilation Bytematch

Does the decompiled code recompile to the same machine code? We run a uniform compilability fixup (define decompiler pseudo-types, strip illegal symbol-version tokens, declare missing symbols) so every decompiler gets a fair shot at building, recompile each function with the original toolchain, and compare the resulting assembly — normalizing link-time-dependent operands (call/jump targets, PC-relative offsets) so only real differences count.

The leaderboard's **Compiles** column reports the first half of this on its own — the share of a decompiler's output that the fixup got to build at all (before any assembly comparison). It is measured only where a matching recompiler exists (x86); ARM/PE firmware and malware abstain rather than count as failures.

<details class="metric-viz" open>
<summary>how bytematch works: fixup &rarr; recompile &rarr; normalized asm diff</summary>
<div class="viz-wrap">

<div class="viz-row">
<div class="viz-rowlabel">A &middot; rebuild the decompiler's own C, the same way the original was built</div>
<div class="viz-pipe">
<span class="viz-chip is-in">decompiled .c</span>
<span class="viz-parrow">&mdash;<b>&nbsp;compilability fixup&nbsp;</b>&rarr;</span>
<span class="viz-chip">buildable .c</span>
<span class="viz-parrow">&mdash;<b>&nbsp;recompile&nbsp;</b>&rarr;</span>
<span class="viz-chip is-out">assembly</span>
<span class="viz-dim">&nbsp;(same toolchain &amp; -O flags as the source: x86&rarr;gcc, ARM&rarr;arm-eabi, PE&rarr;MinGW)</span>
</div>
<div class="viz-grid">

<div class="viz-panel">
<div class="viz-panel-h is-dec">decompiled .c &mdash; pseudo-types injected by the fixup</div>
<pre class="viz-code" data-lang="c"><code>undefined4 scale(int a) {
    uint x = a * 3;
    log_val(x);
    return x + limit;
}</code></pre>
<div class="viz-cap">The fixup adds only <code style="color:var(--green)">typedef</code>s for <span class="tok-type">undefined4</span>/<span class="tok-type">uint</span> &mdash; never rewrites logic</div>
</div>

<div class="viz-panel">
<div class="viz-panel-h is-dec">recompiled assembly (-O2, x86-64)</div>
<pre class="viz-code" data-lang="asm"><code>scale:
    push   rbx
    imul   ebx, edi, 3
    mov    edi, ebx
    call   log_val
    mov    eax, ebx
    add    eax, [rip+limit]
    pop    rbx
    ret</code></pre>
</div>

</div>
</div>

<div class="viz-row">
<div class="viz-rowlabel">B &middot; diff the recompiled bytes against the original .text</div>
<div class="viz-diff">
<div class="dl-head"><span class="h-mk"></span><span>original .text</span><span>recompiled</span></div>
<div class="dl-row dl-match"><span class="dl-mk">&#10003;</span><code class="dl-gt">push   rbx</code><code>push   rbx</code></div>
<div class="dl-row dl-diff"><span class="dl-mk">&#10007;</span><code class="dl-gt">lea    ebx, [rdi+rdi*2]</code><code>imul   ebx, edi, 3</code></div>
<div class="dl-row dl-match"><span class="dl-mk">&#10003;</span><code class="dl-gt">mov    edi, ebx</code><code>mov    edi, ebx</code></div>
<div class="dl-row dl-norm"><span class="dl-mk">&#8776;</span><code class="dl-gt">call   <span class="dl-op">____</span></code><code>call   <span class="dl-op">____</span></code></div>
<div class="dl-row dl-match"><span class="dl-mk">&#10003;</span><code class="dl-gt">mov    eax, ebx</code><code>mov    eax, ebx</code></div>
<div class="dl-row dl-norm"><span class="dl-mk">&#8776;</span><code class="dl-gt">add    eax, [rip+<span class="dl-op">____</span>]</code><code>add    eax, [rip+<span class="dl-op">____</span>]</code></div>
<div class="dl-row dl-match"><span class="dl-mk">&#10003;</span><code class="dl-gt">pop    rbx</code><code>pop    rbx</code></div>
<div class="dl-row dl-match"><span class="dl-mk">&#10003;</span><code class="dl-gt">ret</code><code>ret</code></div>
</div>

<div class="viz-legend">
<span class="pass"><span style="color:var(--green)">&#10003;</span> identical line</span>
<span class="pass"><span style="color:var(--amber)">&#8776;</span> matches after normalizing a link-time operand (<span class="dl-op">____</span> = <code>call</code> target / <code>[rip+disp]</code>)</span>
<span class="pass"><span style="color:var(--red)">&#10007;</span> real difference (edit distance = changed asm lines)</span>
</div>

<div class="viz-score">
<div>byte_match = <span class="viz-dim">matching / total</span> = <span class="viz-good">7</span> <span class="viz-dim">/</span> 8 = <span class="viz-good big">0.88</span></div>
<div class="perfect"><span class="viz-good">1.0</span> &rarr; recompiled assembly matches the original = perfect</div>
</div>

</div>

<p class="viz-note">Recompilation Bytematch rebuilds the decompiler's own C the SAME way the original was built &mdash; toolchain and <code>-O*/-m*</code> flags read from the DWARF producer &mdash; then compares assembly line by line. A compilability fixup injects <em>only</em> what gcc reports missing (typedefs for pseudo-types like <code>undefined4</code>/<code>uint</code>, decls for implicit functions) and never rewrites logic. Link-time-dependent operands &mdash; <code>call</code>/branch targets and <code>[rip&plusmn;disp]</code> displacements &mdash; are normalized away, so an unlinked address difference is not a penalty. Type recovery is scored separately (type_match), so fixing types just to compile is fair.</p>

</div>
</details>

**perfect =** 1.0 (recompiled assembly matches the original).

# [outro]

<div class="recovered">
    [ = ] When a function is perfect on <strong>at least one</strong> metric,
    the decompiler has exactly recovered that aspect of the original source:
    the control flow, the types, or code that recompiles to the same bytes.
    That is the Union column on the leaderboard.
</div>

### the dataset

### summary

<div id="dataset-summary" class="goal"></div>

### pipeline health (our own tooling)

GED depends on Joern parsing both the source and the decompiler output.
When Joern fails on the **source**, that's our tooling — those
functions are excluded from GED for every decompiler (never counted against
them). When Joern fails on a single decompiler's **output**,
that's reported here (per decompiler), not folded into the headline score.

<div id="joern-source" class="goal"></div>
<table id="joern-output-table"><thead><tr></tr></thead><tbody></tbody></table>

### projects

<p class="view-desc" id="dataset-projects-note"></p>

<table id="dataset-projects"><thead><tr></tr></thead><tbody></tbody></table>
