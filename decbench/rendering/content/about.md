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

<details class="metric-viz">
<summary>how GED works: source &rarr; CFG &rarr; graph diff [click to expand]</summary>
<div style="background:#000;color:#DBDBDB;padding:8px 0;font-family:'Source Code Pro',monospace;">
<svg viewBox="0 0 760 350" font-family="'Source Code Pro', monospace" style="max-width:100%;height:auto;display:block">
  <defs>
    <marker id="ged-p" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#d4a72c"/></marker>
    <marker id="ged-e" markerWidth="8" markerHeight="8" refX="5.5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#8a8a8a"/></marker>
    <marker id="ged-r" markerWidth="8" markerHeight="8" refX="5.5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#c0504d"/></marker>
  </defs>

  <!-- ============ 1. SOURCE CODE PANEL ============ -->
  <text x="16" y="66" font-size="10" fill="#8a8a8a">source.c</text>
  <rect x="12" y="72" width="210" height="188" rx="4" fill="#141414" stroke="#545454" stroke-width="1"/>
  <text x="20" y="92"  font-size="11" fill="#8a8a8a">// sum of |x[i]|</text>
  <text x="20" y="110" font-size="11" fill="#DBDBDB"><tspan fill="#d4a72c">int</tspan> sum(<tspan fill="#d4a72c">int</tspan> *x, <tspan fill="#d4a72c">int</tspan> n) {</text>
  <text x="28" y="128" font-size="11" fill="#DBDBDB"><tspan fill="#d4a72c">int</tspan> i, s = 0;</text>
  <text x="28" y="146" font-size="11" fill="#DBDBDB"><tspan fill="#d4a72c">for</tspan> (i=0; i&lt;n; i++)</text>
  <text x="36" y="164" font-size="11" fill="#DBDBDB"><tspan fill="#d4a72c">if</tspan> (x[i] &lt; 0)</text>
  <text x="44" y="182" font-size="11" fill="#DBDBDB">s -= x[i];</text>
  <text x="36" y="200" font-size="11" fill="#DBDBDB"><tspan fill="#d4a72c">else</tspan> s += x[i];</text>
  <text x="28" y="218" font-size="11" fill="#DBDBDB"><tspan fill="#d4a72c">return</tspan> s;</text>
  <text x="20" y="236" font-size="11" fill="#DBDBDB">}</text>

  <!-- arrow 1: joern -->
  <text x="245" y="147" font-size="10.5" fill="#d4a72c" text-anchor="middle">joern</text>
  <line x1="224" y1="156" x2="263" y2="156" stroke="#8a8a8a" stroke-width="1.5" marker-end="url(#ged-p)"/>

  <!-- ============ 2. SOURCE CFG (green) ============ -->
  <rect x="268" y="72" width="214" height="188" rx="4" fill="none" stroke="rgba(219,219,219,0.4)" stroke-width="1" stroke-dasharray="4 3"/>
  <text x="375" y="88" font-size="11" fill="#6ab04c" text-anchor="middle">source CFG</text>

  <!-- edges -->
  <line x1="375" y1="113" x2="375" y2="127" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <line x1="364" y1="151" x2="349" y2="170" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <line x1="386" y1="151" x2="401" y2="170" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <line x1="352" y1="193" x2="366" y2="212" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <line x1="398" y1="193" x2="384" y2="212" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <path d="M349,222 C300,208 300,150 349,142" fill="none" stroke="#8a8a8a" stroke-width="1.1" stroke-dasharray="3 3" marker-end="url(#ged-e)"/>
  <text x="292" y="185" font-size="9" fill="#8a8a8a" text-anchor="middle">loop</text>
  <!-- nodes -->
  <rect x="349" y="91"  width="52" height="22" rx="4" fill="#141414" stroke="#6ab04c" stroke-width="1.3"/><text x="375" y="106" font-size="11" fill="#DBDBDB" text-anchor="middle">entry</text>
  <rect x="349" y="129" width="52" height="22" rx="4" fill="#141414" stroke="#6ab04c" stroke-width="1.3"/><text x="375" y="144" font-size="11" fill="#DBDBDB" text-anchor="middle">cond</text>
  <rect x="315" y="171" width="52" height="22" rx="4" fill="#141414" stroke="#6ab04c" stroke-width="1.3"/><text x="341" y="186" font-size="11" fill="#DBDBDB" text-anchor="middle">then</text>
  <rect x="383" y="171" width="52" height="22" rx="4" fill="#141414" stroke="#6ab04c" stroke-width="1.3"/><text x="409" y="186" font-size="11" fill="#DBDBDB" text-anchor="middle">else</text>
  <rect x="349" y="213" width="52" height="22" rx="4" fill="#141414" stroke="#6ab04c" stroke-width="1.3"/><text x="375" y="228" font-size="11" fill="#DBDBDB" text-anchor="middle">exit</text>

  <!-- arrow 2: decompiler output -> joern -->
  <text x="509" y="127" font-size="9.5" fill="#d4a72c" text-anchor="middle">decompiler</text>
  <text x="509" y="139" font-size="9.5" fill="#d4a72c" text-anchor="middle">output &rarr; joern</text>
  <line x1="484" y1="156" x2="533" y2="156" stroke="#8a8a8a" stroke-width="1.5" marker-end="url(#ged-p)"/>

  <!-- ============ 3. DECOMPILED CFG (matched grey + red diff) ============ -->
  <rect x="536" y="72" width="212" height="188" rx="4" fill="none" stroke="rgba(219,219,219,0.4)" stroke-width="1" stroke-dasharray="4 3"/>
  <text x="642" y="88" font-size="11" fill="#DBDBDB" text-anchor="middle">decompiled CFG</text>

  <!-- matched edges -->
  <line x1="642" y1="113" x2="642" y2="127" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <line x1="631" y1="151" x2="616" y2="170" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <line x1="653" y1="151" x2="668" y2="170" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <line x1="619" y1="193" x2="633" y2="212" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <line x1="665" y1="193" x2="651" y2="212" stroke="#8a8a8a" stroke-width="1.2" marker-end="url(#ged-e)"/>
  <path d="M616,222 C567,208 567,150 616,142" fill="none" stroke="#8a8a8a" stroke-width="1.1" stroke-dasharray="3 3" marker-end="url(#ged-e)"/>
  <text x="559" y="185" font-size="9" fill="#8a8a8a" text-anchor="middle">loop</text>

  <!-- RED inserted node + its 2 edges (the difference) -->
  <line x1="668" y1="143" x2="684" y2="149" stroke="#c0504d" stroke-width="1.5" marker-end="url(#ged-r)"/>
  <path d="M709,161 C742,190 722,226 662,222" fill="none" stroke="#c0504d" stroke-width="1.5" marker-end="url(#ged-r)"/>
  <rect x="686" y="139" width="52" height="22" rx="4" fill="#1a0f0f" stroke="#c0504d" stroke-width="1.4"/><text x="712" y="154" font-size="11" fill="#c0504d" text-anchor="middle">blk</text>
  <text x="706" y="198" font-size="9" fill="#c0504d" text-anchor="middle">+1 node</text>
  <text x="706" y="210" font-size="9" fill="#c0504d" text-anchor="middle">+2 edges</text>

  <!-- matched nodes (normal colour) -->
  <rect x="616" y="91"  width="52" height="22" rx="4" fill="#141414" stroke="#545454" stroke-width="1.2"/><text x="642" y="106" font-size="11" fill="#DBDBDB" text-anchor="middle">entry</text>
  <rect x="616" y="129" width="52" height="22" rx="4" fill="#141414" stroke="#545454" stroke-width="1.2"/><text x="642" y="144" font-size="11" fill="#DBDBDB" text-anchor="middle">cond</text>
  <rect x="582" y="171" width="52" height="22" rx="4" fill="#141414" stroke="#545454" stroke-width="1.2"/><text x="608" y="186" font-size="11" fill="#DBDBDB" text-anchor="middle">then</text>
  <rect x="650" y="171" width="52" height="22" rx="4" fill="#141414" stroke="#545454" stroke-width="1.2"/><text x="676" y="186" font-size="11" fill="#DBDBDB" text-anchor="middle">else</text>
  <rect x="616" y="213" width="52" height="22" rx="4" fill="#141414" stroke="#545454" stroke-width="1.2"/><text x="642" y="228" font-size="11" fill="#DBDBDB" text-anchor="middle">exit</text>

  <!-- ============ 4. RESULT STRIP ============ -->
  <rect x="12" y="270" width="736" height="66" rx="4" fill="#141414" stroke="rgba(219,219,219,0.4)" stroke-width="1" stroke-dasharray="4 3"/>
  <text x="26" y="298" font-size="11.5"><tspan fill="#c0504d" font-weight="bold">GED = 3</tspan><tspan fill="#8a8a8a">   node &amp; edge insertions + deletions + substitutions to align the two CFGs</tspan></text>
  <text x="26" y="322" font-size="11.5"><tspan fill="#6ab04c" font-weight="bold">GED = 0</tspan><tspan fill="#8a8a8a">   &rarr;  graph-isomorphic control flow = a perfect structural match</tspan></text>
</svg>
<p style="color:#8a8a8a;font-size:0.85em;margin:6px 4px 0;">Structural Correctness (GED): Joern lifts both the original source and each decompiler's C output to control-flow graphs, then counts the fewest node/edge edits needed to make them isomorphic &mdash; 0 means an identical shape. Only control structure is scored (node labels are ignored), so the signal is fair across decompilers.</p>
</div>
</details>

**perfect =** GED of 0 (graph-isomorphic control flow).

## [2] Type correctness
metric: Type Correctness

Did the decompiler recover the right variable and argument types? We match the decompiled variables against DWARF ground truth (arguments by ABI position, stack variables by calibrated offset, the rest by name) and score the fraction recovered correctly.

<details class="metric-viz">
<summary>how type matching works: DWARF ground truth &harr; decompiled variables [click to expand]</summary>
<div style="background:#000;padding:8px 0;">
<svg viewBox="0 0 760 396" style="max-width:100%;height:auto;display:block" xmlns="http://www.w3.org/2000/svg" font-family="Source Code Pro, monospace">
  <defs>
    <marker id="tm-arrow-green" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#6ab04c"/></marker>
    <marker id="tm-arrow-amber" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#d4a72c"/></marker>
    <marker id="tm-arrow-red" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#c0504d"/></marker>
  </defs>

  <!-- title -->
  <text x="380" y="26" text-anchor="middle" font-size="12.5" fill="#DBDBDB">type_match &mdash; recovered variable types vs DWARF ground truth</text>

  <!-- ============ LEFT PANEL ============ -->
  <rect x="16" y="44" width="250" height="256" fill="none" stroke="rgba(219,219,219,0.4)" stroke-width="1" stroke-dasharray="4 3"/>
  <text x="24" y="64" font-size="10.5" fill="#DBDBDB">DWARF ground truth <tspan fill="#8a8a8a">(from -g build)</tspan></text>
  <line x1="24" y1="72" x2="258" y2="72" stroke="rgba(219,219,219,0.4)" stroke-width="1" stroke-dasharray="4 3"/>

  <!-- left rows -->
  <rect x="24" y="82"  width="234" height="48" fill="#141414" stroke="#545454" stroke-width="1"/>
  <rect x="24" y="136" width="234" height="48" fill="#141414" stroke="#545454" stroke-width="1"/>
  <rect x="24" y="190" width="234" height="48" fill="#141414" stroke="#545454" stroke-width="1"/>
  <rect x="24" y="244" width="234" height="48" fill="#141414" stroke="#545454" stroke-width="1"/>

  <text x="32" y="100" font-size="10.5" fill="#8a8a8a">arg 0</text>
  <text x="32" y="119" font-size="12" fill="#DBDBDB">char *<tspan fill="#8a8a8a">path</tspan></text>

  <text x="32" y="154" font-size="10.5" fill="#8a8a8a">arg 1</text>
  <text x="32" y="173" font-size="12" fill="#DBDBDB">int <tspan fill="#8a8a8a">mode</tspan></text>

  <text x="32" y="208" font-size="10.5" fill="#8a8a8a">local @ rsp-0x18</text>
  <text x="32" y="227" font-size="12" fill="#DBDBDB">size_t <tspan fill="#8a8a8a">len</tspan></text>

  <text x="32" y="262" font-size="10.5" fill="#8a8a8a">local @ rsp-0x20</text>
  <text x="32" y="281" font-size="12" fill="#DBDBDB">struct stat <tspan fill="#8a8a8a">st</tspan></text>

  <!-- ============ RIGHT PANEL ============ -->
  <rect x="494" y="44" width="250" height="256" fill="none" stroke="rgba(219,219,219,0.4)" stroke-width="1" stroke-dasharray="4 3"/>
  <text x="502" y="64" font-size="10.5" fill="#DBDBDB">decompiler output</text>
  <line x1="502" y1="72" x2="736" y2="72" stroke="rgba(219,219,219,0.4)" stroke-width="1" stroke-dasharray="4 3"/>

  <rect x="502" y="82"  width="234" height="48" fill="#141414" stroke="#545454" stroke-width="1"/>
  <rect x="502" y="136" width="234" height="48" fill="#141414" stroke="#545454" stroke-width="1"/>
  <rect x="502" y="190" width="234" height="48" fill="#141414" stroke="#545454" stroke-width="1"/>
  <rect x="502" y="244" width="234" height="48" fill="#141414" stroke="#545454" stroke-width="1"/>

  <text x="510" y="100" font-size="10.5" fill="#8a8a8a">arg a1</text>
  <text x="510" y="119" font-size="12" fill="#6ab04c">char *</text>
  <text x="728" y="120" text-anchor="end" font-size="13" fill="#6ab04c">&#10003;</text>

  <text x="510" y="154" font-size="10.5" fill="#8a8a8a">arg a2</text>
  <text x="510" y="173" font-size="12" fill="#d4a72c">uint</text>
  <text x="728" y="174" text-anchor="end" font-size="13" fill="#c0504d">&#10007;</text>

  <text x="510" y="208" font-size="10.5" fill="#8a8a8a">var_18  @ -0x18</text>
  <text x="510" y="227" font-size="12" fill="#6ab04c">unsigned long</text>
  <text x="728" y="228" text-anchor="end" font-size="13" fill="#6ab04c">&#10003;</text>

  <text x="510" y="262" font-size="10.5" fill="#8a8a8a">var_20</text>
  <text x="510" y="281" font-size="12" fill="#c0504d">undefined8</text>
  <text x="728" y="282" text-anchor="end" font-size="13" fill="#c0504d">&#10007;</text>

  <!-- ============ MATCH ARROWS (gap 266..494) ============ -->
  <!-- row 1: match, pass 1 -->
  <line x1="266" y1="106" x2="490" y2="106" stroke="#6ab04c" stroke-width="1.6" marker-end="url(#tm-arrow-green)"/>
  <text x="380" y="98" text-anchor="middle" font-size="9.5" fill="#cfcfcf"><tspan fill="#6ab04c" font-weight="bold">[1]</tspan> arg 0 &harr; by ABI position</text>

  <!-- row 2: mismatch, pass 1 -->
  <line x1="266" y1="160" x2="490" y2="160" stroke="#d4a72c" stroke-width="1.6" marker-end="url(#tm-arrow-amber)"/>
  <text x="380" y="152" text-anchor="middle" font-size="9.5" fill="#cfcfcf"><tspan fill="#d4a72c" font-weight="bold">[1]</tspan> int != uint  (mismatch)</text>

  <!-- row 3: match, pass 2 -->
  <line x1="266" y1="214" x2="490" y2="214" stroke="#6ab04c" stroke-width="1.6" marker-end="url(#tm-arrow-green)"/>
  <text x="380" y="206" text-anchor="middle" font-size="9.5" fill="#cfcfcf"><tspan fill="#6ab04c" font-weight="bold">[2]</tspan> stack offset -0x18, calibrated</text>

  <!-- row 4: miss, pass 2 -->
  <line x1="266" y1="268" x2="490" y2="268" stroke="#c0504d" stroke-width="1.6" marker-end="url(#tm-arrow-red)"/>
  <text x="380" y="260" text-anchor="middle" font-size="9.5" fill="#cfcfcf"><tspan fill="#c0504d" font-weight="bold">[2]</tspan> missed struct type</text>

  <!-- ============ PASS LEGEND ============ -->
  <text x="380" y="318" text-anchor="middle" font-size="9.5" fill="#8a8a8a">matching passes: <tspan fill="#DBDBDB" font-weight="bold">[1]</tspan> args by ABI position (name-independent) &#183; <tspan fill="#DBDBDB" font-weight="bold">[2]</tspan> stack vars by calibrated offset &#183; <tspan fill="#DBDBDB" font-weight="bold">[3]</tspan> rest by exact name</text>

  <!-- ============ RESULT STRIP ============ -->
  <rect x="16" y="330" width="728" height="54" fill="#141414" stroke="#545454" stroke-width="1"/>
  <text x="30" y="356" font-size="13.5" fill="#DBDBDB">score = <tspan fill="#8a8a8a">matched-correct / recoverable</tspan> = <tspan fill="#6ab04c" font-weight="bold">2</tspan> / 4 = <tspan fill="#d4a72c" font-weight="bold">0.50</tspan></text>
  <text x="30" y="376" font-size="11" fill="#8a8a8a"><tspan fill="#6ab04c">1.0</tspan> &rarr; every recoverable variable typed correctly = perfect</text>
</svg>
<p style="color:#8a8a8a;font-size:0.85em;">Only variables carrying a DWARF location count as <em>recoverable</em> &mdash; fully optimized-out vars are dropped for everyone, so the denominator is identical across decompilers. Arguments match by ABI position (name-independent, so angr's <code>a1</code>/<code>a2</code> get fair credit), stack locals by an auto-calibrated frame-offset shift, and the remainder by exact name.</p>
</div>
</details>

**perfect =** 1.0 (every recoverable variable typed correctly).

## [3] Recompilation correctness
metric: Recompilation Bytematch

Does the decompiled code recompile to the same machine code? We run a uniform compilability fixup (define decompiler pseudo-types, strip illegal symbol-version tokens, declare missing symbols) so every decompiler gets a fair shot at building, recompile each function with the original toolchain, and compare the resulting assembly &mdash; normalizing link-time-dependent operands (call/jump targets, PC-relative offsets) so only real differences count.

<details class="metric-viz">
<summary>how bytematch works: fixup &rarr; recompile &rarr; normalized asm diff [click to expand]</summary>
<div style="background:#000;color:#DBDBDB;font-family:'Source Code Pro',monospace;padding:4px 0;">
<svg viewBox="0 0 760 374" style="max-width:100%;height:auto;display:block;">
  <defs>
    <marker id="bm-arrow" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto" markerUnits="userSpaceOnUse">
      <path d="M0,0 L6,3 L0,6 Z" fill="#8a8a8a"/>
    </marker>
  </defs>

  <g font-family="'Source Code Pro',monospace" fill="#DBDBDB">

    <!-- title -->
    <text x="50" y="22" font-size="14" fill="#DBDBDB">byte_match</text>
    <text x="140" y="22" font-size="12" fill="#8a8a8a">— recompile the decompiled C, then diff the bytes against the original</text>

    <!-- ============ TOP LANE: decompiled C -> fixup -> buildable .c -> recompile -> .o ============ -->

    <!-- Panel A: decompiled C -->
    <rect x="50" y="40" width="160" height="84" fill="#141414" stroke="#545454" stroke-width="1"/>
    <text x="58" y="57" font-size="11" fill="#DBDBDB">decompiled C</text>
    <text x="58" y="76" font-size="11"><tspan fill="#d4a72c">undefined4</tspan><tspan fill="#DBDBDB"> f(int a){</tspan></text>
    <text x="58" y="92" font-size="11"><tspan fill="#DBDBDB">  </tspan><tspan fill="#d4a72c">uint</tspan><tspan fill="#DBDBDB"> x = a*3;</tspan></text>
    <text x="58" y="108" font-size="11" fill="#DBDBDB">  return x; }</text>

    <!-- arrow 1: compilability fixup -->
    <line x1="212" y1="82" x2="297" y2="82" stroke="#8a8a8a" stroke-width="1.4" marker-end="url(#bm-arrow)"/>
    <text x="255" y="60" font-size="11" fill="#6ab04c" text-anchor="middle">compilability</text>
    <text x="255" y="72" font-size="11" fill="#6ab04c" text-anchor="middle">fixup</text>
    <text x="255" y="98" font-size="8.5" fill="#8a8a8a" text-anchor="middle">inject only</text>
    <text x="255" y="108" font-size="8.5" fill="#8a8a8a" text-anchor="middle">what gcc needs;</text>
    <text x="255" y="118" font-size="8.5" fill="#8a8a8a" text-anchor="middle">never rewrite logic</text>

    <!-- Panel B: buildable .c -->
    <rect x="300" y="40" width="150" height="84" fill="#141414" stroke="#545454" stroke-width="1"/>
    <text x="308" y="57" font-size="11" fill="#DBDBDB">buildable .c</text>
    <text x="308" y="74" font-size="9" fill="#6ab04c">+ typedef u32 undefined4;</text>
    <text x="308" y="88" font-size="9" fill="#6ab04c">+ typedef u32 uint;</text>
    <text x="308" y="106" font-size="9" fill="#8a8a8a">undefined4 f(int a){…}</text>

    <!-- arrow 2: recompile -->
    <line x1="452" y1="82" x2="537" y2="82" stroke="#8a8a8a" stroke-width="1.4" marker-end="url(#bm-arrow)"/>
    <text x="495" y="60" font-size="11" fill="#d4a72c" text-anchor="middle">recompile</text>
    <text x="495" y="72" font-size="9.5" fill="#d4a72c" text-anchor="middle">same toolchain</text>
    <text x="495" y="98" font-size="8.5" fill="#8a8a8a" text-anchor="middle">PE→MinGW</text>
    <text x="495" y="108" font-size="8.5" fill="#8a8a8a" text-anchor="middle">ARM→arm-eabi</text>
    <text x="495" y="118" font-size="8.5" fill="#8a8a8a" text-anchor="middle">x86→gcc</text>

    <!-- Panel C: .o recompiled -->
    <rect x="540" y="40" width="170" height="84" fill="#141414" stroke="#545454" stroke-width="1"/>
    <text x="548" y="57" font-size="11" fill="#DBDBDB">.o  (recompiled)</text>
    <text x="548" y="78" font-size="10" fill="#8a8a8a">recompiled the SAME</text>
    <text x="548" y="94" font-size="10" fill="#8a8a8a">way as the source:</text>
    <text x="548" y="110" font-size="10" fill="#d4a72c">-O2 · x86-64</text>

    <!-- ============ CONVERGE: .o bytes + original bytes -> normalize + diff ============ -->

    <!-- feed arrow: .o -> diff -->
    <line x1="600" y1="124" x2="562" y2="147" stroke="#8a8a8a" stroke-width="1.4" marker-end="url(#bm-arrow)"/>
    <text x="606" y="140" font-size="9" fill="#8a8a8a">recompiled bytes</text>

    <!-- Panel D: original binary -->
    <rect x="50" y="168" width="150" height="100" fill="#141414" stroke="#545454" stroke-width="1"/>
    <text x="58" y="187" font-size="11" fill="#DBDBDB">original binary</text>
    <text x="58" y="208" font-size="10" fill="#8a8a8a">ground-truth</text>
    <text x="58" y="224" font-size="10" fill="#8a8a8a">func f @ 0x1149</text>
    <text x="58" y="240" font-size="10" fill="#8a8a8a">raw .text bytes</text>
    <text x="58" y="258" font-size="9" fill="#6ab04c">the reference</text>

    <!-- feed arrow: original -> diff -->
    <line x1="200" y1="218" x2="247" y2="218" stroke="#8a8a8a" stroke-width="1.4" marker-end="url(#bm-arrow)"/>
    <text x="224" y="212" font-size="9" fill="#8a8a8a" text-anchor="middle">bytes</text>

    <!-- Box E: normalize + diff -->
    <rect x="250" y="148" width="340" height="138" fill="none" stroke="rgba(219,219,219,0.4)" stroke-width="1" stroke-dasharray="4 3"/>
    <text x="262" y="166" font-size="12" fill="#DBDBDB">normalize + diff</text>
    <text x="262" y="179" font-size="9" fill="#8a8a8a">blank link-time operands, then compare asm lines</text>

    <!-- asm inner panel -->
    <rect x="258" y="184" width="324" height="94" fill="#141414" stroke="#545454" stroke-width="1"/>
    <text x="340" y="196" font-size="10" fill="#8a8a8a" text-anchor="middle">recompiled</text>
    <text x="500" y="196" font-size="10" fill="#8a8a8a" text-anchor="middle">original</text>
    <line x1="420" y1="186" x2="420" y2="276" stroke="rgba(219,219,219,0.35)" stroke-width="1" stroke-dasharray="3 3"/>

    <!-- row match rects -->
    <rect x="259" y="200" width="322" height="16" fill="#6ab04c" fill-opacity="0.12"/>
    <rect x="259" y="216" width="322" height="16" fill="#6ab04c" fill-opacity="0.12"/>
    <rect x="259" y="232" width="322" height="16" fill="#6ab04c" fill-opacity="0.12"/>
    <rect x="259" y="248" width="322" height="16" fill="#c0504d" fill-opacity="0.16"/>

    <!-- row 1: match -->
    <text x="270" y="212" font-size="11" fill="#6ab04c">push rbp</text>
    <text x="430" y="212" font-size="11" fill="#6ab04c">push rbp</text>
    <!-- row 2: match, normalized rip-disp -->
    <text x="270" y="228" font-size="11"><tspan fill="#6ab04c">mov eax,[rip+</tspan><tspan fill="#d4a72c">____</tspan><tspan fill="#6ab04c">]</tspan></text>
    <text x="430" y="228" font-size="11"><tspan fill="#6ab04c">mov eax,[rip+</tspan><tspan fill="#d4a72c">____</tspan><tspan fill="#6ab04c">]</tspan></text>
    <!-- row 3: match, normalized call target -->
    <text x="270" y="244" font-size="11"><tspan fill="#6ab04c">call </tspan><tspan fill="#d4a72c">____</tspan></text>
    <text x="430" y="244" font-size="11"><tspan fill="#6ab04c">call </tspan><tspan fill="#d4a72c">____</tspan></text>
    <!-- row 4: differ -->
    <text x="270" y="260" font-size="11" fill="#c0504d">shl eax, 2</text>
    <text x="430" y="260" font-size="11" fill="#c0504d">lea eax,[eax*4]</text>
    <!-- ellipsis -->
    <text x="340" y="273" font-size="11" fill="#8a8a8a" text-anchor="middle">⋮</text>
    <text x="500" y="273" font-size="11" fill="#8a8a8a" text-anchor="middle">⋮</text>

    <!-- legend -->
    <rect x="250" y="294" width="10" height="10" fill="#6ab04c" fill-opacity="0.55" stroke="#6ab04c" stroke-width="0.8"/>
    <text x="264" y="303" font-size="9" fill="#8a8a8a">match</text>
    <rect x="318" y="294" width="10" height="10" fill="#d4a72c" fill-opacity="0.55" stroke="#d4a72c" stroke-width="0.8"/>
    <text x="332" y="303" font-size="9" fill="#8a8a8a">normalized operand</text>
    <rect x="470" y="294" width="10" height="10" fill="#c0504d" fill-opacity="0.55" stroke="#c0504d" stroke-width="0.8"/>
    <text x="484" y="303" font-size="9" fill="#8a8a8a">byte differs</text>

    <!-- ============ RESULT STRIP ============ -->
    <rect x="50" y="314" width="660" height="48" fill="none" stroke="rgba(219,219,219,0.4)" stroke-width="1" stroke-dasharray="4 3"/>
    <text x="64" y="337" font-size="12"><tspan fill="#8a8a8a">byte_match = </tspan><tspan fill="#DBDBDB">matching asm lines / total</tspan><tspan fill="#8a8a8a"> = </tspan><tspan fill="#6ab04c" font-size="16">0.87</tspan></text>
    <text x="64" y="354" font-size="10" fill="#8a8a8a"><tspan fill="#6ab04c">1.0</tspan> → recompiled assembly matches the original = perfect</text>

  </g>
</svg>
<p style="color:#8a8a8a;font-size:0.85em;">Recompilation Bytematch rebuilds the decompiler's own C the SAME way the original was built — toolchain and <code>-O*/-m*</code> flags read from the DWARF producer (PE→MinGW, ARM→arm-none-eabi, x86→gcc) — then compares assembly line by line. A compilability fixup injects <em>only</em> what gcc reports missing (typedefs for pseudo-types like <code>undefined4</code>/<code>uint</code>/<code>code</code>, decls for implicit functions, globals for undeclared ids) and never rewrites logic. Link-time-dependent operands — call/branch targets and <code>[rip±disp]</code> PC-relative displacements — are normalized away, so an unlinked address difference is not a penalty. Type recovery is scored separately (type_match), so fixing types just to compile is fair.</p>
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
