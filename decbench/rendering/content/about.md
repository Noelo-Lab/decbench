<!--
The "about" page — NOT the page the site opens on.

If you came here to edit the text people see FIRST, you want leaderboard.md:
the site opens on the leaderboard (`default = true` in views.toml) and this page
is the LAST nav item. The starting-page prose is split between the two — the
short intro above the table lives in leaderboard.md, the long explainer is here.

File name, view id, and nav label all agree: about / #about / "about".
See leaderboard.md for the conventions every *.md in this directory follows.
-->

# decbench

a benchmark for decompilers. we compile real C projects at several optimization
levels, decompile every function of the resulting binaries with each decompiler,
and score the output against the source it came from &mdash; not against taste.

### the three metrics

a decompiler is trying to do three separable things, so we measure three things:

<div class="goal-body">
    <strong>structure</strong> &mdash; does it branch and loop like the source?
    graph edit distance between the two control-flow graphs.<br>
    <strong>types</strong> &mdash; did it recover the right variable and argument
    types? matched against DWARF ground truth.<br>
    <strong>recompile</strong> &mdash; does its C build back into the same machine
    code? recompiled with the original toolchain and diffed.
</div>

each is reported as how often a decompiler gets it <em>perfect</em>, because a
decompilation that is <em>nearly</em> right is still a thing you have to read
twice. see <a href="#metrics">metrics</a> for what perfect means, and
<a href="#distance">distance</a> for how far off the rest are.

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
all.

### the corpus

real software, not toy functions: coreutils-scale unix packages, drone and RTOS
firmware cross-compiled for ARM, and a handful of malware samples. see
<a href="#dataset">dataset</a> for every project, its size, and how much of the
pipeline we lose to our own tooling rather than to the decompilers &mdash; we
count that against ourselves.
