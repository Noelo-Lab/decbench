<!-- View template — see leaderboard.md for the shared conventions.

The dated scoreboard snapshots. Everything below the prose is scaffold that
app.js fills from data/snapshots/index.json:

  #snap-filters     the decompiler + version filter row, unhidden once populated
  #snap-dec         decompiler select ("any" + every decompiler ever recorded)
  #snap-ver         version select ("any" + the versions that decompiler had)
  #snap-count       "showing N of M" for the active filter
  #snapshots-body   the table (#snapshots-table), or the empty state
-->

# snapshots

A snapshot freezes the scoreboard on a given day, so a score you cite keeps a
stable link after the benchmark moves on. Open one by adding
`?snapshot=DD-MM-YYYY` to any page, or follow a date below.

Snapshots are recorded deliberately, not on a schedule — one is taken whenever a
change moves published scores or breaks comparability, which is the same moment
the [changelog](#changelog) earns an entry. Use the filters to find the
snapshots where a decompiler was on a particular version.

Each snapshot carries the leaderboard, metrics, data and about pages exactly as
they stood. The [view](#view) page is the one exception: its side-by-side source
is ~31 MB per build, far too heavy to freeze per date, so it always shows live
code.

<div class="snap-filters" id="snap-filters" hidden>
  <label for="snap-dec">decompiler</label>
  <select id="snap-dec"></select>
  <label for="snap-ver">version</label>
  <select id="snap-ver"></select>
  <span id="snap-count"></span>
</div>

<div id="snapshots-body"></div>
