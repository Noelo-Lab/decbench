<!-- View template — see leaderboard.md for the shared conventions. -->

# distance

The raw <em>edit distance</em> to a perfect result for each metric
(lower is better) — a finer signal than the perfect / not-perfect rate
on the leaderboard. <strong>GED</strong> = the graph edit distance
itself; <strong>types</strong> = number of type-flips to reach the
ground truth (false-typed + missing vars); <strong>byte</strong> =
number of changed assembly lines after recompiling. Each cell shows the
<em>mean</em>, the <em>median</em>, and how many functions are already
at distance 0 (perfect). Averaged over the functions each decompiler was
scored on.

<p class="view-desc" id="distance-table-note">over the selected dataset
    (mean &middot; median &middot; #at-0 / #measured).</p>

<table id="distance-table"><thead><tr></tr></thead><tbody></tbody></table>
