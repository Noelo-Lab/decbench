<!-- View template — see leaderboard.md for the shared conventions. -->

# insights

what the numbers actually say so far. every claim below is over the published
data on this site — click through to the leaderboard or distance pages to check
any of it. (maintainer's notebook: expect this page to change as results land.)

### nobody is close to solved

The best conventional decompiler recovers a function perfectly — on even one
metric — less than half the time on the *easiest* preset (unoptimized builds:
Hex-Rays 47.7%, Kuna 47.5%). Turn optimization on and the leaders drop to ~34%.
Decompilation at the function level, measured against ground truth instead of
taste, is far from a finished problem.

### an LLM agent doubles the field — on the slice it can afford

On the ~250-function `sample-set`, Codex reaches **53.9%** Union — roughly
double the best conventional decompiler on the same functions (angr 28.4%,
Hex-Rays 27.2%). Two caveats keep this honest: LLM backends only run on the
sample-set (one agentic call per function is orders of magnitude slower and
costlier than any decompiler here), and Codex's type accuracy is still near
zero — it wins on control-flow structure and on producing code that actually
recompiles (21.4% vs. low single digits for everyone else).

### structuring beats frontends

Kuna — a research port that reuses Ghidra's frontend but replaces the
structuring — beats stock Ghidra by ~15 points of Union on every preset. Where
the control-flow graph gets turned back into `if`/`while`, not where the bytes
get lifted, is where perfection is won or lost.

### type recovery is the weakest link

Structure is regularly recovered perfectly; types almost never are. The best
type score on any preset is angr's 12.1% at O0, and every decompiler falls to
low single digits once the optimizer erases stack frames. If you want a
research gap, this is the widest one on the board.

### optimization is the great equalizer

From O0 to O2-noinline, every conventional decompiler loses roughly a third of
its perfect functions (Hex-Rays 47.7% → 33.9%, angr 45.3% → 33.4%). Inlining
(plain O2) costs a few points more. The ranking barely changes — optimization
hurts everyone about equally.

### recompilable output is still rare

Even after the fairness passes (uniform compilability fixups, link-time operand
normalization), conventional decompilers produce assembly-matching recompiles
for under 7% of functions. Readable-but-unrebuildable remains the norm.

### the errors column is a story of its own

dewolf fails outright on half the corpus (50–72% depending on preset) — the
cost of a research pipeline with aggressive simplification. The LLM backends are
listed only under the `sample-set` preset, the one slice they are run on; on
every other preset their rows are omitted rather than shown, so there is no
inflated error rate there to read into.
