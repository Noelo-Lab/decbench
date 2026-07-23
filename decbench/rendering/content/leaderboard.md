<!--
View template. Conventions (shared by every *.md in this directory, parsed by
decbench/rendering/content.py):

  # <title>            the view heading, rendered as <h2 class="view-title">.
                       Everything until the next `# ` is the view BODY.
  # [empty] <title>    the empty-state section, shown when the view has no data.
                       Omit the title to reuse the main one.
  # [outro]            body content that the renderer places AFTER its generated
                       markup (see about.md).

WRITE PLAIN MARKDOWN. Prose is markdown, not HTML: **bold**, *italic*,
[text](url), `code`, and literal unicode punctuation (— · ≥) — never
<strong>/<em>/<a> tags or &mdash;/&middot;/&ge; entities. Paragraphs become
<p class="view-desc">, `###` becomes <h3 class="sub">, `- ` bullets become styled
lists.

Reach for raw HTML ONLY where markdown can't carry the meaning: scaffold elements
the JS fills or toggles (anything with an id — <table id=...>, <div id=...>,
<p id=...>), styling hooks (<div class="recovered">), and the hand-authored
metric-viz "islands" in about.md. Inline HTML still passes through UNESCAPED when
you do use it (it is treated as final markup), so keep raw tags to those cases.
HTML comments like this one are stripped before rendering. Static scaffold
elements live here too, so prose and scaffold keep their order; data-dependent
tables are appended by the renderer.

THIS is the page the site opens on (`default = true` in views.toml), so the prose
below is the first text a visitor reads. The empty #leaderboard-dataset-desc div
is the DYNAMIC per-dataset paragraph: app.js fills it from the selected preset's
`long_description` in datasets.toml (shipped via aggregates.json), so per-dataset
wording is edited THERE, not here. The full explainer — metrics, corpus,
methodology — lives in about.md; changing what the site says on arrival usually
means editing both.
-->

# leaderboard

Decompilers have advanced significantly over
[the last 30 years](https://mahaloz.re/dec-history-pt1), quickly approaching the
point where they can recover the exact source code from various binaries. This
benchmark ranks decompilers by their ability to recover exact source code,
measured across three metrics. All metrics are shown as the percentage of
functions on which a decompiler achieves a perfect score. Decompilers are
initially ranked by Union — their ability to score perfectly on
*at least one* of those metrics. Click a column to sort.

AI can also compete on these metrics, as seen on the
[sample-set leaderboard](https://decbench.com/leaderboard/?dataset=sample-set)
where Codex and Claude Code take on the traditional decompilers. You can find
more information about these metrics, datasets, and methodology on the
[about page](https://decbench.com/about/). You can also view some sample results
on the [view page](https://decbench.com/view/?dataset=sample-set&tier=sample-set&dec=codex&metric=ged&fn=base-passwd%2FO0%2Fupdate-passwd%3A%3Aread_shadow).

<div id="leaderboard-dataset-desc"></div>
