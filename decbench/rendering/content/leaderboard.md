<!--
View template. Conventions (shared by every *.md in this directory, parsed by
decbench/rendering/content.py):

  # <title>            the view heading, rendered as <h2 class="view-title">.
                       Everything until the next `# ` is the view BODY.
  # [empty] <title>    the empty-state section, shown when the view has no data.
                       Omit the title to reuse the main one.
  # [outro]            body content that the renderer places AFTER its generated
                       markup (see metrics.md).

Markdown paragraphs become <p class="view-desc">, `###` becomes <h3 class="sub">.
Inline HTML (<em>, <strong>, &mdash;) is passed through UNESCAPED — it is already
final markup. HTML comments like this one are stripped before rendering. Static
scaffold elements (empty divs/tables the JS fills in) live here too, so prose and
scaffold keep their order; data-dependent tables are appended by the renderer.

THIS is the page the site opens on (`default = true` in views.toml), so the prose
below is the first text a visitor reads. It is deliberately short: the longer
explainer — what the benchmark is, how to read the columns, what the corpus is —
lives in about.md, the last nav item. Changing what the site says on arrival
usually means editing BOTH.
-->

# leaderboard

ranked by Overall &mdash; the share of functions a decompiler recovers
<em>perfectly on all three metrics</em>. click a column to sort.
