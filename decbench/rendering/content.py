"""Loader for the report's maintainer-editable *content*.

Every string a maintainer might want to reword — brand, nav labels, metric names,
dataset descriptions, per-view prose — lives in :mod:`decbench.rendering.content`
(the ``content/`` directory next to this module), not in the renderer. This module
reads that directory once and hands the renderer typed, frozen objects.

The files:

* ``site.toml`` — brand, footer, banners, sidebar labels.
* ``views.toml`` — the view registry (id, nav label, whether it needs function
  data, which one is ``default``). The single source of truth for what views
  exist, their nav order, and which the site opens on.
* ``metrics.toml`` — per-metric display name, short column label, order, and the
  canonical definition of *perfect*.
* ``datasets.toml`` — the dataset presets' labels and descriptions, one of which
  is explicitly ``default``. Which functions are *in* a preset is a scoring
  concern and lives in :mod:`decbench.scoring.datasets`; the two are joined at
  render time, so preset text is editable without re-running the benchmark.
* ``categories.toml`` — the software-type taxonomy of the Dataset page.
* ``<view>.md`` — each view's title, prose, and static scaffold.

Markdown conventions (documented in the files themselves, parsed here):

* ``# <title>`` opens a section. A bare title is the view **body**; ``# [empty]
  <title>`` is the empty state; ``# [outro]`` is body content the renderer emits
  *after* its generated markup.
* In ``about.md``, ``## [n] <title>`` blocks are structured **goal cards**
  (:class:`GoalCard`) — a ``metric:`` line, a body, and a ``**perfect =**`` line.
* Inline HTML passes through unescaped: the prose is already final markup.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from functools import lru_cache
from importlib.resources import files

import mistune

__all__ = [
    "Brand",
    "Category",
    "Content",
    "DatasetPresetSpec",
    "DecompilerSpec",
    "Footer",
    "GoalCard",
    "MetricSpec",
    "Sidebar",
    "SiteContent",
    "ViewContent",
    "ViewSpec",
    "load_content",
]

_CONTENT_DIR = "content"

# `# <title>` / `# [tag] <title>` — opens a section of a view markdown file.
_SECTION_RE = re.compile(r"^#[ \t]+(?:\[(?P<tag>[a-z]+)\][ \t]*)?(?P<title>.*)$")
# `## [1] <title>` — opens a goal card in metrics.md.
_CARD_RE = re.compile(r"^##[ \t]+\[(?P<num>\d+)\][ \t]*(?P<title>.*)$")
_METRIC_LINE_RE = re.compile(r"^metric:[ \t]*(?P<name>.+)$")
_PERFECT_RE = re.compile(r"^\*\*perfect\s*=\*\*[ \t]*(?P<rest>.+)$")
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_WRAPPING_P_RE = re.compile(r"^<p[^>]*>(?P<inner>.*)</p>\s*$", re.DOTALL)
# `<details class="metric-viz">...</details>` — a hand-authored raw-HTML island.
# Mistune knows nothing of SVG: blank-line-separated `<text>`/`<rect>` runs inside
# one are "loose paragraphs" to it, and the `<p>` it wraps them in — INSIDE an
# `<svg>` — is invalid foreign content that makes the browser abandon SVG parsing.
# Islands are therefore lifted out before markdown rendering and spliced back in
# verbatim afterwards. Lines inside an island still must not start with `# `/`## `
# (the section/card splitters are line-based and run first).
_ISLAND_RE = re.compile(r"<details class=\"metric-viz\"[^>]*>.*?</details>", re.DOTALL)
_ISLAND_TOKEN = "decbench-viz-island-{index}"

_BODY_SECTION = "body"
_EMPTY_SECTION = "empty"
_OUTRO_SECTION = "outro"


class _RawTextRenderer(mistune.HTMLRenderer):
    """Renderer that treats the markdown's text as the final HTML it already is.

    Mistune's default ``text`` handling round-trips entities (``&mdash;`` comes
    back out as ``—``). The content files are hand-written HTML fragments whose
    entities are deliberate, so text is passed through byte-for-byte instead.
    """

    def text(self, text: str) -> str:
        """Emit text verbatim — entities included, nothing re-escaped."""
        return text


class _ReportRenderer(_RawTextRenderer):
    """Renderer that additionally emits the report's own CSS classes."""

    def paragraph(self, text: str) -> str:
        """Prose paragraphs are the report's muted ``.view-desc`` blocks."""
        return f'<p class="view-desc">{text}</p>\n'

    def heading(self, text: str, level: int, **attrs: object) -> str:
        """``###`` is the report's ``> ``-prefixed subsection heading."""
        if level == 3:
            return f'<h3 class="sub">{text}</h3>\n'
        return super().heading(text, level, **attrs)


# escape=False: the prose IS final HTML (<em>, <strong>, &mdash;) and must pass
# through untouched. The content directory ships with the package; it is never
# user-supplied, so there is no injection surface here.
_render_view = mistune.create_markdown(renderer=_ReportRenderer(escape=False))
_render_inline = mistune.create_markdown(renderer=_RawTextRenderer(escape=False))


@dataclass(frozen=True)
class Brand:
    """The sidebar brand block."""

    prompt: str
    title: str
    subtitle: str


@dataclass(frozen=True)
class Footer:
    """The page footer template."""

    template: str
    projects_empty: str

    def render(self, version: str, projects: list[str]) -> str:
        """Fill the footer template with a version and a project list."""
        joined = ", ".join(projects) or self.projects_empty
        return self.template.format(version=version, projects=joined)


@dataclass(frozen=True)
class Sidebar:
    """Labels for the sidebar dataset selector."""

    dataset_label: str
    normalize_label: str
    normalize_title: str


@dataclass(frozen=True)
class SiteContent:
    """Report chrome: brand, footer, banners, sidebar, side-stat labels."""

    brand: Brand
    footer: Footer
    sidebar: Sidebar
    banners: dict[str, str]
    side_stats: dict[str, str]
    hidden_decompilers: tuple[str, ...] = ()
    sample_set_only_decompilers: tuple[str, ...] = ()
    pages_domain: str = ""
    """Custom domain the split site is served from (``[pages] domain``).

    When set, :func:`decbench.rendering.site.build_site` emits a ``CNAME`` file
    carrying it. Empty = no custom domain (the github.io URL).
    """

    @property
    def no_function_data_banner(self) -> str:
        """The banner shown when function_results.json is missing."""
        return self.banners["no_function_data"]


@dataclass(frozen=True)
class ViewSpec:
    """A registered view: its id, nav label, data requirement, and default flag."""

    id: str
    nav_label: str
    requires_function_data: bool
    default: bool = False


@dataclass(frozen=True)
class GoalCard:
    """One of the Metrics page's three ``.goal`` cards.

    ``metric_key`` is resolved from :attr:`metric_display_name` against
    ``metrics.toml``; it is ``""`` when the card names no known metric.
    """

    number: str
    title: str
    metric_display_name: str
    metric_key: str
    body_html: str
    perfect: str


@dataclass(frozen=True)
class ViewContent:
    """A view's prose: title, body, optional outro and empty state."""

    id: str
    title: str
    body_html: str
    outro_html: str = ""
    empty_title: str = ""
    empty_html: str = ""
    goals: tuple[GoalCard, ...] = ()

    @property
    def has_empty_state(self) -> bool:
        """Whether the view declares an ``# [empty]`` section."""
        return bool(self.empty_html)


@dataclass(frozen=True)
class MetricSpec:
    """Presentation of one metric: names, column order, perfect definition."""

    name: str
    display_name: str
    short_name: str
    order: int
    perfect_definition: str

    @property
    def perfect_line(self) -> str:
        """The goal card's wording: ``perfect = <definition>``."""
        return f"perfect = {self.perfect_definition}"


@dataclass(frozen=True)
class DatasetPresetSpec:
    """Presentation of one dataset preset (membership lives in scoring)."""

    name: str
    label: str
    description: str
    long_description: str = ""
    """The leaderboard's per-dataset explainer paragraph (final inline HTML).

    Swapped in client-side whenever the selected preset changes; empty = the
    leaderboard shows no per-dataset paragraph for this preset.
    """
    default: bool = False


@dataclass(frozen=True)
class DecompilerSpec:
    """Presentation of one decompiler: its official name, link, and version labels.

    ``version_overrides`` maps a raw version string (as a run recorded it) to a
    prettier one, e.g. IDA's ``"920"`` -> ``"9.2"``.

    ``license`` is ``"open-source"`` / ``"closed-source"`` (or ``""`` for none) and
    is shown as a muted tag in the leaderboard's stacked name cell. ``logo`` marks
    that a ``.dlogo-<id>`` background-image is shipped in ``app.css``; both flow
    through the registry so the client can render them (see ``aggregate.py``).
    """

    id: str
    display_name: str
    url: str = ""
    license: str = ""
    logo: bool = False
    version_overrides: dict[str, str] = field(default_factory=dict)

    def pretty_version(self, raw: str | None) -> str | None:
        """Prettify a raw version string, or pass it through when unmapped/absent."""
        if raw is None:
            return None
        return self.version_overrides.get(raw, raw)


@dataclass(frozen=True)
class Category:
    """One software type, and the binary labels that place a project in it."""

    name: str
    labels: tuple[str, ...]


@dataclass(frozen=True)
class Content:
    """Everything under ``content/``, parsed and typed."""

    site: SiteContent
    view_specs: tuple[ViewSpec, ...]
    views: dict[str, ViewContent]
    metrics: tuple[MetricSpec, ...]
    dataset_presets: tuple[DatasetPresetSpec, ...]
    categories: tuple[Category, ...] = ()
    decompilers: tuple[DecompilerSpec, ...] = ()

    # -- views -------------------------------------------------------------
    def view(self, view_id: str) -> ViewContent:
        """Return one view's prose by id."""
        return self.views[view_id]

    @property
    def default_view(self) -> str:
        """The view id the site opens on (``default = true`` in views.toml).

        Explicit, and one line of config: it used to be the string "leaderboard"
        hardcoded in three places (the renderer's ``active`` class, the client's
        routing fallback, and the nav), which is three chances to disagree.
        """
        for spec in self.view_specs:
            if spec.default:
                return spec.id
        return self.view_specs[0].id if self.view_specs else ""

    def visible_views(self, has_function_data: bool) -> tuple[ViewSpec, ...]:
        """The views to render/navigate, in nav order.

        Views that need per-function data are dropped when the report has none.
        """
        return tuple(
            v for v in self.view_specs if has_function_data or not v.requires_function_data
        )

    def with_view(self, view_id: str, markdown_text: str) -> Content:
        """Return a copy with ``view_id``'s prose re-parsed from ``markdown_text``.

        The view must already be registered (a :class:`ViewSpec` in
        ``view_specs``); only its :class:`ViewContent` is replaced, every other
        view and all other content left untouched. This is how the CLI injects
        an external single source of truth — the repo-root ``CHANGELOG.md`` —
        into the ``changelog`` view at build time without writing into the
        packaged ``content/`` tree. An unregistered id is a no-op.
        """
        if not any(spec.id == view_id for spec in self.view_specs):
            return self
        views = dict(self.views)
        views[view_id] = _parse_view(view_id, markdown_text, self.metrics)
        return replace(self, views=views)

    # -- metrics -----------------------------------------------------------
    def metric(self, name: str) -> MetricSpec | None:
        """Look up a metric's presentation, or ``None`` if it is unregistered."""
        for m in self.metrics:
            if m.name == name:
                return m
        return None

    def ordered_metrics(self, metrics: list[str]) -> list[str]:
        """Sort ``metrics`` by registry order; unknown metrics keep their order."""
        rank = {m.name: m.order for m in self.metrics}
        known = sorted((m for m in metrics if m in rank), key=lambda m: rank[m])
        extra = [m for m in metrics if m not in rank]
        return known + extra

    def short_name(self, metric: str) -> str:
        """Short column label for a metric, falling back to its raw name."""
        spec = self.metric(metric)
        return spec.short_name if spec else metric

    def display_name(self, metric: str) -> str:
        """Full display name for a metric, falling back to its raw name."""
        spec = self.metric(metric)
        return spec.display_name if spec else metric

    # -- datasets ----------------------------------------------------------
    @property
    def default_dataset(self) -> DatasetPresetSpec | None:
        """The preset the report opens with (explicit, never positional)."""
        for p in self.dataset_presets:
            if p.default:
                return p
        return None

    # -- decompilers -------------------------------------------------------
    def decompiler(self, dec_id: str) -> DecompilerSpec | None:
        """Presentation for a decompiler id, by exact match then base name.

        A versioned id (``ghidra@12.1``) with no exact entry resolves to the base
        ``ghidra`` entry; an id with neither returns ``None`` (the caller falls
        back to the raw id).
        """
        base = dec_id.split("@", 1)[0]
        fallback: DecompilerSpec | None = None
        for spec in self.decompilers:
            if spec.id == dec_id:
                return spec
            if spec.id == base:
                fallback = spec
        return fallback


def _read(name: str) -> str:
    """Read one content file as text, working from a wheel or a checkout."""
    return (files(__package__).joinpath(_CONTENT_DIR) / name).read_text(encoding="utf-8")


def _load_toml(name: str) -> dict:
    """Parse one content TOML file."""
    import toml

    return toml.loads(_read(name))


def _strip_comments(text: str) -> str:
    """Drop HTML comments — the files use them for convention docs."""
    return _COMMENT_RE.sub("", text)


def _unwrap_paragraph(html: str) -> str:
    """Strip the single wrapping ``<p>`` mistune adds to a lone paragraph.

    Goal-card bodies are rendered inline (into ``.goal-body``), so the block
    wrapper has to go.
    """
    stripped = html.strip()
    match = _WRAPPING_P_RE.match(stripped)
    return match.group("inner").strip() if match else stripped


def _render_with_islands(markdown: str, render: mistune.Markdown) -> str:
    """Render markdown while passing raw-HTML islands through byte-for-byte.

    Each island is swapped for a bare single-word token (which mistune renders as
    a lone paragraph), then spliced back over that paragraph after rendering.
    """
    islands: list[str] = []

    def _lift(match: re.Match[str]) -> str:
        islands.append(match.group(0))
        return _ISLAND_TOKEN.format(index=len(islands) - 1)

    html = render(_ISLAND_RE.sub(_lift, markdown))
    # Descending index: token "…-1" is a prefix of "…-10", so ascending bare-token
    # replacement would corrupt the tenth island while splicing the second.
    for index, island in reversed(list(enumerate(islands))):
        token = _ISLAND_TOKEN.format(index=index)
        for wrapped in (f"<p>{token}</p>", f'<p class="view-desc">{token}</p>'):
            if wrapped in html:
                html = html.replace(wrapped, island)
                break
        else:
            html = html.replace(token, island)
    return html


def _split_sections(text: str) -> dict[str, tuple[str, str]]:
    """Split a view markdown into ``tag -> (title, markdown)``.

    Untagged sections land under ``body``; ``# [empty] x`` and ``# [outro]`` land
    under their tag. Text before the first heading is ignored.
    """
    sections: dict[str, tuple[str, list[str]]] = {}
    tag: str | None = None
    for line in _strip_comments(text).splitlines():
        match = _SECTION_RE.match(line)
        if match:
            tag = match.group("tag") or _BODY_SECTION
            sections[tag] = (match.group("title").strip(), [])
            continue
        if tag is not None:
            sections[tag][1].append(line)
    return {t: (title, "\n".join(lines).strip()) for t, (title, lines) in sections.items()}


def _parse_goal_cards(
    markdown: str, metrics: tuple[MetricSpec, ...]
) -> tuple[tuple[GoalCard, ...], str]:
    """Pull ``## [n]`` goal cards out of a body section.

    Returns the parsed cards and the body markdown with the cards removed (so the
    remaining prose renders as the view's intro).
    """
    by_display = {m.display_name: m.name for m in metrics}
    cards: list[GoalCard] = []
    kept: list[str] = []
    current: list[str] | None = None
    number = title = ""

    def flush() -> None:
        if current is None:
            return
        cards.append(_build_card(number, title, current, by_display))

    for line in markdown.splitlines():
        match = _CARD_RE.match(line)
        if match:
            flush()
            number, title = match.group("num"), match.group("title").strip()
            current = []
            continue
        if current is None:
            kept.append(line)
        else:
            current.append(line)
    flush()
    return tuple(cards), "\n".join(kept).strip()


def _build_card(number: str, title: str, lines: list[str], by_display: dict[str, str]) -> GoalCard:
    """Build one :class:`GoalCard` from the lines under a ``## [n]`` heading."""
    metric_display = ""
    perfect = ""
    body: list[str] = []
    for line in lines:
        metric_match = _METRIC_LINE_RE.match(line.strip())
        if metric_match and not metric_display:
            metric_display = metric_match.group("name").strip()
            continue
        perfect_match = _PERFECT_RE.match(line.strip())
        if perfect_match:
            perfect = f"perfect = {perfect_match.group('rest').strip()}"
            continue
        body.append(line)
    return GoalCard(
        number=number,
        title=title,
        metric_display_name=metric_display,
        metric_key=by_display.get(metric_display, ""),
        body_html=_unwrap_paragraph(_render_with_islands("\n".join(body).strip(), _render_inline)),
        perfect=perfect,
    )


def _load_view(view_id: str, metrics: tuple[MetricSpec, ...]) -> ViewContent:
    """Parse the packaged ``<view_id>.md`` into a :class:`ViewContent`."""
    return _parse_view(view_id, _read(f"{view_id}.md"), metrics)


def _parse_view(view_id: str, text: str, metrics: tuple[MetricSpec, ...]) -> ViewContent:
    """Parse a view's markdown *text* into a :class:`ViewContent`.

    Split out from :func:`_load_view` so the same parse can run on a string a
    caller supplies rather than the packaged file — e.g. the CLI injecting the
    repo-root ``CHANGELOG.md`` into the ``changelog`` view (see
    :meth:`Content.with_view`).
    """
    sections = _split_sections(text)
    title, body_md = sections.get(_BODY_SECTION, ("", ""))
    goals: tuple[GoalCard, ...] = ()
    if view_id == "about":
        goals, body_md = _parse_goal_cards(body_md, metrics)
    empty_title, empty_md = sections.get(_EMPTY_SECTION, ("", ""))
    _, outro_md = sections.get(_OUTRO_SECTION, ("", ""))
    return ViewContent(
        id=view_id,
        title=title,
        body_html=_render_with_islands(body_md, _render_view).strip(),
        outro_html=_render_with_islands(outro_md, _render_view).strip() if outro_md else "",
        empty_title=empty_title or title,
        empty_html=_render_view(empty_md).strip() if empty_md else "",
        goals=goals,
    )


def _load_site() -> SiteContent:
    """Parse ``site.toml``."""
    raw = _load_toml("site.toml")
    decs = raw.get("decompilers") or {}
    hidden = tuple(decs.get("hidden") or ())
    sample_set_only = tuple(decs.get("sample_set_only") or ())
    return SiteContent(
        brand=Brand(**raw["brand"]),
        footer=Footer(**raw["footer"]),
        sidebar=Sidebar(**raw["sidebar"]),
        banners=dict(raw["banners"]),
        side_stats=dict(raw["side_stats"]),
        hidden_decompilers=hidden,
        sample_set_only_decompilers=sample_set_only,
        pages_domain=str((raw.get("pages") or {}).get("domain") or ""),
    )


@lru_cache(maxsize=1)
def load_content() -> Content:
    """Load and parse the whole ``content/`` directory.

    Cached: the content ships with the package and cannot change at runtime.
    """
    metrics = tuple(
        sorted(
            (MetricSpec(**m) for m in _load_toml("metrics.toml")["metric"]),
            key=lambda m: m.order,
        )
    )
    view_specs = tuple(ViewSpec(**v) for v in _load_toml("views.toml")["view"])
    presets = tuple(DatasetPresetSpec(**p) for p in _load_toml("datasets.toml")["preset"])
    categories = tuple(
        Category(name=c["name"], labels=tuple(c["labels"]))
        for c in _load_toml("categories.toml")["category"]
    )
    decompilers = tuple(
        DecompilerSpec(
            id=d["id"],
            display_name=d["display_name"],
            url=d.get("url", ""),
            license=d.get("license", ""),
            logo=bool(d.get("logo", False)),
            version_overrides=dict(d.get("version_overrides") or {}),
        )
        for d in _load_toml("decompilers.toml")["decompiler"]
    )
    views = {spec.id: _load_view(spec.id, metrics) for spec in view_specs}
    return Content(
        site=_load_site(),
        view_specs=view_specs,
        views=views,
        metrics=metrics,
        dataset_presets=presets,
        categories=categories,
        decompilers=decompilers,
    )
