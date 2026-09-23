"""Chart geometry, computed in Python and rendered as SVG by the templates.

Why here rather than in JavaScript or in Jinja: the Content-Security-Policy
forbids inline scripts and inline styles, so every chart must arrive as static
markup whose sizes are SVG presentation attributes (``width``, ``height``,
``fill``) - which the policy permits - rather than ``style=""`` attributes,
which it blocks. Doing the arithmetic in plain functions also makes it testable:
a bar that is 3px too tall is a unit-test failure, not a screenshot argument.

The mark specifications follow the house data-visualisation rules:

* columns at most 24px wide, 4px rounded data-end, square at the baseline;
* a 2px surface-coloured gap between touching segments rather than a stroke;
* one direct label (the peak), never a number on every mark;
* every chart has a table-view twin in the template, so nothing is readable
  only by hovering.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.models.alert import AlertSeverity
from app.models.enums import Severity

#: Data-end radius and the gap between touching fills, in px.
RADIUS = 4
GAP = 2
MAX_COLUMN_WIDTH = 24

#: Bucket widths the trend may use, smallest first. The first one that yields
#: no more than ``MAX_BUCKETS`` columns wins.
BUCKET_STEPS = (
    timedelta(minutes=1),
    timedelta(minutes=2),
    timedelta(minutes=5),
    timedelta(minutes=10),
    timedelta(minutes=15),
    timedelta(minutes=30),
    timedelta(hours=1),
    timedelta(hours=2),
    timedelta(hours=3),
    timedelta(hours=6),
    timedelta(hours=12),
    timedelta(days=1),
    timedelta(days=2),
    timedelta(days=7),
)
MAX_BUCKETS = 24
MIN_BUCKETS = 6

#: The emphasis split. The story an analyst wants from a trend is "when did the
#: serious activity happen", so high and critical carry the accent and the rest
#: recede - two series, not four hues that colour-blind readers cannot separate.
EMPHASIS = frozenset({Severity.HIGH, Severity.CRITICAL})


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
def _fmt(value: float) -> str:
    """Compact coordinate formatting for path data."""
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return text or "0"


def column_path(x: float, y: float, width: float, height: float, *, rounded: bool) -> str:
    """A column whose top corners are rounded and whose base is square."""
    if height <= 0 or width <= 0:
        return ""
    r = min(RADIUS, width / 2, height) if rounded else 0
    if r <= 0:
        return f"M{_fmt(x)},{_fmt(y + height)}V{_fmt(y)}H{_fmt(x + width)}V{_fmt(y + height)}Z"
    return (
        f"M{_fmt(x)},{_fmt(y + height)}"
        f"V{_fmt(y + r)}"
        f"A{_fmt(r)},{_fmt(r)} 0 0 1 {_fmt(x + r)},{_fmt(y)}"
        f"H{_fmt(x + width - r)}"
        f"A{_fmt(r)},{_fmt(r)} 0 0 1 {_fmt(x + width)},{_fmt(y + r)}"
        f"V{_fmt(y + height)}Z"
    )


def bar_path(x: float, y: float, width: float, height: float, *, rounded: bool) -> str:
    """A horizontal bar whose right end is rounded and whose left end is square."""
    if height <= 0 or width <= 0:
        return ""
    r = min(RADIUS, height / 2, width) if rounded else 0
    if r <= 0:
        return f"M{_fmt(x)},{_fmt(y)}H{_fmt(x + width)}V{_fmt(y + height)}H{_fmt(x)}Z"
    return (
        f"M{_fmt(x)},{_fmt(y)}"
        f"H{_fmt(x + width - r)}"
        f"A{_fmt(r)},{_fmt(r)} 0 0 1 {_fmt(x + width)},{_fmt(y + r)}"
        f"V{_fmt(y + height - r)}"
        f"A{_fmt(r)},{_fmt(r)} 0 0 1 {_fmt(x + width - r)},{_fmt(y + height)}"
        f"H{_fmt(x)}Z"
    )


# ---------------------------------------------------------------------------
# Ranked bar list (top hosts, top rules)
# ---------------------------------------------------------------------------
@dataclass
class BarRow:
    label: str
    value: int
    #: Share of the largest value, 0-100, for the SVG ``width`` attribute.
    percent: float
    sublabel: str | None = None
    href: str | None = None


def bar_list(items: Sequence[tuple[Any, ...]]) -> list[BarRow]:
    """Rows scaled against the largest value, which fills the track.

    Scaling to the maximum rather than to the total is deliberate: this is a
    ranking, and the reader's question is "how does each compare to the top
    one", not "what share of everything is this".
    """
    rows: list[BarRow] = []
    peak = max((int(item[1]) for item in items), default=0)
    for item in items:
        label, value = str(item[0]), int(item[1])
        # Optional third and fourth fields: a sublabel and a link.
        sublabel = str(item[2]) if len(item) > 2 and item[2] is not None else None
        href = str(item[3]) if len(item) > 3 and item[3] is not None else None
        percent = (value / peak * 100) if peak else 0.0
        rows.append(
            BarRow(
                label=label,
                value=value,
                # A non-zero value never renders as a zero-width bar.
                percent=round(max(percent, 1.5) if value else 0.0, 2),
                sublabel=sublabel,
                href=href,
            )
        )
    return rows


# ---------------------------------------------------------------------------
# Alert trend: stacked columns, emphasis split
# ---------------------------------------------------------------------------
@dataclass
class Segment:
    series: str
    value: int
    path: str


@dataclass
class Column:
    index: int
    x: float
    width: float
    slot_x: float
    slot_width: float
    start: datetime
    end: datetime
    emphasis: int
    other: int
    segments: list[Segment] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.emphasis + self.other


@dataclass
class TrendChart:
    width: int
    height: int
    plot_left: float
    plot_top: float
    plot_width: float
    plot_height: float
    step: timedelta
    columns: list[Column] = field(default_factory=list)
    y_ticks: list[tuple[float, int]] = field(default_factory=list)
    x_labels: list[tuple[float, str]] = field(default_factory=list)
    peak: Column | None = None
    peak_label_y: float = 0.0

    @property
    def baseline(self) -> float:
        return self.plot_top + self.plot_height

    @property
    def is_empty(self) -> bool:
        return not any(column.total for column in self.columns)

    @property
    def step_label(self) -> str:
        minutes = int(self.step.total_seconds() // 60)
        if minutes < 60:
            return f"{minutes}-minute"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}-hour"
        return f"{hours // 24}-day"


def _floor(moment: datetime, step: timedelta) -> datetime:
    epoch = datetime(2000, 1, 1, tzinfo=UTC)
    seconds = step.total_seconds()
    offset = (moment - epoch).total_seconds()
    return epoch + timedelta(seconds=math.floor(offset / seconds) * seconds)


def choose_step(span: timedelta) -> timedelta:
    """The smallest bucket width that keeps the column count readable."""
    for step in BUCKET_STEPS:
        if span / step <= MAX_BUCKETS:
            return step
    return BUCKET_STEPS[-1]


def nice_ceiling(value: int) -> int:
    """Round an axis maximum up to 1, 2 or 5 times a power of ten."""
    if value <= 1:
        return 1
    magnitude = 10 ** math.floor(math.log10(value))
    for factor in (1, 2, 5, 10):
        if value <= factor * magnitude:
            return factor * magnitude
    return 10 * magnitude


def trend_chart(
    points: Sequence[tuple[datetime, Severity]],
    *,
    width: int = 720,
    height: int = 240,
) -> TrendChart:
    """Bucket alert times into columns, split into emphasis and the rest."""
    left, right, top, bottom = 36.0, 12.0, 22.0, 30.0
    plot_width = width - left - right
    plot_height = height - top - bottom

    chart = TrendChart(
        width=width,
        height=height,
        plot_left=left,
        plot_top=top,
        plot_width=plot_width,
        plot_height=plot_height,
        step=timedelta(hours=1),
    )
    if not points:
        return chart

    first = min(moment for moment, _ in points)
    last = max(moment for moment, _ in points)
    step = choose_step(max(last - first, timedelta(minutes=1)))
    start = _floor(first, step)
    count = max(math.ceil((last - start) / step) + 1, 1)
    if count < MIN_BUCKETS:
        # Centre a short burst so it reads as a burst, not as a wall.
        pad = (MIN_BUCKETS - count) // 2
        start -= step * pad
        count = MIN_BUCKETS
    chart.step = step

    emphasis = [0] * count
    other = [0] * count
    for moment, level in points:
        index = min(int((moment - start) / step), count - 1)
        if level in EMPHASIS:
            emphasis[index] += 1
        else:
            other[index] += 1

    ceiling = nice_ceiling(max(e + o for e, o in zip(emphasis, other, strict=True)))
    scale = plot_height / ceiling
    slot = plot_width / count
    bar = min(MAX_COLUMN_WIDTH, slot * 0.62)

    for index in range(count):
        slot_x = left + index * slot
        x = slot_x + (slot - bar) / 2
        column = Column(
            index=index,
            x=round(x, 2),
            width=round(bar, 2),
            slot_x=round(slot_x, 2),
            slot_width=round(slot, 2),
            start=start + step * index,
            end=start + step * (index + 1),
            emphasis=emphasis[index],
            other=other[index],
        )
        # Emphasis sits on the baseline, where columns are easiest to compare.
        y = top + plot_height
        stack = [("emphasis", emphasis[index]), ("other", other[index])]
        visible = [(name, value) for name, value in stack if value]
        for position, (name, value) in enumerate(visible):
            segment_height = value * scale
            y -= segment_height
            if position == len(visible) - 1:
                # The top of the stack is the data-end: rounded, full height.
                path = column_path(x, y, bar, segment_height, rounded=True)
            else:
                # A lower segment gives up its top 2px as the surface gap to
                # the segment above, so the column's total height stays true.
                path = column_path(x, y + GAP, bar, max(segment_height - GAP, 1), rounded=False)
            column.segments.append(Segment(series=name, value=value, path=path))
        chart.columns.append(column)

    # Integer ticks only: these are counts of alerts.
    tick_step = max(ceiling // 4, 1) if ceiling >= 4 else 1
    chart.y_ticks = [
        (round(top + plot_height - value * scale, 2), value)
        for value in range(0, ceiling + 1, tick_step)
    ]

    label_every = max(1, math.ceil(count / 6))
    time_format = "%H:%M" if step < timedelta(days=1) else "%d %b"
    chart.x_labels = [
        (round(column.slot_x + column.slot_width / 2, 2), column.start.strftime(time_format))
        for column in chart.columns
        if column.index % label_every == 0
    ]

    chart.peak = max(chart.columns, key=lambda c: (c.total, -c.index))
    if chart.peak.total == 0:
        chart.peak = None
    else:
        chart.peak_label_y = round(top + plot_height - chart.peak.total * scale - 7, 2)
    return chart


# ---------------------------------------------------------------------------
# Severity track: how a score was built
# ---------------------------------------------------------------------------
@dataclass
class TrackSegment:
    name: str
    points: int
    detail: str
    x: float
    width: float
    path: str


@dataclass
class SeverityTrack:
    width: int
    height: int
    track_x: float
    track_y: float
    track_width: float
    track_height: float
    level: Severity
    score: int
    score_x: float
    positive: list[TrackSegment] = field(default_factory=list)
    deductions: list[TrackSegment] = field(default_factory=list)
    bands: list[tuple[float, float, str]] = field(default_factory=list)
    band_edges: list[float] = field(default_factory=list)
    clamped: bool = False


#: Score thresholds, matching Severity.from_score.
BAND_EDGES = ((0, 30, "low"), (30, 60, "medium"), (60, 85, "high"), (85, 100, "critical"))


def severity_track(verdict: AlertSeverity, *, width: int = 640, height: int = 64) -> SeverityTrack:
    """Lay out a verdict's factors along a 0-100 track.

    Positive factors stack left to right in the order the engine produced
    them, so the track reads as the explanation reads. Deductions are drawn
    back from the positive total to the final score in a receding tone. When
    the sum ran past 100 the overflow is marked as clamped rather than hidden.
    """
    left, right = 8.0, 8.0
    track_y, track_height = 26.0, 16.0
    track_width = width - left - right
    unit = track_width / 100

    track = SeverityTrack(
        width=width,
        height=height,
        track_x=left,
        track_y=track_y,
        track_width=track_width,
        track_height=track_height,
        level=verdict.level,
        score=verdict.score,
        score_x=round(left + verdict.score * unit, 2),
    )
    track.bands = [
        (round(left + low * unit, 2), round((high - low) * unit, 2), label)
        for low, high, label in BAND_EDGES
    ]
    track.band_edges = [round(left + edge * unit, 2) for edge in (30, 60, 85)]

    positives = [f for f in verdict.factors if f.points > 0]
    negatives = [f for f in verdict.factors if f.points < 0]
    raw_total = sum(f.points for f in positives)
    track.clamped = raw_total > 100 or raw_total + sum(f.points for f in negatives) < 0

    cursor = 0
    for position, factor in enumerate(positives):
        begin = min(cursor, 100)
        end = min(cursor + factor.points, 100)
        cursor += factor.points
        if end <= begin:
            continue
        x = left + begin * unit
        span = (end - begin) * unit
        is_last = position == len(positives) - 1 or end >= 100
        drawn = span if is_last else max(span - GAP, 1)
        track.positive.append(
            TrackSegment(
                name=factor.name,
                points=factor.points,
                detail=factor.detail,
                x=round(x, 2),
                width=round(drawn, 2),
                path=bar_path(x, track_y, drawn, track_height, rounded=is_last),
            )
        )

    # Deductions run backwards from the (capped) positive total.
    cursor = min(raw_total, 100)
    for factor in negatives:
        begin = max(cursor + factor.points, 0)
        end = cursor
        cursor = begin
        if end <= begin:
            continue
        x = left + begin * unit
        span = (end - begin) * unit
        track.deductions.append(
            TrackSegment(
                name=factor.name,
                points=factor.points,
                detail=factor.detail,
                x=round(x, 2),
                width=round(span, 2),
                path=bar_path(x, track_y, span, track_height, rounded=False),
            )
        )
    return track
