# The Analyst Console

```bash
sentinelflow serve          # http://127.0.0.1:8000
```

A server-rendered console over the same pipeline as the REST API: same
process, same port, same security headers. Five pages — **Overview**,
**Alerts**, **alert detail**, **Investigations**, **Rules** — built from
Jinja2 templates, one stylesheet and one small script.

## The design idea: strata of trust

The project's central claim is that evidence, deterministic analysis, AI
interpretation and human decision are different kinds of statement and must
never blur. The alert page makes that visible. Every alert is laid out in four
layers, in the order its trust was established:

| Layer | What it holds | How it is marked |
|---|---|---|
| **01 Observed** | The event, verbatim, plus the original record as received | Neutral rail; machine values in monospace |
| **02 Determined** | Severity with its working, the rules that fired and why, ATT&CK mappings with reasons, indicators, next steps | Accent rail — reproducible |
| **03 Suggested** | Optional AI analysis | Hatched rail, dashed border, *"Advisory only. Cannot change anything above."* |
| **04 Decided** | Status, classification, analyst notes | Solid ink rail — the only layer with authority |

With AI disabled (the default) the third layer says so plainly — *"Everything
above is complete without it"* — rather than disappearing, because the
absence is itself the point.

When an AI analysis exists, its severity opinion is shown **beside** the
deterministic verdict under separate labels, never in place of it. A prompt-
injection flag, if the model's input tripped it, is shown above the analysis.

Two typographic voices carry the same distinction: **monospace for machine
evidence** (IPs, hashes, command lines, IDs) and **sans for human language**
(labels, explanations). Nothing is monospaced for decoration.

## Severity that shows its working

The Determined layer draws each alert's score as a track from 0 to 100. Each
positive factor is a segment, left to right in the order the engine produced
it; deductions are drawn back from the positive total in a receding tone; the
band thresholds (30 / 60 / 85) sit outside the bar so a band boundary is never
mistaken for the gap between two factors. The factor table beneath is the
same information as text.

## The Content-Security-Policy shaped everything

The API's middleware sends:

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'
```

No inline script, no inline style, no remote origin of any kind. That is the
backstop for the one threat a SOC console must take seriously: **the data it
displays is written by the attacker.** A hostname of `<script>…` is a perfectly
valid thing for an adversary to put in a log. Jinja2 autoescaping is the first
line of defence; if it were ever bypassed, the policy means an injected script
would still have nowhere to run and nowhere to send anything.

The policy has consequences, and each was designed for rather than worked
around:

* **Charts are server-rendered SVG.** Geometry is computed in
  `app/web/charts.py` and emitted as SVG presentation attributes (`width`,
  `fill`, `d`), which the policy permits — unlike `style=""`, which it blocks.
  Doing the arithmetic in Python also makes it unit-testable.
* **One static script**, `console.js`, for tooltips only. It writes content
  with `textContent` and never parses HTML, because tooltip text can be
  attacker-controlled.
* **System fonts, chosen deliberately.** `font-src 'self'` and the project's
  offline promise rule out webfonts from a CDN. The stacks prefer
  characterful installed faces (Avenir Next; SF Mono or Cascadia Mono).
* **No theme toggle.** Setting a theme before first paint needs inline script;
  without it a toggle flashes. The console follows the operating system's
  preference instead, with both themes designed rather than auto-inverted.

A test audits both the template sources and the rendered HTML of every page
for anything the policy would block, and fails the build if one appears.

## Charts

Every chart follows the house data-visualisation method.

**The trend is an emphasis chart, not a four-colour stack.** A
yellow→orange→red severity stack fails colour-vision checks: medium and high
sat 13.6 apart under normal vision against a floor of 15. The question an
analyst actually asks of the trend is *"when did the serious activity
happen?"*, so high-and-critical carry the accent and everything else recedes.
The pair was validated with the palette validator in both themes: CVD
separation 9.8 (dark) and 20.3 (light) against a target of 8. The first dark
gray tried failed at 4.7 under protanopia — red darkens toward gray for
protanopes — and was lightened until it passed.

Other rules the charts keep:

* columns at most 24px, 4px rounded data-end, square at the baseline, a 2px
  surface gap between stacked segments rather than an outline;
* one direct label, on the peak — never a number on every mark;
* buckets sized so the trend never exceeds 24 columns, and a short burst is
  centred rather than drawn as a wall;
* **a single value is a stat, not a chart.** When every alert is on one host,
  "Where it happened" renders *"9 alerts, all on WIN-LAB-01"* instead of a
  one-bar bar chart;
* every chart has a **table view** (`<details>`, no script needed), so a
  tooltip never gates a value;
* severity is never colour alone — a word and four rank pips whose count
  carries the order with every colour removed. Status uses glyph shapes
  (● ◐ ▲ ○ ✓) for the same reason.

## One set of numbers

`app/services/dashboard.py` computes every figure once. The overview page and
`GET /api/v1/stats` both read from it, so they cannot disagree — before it
existed, the stats endpoint computed its own figures and returned an empty
`top_rules`.

Every figure is scoped to the selected window **on event time**, not on when
the alert row was written. A week-old export imported this afternoon is not
"last 24 hours" activity, and a test holds that line.

## Accessibility

Landmarks and a skip link; `aria-current` on navigation and filters; visible
focus rings; keyboard focus shows the same tooltip as hover; charts carry
`role="img"` with a description plus a table view; reduced-motion users get no
entrance animation; `forced-colors` and print styles keep identity without
hue. The layout reflows to a single column at phone width with no horizontal
page scroll.
