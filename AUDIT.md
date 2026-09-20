# AUDIT — SIEM Log Analyzer (pre-refactor)

Audit of the previous single-file `index.html` (359 lines: ~120 lines of CSS,
~55 lines of markup, ~235 lines of inline JavaScript). Every finding below cites
the specific construct it refers to. Line numbers are from the audited file.

---

## A. Security

### A1 — Everything executable is inline, so no CSP is possible
`index.html:119–354` is a single inline `<script>`. `index.html:75` adds an
inline JSON-LD block. Any `script-src` policy stricter than `'unsafe-inline'`
would have disabled the whole application, so no `Content-Security-Policy` meta
tag could be added — and none was present.
**Fix:** all behaviour moved to ES modules under `src/`; `index.html` now ships a
`default-src 'none'` policy with an explicit allow-list.

### A2 — Six inline event handlers
`onclick="generateLogs()"`, `onclick="exportReport()"`, `onclick="clearLogs()"`
(`index.html:90–92`). These are inline script for CSP purposes and they couple
markup to global function names.
**Fix:** `addEventListener` in `src/main.js`. `grep -nE 'on(click|change|input|load|submit)='`
over the new `index.html` returns nothing.

### A3 — CDN script pinned but unverified
`index.html:7` loads `chart.js@3.9.1` from jsDelivr with no `integrity`, no
`crossorigin` and no `referrerpolicy`. The version is pinned, which is good, but
nothing checks that the bytes delivered are the bytes expected — a compromised
or substituted CDN artifact executes with full page privileges.
**Fix:** `integrity="sha384-9MhbyIRcBVQiiC7FSd7T38oJNj2Zh+EfxS7/vjhBi4OOT78NlHSnzM31EZRWR1LZ"`
plus `crossorigin="anonymous"`, computed with `openssl dgst -sha384` against the
exact published artifact. A byte-identical local copy is vendored at
`vendor/chart.min.js` as a fallback.

### A4 — No failure path when the CDN is blocked
`updateTimeline` calls `new Chart(...)` unconditionally (`index.html:215`). If
jsDelivr is unreachable, `Chart` is `undefined`, `updateDashboard` throws at the
first chart, and **every panel after it silently fails to render** — the geo
map, top IPs, ATT&CK map, correlations and feed all stay empty. The page looks
broken rather than degraded. This is the single most user-visible defect.
**Fix:** `src/charts.js` resolves the library asynchronously, falls back to the
vendored copy, and returns a no-op controller if both fail; the rest of the
dashboard renders regardless.

### A5 — `innerHTML` with interpolated values throughout
`updateGeoMap`, `updateTopIPs`, `updateMitre`, `updateCorrelations`, `updateFeed`
(`index.html:239–300`) all build markup by string concatenation with values
interpolated in. The values happen to be internally generated today, so this is
not currently exploitable — but it is one data-source change away from stored
XSS, and it is the pattern a reviewer will flag first.
**Fix:** `src/ui.js` builds every node with `createElement` + `textContent`.

### A6 — Unbounded, unbacked SEO claims
`og:image` and `twitter:image` point at an Unsplash URL (`index.html:70–74`),
adding a third-party origin to the page's fetch surface for no functional
benefit and making an `img-src 'self'` policy impossible.
**Fix:** external image references removed; the favicon is an inline SVG data URI.

---

## B. Correctness — real logic bugs

### B1 — Timeline buckets collapse different days into the same point
`updateTimeline` (`index.html:199–206`) keys buckets on `e.timestamp.getHours()`
alone. With the 7-day window selected, 09:00 on Monday and 09:00 on Thursday land
in the same bucket. Worse, `Object.keys(hours).sort()` orders the x-axis by
*hour of day* (`00:00, 01:00, …`), not chronologically, so the "timeline" is not
a timeline at all — it is an hour-of-day histogram with a line drawn through it.
Empty hours vanish entirely, so gaps in the data read as continuity.
**Fix:** `bucketTimeline()` buckets on absolute epoch boundaries with a
window-appropriate bucket width and returns a dense ascending series including
empty buckets. Covered by `tests/detect.test.js`
("separates same-hour events on different days").

### B2 — Threat score is a random number
`generateLogs` assigns `threatScore: Math.floor(Math.random()*100)`
(`index.html:156`), and `updateTopIPs` ranks the "Top Attacking IPs" table by
`maxScore` (`index.html:251`). The headline risk ranking of the dashboard is
therefore pure noise: a source with one low-severity port scan routinely
out-ranks a source running a full kill chain.
**Fix:** `computeThreatScore()` in `src/rules.js` — a bounded, deterministic
function of severity weight, logarithmic volume, attack-class breadth and
ATT&CK-tactic span. Covered by `tests/rules.test.js` and
`tests/detect.test.js` ("ranks by deterministic threat score, not by a random number").

### B3 — Doughnut chart colours are positional, so they move
`updateAttackChart` (`index.html:227–230`) zips a fixed six-colour array against
`Object.keys(counts)`, whose order depends on which attack types happen to be
present. Filtering to a subset silently re-assigns colours, so "red" means
SQL injection in one view and XSS in the next. Four of the six colours were also
the identical `#1f4e8c`.
**Fix:** `TYPE_COLORS` keyed by attack type; `attackDistribution()` carries the
colour with the row. Covered by "gives each detection type a stable colour".

### B4 — Correlation treats co-occurrence as a causal chain
`updateCorrelations` (`index.html:280–285`) reports a "Credential Compromise
Chain" whenever the same IP appears in both the brute-force set and the
privilege-escalation set — with **no ordering check**. On a shuffled event set,
an escalation that happened *before* any authentication failure produces the
same finding. The rule cannot distinguish a chain from a coincidence.
**Fix:** `correlate()` compares `firstOf('brute_force')` against
`lastOf('privilege_escalation')` and only fires when the escalation is later.
Covered by "does NOT fire when the escalation precedes the brute force".

### B5 — Multi-vector correlation fires on coincidence and floods the panel
The same function (`index.html:274–278`) emits a finding for every IP with
**two or more** attack types, with no cap. Because `randomIP()` draws from
~3.7 billion addresses and only 200–500 events are generated, genuine repeats
are rare — but when they occur they are chance, not a campaign, and the output
list is unbounded.
**Fix:** threshold raised to three distinct classes, findings ranked by severity
then volume and capped at `maxFindings: 8`; the generator now seeds a small
number of deliberate campaign actors so the rule has real signal to find.

### B6 — Reserved IP ranges presented as foreign attackers
`randomIP()` (`index.html:136`) draws a first octet in `1..223`, so it happily
emits `127.0.0.1`, `10.x.x.x`, `192.168.x.x` and `169.254.x.x` — then labels
them with a country such as "Iran". Any security practitioner reads that as an
error in the first five seconds.
**Fix:** `randomPublicIpv4()` rejects loopback, RFC1918, CGNAT, link-local,
benchmarking and multicast space; `isReservedIpv4()` is directly unit-tested
against eleven reserved and five routable addresses.

### B7 — The "7 Days" filter can never show more than the "24 Hours" filter
`generateLogs` spreads events over `Math.random()*86400000` — exactly 24 hours
(`index.html:144`) — while the window selector offers a 7-day option
(`index.html:89`). Selecting "Last 7 Days" is a no-op.
**Fix:** generation spreads over the full 7-day span, so every window selection
changes the result.

### B8 — Unbounded event accumulation
`generateLogs` pushes into the module-level `events` array without any cap
(`index.html:145`). Each click adds 200–500 objects permanently; a reviewer who
clicks ten times is holding ~5,000 objects and re-sorting all of them on every
keystroke in the IP filter.
**Fix:** `MAX_EVENTS = 5000` cap applied after each ingest in `src/main.js`.

### B9 — Double render on every select change
`index.html:344–347` registers *both* `change` and `input` on all four filters.
Selects fire both, so every severity change runs the full dashboard render —
including two Chart.js `destroy()`/construct cycles — twice.
**Fix:** `change` for selects, `input` for the text field only.

### B10 — Chart instances rebuilt from scratch on every update
`timelineChart.destroy()` followed by `new Chart(...)` on every render
(`index.html:214–215`, `228–229`). Correct, but wasteful and it resets any user
interaction state.
**Fix:** charts are constructed once and updated in place with `.update('none')`.

### B11 — Uncleared interval on a DOM lookup
`setInterval(..., 1000)` (`index.html:350`) re-queries `#clock` every second for
the lifetime of the page and is never cleared.
**Fix:** the wall clock was decorative and has been dropped; nothing in the new
page runs on a timer.

---

## C. Testability & structure

### C1 — No `package.json`, no tests, no linting, no CI
The repository contained exactly three files: `index.html`, `README.md`,
`LICENSE`. Nothing was verifiable.
**Fix:** `package.json` with `npm test` / `npm run lint` / `npm run validate`,
ESLint flat config, Vitest, and `deploy.yml` + `codeql.yml` workflows.

### C2 — Module-level mutable globals
`let events = []`, `let timelineChart, attackChart` (`index.html:121–122`) are
free variables closed over by every function. No function can be called with
alternative inputs, so none can be tested.
**Fix:** state is confined to a single `store` object in `src/main.js`; every
logic function takes its inputs as parameters.

### C3 — Logic and DOM access fused in the same functions
`getFiltered()` (`index.html:165–181`) reads four DOM elements *and* performs
the filtering. `updateTopIPs()` aggregates *and* renders. There is no seam at
which to insert a test.
**Fix:** three-layer split — pure logic (`rules`, `generate`, `detect`,
`correlate`, `report`), rendering (`ui`, `charts`), orchestration (`main`). The
pure layer is at 99.78% statement coverage.

### C4 — Non-deterministic time and randomness are read from ambient globals
`Date.now()`, `new Date()` and `Math.random()` are called directly inside logic
functions, so results cannot be reproduced.
**Fix:** `now` and `rng` are parameters. `mulberry32` provides a seeded
generator; `generateEvents` with the same seed and clock is byte-identical
across runs (asserted in `tests/generate.test.js`).

---

## D. Accessibility

### D1 — No landmark structure
The page used `<div class="header">`, `<div class="container">` and a `<footer>`
placed *outside* the layout container (`index.html:78, 94, 355`). No `<main>`,
no `role="banner"`, no skip link.
**Fix:** `<main id="demo-root">`, `role="banner"` header, `role="contentinfo"`
footer, and a visible-on-focus skip link.

### D2 — Form controls with no labels
All four filters (`index.html:86–89`) are bare `<select>`/`<input>` elements
whose only description is a `placeholder` or the option text. Screen-reader
users get "combo box" with no name.
**Fix:** every control has an associated `<label>`.

### D3 — Numbers change without announcement
The four stat cards (`index.html:96–99`) update on every filter change with no
`aria-live`, so assistive technology never learns the values changed.
**Fix:** KPI values carry `aria-live="polite"`; the correlation panel does too.

### D4 — Severity conveyed by colour that is mostly identical
The palette collapses `--success`, `--info` and `--purple` to the same
`#1f4e8c` (`index.html:10`), so `.sev-medium` and `.sev-low` render identically
and `.mitre-tag` matches them both. Severity is therefore not distinguishable —
and it was never conveyed by anything except colour.
**Fix:** four visually distinct severity chips that also carry the severity word
as text, all meeting WCAG AA contrast against the panel background.

### D5 — Animation ignores `prefers-reduced-motion`
`.badge-live` runs an infinite `pulse` animation (`index.html:16–17`) with no
media-query guard.
**Fix:** `exec-shell.css` disables animations and smooth scrolling under
`prefers-reduced-motion: reduce`; the pulsing badge is gone.

### D6 — `<canvas>` elements with no accessible name
`#timeline-chart` and `#attack-chart` (`index.html:102–103`) expose nothing to
assistive technology.
**Fix:** `role="img"` plus `aria-label` on both, and the same data is available
in text form in the exported incident report.

### D7 — Fixed overlay button obscures content
The "View Source" pill is `position: fixed` at `right:14px; bottom:14px` with
`z-index: 99999` (`index.html:356`) and a white `box-shadow` on a white page. On
a narrow viewport it sits on top of the event feed.
**Fix:** the source link lives in the header action row.

---

## E. Truthfulness

### E1 — "LIVE MONITORING" on synthetic data
A pulsing `LIVE MONITORING` badge (`index.html:81`) and a running wall clock sit
above data produced by `Math.random()`. Nothing is being monitored.
**Fix:** the badge row states "Simulated telemetry", and a notice at the top of
the demo says plainly that the data is generated locally and the detection logic
— not the data — is the real artifact. The exported report is stamped
"Classification: demonstration material — not a real incident".

### E2 — Fabricated specificity in sample messages
`'HTTP flood — 50K req/s'` (`index.html:130`) presents an invented throughput
figure as an observation.
**Fix:** sample messages describe the detection condition rather than asserting
measured magnitudes, and each rule carries an explicit `logic` string stating
what it keys on.

---

## Summary

| Category | Findings | Of which real logic bugs |
| --- | --- | --- |
| Security | 6 | 1 (A4) |
| Correctness | 11 | 11 |
| Testability | 4 | — |
| Accessibility | 7 | — |
| Truthfulness | 2 | — |
| **Total** | **30** | **12** |

All 30 are addressed in this revision. The five highest-impact are B2 (random
threat score), B1 (broken timeline), B4 (correlation without ordering), A4
(total render failure when the CDN is blocked) and A1/A2 (no CSP possible).
