# Design

<!-- impeccable:design-schema 1 -->

## World

**Mission-control big board**, raised by two donated disciplines: an aviation instrument panel (calm, trustworthy dial readouts standing in for stat cards/progress bars) and an orienteering map's legend-and-route grammar (the Framework Browser: controls are the fixed legend/terrain, a CVE's CWE cross-links are the route drawn over it).

Scene: a security analyst reads this mid-shift or during incident response, often in a dim ops room. Dark is the deliberate choice for that scene, not a category default.

## Palette

Restrained strategy — neutrals plus disciplined accent roles, each meaning one thing only:

- `--ground` `#0a0d10`, `--panel` `#10151a`, `--panel-raised` `#161c22` — near-black layered surfaces
- `--panel-line` `#232b32` / `--panel-line-bright` `#364049` — hairline dividers and borders
- `--ink` `#e8edf1` (primary text), `--ink-dim` `#93a2ad` (secondary), `--ink-faint` `#5c6b75` (tertiary/meta)
- `--nominal` `#4ade80` (green) — healthy/low-severity/CVE-domain tag, used sparingly and consistently
- `--caution` `#f5b942` (amber) — medium severity only
- `--critical` `#f2495c` (red) — critical/high severity only
- `--route` `#b98af0` (purple) — reserved **exclusively** for cross-domain routing (CVE→control links, compliance-domain tag). Never used decoratively.
- `--focus` `#6fd3e0` (cyan) — focus rings only

## Type

- `IBM Plex Sans` — UI body text (Operate mode: workhorse face, not a display statement)
- `IBM Plex Sans Condensed` (600/700) — chrome: nav labels, panel headers, gauge labels, all-caps tracked micro-labels
- `IBM Plex Mono` — earned monospace: CVE IDs, control IDs, timestamps, clock, index counts — actual data/measurement identifiers, not a "technical" costume

## Components

- **Ops rail** (left sidebar): brand mark, live status pill (pulsing dot), nav list, footer. Fixed 232px, collapses off-canvas under 860px with a toggle.
- **Instrument gauges** (dashboard): SVG arc dials with animated stroke-dashoffset fill, not circular progress-ring clichés — proportioned like a six-pack panel, damped-feeling ease curve on load.
- **Transmission log** (query view): each Q&A is a bordered panel with a head (domain tag + timestamp), body, and a foot row for source chips / route chips / hallucination warnings. Replaces generic chat bubbles.
- **Legend table** (framework browser): grid rows styled as a map legend — monospace ID in route-purple, framework name, title + truncated description, CWE chips in dashed outline (evoking notation symbols, not badges).
- **Domain tags**: `cve` = green, `compliance` = purple, `query` = neutral gray. Consistent across transmission log, history rows, and nav active-state.

## Anti-patterns avoided

No colored `border-left` accents (chips/backgrounds carry color instead), no gradient text, no icon-font/emoji (hand-drawn stroke SVG icons only, 1.8px weight, consistent), no kicker/eyebrow labels, no same-size icon+heading+text card grid as page structure.

## Known gaps for a future pass

- Contrast was checked by token relationship (all body text pairs are ink/ink-dim on panel/ground, high-contrast by construction) but not machine-verified — the detector ran degraded (missing HTML/CSS parser modules) and could not compute contrast ratios.
- No dedicated empty/error/loading skeleton states beyond the basic "NO TRANSMISSIONS" / "Transmitting…" text states.
- Mobile layout (rail collapses under 860px) was written but not visually verified on a real narrow viewport — no screenshot capability was available in this session.
