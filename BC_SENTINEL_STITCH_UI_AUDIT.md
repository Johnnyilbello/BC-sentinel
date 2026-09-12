# BC Sentinel Stitch UI Audit

Status: COMPLETED
Scope: complete product-owner Stitch bundle `stitch_bc_sentinel_antivirus_ui.zip`
Files reviewed: 15/15

## Inventory reviewed

1. `bc_sentinel_app_icon/screen.png`
2. `dashboard_bc_sentinel_v0.1.x/code.html`
3. `dashboard_bc_sentinel_v0.1.x/screen.png`
4. `scansione_bc_sentinel_v0.1.x/code.html`
5. `scansione_bc_sentinel_v0.1.x/screen.png`
6. `quarantena_bc_sentinel_v0.1.x/code.html`
7. `quarantena_bc_sentinel_v0.1.x/screen.png`
8. `cronologia_bc_sentinel_v0.1.x/code.html`
9. `cronologia_bc_sentinel_v0.1.x/screen.png`
10. `impostazioni_bc_sentinel_v0.1.x/code.html`
11. `impostazioni_bc_sentinel_v0.1.x/screen.png`
12. `minaccia_rilevata_bc_sentinel_v0.1.x/code.html`
13. `minaccia_rilevata_bc_sentinel_v0.1.x/screen.png`
14. `sentinel_elite/DESIGN.md`
15. `brutalist_luxe_command/DESIGN.md`

## Canonical conclusion

The bundle contains two related visual systems, not one contradictory global system.

### Sentinel Elite — canonical application shell and consumer security surfaces

Use Sentinel Elite for:
- Dashboard / Home
- Scan progress
- Quarantine
- Settings
- Threat detected overlay
- protection/settings cards and primary interaction surfaces

Its consistent traits are:
- deep green-charcoal surfaces;
- emerald `#10b981` as the brand/action accent;
- fixed 240–260 px left navigation;
- compact 48–56 px top application bar;
- 24 px main canvas margin;
- 4 px base / 8 px rhythm;
- rounded 8 / 16 / 24 px structural hierarchy;
- Plus Jakarta Sans body direction and Hanken Grotesk headline direction where available;
- tonal layering and 1 px borders rather than heavy shadows;
- pill/Windows-style toggles;
- calm enterprise-security presentation.

### Brutalist Luxe Command — data-density sublanguage only

The `brutalist_luxe_command/DESIGN.md` and the Cronologia screen introduce a sharper,
denser command-center language. This is appropriate for:
- event history;
- evidence tables;
- technical logs;
- high-density expert data views.

It is **not** the global shell and must not replace Sentinel Elite on the Home.
Its zero-radius/monospace rules are scoped to dense technical surfaces.

## Global shell extracted from all screens

- Left sidebar remains persistent on desktop.
- Navigation order is fixed:
  Dashboard → Scansione → Quarantena → Cronologia → Protezione → Impostazioni.
- Sidebar width is 240 px in most screens and 260 px in the original Dashboard; Home uses 260 px.
- Top bar is compact and visually belongs to a desktop application, not a website.
- Main content starts immediately after the sidebar and uses about 24 px internal margin.
- Content is fluid across the available application canvas. Do not place equal stretch spacers
  around the page root: this caused the B6-2 one-third-width clipping regression.
- Horizontal scrolling is not acceptable in the normal desktop Home.
- Native title-bar controls are handled by the real Windows window; do not fake duplicate controls
  inside the PySide application shell.

## Dashboard composition extracted from `dashboard_*`

Canonical Home order:
1. status hero;
2. quick/full scan actions;
3. three KPI cards;
4. one outer protection-modules panel;
5. 2 × 2 protection module cards inside that panel;
6. optional compact recent-activity strip below.

The hero is horizontal at normal desktop width:
- ~80 px Sentinel mark at left;
- concise protection headline/copy in the center;
- scan actions at right.

At smaller supported widths it may reflow vertically, but it must never compress the content into
a narrow center column.

## Typography

Stitch sources define:
- headline sizes roughly 24–32 px on desktop;
- body 14–16 px;
- labels 11–13 px;
- technical evidence/logs may use a monospaced font.

PySide production fallback:
`Plus Jakarta Sans` → `Segoe UI Variable Text` → `Segoe UI`.
Do not shrink body text to 10–11 px simply to fit more content.

## Color contract

Core:
- canvas `#0f1412` / nearby `#0e1511`;
- panel `#1c211f` / `#1a211d`;
- higher surface `#262b29`;
- border `#3c4a42`;
- primary text `#dde4dd`;
- secondary text `#bbcabf`;
- emerald `#10b981`;
- bright secure emerald `#4edea3`.

Semantic:
- emerald = verified safe state / primary allowed action;
- amber = warning or unverified;
- coral/red = active threat/failure;
- blue = secondary informational/neutral technical accent only.

Runtime truth has priority over reference screenshots. A green secure state is forbidden without
accepted runtime evidence.

## Shape hierarchy

For the canonical Home:
- nav/buttons: ~8 px radius;
- KPI / inner cards: ~16 px;
- hero / major panels: ~24 px;
- toggles: pill-shaped.

The zero-radius Brutalist rule is reserved for dense log/history surfaces.

## Motion / cinematics

Derived from the bundle and Beta6 contract:
- 140 ms micro feedback;
- 180–220 ms state transitions;
- ~250 ms details expansion;
- <=300 ms page entrance;
- optional subtle stagger on first render;
- no decorative looping animations;
- reduced-motion mode remains mandatory.

## Findings from each screen

### Dashboard
Primary visual source for Home. It defines the 260 px sidebar, 56 px top bar, hero/KPI/modules
hierarchy, rounded panels, emerald CTA and 2 × 2 module grid.

### Scan
Confirms a centered high-priority task panel, clear progress hierarchy, status dot, elapsed time,
file path evidence and single destructive/cancel action. Scan pages should reduce peripheral noise.

### Quarantine
Confirms dense but readable management tables, search/filter row, semantic risk chips and pagination.
Danger actions remain contextual rather than dominating the page.

### History
Confirms the command-center variant: denser table, score/level/status columns and stronger grid lines.
This is where the Brutalist-Luxe sublanguage is appropriate.

### Settings
Confirms 12-column style composition with a large protection panel and narrower general/folder/
allowlist column. Toggles are Windows-style pills with strong label/description hierarchy.

### Threat detected
Confirms critical overlays should use a blurred/dimmed background, compact centered modal,
coral/red semantic accent, clear evidence fields and one primary containment action.

### App icon
Confirms the brand mark is an emerald nested Sentinel shield/S motif on a deep charcoal field.
Temporary single-letter logo blocks are not acceptable as the long-term visual identity.

## B6-2 regression found from the real Windows screenshot

The Home root was placed in a horizontal layout as:
`stretch(1) + root(1) + stretch(1)`.

Those equal stretch factors divided the page into thirds. The root therefore received roughly one
third of the main canvas, causing:
- clipped hero copy;
- clipped KPI cards;
- module cards cut off at both sides;
- large unused dark areas;
- apparent typography/layout corruption.

The corrected architecture is:
- one fluid page host;
- 24 px margins;
- root widget expands to the viewport width;
- no equal horizontal stretch siblings;
- horizontal scrollbar forced off;
- geometry acceptance at 1600 px and at the minimum supported desktop size.

## Acceptance requirements added

B6-2 must now fail if:
- the 1600 px Home content root is narrower than the expected desktop canvas;
- the hero or module panel collapses into a narrow center column;
- a horizontal scrollbar appears;
- 2-column module cards are clipped;
- sidebar width/order changes unexpectedly;
- Stitch color/spacing tokens drift;
- unicode/emoji fallback icons replace the native line-icon treatment;
- green protected posture appears without runtime verification.
