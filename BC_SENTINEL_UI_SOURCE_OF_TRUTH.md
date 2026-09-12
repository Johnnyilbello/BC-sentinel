# BC Sentinel UI Source of Truth

Status: ACTIVE VISUAL CONTRACT
Applies to: Beta6 Home and all future desktop UI milestones unless explicitly superseded by an approved redesign.

## Primary evidence

The complete original product-owner Stitch bundle has been audited file-by-file. The detailed inventory and findings live in `BC_SENTINEL_STITCH_UI_AUDIT.md`.

Primary visual reference for Home: `dashboard_bc_sentinel_v0.1.x`.
Supporting references: scan, quarantine, history, settings, threat-detected and app-icon screens, plus the `Sentinel Elite` and `Brutalist Luxe Command` design documents.

## Visual-language decision

`Sentinel Elite` is the canonical application shell and consumer-security language.

Use it for:
- Dashboard / Home;
- scan surfaces;
- quarantine;
- settings;
- threat overlays;
- ordinary protection cards and controls.

`Brutalist Luxe Command` is a scoped expert/data-density sublanguage for event history, evidence tables, technical logs and other operator-heavy surfaces. Its zero-radius/monospace rules must not replace the Home shell.

## Core identity

- Persistent 260 px desktop sidebar on Home.
- Navigation order: Dashboard, Scansione, Quarantena, Cronologia, Protezione, Impostazioni.
- Compact 56 px application top bar.
- Deep green-charcoal canvas and layered surfaces.
- Emerald `#10b981` is the primary brand/action accent.
- No hacker/neon aesthetic and no arbitrary blue SaaS-dashboard look.
- Tonal layering and subtle 1 px borders provide depth; heavy shadows are avoided.
- Main Home content uses the full available desktop canvas with about 24 px internal margins.
- Do not center the page with equal stretch spacers around the root. That pattern caused the real B6-2 clipping regression.
- Normal Home must not require horizontal scrolling.

## Dashboard composition

Canonical order:

1. fixed sidebar + compact top bar;
2. status hero with Sentinel mark;
3. Quick Scan / Full Scan actions;
4. three KPI cards;
5. one outer `Moduli Protezione` panel;
6. 2 × 2 module cards inside that panel;
7. optional compact recent-activity strip;
8. Advanced details available without dominating the consumer view.

The hero is horizontal on ordinary desktop widths and may reflow vertically only at smaller supported widths.

## Typography

Stitch direction:
- Hanken Grotesk for display/headlines where available;
- Plus Jakarta Sans for body/labels where available;
- technical evidence may use Cascadia Mono / Consolas.

PySide fallback:
`Plus Jakarta Sans` → `Segoe UI Variable Text` → `Segoe UI`.

Desktop hierarchy:
- major headline about 24–32 px;
- module titles 15–18 px;
- body 13–16 px;
- labels 11–13 px.

Body and secondary text must never be shrunk merely to force more content into the viewport.

## Spacing

Canonical Stitch rhythm:
- base: 4 px;
- xs: 4 px;
- sm: 8 px;
- md: 16 px;
- lg: 24 px;
- xl: 32 px;
- xxl: 48 px.

Home canvas margin: about 24 px.

## Shape hierarchy

Home / Sentinel Elite:
- nav and compact buttons: ~8 px radius;
- KPI and inner cards: ~16 px;
- hero and major panels: ~24 px;
- toggles: pill-shaped.

Brutalist zero-radius styling is reserved for dense history/log/evidence views.

## Color semantics

Core Home palette:
- canvas `#0f1412`;
- panel `#1c211f`;
- higher surface `#262b29`;
- border `#3c4a42`;
- primary text `#dde4dd`;
- secondary text `#bbcabf`;
- brand emerald `#10b981`;
- verified secure emerald `#4edea3`.

Semantic use:
- emerald = verified safe state or allowed primary action;
- amber = warning/unverified;
- coral/red = active threat/failure;
- blue = secondary information only.

A brand color must never imply active protection without current runtime evidence.

## Iconography

- Use coherent line icons matching the Stitch/Material-symbol direction.
- Do not use emoji/unicode text glyphs as production navigation icons; Windows fallback fonts make them inconsistent.
- The brand mark is the emerald nested Sentinel shield/S motif. A single-letter placeholder is not the final identity.

## Runtime truth rule

Visual fidelity never overrides security truthfulness.

- Engine/source availability is not proof of active protection.
- `Protected` requires accepted current runtime evidence.
- Unverified state must remain visually distinct from protected state.
- Controls not implemented in the current milestone stay disabled rather than being mocked as functional.
- Rescue/discovery remains explicit and passive at startup.

## Module cards

- One outer modules container, as in the original Dashboard.
- Inner module cards use icon, title, concise description and read-only state indicator/toggle.
- `Dettagli avanzati` remains available on every relevant protection layer.
- Runtime switches become interactive only after their controlling engine contract is implemented and accepted.
- System & Recovery may expose its accepted B6-1 entry action while retaining all B6-1 fail-closed behavior.

## Motion / cinematics

Motion is functional and restrained:
- 140 ms micro-interactions;
- about 200 ms state transitions;
- about 250 ms advanced-panel expansion;
- up to 300 ms page entrance;
- subtle stagger may be used sparingly;
- reduced-motion mode remains supported;
- no decorative looping motion competing with security status.

## Required geometry acceptance

The automated B6-2 gate must verify at 1600 px desktop width that:
- the Home root occupies the expected fluid canvas;
- hero and modules panel do not collapse into a narrow center column;
- 2-column module cards are not clipped;
- KPI cards remain readable;
- horizontal scroll maximum is zero.

Minimum supported desktop width must reflow safely without overflow.

## Anti-regression rules

Do not reintroduce:
- white/light accidental viewports;
- generic white primary buttons unrelated to the Sentinel palette;
- a narrow website-like centered column on desktop;
- equal horizontal stretch siblings around the Home root;
- tiny low-contrast body text;
- unicode/emoji fallback icons in primary navigation;
- inconsistent card radii/spacing;
- positive/green protection status without runtime proof;
- a separate Technician UI as the primary product mode.

The product remains one Home experience with simple information first and complete technical evidence available through Advanced details.
