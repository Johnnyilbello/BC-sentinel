# BC Sentinel UI Source of Truth

Status: **ACTIVE VISUAL CONTRACT**  
Applies to: Beta6 Home and all future desktop UI milestones unless explicitly superseded by an approved redesign.

## Primary rule

**The current accepted Dashboard is the visual source of truth for the entire product.**

Secondary pages must feel like extensions of the Dashboard, not independently designed templates. The Dashboard must not be redesigned without a functional or responsive necessity.

The original product-owner Stitch bundle remains supporting design evidence and historical reference. Its detailed inventory lives in `BC_SENTINEL_STITCH_UI_AUDIT.md`, but it no longer overrides the visual decisions already consolidated in the current Dashboard.

Practical rule:

```text
Current Dashboard -> primary visual contract
Current BC Sentinel runtime/model -> functional/security truth
Stitch bundle -> supporting visual evidence
```

## Unified product language

Use the Dashboard language for:
- Dashboard / Home;
- Scansione;
- Quarantena;
- Cronologia;
- Protezione;
- Impostazioni;
- threat overlays;
- System & Recovery where it is exposed from Home.

Dense History/evidence/log surfaces may use monospace typography and a slightly more technical density, but they must retain the same app background, semantic colors, borders, spacing system and shell.

There is one application shell, not a Dashboard template plus a separate internal-page template.

## Core identity

- persistent 260 px desktop sidebar, compacting intentionally at narrower widths;
- navigation order: Dashboard, Scansione, Quarantena, Cronologia, Protezione, Impostazioni;
- compact application top bar;
- deep green-charcoal app background with layered dark surfaces;
- emerald `#10b981` as brand/action accent;
- no accidental white/light surfaces;
- no hacker/neon aesthetic and no generic blue SaaS-dashboard language;
- subtle borders and tonal layering instead of heavy shadows;
- full available desktop canvas with coherent gutters;
- no horizontal scrolling in normal Home or secondary pages.

## Dashboard preservation rule

Canonical Dashboard composition remains:

1. sidebar + compact top bar;
2. status hero with Sentinel mark;
3. Quick Scan / Full Scan actions;
4. three KPI cards;
5. `Moduli Protezione` outer panel;
6. 2 × 2 module cards on wide desktop;
7. compact recent-activity strip;
8. Advanced details available without dominating the consumer view.

Allowed Dashboard changes are limited to:
- extracting or reusing shared components;
- centralizing design tokens;
- fixing responsive/overflow defects;
- correcting technical inconsistencies required for global coherence.

Do not restyle it merely to make it different.

## Semantic design tokens

Canonical token ownership lives in `sentinel/ui_design_system.py`.

### Surfaces

- `bg_app`: `#0f1412`
- `bg_sidebar`: `#1c211f`
- `bg_header`: `#0f1412`
- `surface_1`: `#1c211f`
- `surface_2`: `#262b29`
- `surface_3`: `#313634`
- `surface_nested`: `#131916`
- `surface_lowest`: `#0a0f0d`
- `border_subtle`: `#314038`
- `border_strong`: `#46564d`

### Text

- `text_primary`: `#edf2ee`
- `text_secondary`: `#c6d2ca`
- `text_muted`: `#9aa89f`

Secondary/muted text must remain readable on the Dashboard-derived dark surfaces. Automated contrast checks protect the normal text roles at WCAG-AA-level contrast where applicable.

### Semantic colors

- accent: `#10b981`
- verified success: `#4edea3`
- warning/unverified: `#f0b766`
- critical/failure: `#ff8b82`
- secondary information: `#adc6ff`
- keyboard focus: `#6ffbbe`

Warning and critical colors are state semantics, never decoration. A green/accent state must never imply active protection without accepted runtime evidence.

## Typography

Application fallback:

`Plus Jakarta Sans` -> `Segoe UI Variable Text` -> `Segoe UI`

Technical evidence may use `Cascadia Mono` / `Consolas`.

Central roles:
- caption: 11 px;
- body/bodyStrong: 13 px;
- subtitle: 14 px;
- section title: 18 px;
- page title: 30 px;
- metric: 24 px.

Body and secondary copy must never be made tiny or low-contrast simply to fit more content.

## Spacing and shape

Canonical spacing rhythm:
- xs: 4 px;
- sm: 8 px;
- md: 16 px;
- lg: 24 px;
- xl: 32 px;
- xxl: 48 px.

Shape hierarchy:
- controls/navigation: ~8 px radius;
- cards/secondary panels: ~12–16 px;
- hero/major panels: ~24 px;
- toggles/pills: pill-shaped.

All pages share the same horizontal origin, gutter logic, page-header rhythm and section spacing.

## Shared secondary-page structure

Every internal page uses the same shell and shared primitives where appropriate:
- AppShell;
- Sidebar;
- TopBar;
- scroll-safe PageContainer;
- PageHeader;
- SectionHeader;
- Panel/Card;
- reusable EmptyState;
- reusable SettingsRow;
- semantic StatusBadge.

PageHeader consists of a clear page title plus readable concise subtitle. Secondary pages must not start from a different visual origin than Dashboard content.

## Empty states

Empty states are intentional states, not placeholders and not full-screen voids.

Rules:
- do not invent threats, scans, history events, settings values or metrics;
- use the single shared `EmptyState` pattern where the same semantic applies;
- bound the empty-state height so the page does not become a small header followed by an arbitrary empty screen;
- show only actions/providers that really exist;
- if a real provider is absent, say so plainly.

Scan uses a bounded task-state panel because its action hierarchy differs from data-list empty states.

## Protection hierarchy

Every protection module must communicate separately:
1. icon / identity;
2. module name;
3. concise description;
4. engine/status badge;
5. runtime verification state;
6. read-only enabled/off indicator when applicable;
7. real manual action only when authorized by the current contract.

Engine/source availability is never equivalent to runtime verification.

## Settings hierarchy

Settings are grouped into:
- Protezione;
- Generale;
- Cartelle monitorate;
- Esclusioni / Allowlist.

Reusable `SettingsRow` structure:

```text
[optional icon]  Setting title                 [control]
                 Description
                 Secondary/runtime metadata
```

No control may visually imply a functional setting if its provider/runtime authority is not connected.

## Sidebar and Topbar

Sidebar:
- preserve the current green active state;
- inactive items remain clearly readable but subordinate;
- Quick Scan has more hierarchy than Supporto/Account;
- footer separator, alignment and spacing must feel part of the same design system.

Topbar:
- keep the current structure;
- `BC SENTINEL · Sezione` remains compact and secondary to page content;
- `Aggiorna stato` is a subtle/ghost secondary action with visible hover/focus;
- it must not compete with primary security actions.

## Runtime truth rule

Visual fidelity never overrides security truthfulness.

- Engine/source availability is not proof of active protection.
- `Protected` requires accepted current runtime evidence.
- Unverified state remains visually distinct from protected state.
- Controls not implemented in the current milestone stay disabled rather than being mocked as functional.
- Rescue/discovery remains explicit and passive at startup.
- No UI refinement may add repair/quarantine/unlock/write/format/reimage authority.

## Responsive contract

BC Sentinel is desktop-first but must survive intentional resize.

Acceptance covers at minimum:
- large desktop;
- standard laptop/desktop;
- narrow/icon-rail width;
- minimum supported window.

When space decreases:
- sidebar compacts intentionally;
- hero/actions stack;
- card grids reflow;
- settings sections stack;
- page-header actions reflow;
- no outer horizontal scrollbar is allowed;
- no clipping, overlap, cut card or off-viewport control is acceptable.

Secondary scroll hosts must re-sync when a vertical scrollbar appears so its scrollbar extent cannot create stale horizontal overflow.

## Accessibility / interaction

Required:
- visible keyboard focus;
- readable normal/secondary/muted text;
- hover, pressed, selected and disabled states;
- status communicated with text as well as color;
- useful accessible names on important controls;
- adequate clickable targets;
- consistent tooltips only where they clarify unavailable/read-only behavior.

## Anti-regression rules

Do not reintroduce:
- white/light accidental viewports;
- a second visual template for internal pages;
- narrow website-like centered content on desktop;
- huge unstructured empty regions;
- tiny low-contrast body text;
- unicode/emoji fallback icons in primary navigation;
- inconsistent card radii/gutters;
- green/positive protection status without runtime proof;
- enabled scan/quarantine actions without actual authority;
- horizontal page overflow;
- a separate Technician UI as the primary product mode.

## Required validation

The automated B6-2 gate must cover:
- B6-0/B6-1 safety regressions;
- current B6-2 functional/runtime-truth regressions;
- Dashboard structure preservation;
- semantic dark ownership for secondary scroll surfaces;
- normal text contrast checks;
- shared PageHeader/EmptyState/Settings hierarchy;
- bounded Scan/Quarantine/History empty compositions;
- Protection hierarchy;
- large/laptop/narrow responsive geometry;
- zero outer/secondary horizontal overflow;
- passive self-check;
- offscreen Qt construction;
- protected-source hash checks in the local Windows gate.

A real Windows visual review is still required before checkpoint stabilization. The intended final perception is simple:

> The Dashboard has been extended to the entire product.
