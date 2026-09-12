# BC Sentinel — Stitch UI Migration Report

## Scope

The visual migration uses `stitch_bc_sentinel_antivirus_ui.zip` as the visual source of truth and the current BC Sentinel branch as the functional source of truth.

## Audited ZIP

15/15 files reviewed:

- Dashboard HTML + screenshot
- Scan HTML + screenshot
- Quarantine HTML + screenshot
- History HTML + screenshot
- Settings HTML + screenshot
- Threat-detected HTML + screenshot
- App icon screenshot
- Sentinel Elite design document
- Brutalist Luxe Command design document

## Decisions

- **Sentinel Elite** is the global product shell and consumer-security visual language.
- **Brutalist Luxe Command** is restricted to dense History/evidence surfaces.
- Native Windows title-bar chrome is not duplicated inside PySide.
- Example data from Stitch is never copied into operational runtime screens.
- Runtime safety/truth overrides cosmetic fidelity where the mockup displays an optimistic protected state.

## Structural migration

The application now has a single shared shell and six visual destinations matching the Stitch navigation:

`Dashboard → Scansione → Quarantena → Cronologia → Protezione → Impostazioni`

Shared visual primitives centralize palette, spacing, radii, motion, breakpoints, line icons, Sentinel mark and read-only toggles.

The Home Dashboard follows the Stitch hierarchy:

`Status hero → scan actions → 3 KPI cards → Moduli Protezione panel → 2×2 protection cards → recent activity`

## Responsive migration

The former centered/narrow layout and stale minimum-size behavior are removed. The outer Home page is width-locked to the real scroll viewport and all primary layouts reflow intentionally.

The acceptance suite exercises large desktop, standard laptop and tablet/narrow geometries and treats any outer horizontal scrolling as a failure. Secondary pages use vertical-only shrink-safe scroll hosts, and compact/narrow modes reflow page headers, controls and settings composition intentionally.

## Cleanup

- public Home entry consolidated in `sentinel.home_security_ui`; the internal `home_security_ui_impl.py` remains only as the Dashboard presentation component, not as a second user-facing UI;
- no emoji/unicode navigation icons;
- old blue/white Rescue surface restyled into the shared Sentinel system;
- common tokens moved to `sentinel/ui_design_system.py`;
- centralized application/Rescue QSS moved to `sentinel/ui_styles.py`;
- secondary surfaces moved to `sentinel/ui_pages.py`;
- functional engines are not modified.

## Functional preservation

The migration does not grant new security authority. Smart Scan/Full Scan execution remains disabled in B6-2. Recovery keeps B6-1 passive startup and explicit discovery. Engine/source availability is never promoted to `Protected` without accepted runtime evidence.

Quarantine, History, Settings and Scan do not display example/mock data from Stitch. Where a real provider is not connected, the surface exposes an explicit unavailable/empty state instead.

## Verification state

Static Python syntax validation of the new migration modules was completed before commit generation.

The authoritative Windows/Qt runtime result remains the repository gate:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST-V011-BETA6-B62.ps1
```

The gate compiles the migrated presentation modules, runs B6-0/B6-1/B6-2 regressions, deterministic acceptance, six-page shell checks, runtime-truth checks, large/laptop/tablet responsive geometry, outer/secondary overflow checks and protected-source hash checks.

A real Windows visual review remains mandatory before checkpoint stabilization.
