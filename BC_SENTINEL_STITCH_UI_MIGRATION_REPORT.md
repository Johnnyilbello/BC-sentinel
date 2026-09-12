# BC Sentinel — Dashboard Visual Consistency Refinement Report

## Scope

This pass refines the complete B6-2 desktop UI after the initial Stitch migration.

The governing rule is now:

```text
Current accepted Dashboard = primary visual source of truth
Current BC Sentinel model/runtime = functional and security source of truth
Original Stitch bundle = supporting visual evidence
```

The Dashboard is intentionally preserved. The objective is to make Scansione, Quarantena, Cronologia, Protezione and Impostazioni feel like direct extensions of it.

## Files changed in this refinement

Presentation / shell:
- `sentinel/ui_design_system.py`
- `sentinel/ui_styles.py`
- `sentinel/ui_pages.py`
- `sentinel/home_security_ui.py`

Validation:
- `tests/test_v011_beta6_b62_visual_consistency_refinement.py`
- `tools/v011_beta6_b62_acceptance.py`
- `TEST-V011-BETA6-B62.ps1`
- `.github/workflows/b62-stitch-ui.yml`

Documentation:
- `BC_SENTINEL_UI_SOURCE_OF_TRUTH.md`
- this report

No antimalware/EDR/Web Protection/target-discovery/security-state engine source was intentionally modified by the visual refinement.

## Shared design system consolidated

Semantic colors now explicitly cover:
- app/sidebar/header backgrounds;
- primary/secondary/nested/elevated surfaces;
- subtle/strong borders;
- primary/secondary/muted copy;
- BC emerald accent;
- success, warning, critical and info states;
- hover, pressed, selected, focus and disabled states.

Typography roles now centralize:
- caption;
- body;
- bodyStrong;
- subtitle;
- title;
- pageTitle;
- metric.

Existing 4/8/16/24/32/48 spacing, radius and motion tokens remain centralized.

## Problems found and corrected

### 1. Secondary dark ownership

The Dashboard already owned its dark canvas correctly, but secondary `QScrollArea` viewport/host surfaces were not explicitly included in the central dark selector. Native Qt background leakage could therefore appear as a white/light internal page.

Fixed by giving `SecondaryPageScroll`, `SecondaryPageViewport` and `SecondaryPageHost` explicit `bg_app` ownership.

### 2. Secondary/muted contrast

The previous gray-green copy was too subdued in several internal surfaces.

Primary/secondary/muted text tokens were raised while preserving the Dashboard green-charcoal character. Deterministic WCAG contrast checks now protect normal secondary/muted copy against the main dark surfaces.

### 3. Empty-page composition

Scansione, Quarantena and Cronologia previously risked reading as a small control area followed by an unfinished empty screen.

Fixed without fabricated security data:
- one bounded reusable `EmptyState` for Quarantena/Cronologia;
- bounded task-state composition for Scansione;
- no fake rows, threats, metrics or events;
- page content no longer expands empty states arbitrarily to fill the entire viewport.

### 4. Shared page structure

All internal pages now use the same Dashboard-derived origin and hierarchy through shared `PageHeader` and section primitives. Secondary pages use the same app shell, gutter logic, dark hierarchy and page-title rhythm.

### 5. Protezione hierarchy

Protection modules now explicitly separate:
- identity/icon;
- module name;
- description;
- engine/status badge;
- runtime verification state;
- read-only toggle/state indicator;
- real action only when the current contract authorizes it.

This preserves the critical distinction `engine available != runtime verified`.

### 6. Impostazioni hierarchy

Settings now use reusable `SettingsRow` and `SettingsSection` primitives with four clear groups:
- Protezione;
- Generale;
- Cartelle monitorate;
- Esclusioni / Allowlist.

Unconnected controls remain visibly read-only/unavailable instead of appearing functional.

### 7. Topbar / Sidebar refinement

The Dashboard sidebar structure and green active state remain intact. Inactive content uses more readable secondary text, footer spacing/separation is more coherent, and `Aggiorna stato` remains a restrained ghost/secondary action.

### 8. Narrow resize overflow

The new visual-consistency suite found a real 8 px horizontal overflow after sequential navigation/resizing on a secondary page. Root cause: Qt could expose the vertical scrollbar one event-loop tick after the secondary host width had been fixed, leaving the host stale by exactly the scrollbar extent.

Fixed in `_PageScroll` by re-synchronizing host width when:
- the scroll viewport resizes;
- the vertical scrollbar range changes;
- the normal global responsive sync runs.

The fix passed the subsequent Windows CI geometry suite.

## Functional preservation

The refinement does not grant new security authority.

- Smart Scan / Full Scan execution remains disabled in B6-2.
- no automatic scan starts at Home startup;
- no automatic Rescue starts at Home startup;
- Quarantine does not invent rows or actions without a real provider;
- History does not invent events;
- Settings does not invent persisted configuration;
- `Protected` still requires accepted runtime evidence;
- System & Recovery preserves B6-1 passive/explicit behavior.

## Automated validation

The Windows GitHub Actions gate runs:
1. dependency installation;
2. Python compile validation;
3. B6-0/B6-1/B6-2 deterministic regression suite;
4. dedicated visual-consistency tests;
5. deterministic B6-2 acceptance;
6. passive Home self-check;
7. Qt offscreen smoke.

The visual-consistency tests cover:
- Dashboard structure preservation;
- semantic token completeness;
- text contrast;
- explicit dark secondary surfaces;
- shared PageHeader and EmptyState usage;
- bounded empty compositions;
- Quarantine controls and zero fabricated rows;
- Protection hierarchy;
- Settings shared rows and four sections;
- laptop, narrow/icon-rail and minimum-window overflow checks across every page.

## Acceptance boundary

Automated Windows/Qt acceptance can prove deterministic geometry, dark ownership, hierarchy contracts and regression safety. It cannot replace a human visual review of the actual Windows application on the target display.

Before B6-2 checkpoint stabilization, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST-V011-BETA6-B62.ps1
```

Then open:

```powershell
.\.venv\Scripts\python.exe -m sentinel.home_security_ui
```

Review Dashboard, Scansione, Quarantena, Cronologia, Protezione and Impostazioni at maximized/normal/narrow sizes.

The target perception is:

> **The Dashboard has been extended to the entire product.**
