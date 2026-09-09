# BC Sentinel — Premium UI / Motion / Design System Elevation

Scope: existing BC Sentinel v0.3 Beta codebase. The security engine, scan worker, quarantine logic, real-time protection, telemetry, persistence/network monitoring and navigation routes were preserved. UI integration changes are concentrated in `app/ui/main_window.py`; no new runtime dependency was added.

## A. UI issues discovered

- The dark theme was functional but visually inconsistent: semantic status colors, borders, muted text and card surfaces were partly centralized and partly repeated as one-off values.
- Typography hierarchy was implemented through many local `setStyleSheet()` calls, creating inconsistent sizes/weights between dashboard, activity, settings and dialogs.
- The 212 px fixed sidebar compressed the main content at the existing 820 px minimum width and at 125–150% Windows scaling.
- Protection/status badges duplicated styling logic in dashboard, protection and telemetry states.
- Toggle switches changed instantly with no transition or keyboard-focus affordance.
- Scan feedback had motion but lacked a coherent visual state model linking IDLE → SCANNING → ANALYZING → SAFE / VERIFY / THREAT.
- Dashboard numeric metrics changed abruptly.
- Quarantine, history and activity tables had no explicit empty states.
- Dense tables used full-width paths and many columns at narrow desktop widths, increasing clipping/horizontal-scroll pressure.
- Scrollbars, menus, tooltips, focus states and list selections were under-styled relative to the rest of the app.
- A ransomware dialog still referenced “BC Sentinel v0.2”, which was stale UI copy in the v0.3 codebase.
- The ambient status pulse continued repaint requests while hidden.

## B. Design system created/refined

Centralized tokens now cover:

- semantic palette: background, surfaces, safe, warning, danger, information, inactive/disabled and focus;
- typography roles through QSS properties (`pageTitle`, `heroTitle`, `sectionTitle`, `metricValue`, `caption`, etc.);
- motion durations through `MOTION`;
- spacing through `SPACING`;
- radius through `RADIUS`;
- icon sizing through `ICON_SIZE`;
- elevation through `ELEVATION` and one restrained hero shadow;
- semantic components for status badges and inline status surfaces.

The system intentionally avoids neon borders, multi-color gradients and gamer-style glow.

## C. Typography changes

- Primary family moved to `Segoe UI Variable Text` with `Segoe UI` fallback.
- Page, hero, section, subsection, caption, eyebrow, metric and scan-status roles are centralized.
- Hero/status hierarchy was strengthened while supporting text remains lower contrast but readable.
- Dashboard metric values use a dedicated large numerical role.
- Dialog titles and evidence copy now reuse the shared hierarchy rather than local ad-hoc sizes.
- Long table content uses middle elision instead of forcing uncontrolled expansion.

## D. Color changes

- Backgrounds moved to deeper neutral green-black surfaces with more controlled contrast.
- Safe/Protected: restrained emerald.
- Warning: warm amber.
- Threat/Critical: controlled red.
- Information: soft blue.
- Inactive/Disabled: neutral desaturated gray-green.
- Status badges, telemetry states and scan-state borders now use semantic tones consistently.

## E. Motion / cinematic improvements

- Existing page fade transitions retained and normalized with shared motion intent.
- First-level cards use a capped four-card stagger on navigation; the cap avoids effect stacking on long settings pages.
- Toggle thumb movement now uses a non-blocking `QPropertyAnimation` and respects the global animation setting.
- Protection/status changes receive a subtle fade when their semantic state changes.
- Dashboard integer metrics animate without blocking database/security work.
- Scan UI now maps actual callbacks to visual states:
  - SCANNING during startup/preparation;
  - ANALYZING after real worker progress arrives;
  - THREAT only when a real detection callback is received;
  - SAFE when a completed scan reports no detections;
  - WARNING/verification when a completed scan reports detections.
- Scan detection state automatically returns to ANALYZING only while the real scan worker is still running.
- Animations remain presentation-only and never gate a security action.

## F. Components modified

- Sidebar/navigation: compact responsive mode below 980 px, icon-only labels plus tooltips, routes unchanged.
- Dashboard hero: refined hierarchy, semantic live status and restrained elevation.
- Metric cards: centralized typography and animated numeric values.
- Protection cards/status badges: shared semantic styling.
- Scan panel: explicit cinematic states and refined progress/status surfaces.
- Toggle switches: animated, focusable and disabled-aware.
- Tables: cleaner rows, no grid noise, single-row selection, 40 px row height, middle elision and responsive column hiding.
- Quarantine/history/activity: explicit empty states.
- Tabs, lists, inputs, menus, tooltips and scrollbars: brought into the same surface/border system.
- Threat/ransomware dialogs: colors and typography aligned to the design system; stale version-specific UI copy removed.
- Settings: headings and row hierarchy standardized.

## G. Performance optimizations

- No new dependency added.
- Scan/security workers and monitor logic were not moved to the UI thread or otherwise changed.
- Card entrance effects are limited to the first four first-level cards on navigation.
- Toggle, counters and badge transitions are short and event-driven.
- The scan activity ring runs only while active.
- The ambient protection pulse skips repaint work while not visible.
- Existing global “Animations” accessibility/performance setting remains authoritative.
- Responsive changes are handled in `resizeEvent` without recreating pages or security services.

Validation performed:

- `python -m py_compile app/ui/main_window.py` — PASS
- Full test suite after changes — **117 passed**
- Added regression coverage for semantic design tokens, typography roles, animated toggle, real scan-state mapping, compact navigation, empty states and table hardening.

## H. Remaining UI weaknesses

- The execution environment used for this edit does not contain PySide6, so an actual Qt off-screen/live render could not be launched here. Visual acceptance should still be performed on the target Windows machine at 100%, 125%, 150% and 175% display scaling.
- Qt Style Sheets do not provide native CSS-style transition/blur primitives; motion is deliberately limited to Qt property/opacity animation rather than adding a heavier animation framework.
- QMessageBox remains largely platform/Qt-native; replacing every confirmation with bespoke dialogs would increase maintenance and was avoided to preserve behavior.
- Sidebar icons are still the existing text glyphs. A future dedicated SVG icon set could further increase polish without changing navigation semantics.
- A real Windows visual pass should confirm font fallback if `Segoe UI Variable Text` is unavailable and validate the final pixel balance across 820×520, 1024×640, 1280×720, 1440×900 and high-DPI equivalents.
