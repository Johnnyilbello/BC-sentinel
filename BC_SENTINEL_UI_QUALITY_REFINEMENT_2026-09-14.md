# BC Sentinel — UX/UI Quality Refinement

Date: 2026-09-14
Scope: current B6-5 Home / Smart Scan / Threat Cards / Guided Resolution presentation only.

## Objective

Move the interface from "visually coherent" to "task-clear and product-grade" without changing security semantics or execution authority.

Primary user flow:

1. Understand current protection/status.
2. Start the safe primary action.
3. See live system status and progress.
4. Understand findings in plain language.
5. See the safest next step.
6. Open technical evidence only when needed.

## UX decisions

- UX takes precedence over decorative UI. Security state, action availability, progress, findings and next step must be understandable before visual embellishment.
- Progressive disclosure remains the core information model: plain-language summary first; `Dettagli avanzati` second.
- Internal milestone/state vocabulary is not primary user copy. Technical enums remain available in evidence/tooltips/details.
- No severity or confidence is inferred or cosmetically upgraded. Presentation follows canonical data.
- Danger color is reserved for real severity/attention semantics rather than decoration.
- Buttons and interactive controls use a clearer minimum target height and explicit focus state.
- The current Windows product uses native Windows typography preference (`Segoe UI Variable Text` / `Segoe UI`) before non-native alternatives.

## Visual hierarchy

The intended order of attention is:

1. Page purpose / security posture.
2. Primary safe action.
3. Live status / progress.
4. Finding title + severity.
5. Reason and location.
6. Recommended next step / Guided Resolution.
7. Advanced evidence.

Threat Cards now use distinct information groups instead of one dense metadata sentence: category, confidence and source are separated; path/evidence location is visually distinct; recommendation has its own next-step surface.

## Spacing and typography

- Existing 4/8-based spacing system is retained.
- Card internal spacing is made more consistent and responsive.
- Secondary-page title scale is aligned more closely with the accepted Dashboard instead of competing with it.
- Long technical evidence stays monospace and hidden by default.
- Plain-language labels remain sentence case; all-caps is not used as the main hierarchy device.

## Product imagery

Not applicable to this product flow. BC Sentinel is a Windows security application, not a commerce/product-detail experience. Decorative product photography was intentionally not introduced. Functional vector icons and technical evidence are preferred because they communicate state/action without adding visual noise.

## Quantity selectors

Not present in the current BC Sentinel Home or B6-5 flow. No quantity selector was added. If numeric settings appear in a later milestone, they should be evaluated as task-specific controls rather than imported from ecommerce patterns.

## Product-grade experience vs attractive UI

The quality gate is not whether the interface looks polished. It is whether the user can correctly answer:

- What is happening?
- Is the system protected or only unverified?
- What can I safely do now?
- What did the scan actually cover?
- Why was this item flagged?
- What evidence supports the finding?
- What is the next safe step?
- What will happen before any system-changing action?

The current refinement therefore preserves all existing fail-closed security contracts and adds no automatic remediation authority.

## Implemented

- Visual Smart Scan progress bar plus status text.
- More concise Smart Scan copy and clearer result summary.
- Threat Card hierarchy: title/severity, reason, metadata, location, recommendation, advanced evidence.
- Plain-language severity badge while exact canonical severity remains in evidence.
- Responsive metadata stacking on compact layouts.
- Guided Resolution uses plain-language review/authority labels and explicit next-step hierarchy.
- Advanced evidence remains collapsed by default and can be explicitly expanded/collapsed.
- Native Windows font preference on current B6-5 Home.
- 40 px minimum height for primary/secondary interaction classes in the refinement layer.
- Explicit keyboard-focus treatment.
- Regression coverage for no horizontal overflow, no quantity controls, progressive disclosure and unchanged non-destructive authority.
