# BC Sentinel UI Source of Truth

Status: ACTIVE VISUAL CONTRACT
Applies to: Beta6 Home and all future desktop UI milestones unless explicitly superseded by an approved redesign.

## Reference

Primary visual reference: the original BC Sentinel Stitch desktop UI supplied by the product owner (dashboard, scan, quarantine, history, settings and threat-detected screens).

The interface must feel like a Windows security product, not a generic web dashboard. Preserve the original Sentinel identity while keeping all newer safety and truthfulness contracts.

## Core identity

- Fixed left sidebar with BC Sentinel branding and desktop navigation.
- Navigation order: Dashboard, Scansione, Quarantena, Cronologia, Protezione, Impostazioni.
- Compact top application bar.
- Deep green-charcoal canvas and layered surfaces.
- Emerald `#10b981` is the primary brand/action accent.
- No hacker/neon aesthetic and no arbitrary blue SaaS-dashboard look.
- Tonal layering and subtle borders provide depth; heavy shadows are avoided.
- Main content is constrained so wide displays do not stretch cards excessively.

## Typography

- Preferred display/headline direction: Hanken Grotesk when available.
- Preferred body/label direction: Plus Jakarta Sans when available.
- Native Windows fallback: Segoe UI Variable / Segoe UI.
- Headline hierarchy must remain strong but compact enough for desktop software.
- Body and secondary text must never become tiny merely to increase information density.
- Technical evidence may use Cascadia Mono / Consolas.

## Spacing

- Base rhythm: 4 px.
- Primary spacing rhythm: 8 / 12 / 16 / 20 / 24 / 32 / 40 px.
- Main content margins should visually approximate the original 24 px desktop canvas.
- Cards must remain dense and useful without looking crowded.

## Color semantics

- Brand emerald: `#10b981`.
- Secure/verified status may use brighter emerald tones.
- Amber is reserved for unverified or warning states.
- Red/crimson is reserved for threats, failures and critical states.
- A brand color must never be used to imply protection is active without runtime evidence.

## Dashboard composition

Preferred Home order:

1. Sidebar + compact top bar.
2. Main protection/status hero with Sentinel shield.
3. Quick Scan / Full Scan actions.
4. Three compact metrics: last scan, detections, quarantine.
5. Protection modules grid.
6. Recent activity.
7. Advanced details remain available without dominating the consumer view.

## Runtime truth rule

Visual fidelity never overrides security truthfulness.

- Engine/source availability is not proof of active protection.
- `Protected` requires accepted current runtime evidence.
- Unverified state must remain visually distinct from protected state.
- Controls not implemented in the current milestone stay disabled rather than being mocked as functional.
- Rescue/discovery remains explicit and passive at startup.

## Module cards

- Compact card with icon, title, one-line description, status and read-only state indicator/toggle.
- Advanced details must be available on every relevant protection layer.
- Runtime switches may only become interactive when their controlling engine contract is implemented and accepted.
- System & Recovery may expose its accepted B6-1 entry action while retaining all B6-1 fail-closed behavior.

## Motion / cinematics

Motion is functional and restrained:

- 140 ms micro-interactions.
- About 200 ms state transitions.
- About 250 ms advanced-panel expansion.
- Up to 300 ms page entrance.
- Staggered module entrance may be used sparingly.
- Reduced-motion mode must remain supported.
- No decorative looping motion that competes with security status.

## Anti-regression rules

Do not reintroduce:

- white/light accidental viewports inside the dark application;
- generic white primary buttons unrelated to the Sentinel palette;
- oversized empty page layouts resembling a website;
- tiny low-contrast body text;
- inconsistent card radii or spacing;
- positive/green protection status without runtime proof;
- a separate Technician UI as the primary product mode.

The product remains one Home experience with simple information first and technical evidence available through Advanced details.
