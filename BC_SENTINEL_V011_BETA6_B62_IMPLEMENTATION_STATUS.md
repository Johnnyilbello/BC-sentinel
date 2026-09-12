# BC Sentinel v0.11.0-beta.6 — B6-2 Implementation Checkpoint 1

Status: **IMPLEMENTED ON FEATURE BRANCH / LOCAL GATE DEFINED / REAL WINDOWS VISUAL ACCEPTANCE PENDING**

Branch:

```text
feature/v011-beta6-b62-home-security-overview
```

Parent development checkpoint:

```text
B6-1 Unified Home Target Discovery
ff52bb3d79e0b2a6f71a80dc874d5990186c51ae
```

Stable release remains unchanged:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```

## Implemented

B6-2 now contains the first primary consumer-facing BC Sentinel Home foundation:

- `Security overview` Home surface;
- conservative protection-posture hero;
- four protection cards:
  - Malware protection
  - Behavior & EDR
  - Web protection
  - System & Recovery
- technical evidence through **Advanced details** on every card;
- passive `Refresh status`;
- visible but disabled `Smart Scan` placeholder for B6-3;
- `System & Recovery` navigation into the accepted B6-1 Home without automatic target discovery;
- honest `Recent activity` unavailable state instead of invented incident data;
- deterministic design tokens for spacing, motion and colors;
- premium dark surface ownership for page, viewport, cards and evidence panels;
- reduced-motion override through `BC_SENTINEL_REDUCED_MOTION`;
- subtle page/card opacity entrance and Advanced-details expansion;
- B6-2 deterministic pytest coverage;
- B6-2 deterministic acceptance tool;
- B6-2 Windows local gate;
- standalone packaging entry.

## Runtime truth model

B6-2 deliberately separates capability presence from current protection state.

The default passive provider may prove that a source/engine is available, but it does **not** promote this to `Active` or `Protected`.

```text
module exists           -> ENGINE_AVAILABLE
accepted runtime proof  -> may become ACTIVE
missing runtime proof   -> neutral / UNVERIFIED posture
verified OFF/ATTENTION  -> ATTENTION posture
all required verified ACTIVE -> PROTECTED posture
```

This is a safety and product-trust requirement. A green protected state must always be supported by current runtime evidence.

## Safety state

B6-2 adds no mutation or protection-control authority.

```text
startup scan dispatch       = false
startup Rescue dispatch     = false
Smart Scan execution        = false in B6-2
automatic repair            = false
automatic quarantine        = false
unlock                      = false
mount-write                  = false
format                       = false
reimage                      = false
registry/boot write          = false
target execution            = false
```

`Refresh status` rebuilds passive status evidence only.

Opening `System & Recovery` constructs the B6-1 UI in `IDLE` state and does not run discovery.

## Visual contract implemented

The current B6-2 source fixes the visual direction as a product contract rather than a later polish pass:

```text
typography: Segoe UI Variable -> Segoe UI -> system fallback
spacing:    4 / 8 / 12 / 16 / 20 / 24 / 32 / 40
page pad:   32 px desktop foundation
motion:     140 / 200 / 250 / 300 ms + restrained stagger
canvas:     explicit near-black ownership
surfaces:   layered dark neutrals
accent:     restrained cool ice/cyan
success:    used only for proven positive state
warning:    used only for verified attention state
unknown:    neutral, never green
```

No white/native Qt viewport should be able to appear through an unowned background surface.

## Gate

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST-V011-BETA6-B62.ps1
```

The gate:

1. runs the complete B6-1 local gate first;
2. compiles B6-2 model/UI/packaging/tests/acceptance;
3. runs B6-0 + B6-1 + B6-2 deterministic regression tests;
4. runs B6-2 deterministic acceptance;
5. runs Home self-check;
6. runs offscreen Qt smoke;
7. verifies four Home cards and disabled Smart Scan;
8. verifies conservative runtime-truth behavior;
9. verifies visual token and dark-surface contracts;
10. checks hashes of predecessor/security source files to prove the gate did not mutate them.

## Acceptance boundary

B6-2 must **not** be called an accepted checkpoint merely because the implementation and gate exist in Git.

Before checkpoint acceptance, the real Windows Home must be visually reviewed for:

- typography quality;
- spacing rhythm;
- card alignment;
- hierarchy;
- color/contrast;
- no white/native theme leaks;
- motion quality;
- Advanced-details expansion;
- minimum-window layout;
- passive System & Recovery navigation;
- no false `Protected` claim.

The non-fatal PySide6 `QFontDatabase` warning observed during B6-1 remains a packaging issue to resolve before release packaging; B6-2 does not treat it as proof of a UI failure when Qt construction and tests pass.

B6-1 real offline multi-disk and locked-BitLocker hardware edge-case acceptance remains separately pending and is not waived by B6-2.

## Next boundary

If B6-2 passes its local and real-Windows visual gate, the next roadmap block is:

```text
B6-3 — One-Click Smart Scan
```

B6-3 may connect an actual scan action only after defining a truthful scan-state contract, cancellation/progress behavior, safe concurrency, result semantics and Detection & Attack Coverage measurement. No B6-3 execution authority is introduced in this checkpoint.
