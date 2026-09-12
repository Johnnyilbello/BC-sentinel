# BC Sentinel v0.11.0-beta.6 — B6-2 Home / Security Overview

Status: **ACTIVE FEATURE MILESTONE**

Branch: `feature/v011-beta6-b62-home-security-overview`

Parent development checkpoint:

```text
B6-1 Unified Home Target Discovery
ff52bb3d79e0b2a6f71a80dc874d5990186c51ae
LOCAL PASS + real Home UX PASS
hardware edge-case acceptance still pending
```

Stable release remains unchanged:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```

## Objective

B6-2 creates the primary BC Sentinel Home experience for everyday users.

It is an **overview milestone**, not the Smart Scan milestone. B6-2 must make the state of the product understandable without prematurely enabling B6-3 scan orchestration, B6-4 threat resolution, autonomous remediation or destructive actions.

There is one Home experience only. Technical depth remains available through **Advanced details**.

## Truthfulness contract

The Home must never infer `Protected`, `Active`, `Safe` or an equivalent positive runtime claim from any of the following alone:

- a Python module exists;
- an engine can be imported;
- a historical acceptance test passed;
- a capability exists in source;
- B6-0/B6-1 safety contracts are green.

A protection layer may show a positive live state only when its current runtime evidence provider explicitly proves that state.

Until such a provider is wired and accepted, the UI must distinguish:

```text
ENGINE_AVAILABLE       capability exists, runtime state not proven
STATUS_UNAVAILABLE     runtime proof is unavailable
READY                  safe feature/workflow is genuinely available
ATTENTION              current evidence requires user attention
OFF                    runtime evidence proves protection is disabled
ACTIVE                 runtime evidence proves protection is active
```

`ENGINE_AVAILABLE` is never rendered as `Protected`.

## Home information architecture

The initial B6-2 Home contains:

1. **Protection posture hero** — one plain-language summary of what BC Sentinel can currently prove.
2. **Primary action** — `Smart Scan` surface is visible as the next core action but remains explicitly unavailable until B6-3.
3. **Protection layers** — concise cards for:
   - Malware protection
   - Behavior & EDR
   - Web protection
   - System & Recovery
4. **Recent activity** — honest empty/unavailable state; no invented incidents.
5. **Advanced details** — full raw evidence/status provenance for each layer.
6. **System & Recovery** — safe navigation into the accepted B6-1 Windows systems UI; opening it must not auto-discover targets.

Firewall/privacy cards are not fabricated in B6-2 merely because they are roadmap goals. They enter the Home only when there is a defined capability/status contract.

## Visual design contract

B6-2 is the first milestone where the BC Sentinel visual language is treated as a release constraint.

### Character

- premium dark;
- calm, authoritative and precise;
- modern security product, not a generic admin dashboard;
- no hacker aesthetic;
- no gratuitous neon;
- no giant decorative gradients;
- no inconsistent widget-native white surfaces.

### Typography

- use the Windows UI family stack (`Segoe UI Variable` when available, with `Segoe UI` fallback);
- strong hierarchy with a limited number of sizes/weights;
- body copy remains readable at the minimum window size;
- technical evidence uses a monospaced system fallback;
- no condensed decorative type;
- no arbitrary bolding.

### Spacing

Use a coherent 4 px base scale with primary rhythm:

```text
4 / 8 / 12 / 16 / 20 / 24 / 32 / 40
```

Primary page padding: 32 px desktop, never below 24 px at the supported minimum.
Card internal padding: 18–20 px.
Related controls: 8–12 px gaps.
Sections: 24–32 px gaps.

### Color roles

The palette is role-based, not decorative:

```text
canvas        near-black
surface-1     elevated dark neutral
surface-2     secondary dark neutral
border        low-contrast cool neutral
text-primary  high-contrast off-white
text-muted    cool gray-blue
accent        restrained ice/cyan-blue
success       muted green only for proven positive state
warning       muted amber only for actual attention state
critical      muted red only for actual risk/error state
```

Unknown/unverified states use neutral colors and may never borrow success green.

### Motion / cinematics

Motion communicates hierarchy and state.

- short, calm opacity/position reveal on Home content after first show;
- protection cards enter with subtle stagger, never dramatic travel;
- Advanced details expands/collapses smoothly;
- hover/focus transitions are restrained;
- no looping decorative animation;
- no pulsing green `protected` indicator;
- respect reduced-motion intent where practical;
- UI remains fully correct when animation is disabled.

Recommended durations:

```text
micro interaction   120–160 ms
card/state change   180–220 ms
panel reveal        220–280 ms
page entrance       <= 320 ms
```

## Safety invariants

B6-2 does not add mutation authority.

```text
automatic scan dispatch       = false
automatic rescue dispatch     = false
automatic repair              = false
automatic quarantine          = false
unlock                        = false
mount-write                    = false
format                         = false
reimage                        = false
registry/boot write            = false
target execution              = false
```

Opening Home, expanding details, opening System & Recovery or refreshing overview evidence must not start a scan or remediation.

## Model contract

Each Home protection card must carry:

```text
id
label
short description
status
plain-language status label
summary
runtime_verified (bool)
action_enabled (bool)
action_label
advanced_details
provenance
```

The raw evidence/provenance object is retained for Advanced details.

The overall protection posture is conservative:

- any verified critical/attention state -> attention posture;
- all relevant layers verified active/ready -> positive posture;
- otherwise -> `STATUS_UNAVAILABLE` / neutral posture.

No optimistic inference is allowed.

## B6-2 actions

Allowed:

- refresh passive overview status;
- expand/collapse Advanced details;
- open the B6-1 System & Recovery UI without automatic discovery;
- view capability provenance.

Not allowed yet:

- execute Smart Scan;
- start on-demand scan;
- quarantine;
- repair;
- automatically change settings;
- automatically enable services;
- start Rescue workflow.

## Acceptance requirements

Minimum deterministic tests:

1. startup is passive and calls no scan/rescue provider;
2. source/module availability alone never becomes `Protected`/`Active`;
3. unknown runtime state renders neutral, not green;
4. explicit verified ACTIVE fixture may render active;
5. overall posture remains neutral when any required runtime proof is missing;
6. Advanced details preserve full raw status/provenance;
7. Smart Scan CTA exists but is disabled in B6-2;
8. System & Recovery navigation creates B6-1 Home without automatic discovery;
9. no forbidden/destructive action is exposed;
10. B6-0 and B6-1 regression tests remain green;
11. offscreen B6-2 UI construction passes;
12. all scroll/viewport/page surfaces have explicit dark-theme ownership;
13. typography, spacing and motion token constants are deterministic and tested;
14. the Home remains usable at the supported minimum window size.

## Windows acceptance gate

B6-2 may become an accepted development checkpoint only after:

- deterministic tests pass;
- B6-0/B6-1 regression set passes;
- Qt offscreen smoke passes;
- real Windows Home opens without white/native-theme leaks;
- minimum-size layout is visually checked;
- System & Recovery navigation is verified passive;
- no false positive runtime protection claim is visible;
- local acceptance evidence is recorded.

B6-1 hardware edge cases remain separately pending and are not silently waived by B6-2.

## Codex execution policy

Recommended reasoning:

- **High** for Home model/UI, visual system, tests and acceptance tooling;
- **Extra High** before wiring any privileged service state, protection control, scan execution or remediation authority.

## Definition of done

A normal user can open BC Sentinel and understand, at a glance, what the product can currently prove about protection, inspect technical evidence when desired, and reach System & Recovery without being exposed to a separate Technician mode or triggering hidden security actions. The UI is visually coherent enough to serve as the foundation of the final consumer product.