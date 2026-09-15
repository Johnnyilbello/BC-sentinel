# BC Sentinel

BC Sentinel is a Windows endpoint-security, recovery, and incident-intelligence project focused on deterministic validation, conservative security claims, and explicit safety boundaries.

> **Development status:** `v0.11.0-beta.7` is complete and frozen. BC Sentinel is still a development build and should not replace Microsoft Defender, Windows Firewall, or a production EDR on an everyday workstation.

## Latest accepted engineering checkpoint

The current accepted Beta7 source checkpoint is:

```text
v0.11.0-beta.7 — Detection Coverage & Incident Intelligence
checkpoint/v011-beta7-b77-pass
4d57f749276c588782147d47078ef4c52d1adc51
```

Final Beta7 acceptance completed successfully on Windows with:

- complete Beta5 + Beta6 + Beta7 regression green;
- **422 tests passed** in the local Windows gate;
- exact-head Windows CI: **PASS**;
- protected Beta6/B2 safety boundaries unchanged;
- deterministic final core snapshot;
- measured resource cost for the final synthetic acceptance pipeline.

The immutable Beta7 checkpoint must not be moved.

## What Beta7 added

Beta7 moves BC Sentinel beyond isolated security features toward connected, evidence-backed incident intelligence:

- **Attack Coverage Ledger** — machine-readable coverage status with no unsupported positive claims;
- **Sentinel Security Graph** — typed, provenance-preserving relationships between processes, files, scripts, persistence, DNS/network, detections, evidence, and actions;
- **Incident Correlation Engine** — deterministic grouping of related evidence into incidents;
- **Confidence Gate** — advisory `RECOMMEND`, `REVIEW_REQUIRED`, and `BLOCKED_INSUFFICIENT_EVIDENCE` outcomes without automatic execution authority;
- **Attack-Chain Acceptance Harness** — harmless in-memory validation of `PROCESS -> SCRIPT -> PERSISTENCE -> DNS -> DETECTION`;
- **Explainable Security** — user-level and technical explanations bound to accepted evidence;
- **Coverage Expansion Campaign** — explicit PARTIAL/GAP accounting instead of overstating detector coverage;
- **Final Windows Acceptance & Freeze** — full regression, resource measurement, and final immutable checkpoint.

## Current coverage snapshot

Beta7 deliberately does **not** convert synthetic evidence into VERIFIED detector coverage.

```text
PARTIAL   3
GAP       3
VERIFIED  0
```

Current PARTIAL scenario families:

- PowerShell / suspicious script abuse;
- persistence;
- suspicious DNS / network activity.

Current explicit GAP scenario families:

- ransomware-like behavior;
- defense evasion / control tampering;
- credential-access indicators.

Those gaps remain visible until dedicated harmless detector-path acceptance exists. A detector, UI element, or synthetic fixture alone is not treated as proof of production-grade protection.

## Safety boundary

Beta7 adds incident intelligence, not new automatic remediation authority.

```text
automatic quarantine          = false
automatic repair              = false
automatic restore             = false
general Home execution        = false
DELETE                        = false
REPAIR                        = false
TERMINATE_PROCESS             = false
TRUST/ALLOWLIST mutation      = false
privileged/system mutation    = false
```

`RECOMMEND` remains advisory. Missing evidence is never interpreted as proof of safety.

## What is on `main`

`main` remains the public launch-oriented stable source line and still contains the existing Windows stable launcher flow. The newer Beta7 engineering line is frozen separately at `checkpoint/v011-beta7-b77-pass` so accepted checkpoints remain immutable and auditable.

To inspect the exact accepted Beta7 source, use:

```text
checkpoint/v011-beta7-b77-pass
```

To review the completed Beta7 roadmap, open:

`BC_Sentinel_Roadmap_v0_11_0_Beta7.md` on the final Beta7 checkpoint/accepted branch.

## Start the current stable launcher on Windows

After cloning/downloading `main`, the simplest method is to double-click:

```text
START-BC-SENTINEL-STABLE.bat
```

or run from PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1
```

Self-check only:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1 -SelfCheckOnly
```

If dependencies are already installed and setup must stay offline:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1 -NoInstall
```

## Existing protection and recovery stack

The wider BC Sentinel codebase contains components for realtime/on-demand scanning, SHA-256/YARA/PE inspection, ransomware and behavior shields, encrypted quarantine workflows, ETW process/file/network attribution, firewall controls, signed threat intelligence, Web Protection, antispyware/persistence analysis, Rescue Technician workflows, reversible recovery foundations, and deterministic security acceptance tooling.

Not every component is represented as VERIFIED protection coverage. Current claims are intentionally limited to what the accepted gates actually prove.

## Roadmap status

```text
Beta5  COMPLETE / FROZEN
Beta6  COMPLETE / FROZEN
Beta7  COMPLETE / FROZEN
```

Beta7 milestones:

```text
B7-0  Coverage Ledger Foundation            PASS
B7-1  Sentinel Security Graph Foundation    PASS
B7-2  Incident Correlation Engine           PASS
B7-3  Confidence Gate                       PASS
B7-4  Attack-Chain Acceptance Harness       PASS
B7-5  Explainable Security                  PASS
B7-6  Coverage Expansion Campaign           PASS
B7-7  Windows Acceptance & Freeze           PASS
```

The next development phase has not yet been frozen as an accepted milestone. New work should branch from the immutable Beta7 final checkpoint rather than moving or rewriting accepted Beta7 history.

## Responsible testing

Use harmless fixtures, disposable VMs, and controlled offline targets. Do not deliberately expose an everyday workstation to live malware solely to test a development build.
