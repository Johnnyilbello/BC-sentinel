# BC Sentinel

BC Sentinel is a Windows endpoint-security, recovery, and incident-intelligence project focused on deterministic validation, conservative security claims, and explicit safety boundaries.

> **Development status:** `v0.11.0-beta.7` is complete and frozen. Beta8 is now the active development line. BC Sentinel is still a development build and should not replace Microsoft Defender, Windows Firewall, or a production EDR on an everyday workstation.

## Latest accepted engineering checkpoint

The current accepted source checkpoint is:

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

Beta7 moved BC Sentinel beyond isolated security features toward connected, evidence-backed incident intelligence:

- **Attack Coverage Ledger** — machine-readable coverage status with no unsupported positive claims;
- **Sentinel Security Graph** — typed, provenance-preserving relationships between processes, files, scripts, persistence, DNS/network, detections, evidence, and actions;
- **Incident Correlation Engine** — deterministic grouping of related evidence into incidents;
- **Confidence Gate** — advisory `RECOMMEND`, `REVIEW_REQUIRED`, and `BLOCKED_INSUFFICIENT_EVIDENCE` outcomes without automatic execution authority;
- **Attack-Chain Acceptance Harness** — harmless in-memory validation of `PROCESS -> SCRIPT -> PERSISTENCE -> DNS -> DETECTION`;
- **Explainable Security** — user-level and technical explanations bound to accepted evidence;
- **Coverage Expansion Campaign** — explicit PARTIAL/GAP accounting instead of overstating detector coverage;
- **Final Windows Acceptance & Freeze** — full regression, resource measurement, and final immutable checkpoint.

## Current measurable coverage

```text
PARTIAL   3
GAP       3
VERIFIED  0
```

PARTIAL scenario families:

- suspicious script / PowerShell abuse;
- persistence;
- suspicious DNS / network activity.

Explicit GAP scenario families:

- ransomware-like behavior;
- defense evasion / control tampering;
- credential-access indicators.

Synthetic evidence alone is never treated as VERIFIED detector coverage.

## Active development: Beta8

Beta8 is **Verified Detection & Predictive Defense**. The first milestone is `B8-0 — Beta8 Foundation + New Coverage Baseline`, which starts from the immutable Beta7 checkpoint and establishes the machine-readable baseline that all new detector verification work must inherit.

The project has exactly one roadmap source of truth:

[**ROADMAP.md**](ROADMAP.md)

## Repository documentation

The repository root is intentionally kept compact for people landing on the project page. Root Markdown documentation is limited to:

- `README.md` — public project entry point;
- `ROADMAP.md` — the single canonical roadmap and development-status source;
- `SECURITY.md` — security and responsible-disclosure guidance;
- `STABLE-RELEASE.md` — current stable release notes/instructions.

Historical milestone reports, implementation-status files, acceptance reports, old test readmes, source-sync notes and superseded release notes are removed from the active working tree. Their history remains recoverable through Git commits and immutable checkpoint refs.

## Safety boundary

Beta7 and the opening Beta8 foundation add intelligence and verification structure, not new automatic remediation authority.

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

`main` is the public landing/source line and contains the stable Windows launcher plus the current public project documentation. Accepted engineering checkpoints remain separate immutable refs for auditability.

To inspect the exact accepted Beta7 source, use:

```text
checkpoint/v011-beta7-b77-pass
```

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

Not every component is represented as VERIFIED protection coverage. Current claims are intentionally limited to what accepted gates actually prove.

## Current roadmap state

```text
Beta5  COMPLETE / FROZEN
Beta6  COMPLETE / FROZEN
Beta7  COMPLETE / FROZEN
Beta8  IN PROGRESS
```

See [ROADMAP.md](ROADMAP.md) for the canonical milestone state and next acceptance gate.

## Responsible testing

Use harmless fixtures, disposable VMs, and controlled offline targets. Do not deliberately expose an everyday workstation to live malware solely to test a development build.
