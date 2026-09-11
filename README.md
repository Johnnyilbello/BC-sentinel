# BC Sentinel

BC Sentinel is a Windows endpoint-security and recovery project under active development. The repository includes the accepted Rescue Technician backend, the stable Beta6 Technician UI foundation, deterministic acceptance gates, packaging scripts, and historical roadmap/report evidence.

> BC Sentinel is still a development build. It should not replace Microsoft Defender, Windows Firewall, or a production EDR on an everyday workstation.

## Current stable version

The latest Windows-accepted stable source checkpoint is:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```

The stable Rescue backend underneath the UI is the frozen Beta5 Portable Technician Release. B6-0 adds the validated PySide6 technician shell without changing the accepted Rescue trust model or exposing new destructive authority.

`main` contains that accepted B6-0 source plus launch-only convenience files. Development beyond B6-0 remains on feature branches until the corresponding Windows gate passes.

## Start the stable build on Windows

The simplest method after cloning/downloading the repository is to double-click:

```text
START-BC-SENTINEL-STABLE.bat
```

or run from PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1
```

The launcher:

1. verifies that the stable Technician UI and frozen Technician engine files are present;
2. creates a local `.venv` with Python 3.12+ if needed;
3. installs `requirements.txt` only when dependencies are missing;
4. runs the passive B6-0 self-check;
5. launches the stable Rescue Technician UI.

Self-check only:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1 -SelfCheckOnly
```

If dependencies are already installed and setup must stay offline:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1 -NoInstall
```

Direct Python entrypoint:

```powershell
.\.venv\Scripts\python.exe -m sentinel.rescue_technician_ui
```

## Stable safety contract

B6-0 starts passively and preserves the frozen Beta5/Beta3 trust boundaries:

```text
automatic rescue dispatch      = false
automatic repair               = false
automatic quarantine           = false
repair-execute exposed         = false
unlock exposed                 = false
mount-write exposed            = false
format execution               = false
reimage execution              = false
registry/boot write authority  = false
target execution               = false
```

RR-6 remains authoritative. `RECOVERED`, `NOT_RECOVERED`, and `INDETERMINATE_REFUSED` are preserved exactly; refusal is never transformed into success.

## Accepted Rescue line

The current stable Rescue line includes:

- offline target discovery and validation;
- hostile/damaged-system assessment;
- bounded large-scale stress probing;
- crash-safe session journal and resume logic;
- advisory recovery decision engine;
- technician report and SHA-256 evidence package;
- controlled real-PC acceptance framework;
- portable Technician Release;
- Beta6 PySide6 Technician UX foundation.

The accepted Beta5 final gate reached 321 cumulative tests. B6-0 added 16 UI-foundation tests and passed its Windows acceptance gate, for 337 cumulative covered tests at the current stable checkpoint.

## Stable and development branches

Stable references:

```text
checkpoint/v011-beta6-b60-pass
stable/v011-beta6-b60
```

Current development work after the stable checkpoint is kept separate. B6-1 Target Discovery & Selection UX is not part of the stable release until its Windows acceptance gate is completed and frozen.

## Repository entrypoints

Important files for the stable build:

```text
START-BC-SENTINEL-STABLE.bat
START-BC-SENTINEL-STABLE.ps1
requirements.txt
sentinel/rescue_technician_ui.py
sentinel/rescue_technician_ui_model.py
sentinel/rescue_technician_portable.py
packaging/rescue_technician_ui_entry.py
STABLE-RELEASE.md
```

For the exact stable checkpoint, launch instructions, and safety state, see `STABLE-RELEASE.md`.

## Existing protection stack

The wider BC Sentinel codebase also contains realtime/on-demand scanning, SHA-256/YARA/PE inspection, ransomware and behavior shields, encrypted quarantine workflows, Windows Protection Service components, ETW process/file/network attribution, firewall controls, signed threat intelligence, Web Protection, antispyware/persistence analysis, and reversible remediation foundations.

## Responsible testing

Use harmless fixtures, disposable VMs, and controlled offline targets. Do not deliberately expose an everyday workstation to live malware solely to test a development build.
