# BC Sentinel — Current Stable Release

## Stable engine / UI checkpoint

The latest Windows-accepted stable source checkpoint is:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```

An immutable convenience branch also points to the same accepted source:

```text
stable/v011-beta6-b60
```

The accepted Beta5 Portable Technician engine remains the frozen rescue backend used by the B6-0 UI foundation.

## Start on Windows

Fastest path:

```text
START-BC-SENTINEL-STABLE.bat
```

or from PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1
```

The launcher:

1. verifies that the stable Technician UI and frozen Technician engine files exist;
2. creates `.venv` with Python 3.12+ if needed;
3. installs `requirements.txt` only when dependencies are missing;
4. runs the passive B6-0 UI self-check;
5. launches `sentinel.rescue_technician_ui`.

To validate without opening the GUI:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1 -SelfCheckOnly
```

If dependencies are already installed and network access must not be used during setup:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1 -NoInstall
```

## Stable safety state

B6-0 is a Technician UX foundation. At startup it remains passive:

- no automatic Rescue command dispatch;
- no automatic repair or quarantine;
- no unlock or mount-write action;
- no format or reimage execution;
- no registry/boot write authority;
- no target execution;
- no installer, Windows service or driver required by the Technician UI;
- frozen RR-6 outcomes and Beta5 trust rules remain authoritative.

## Development versus stable

`main` contains the accepted B6-0 source plus launch-only convenience files.

Development beyond B6-0 remains on feature branches until its Windows acceptance gate passes. In particular, B6-1 Target Discovery & Selection UX is not part of the stable release yet.
