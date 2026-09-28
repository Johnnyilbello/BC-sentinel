# BC Sentinel

For installing the compiled Windows test build without Python, Git or winget,
see [Windows installation and QtWidgets startup repair](docs/WINDOWS-INSTALLATION.md).

BC Sentinel is a Windows endpoint-security, recovery, and incident-intelligence project focused on deterministic validation, conservative security claims, and explicit safety boundaries.

> **Development status:** Beta7 is complete and frozen. Beta8 is active, and **B8-0 — Beta8 Foundation + New Coverage Baseline** is accepted and frozen. BC Sentinel remains a development project and should not replace Microsoft Defender, Windows Firewall, or a production EDR on an everyday workstation.

## Latest accepted engineering checkpoint

```text
v0.11.0-beta.8 — B8-0 Foundation + New Coverage Baseline
checkpoint/v011-beta8-b80-pass
969781bd7633d0b2bc92840e8f12220f00de4279
```

B8-0 acceptance on Windows:

- compile gate: PASS;
- complete Beta5 + Beta6 + Beta7 predecessor regression: PASS;
- **450 tests passed** locally;
- exact-head Windows CI: PASS;
- protected B2 and accepted Beta7 intelligence sources unchanged;
- canonical single-roadmap rule: PASS;
- no remediation authority added.

## Current measurable coverage

```text
PARTIAL   3
GAP       3
VERIFIED  0
```

Current PARTIAL families:

- suspicious script / PowerShell abuse;
- persistence;
- suspicious DNS / network activity.

Current explicit GAP families and Beta8 verification targets:

- ransomware-like behavior;
- defense evasion / control tampering;
- credential-access indicators.

Synthetic evidence alone is never treated as VERIFIED detector coverage.

## Active development

The next security milestone is **B8-1 — Ransomware-like Detector Acceptance**. It must use harmless controlled fixtures and may promote ransomware coverage only after a reproducible detector-path acceptance.

The project has exactly one roadmap source of truth:

[**ROADMAP.md**](ROADMAP.md)

## Repository layout

The public root is intentionally compact. Historical milestone launchers, old acceptance scripts, diagnostic helpers, obsolete patches, historical checksums and superseded reports are kept in Git history/checkpoints rather than displayed in the repository root.

Primary root files:

- `README.md` — public project entry point;
- `ROADMAP.md` — single canonical roadmap and development-status source;
- `SECURITY.md` — security and responsible-disclosure guidance;
- `STABLE-RELEASE.md` — current stable-channel instructions;
- `STABLE_VERSION.json` — machine-readable stable-channel descriptor;
- `START-BC-SENTINEL-STABLE.bat` / `.ps1` — stable Windows launcher;
- `pyproject.toml` / `requirements.txt` — project/dependency metadata.

Core implementation and engineering assets live under folders such as `.github/`, `sentinel/`, `tests/`, `tools/`, and `packaging/`.

## Stable channel versus engineering checkpoints

The latest accepted **engineering** checkpoint is B8-0. The currently published stable launcher remains the separately documented B6-0 stable channel until a later release milestone explicitly promotes a newer build.

See [STABLE-RELEASE.md](STABLE-RELEASE.md) for stable-launch instructions.

## Safety boundary

Unless a future dedicated milestone explicitly expands authority and passes Windows acceptance, the following remain false:

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

## Start the current stable launcher on Windows

Double-click:

```text
START-BC-SENTINEL-STABLE.bat
```

or run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1
```

Self-check only:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\START-BC-SENTINEL-STABLE.ps1 -SelfCheckOnly
```

## Responsible testing

Use harmless fixtures, disposable VMs, and controlled offline targets. Do not deliberately expose an everyday workstation to live malware solely to test a development build.
