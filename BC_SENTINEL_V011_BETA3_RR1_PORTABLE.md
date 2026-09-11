# BC Sentinel v0.11.0-beta.3 — RR-1 Portable

## Goal
RR-1 delivers the first operational Rescue runtime that can be copied to trusted external media and launched on a Windows machine without installing BC Sentinel.

RR-1 is intentionally read-only against the target system. It is an acquisition/inspection milestone, not a repair milestone.

## Runtime contract
- no installer required;
- no Windows service installation;
- no driver installation;
- no registry or boot writes;
- no target filesystem writes;
- no file deletion or process termination;
- no network/cloud dependency;
- no repair execution, quarantine execution or recovery certification;
- RR-0 safety policy remains authoritative.

## Portable acquisition
`sentinel/rescue_portable.py` performs bounded read-only enumeration and SHA-256 evidence acquisition.

Default limits:
- max 2,000 files per run;
- max 32 MiB per file;
- hard caps 10,000 files / 64 MiB per file;
- symlinks are not followed;
- filesystem read/stat errors are contained and represented as evidence status instead of aborting the full run.

Evidence is written only to an operator-selected output directory that must be outside the target tree. The target files are never modified.

## Windows package
`BUILD-RESCUE-PORTABLE.ps1` creates a PyInstaller `onedir` package:

`dist/Rescue/BC-Sentinel-Rescue-Portable/`

`onedir` is preferred for RR-1 because it avoids onefile extraction into a potentially compromised TEMP directory, improves startup predictability from USB media and makes binary/file provenance easier to inspect.

A SHA-256 `portable-integrity.json` manifest is generated beside the executable.

## Acceptance
`TEST-V011-BETA3-RR1.ps1` must pass from normal non-elevated PowerShell and verifies:
- RR-0 safety regression;
- RR-1 unit/safety tests;
- deterministic Python acceptance;
- real PyInstaller portable build;
- portable executable provenance hash;
- real standard-user launch;
- harmless target content unchanged before/after acquisition;
- expected SHA-256 evidence produced;
- no service registration;
- all destructive/write/repair flags remain false.

RR-1 is accepted only after the authoritative FULL Windows run reaches:

`BC SENTINEL v0.11.0-beta.3 RR-1 PORTABLE - PASS`

## Deferred
RR-1 does not claim malware removal, offline repair, boot recovery, Safe Data Rescue or recovery certification. Those remain RR-2 through RR-6 milestones.