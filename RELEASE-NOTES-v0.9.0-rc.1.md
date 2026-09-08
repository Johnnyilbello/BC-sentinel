# BC Sentinel v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening

## Status correction — 8 September 2026

The earlier release note that described the 7 September RC artifact as fully frozen is **superseded by security checkpoint 4**.

The current v0.9.0-rc.1 source-of-record has:

- **578 passed, zero skipped**;
- checkpoint-3 updater hardening retained;
- checkpoint-4 Authenticode command-injection correction;
- OS PowerShell executable/module selection pinned;
- native Authenticode sub-gate PASS;
- local RC acceptance, fresh builds, compileall and artifact integrity PASS.

However, the current-build elevated foundation/live Protection Service/UAC/upgrade/repair/reboot gates remain **OPEN / DEFERRED**. Therefore v0.9.0-rc.1 is not currently claimed as a frozen or production-accepted release.

## Consolidation scope retained

- v0.9 Beta1 antispyware discovery/provenance model;
- v0.9 Beta2 reversible persistence-remediation and PUP/adware boundaries;
- v0.9 Beta3 PowerShell/script/LOLBin/fileless correlation;
- benign dual-use/admin false-positive matrix;
- strong multi-signal/deterministic detection retention;
- no automatic antimalware kill/delete/quarantine from advisory fileless evidence;
- explicit-approval-only persistence remediation.

Development may proceed to v0.10 while the native freeze debt remains documented, but later milestones must preserve all v0.9 and checkpoint-3/4 regressions.