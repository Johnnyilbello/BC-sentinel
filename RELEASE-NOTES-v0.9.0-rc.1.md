# BC Sentinel v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening

Release-candidate freeze completed on the target Windows machine on 2026-09-07. BC Sentinel remains a development preview and is not yet a production replacement for Microsoft Defender or the native Windows security stack.

## Consolidation scope

- freezes the v0.9 Beta1 antispyware discovery and provenance model;
- freezes the v0.9 Beta2 reversible persistence-remediation and PUP/adware safety boundaries;
- freezes the v0.9 Beta3 PowerShell/script/LOLBin and fileless correlation model;
- adds a dedicated v0.9 release-candidate acceptance gate;
- adds a benign dual-use/admin false-positive matrix that must remain below HIGH;
- verifies that strong multi-signal and deterministic chains still qualify HIGH/CRITICAL;
- preserves advisory-only advanced antimalware behavior: no automatic kill, delete or quarantine;
- preserves explicit-approval-only persistence remediation.

## Native acceptance result

The target Windows validation completed with:

- `pytest`: **482/482 PASS**;
- RC1 local acceptance: **PASS**;
- aggregate Windows foundation: **PASS**;
- Protection Service/UAC/firewall build: **PASS**;
- upgrade plan + protected upgrade: **PASS**;
- aggregate live-service acceptance: **PASS**;
- repair plan + protected repair: **PASS**;
- service-hardening benchmark: **PASS**;
- post-reboot live acceptance: **PASS**.

## False-positive hardening

Harmless or legitimate-looking PowerShell, CertUtil, MSIExec, BITSAdmin and browser/Office-to-PowerShell scenarios remain bounded below HIGH. Routine administrative cases remain SAFE. This is not implemented as a blanket allowlist for dual-use binaries, so converging malicious evidence remains detectable.

## Freeze policy

The v0.9 safety boundaries are now frozen regression requirements for v0.10 and later development. A future feature may not weaken these gates merely to make a new acceptance suite pass.
