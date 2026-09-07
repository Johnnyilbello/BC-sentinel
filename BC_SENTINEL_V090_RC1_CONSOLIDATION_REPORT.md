# BC Sentinel v0.9.0-rc.1 — Consolidation & Native Hardening Report

## Goal

Close the v0.9 Antispyware & Advanced Antimalware macro-phase without adding a new enforcement class. The RC focuses on regression freeze, false-positive resistance and native Windows validation.

## Frozen v0.9 invariants

- persistence discovery remains explainable and provenance-backed;
- persistence-only heuristics cannot independently become destructive malware verdicts;
- remediation remains reversible, HMAC-authenticated, anti-race checked and explicitly approved;
- WMI/DNS/proxy remediation remains review-only where safe reversibility is not established;
- one PowerShell/script/LOLBin identity or one evidence family is insufficient for HIGH;
- HIGH behavioral qualification requires converging evidence families or qualified deterministic evidence;
- advanced antimalware remains advisory and never automatically terminates processes, deletes files or quarantines content;
- core local protection remains independent of cloud availability.

## RC gates

The dedicated `tools.v090_release_candidate_acceptance` gate exercises:

1. the frozen v0.8 release-candidate regression baseline;
2. v0.9 Beta1 antispyware acceptance;
3. v0.9 Beta2 reversible-remediation acceptance;
4. v0.9 Beta3 advanced-antimalware/fileless acceptance;
5. a benign dual-use/admin false-positive matrix;
6. strong multi-signal and deterministic detection-retention checks;
7. optional live Protection Service validation.

## Native validation result

The target Windows machine completed the release matrix successfully on 2026-09-07: 482/482 Python tests, aggregate foundation, native build, upgrade, live-service aggregate acceptance, repair, service-hardening benchmark and post-reboot live acceptance all passed.

The v0.9 line is therefore frozen as an accepted regression baseline for subsequent development.
